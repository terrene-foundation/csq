//! Shared managed-daemon lifecycle implementation for both app surfaces.
#[cfg(target_os = "macos")]
use anyhow::Context;
use anyhow::Result;
use std::path::{Path, PathBuf};

/// The managed launchd job's label. The plist builder emits this same literal;
/// `launchd_label_matches_plist` pins the two together so this probe can never
/// drift into confidently answering about a job that does not exist.
#[cfg(any(target_os = "macos", all(test, feature = "cli")))]
pub(crate) const LAUNCHD_LABEL: &str = csq_core::daemon::recovery::LAUNCHD_LABEL;

#[cfg(target_os = "macos")]
pub(crate) fn launchd_plist_path() -> Result<std::path::PathBuf> {
    let home =
        csq_core::platform::home::home_dir().context("could not determine home directory")?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join("foundation.terrene.csq.plist"))
}

/// Whether this user's managed daemon plist is installed on disk.
#[cfg(all(target_os = "macos", feature = "cli"))]
pub(crate) fn managed_daemon_plist_exists() -> bool {
    launchd_plist_path().is_ok_and(|path| path.exists())
}

/// The disposition of an existing managed plist before desktop repair.
#[cfg(any(all(target_os = "macos", feature = "desktop"), test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaleManagedPlistOutcome {
    NoPlist,
    RetainedVerified,
    RetainedUnverifiable,
    RetainedInvalid,
    ReadFailed,
    AlreadyUnloaded,
}

#[cfg(any(all(target_os = "macos", feature = "desktop"), test))]
impl StaleManagedPlistOutcome {
    /// Fixed receipt/log tags; errors never become fabricated successful repairs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoPlist => "no_plist",
            Self::RetainedVerified => "retained_verified",
            Self::RetainedUnverifiable => "retained_unverifiable",
            Self::RetainedInvalid => "retained_invalid",
            Self::ReadFailed => "read_failed",
            Self::AlreadyUnloaded => "already_unloaded",
        }
    }
}

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagedJobState {
    Loaded,
    Unloaded,
    Unknown,
}

#[cfg(any(target_os = "macos", test))]
fn managed_job_state_from_probe(
    result: csq_core::cli_deps::cli_shim::ProbeOutcome<i32>,
) -> ManagedJobState {
    use csq_core::cli_deps::cli_shim::ProbeOutcome;
    match result {
        ProbeOutcome::Ok(0) => ManagedJobState::Loaded,
        // Measured read-only on macOS: `launchctl list <absent-label>` exits
        // 113 (service not found). Other failures do not establish absence.
        ProbeOutcome::Ok(113) => ManagedJobState::Unloaded,
        _ => ManagedJobState::Unknown,
    }
}

#[cfg(all(target_os = "macos", feature = "test-utils"))]
pub(crate) fn managed_launchd_probe_label(override_label: Option<std::ffi::OsString>) -> String {
    managed_launchd_probe_label_for_build(override_label, cfg!(any(debug_assertions, test)))
}

#[cfg(any(
    all(target_os = "macos", feature = "test-utils"),
    all(test, feature = "cli")
))]
fn managed_launchd_probe_label_for_build(
    override_label: Option<std::ffi::OsString>,
    fixture_allowed: bool,
) -> String {
    // Release binaries always observe the canonical job, even with test-utils.
    if !fixture_allowed {
        return LAUNCHD_LABEL.to_owned();
    }
    let Some(override_label) = override_label else {
        return LAUNCHD_LABEL.to_owned();
    };
    let label = override_label
        .into_string()
        .expect("invalid CSQ_TEST_LAUNCHD_LABEL: fixture label must be Unicode");
    assert!(
        label.starts_with("csq.fixture.doctor.")
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
        "invalid CSQ_TEST_LAUNCHD_LABEL: only restricted fixture labels are allowed"
    );
    label
}

#[cfg(target_os = "macos")]
pub(crate) fn managed_launchd_job_state() -> ManagedJobState {
    let mut command = std::process::Command::new("/bin/launchctl");
    // The private binary fixture queries only its unique absent label; production
    // builds always inspect the canonical job and never mutate launchd here.
    #[cfg(feature = "test-utils")]
    let label = managed_launchd_probe_label(std::env::var_os("CSQ_TEST_LAUNCHD_LABEL"));
    #[cfg(not(feature = "test-utils"))]
    let label = LAUNCHD_LABEL;
    command.arg("list").arg(label);
    managed_job_state_from_probe(csq_core::cli_deps::cli_shim::probe_command_exit_code(
        command,
    ))
}

/// Inspect the on-disk managed plist without changing its loaded job.
///
/// `ProgramArguments[0]` may differ from launchd's loaded configuration or a
/// `Program` override, so its verification never authorizes stopping a job.
/// Reuses final verification when the disk path matches the refreshed target.
/// Only the admitted repair flow may change the managed job's lifecycle.
#[cfg(all(target_os = "macos", feature = "desktop"))]
fn inspect_managed_daemon_plist(
    target: Option<&Path>,
    target_verification: &csq_core::cli_deps::cli_shim::InstalledCliVerification,
    policy: &csq_core::cli_deps::cli_shim::SignerPolicy,
) -> StaleManagedPlistOutcome {
    let Ok(plist_path) = launchd_plist_path() else {
        return StaleManagedPlistOutcome::ReadFailed;
    };
    inspect_managed_daemon_plist_with(
        target,
        target_verification,
        || read_managed_daemon_program(&plist_path),
        |program| csq_core::cli_deps::cli_shim::installed_cli_verification(program, policy),
        managed_launchd_job_state,
    )
}

#[cfg(any(all(target_os = "macos", feature = "desktop"), test))]
fn inspect_managed_daemon_plist_with(
    target: Option<&Path>,
    target_verification: &csq_core::cli_deps::cli_shim::InstalledCliVerification,
    read_program: impl FnOnce() -> Result<Option<PathBuf>>,
    mut verify: impl FnMut(&Path) -> csq_core::cli_deps::cli_shim::InstalledCliVerification,
    job_state: impl FnOnce() -> ManagedJobState,
) -> StaleManagedPlistOutcome {
    use csq_core::cli_deps::cli_shim::InstalledCliVerification;
    let program = match read_program() {
        Ok(Some(program)) => program,
        Ok(None) => return StaleManagedPlistOutcome::NoPlist,
        Err(_) => return StaleManagedPlistOutcome::ReadFailed,
    };
    let verification = if target == Some(program.as_path()) {
        target_verification.clone()
    } else {
        verify(&program)
    };
    match verification {
        InstalledCliVerification::Verified(_) => StaleManagedPlistOutcome::RetainedVerified,
        InstalledCliVerification::Unverifiable => StaleManagedPlistOutcome::RetainedUnverifiable,
        InstalledCliVerification::Invalid => match job_state() {
            ManagedJobState::Unloaded => StaleManagedPlistOutcome::AlreadyUnloaded,
            ManagedJobState::Unknown => StaleManagedPlistOutcome::RetainedUnverifiable,
            ManagedJobState::Loaded => StaleManagedPlistOutcome::RetainedInvalid,
        },
    }
}

/// Gate all lifecycle changes on the refreshed CLI's final admission. Disk
/// inspection still records uncertainty, but cannot stop the existing daemon.
#[cfg(all(target_os = "macos", feature = "desktop"))]
pub(crate) fn repair_managed_daemon_plist_after_refresh(
    target: Option<&Path>,
    verified: &csq_core::cli_deps::cli_shim::InstalledCliVerification,
    refresh_failed: bool,
    expected_version_line: &str,
    policy: &csq_core::cli_deps::cli_shim::SignerPolicy,
) -> (String, String) {
    repair_managed_daemon_plist_after_refresh_with(
        target.is_some_and(Path::exists),
        verified,
        refresh_failed,
        expected_version_line,
        || inspect_managed_daemon_plist(target, verified, policy),
        || {
            let exe = target.context("managed_daemon_binary_unavailable")?;
            ensure_managed_daemon_plist_for(exe.to_path_buf())
        },
        managed_daemon_dormant,
    )
}

#[cfg(all(target_os = "macos", any(feature = "desktop", test)))]
fn repair_managed_daemon_plist_after_refresh_with(
    target_exists: bool,
    verified: &csq_core::cli_deps::cli_shim::InstalledCliVerification,
    refresh_failed: bool,
    expected_version_line: &str,
    inspect: impl FnOnce() -> StaleManagedPlistOutcome,
    ensure: impl FnOnce() -> Result<ManagedPlistOutcome>,
    dormant: impl FnOnce() -> Option<bool>,
) -> (String, String) {
    let rejection = csq_core::cli_deps::cli_shim_refresh::managed_plist_rejection(
        target_exists,
        refresh_failed,
        verified.version_line(),
        expected_version_line,
    );
    let stale = inspect();
    let decision = if let Some(reason) = rejection {
        reason
    } else {
        match ensure() {
            Ok(ManagedPlistOutcome::Installed) => "installed",
            Ok(ManagedPlistOutcome::Repaired) => "repaired",
            Ok(ManagedPlistOutcome::AlreadyCurrent) => {
                if dormant() == Some(true) {
                    "daemon_dormant"
                } else {
                    "already_current"
                }
            }
            Err(_) => "install_failed",
        }
    };
    (decision.into(), stale.as_str().into())
}

/// System plutil handles XML entities, binary plists, and dictionary structure;
/// JSON string decoding preserves even whitespace/newlines in executable paths.
/// Extract the array: plutil's JSON serializer rejects a scalar string root.
#[cfg(all(target_os = "macos", any(feature = "desktop", test)))]
fn read_managed_daemon_program(plist_path: &Path) -> Result<Option<PathBuf>> {
    match std::fs::metadata(plist_path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => anyhow::bail!("managed_plist_not_regular"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => anyhow::bail!("managed_plist_read_failed"),
    }
    let mut command = std::process::Command::new("/usr/bin/plutil");
    command
        .args(["-extract", "ProgramArguments", "json", "-o", "-", "--"])
        .arg(plist_path);
    match csq_core::cli_deps::cli_shim::probe_command(command) {
        csq_core::cli_deps::cli_shim::ProbeOutcome::Ok(output) => {
            let programs: Vec<String> =
                serde_json::from_slice(&output).context("managed_plist_program_invalid")?;
            let program = programs
                .into_iter()
                .next()
                .context("managed_plist_program_missing")?;
            let program = PathBuf::from(program);
            if !program.is_absolute() {
                anyhow::bail!("managed_plist_program_not_absolute");
            }
            Ok(Some(program))
        }
        _ => anyhow::bail!("managed_plist_read_failed"),
    }
}

/// Build the launchd plist XML for the given binary path and log path.
/// Exported for unit-testing the generated XML.
///
/// The MANAGED form (daemon-auth-resilience Wave B):
/// - `ProgramArguments` runs `<exe> daemon start --supervised` — the
///   crash-restart supervisor loop, NOT the foreground daemon.
/// - `KeepAlive={SuccessfulExit:false}` restarts the process ONLY on a
///   non-zero/crash exit; a clean `csq daemon stop` (SIGTERM → exit 0)
///   stays stopped.
/// - `ThrottleInterval=10` bounds launchd's respawn rate under a crash
///   loop (its own floor is 10s; stated explicitly for clarity).
///
/// `exe` MUST be a real file OUTSIDE the app bundle (see
/// [`resolve_managed_daemon_exe`]) — a bundle path is misdetected as
/// Desktop mode by `mode::detect()` and would launch the whole app.
#[cfg(target_os = "macos")]
pub(crate) fn build_launchd_plist(exe: &Path, log_path: &Path) -> String {
    // XML-escape: launchd plists are XML 1.0. An unescaped `&`/`<`/`>` in a
    // path (relocated $HOME, unusual install dir) yields a malformed plist
    // that `launchctl load` rejects — which, via the best-effort desktop
    // caller, silently skips the managed-daemon install. Escaping keeps the
    // plist well-formed for ANY path and closes a same-UID injection vector
    // now that the exe can originate from a PATH walk.
    let exe_str = xml_escape(&exe.display().to_string());
    let log_str = xml_escape(&log_path.display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>foundation.terrene.csq</string>
	<key>ProgramArguments</key>
	<array>
		<string>{exe_str}</string>
		<string>daemon</string>
		<string>start</string>
		<string>--supervised</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>ProcessType</key>
	<string>Adaptive</string>
	<key>StandardOutPath</key>
	<string>{log_str}</string>
	<key>StandardErrorPath</key>
	<string>{log_str}</string>
</dict>
</plist>
"#
    )
}

/// Minimal XML text escaper for plist `<string>` values (XML 1.0).
#[cfg(target_os = "macos")]
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Resolve the binary path to bake into the managed plist's
/// `ProgramArguments[0]`.
///
/// MUST be a real file OUTSIDE the app bundle so `mode::detect()`
/// resolves it to CLI mode: a bundle path (`.../Contents/MacOS/csq`) is
/// misdetected as Desktop mode by [`crate::mode::detect`] and would
/// launch the whole desktop app instead of the daemon (an internal journal entry).
///
/// Prefers the current executable when it is a standalone CLI binary;
/// otherwise resolves the persistent shim. CLI admission verifies either
/// candidate before the writer is called. Desktop supplies its vetted target.
#[cfg(all(target_os = "macos", feature = "cli"))]
fn resolve_managed_daemon_exe() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        let s = exe.to_string_lossy();
        let in_bundle =
            s.contains("/Contents/MacOS/") || s.contains(".app/") || s.contains(".AppImage");
        if !in_bundle && exe.is_file() {
            return Some(exe);
        }
    }
    csq_core::cli_deps::cli_shim::resolve_shim_target()
}

/// Outcome of an idempotent managed-plist install/repair.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagedPlistOutcome {
    /// Plist was absent and has been written + loaded.
    Installed,
    /// Existing plist drifted or its matching launchd job was unloaded; reloaded.
    Repaired,
    /// Plist already matched and the launchd job was loaded; nothing changed.
    AlreadyCurrent,
}

/// Idempotently installs or repairs the launchd-managed daemon plist
/// (daemon-auth-resilience Wave B). Safe to call on every desktop launch:
/// - Absent → write + `launchctl load` → [`ManagedPlistOutcome::Installed`].
/// - Present but drifted + loaded → canonical service bootout + rewrite + reload → repaired.
/// - Present but drifted + unloaded → rewrite + load → repaired.
/// - Present + byte-identical + loaded → [`ManagedPlistOutcome::AlreadyCurrent`].
/// - Present + byte-identical + unloaded → load → [`ManagedPlistOutcome::Repaired`].
/// - Present + unknown job state → error, retaining the plist.
///
/// The managed plist runs `<shim> daemon start --supervised` under
/// `KeepAlive={SuccessfulExit:false}`, so the token refresher survives
/// the desktop app quitting or crashing — the structural fix for the
/// mass-token-expiry incident (an internal journal entry).
///
/// CLI installation returns errors to its caller. Desktop repair uses its
/// separately admitted best-effort refresh entrypoint.
#[cfg(all(target_os = "macos", feature = "cli"))]
pub(crate) fn ensure_managed_daemon_plist() -> Result<ManagedPlistOutcome> {
    let exe = resolve_managed_daemon_exe().context("managed_daemon_binary_unavailable")?;
    let policy = if crate::BUILD_EDITION == "enterprise" {
        csq_core::cli_deps::cli_shim::SignerPolicy::PinTrustedTeam
    } else {
        csq_core::cli_deps::cli_shim::SignerPolicy::AnySignature
    };
    let verified = csq_core::cli_deps::cli_shim::installed_cli_verification(&exe, &policy);
    ensure_managed_daemon_plist_admitted(exe.is_file(), &verified, crate::VERSION_LINE, || {
        ensure_managed_daemon_plist_for(exe)
    })
}

/// Admission precedes every CLI install write, including a resolved shim fallback.
/// Private callback exists only for injected, non-native fixtures.
#[cfg(any(all(target_os = "macos", feature = "cli"), test))]
fn ensure_managed_daemon_plist_admitted<T>(
    target_exists: bool,
    verified: &csq_core::cli_deps::cli_shim::InstalledCliVerification,
    expected_version_line: &str,
    ensure: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if let Some(reason) = csq_core::cli_deps::cli_shim_refresh::managed_plist_rejection(
        target_exists,
        false,
        verified.version_line(),
        expected_version_line,
    ) {
        anyhow::bail!(reason);
    }
    ensure()
}

/// `ensure_managed_daemon_plist` with the daemon binary supplied by the caller
/// (the desktop passes the shim target it just refreshed and vetted, so the plist
/// can never point at a different path than the one the gate checked).
/// No fallback resolution occurs after admission.
#[cfg(target_os = "macos")]
fn ensure_managed_daemon_plist_for(exe: PathBuf) -> Result<ManagedPlistOutcome> {
    let plist_path = launchd_plist_path()?;
    let home =
        csq_core::platform::home::home_dir().context("could not determine home directory")?;
    // Same helper the detached mode uses, so the two cannot drift onto
    // different files and leave an operator reading a log nothing writes.
    let log_path = super::daemon_log_path(&home.join(".claude").join("accounts"));
    // SAFETY: geteuid takes no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    ensure_managed_daemon_plist_at(
        &plist_path,
        &exe,
        &log_path,
        euid,
        managed_launchd_job_state,
        run_managed_launchctl_command,
    )
}

/// The actual production wiring with paths and command execution supplied.
/// The test seam injects execution and loaded identity, never the command factory.
#[cfg(target_os = "macos")]
fn ensure_managed_daemon_plist_at(
    plist_path: &Path,
    exe: &Path,
    log_path: &Path,
    euid: u32,
    job_state: impl FnMut() -> ManagedJobState,
    execute: impl FnMut(std::process::Command) -> Result<()>,
) -> Result<ManagedPlistOutcome> {
    ensure_managed_daemon_plist_at_with_identity(
        plist_path,
        exe,
        log_path,
        euid,
        job_state,
        execute,
        managed_daemon_rollback_identity_checker(),
    )
}

/// Production merge, command construction and repair flow; tests also inject
/// loaded-job identity so they never inspect the host's launchd domain.
#[cfg(target_os = "macos")]
fn ensure_managed_daemon_plist_at_with_identity(
    plist_path: &Path,
    exe: &Path,
    log_path: &Path,
    euid: u32,
    mut job_state: impl FnMut() -> ManagedJobState,
    mut execute: impl FnMut(std::process::Command) -> Result<()>,
    rollback_identity: impl FnMut(&Path, bool) -> bool,
) -> Result<ManagedPlistOutcome> {
    let expected = build_launchd_plist(exe, log_path);
    let expected = match merge_managed_daemon_plist(plist_path, &expected) {
        Ok(merged) => merged,
        Err(error) if error.is::<UnparseableManagedPlist>() => {
            // Only a bounded regular-file parse failure may discard old bytes,
            // and only definite job absence admits that recovery.
            if job_state() != ManagedJobState::Unloaded {
                return Err(error);
            }
            expected.into_bytes()
        }
        Err(error) => return Err(error),
    };
    ensure_managed_daemon_plist_with_operations(
        plist_path,
        &expected,
        job_state,
        |operation, path| execute(managed_daemon_launchctl_command(operation, path, euid)?),
        rollback_identity,
        |_from, to, writer| writer.replace(to).map_err(Into::into),
    )
}

/// Distinct from read, staging, execution-override and serializer failures.
#[cfg(target_os = "macos")]
#[derive(Debug, thiserror::Error)]
#[error("managed_plist_merge_unparseable")]
struct UnparseableManagedPlist;

/// Preserve Foundation plist types and every user-owned key. ProcessType is
/// a creation default except legacy csq Background, which migrates to Adaptive.
/// Other user-only changes return the exact original bytes.
#[cfg(target_os = "macos")]
fn merge_managed_daemon_plist(plist_path: &Path, expected: &str) -> Result<Vec<u8>> {
    const LIMIT: u64 = 1024 * 1024;
    match std::fs::symlink_metadata(plist_path) {
        Ok(metadata) if metadata.file_type().is_file() && metadata.len() <= LIMIT => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(expected.as_bytes().to_vec())
        }
        _ => anyhow::bail!("managed_plist_merge_input_invalid"),
    }
    let read_bounded = |path: &Path| -> Result<Vec<u8>> {
        use std::io::Read;
        let file = std::fs::File::open(path).context("managed_plist_merge_read_failed")?;
        let mut bytes = Vec::new();
        file.take(LIMIT + 1)
            .read_to_end(&mut bytes)
            .context("managed_plist_merge_read_failed")?;
        if bytes.len() as u64 > LIMIT {
            anyhow::bail!("managed_plist_merge_size_exceeded");
        }
        Ok(bytes)
    };
    let original = read_bounded(plist_path)?;
    let mut staged = Vec::new();
    let result = (|| -> Result<Vec<u8>> {
        for bytes in [original.as_slice(), expected.as_bytes(), &[]] {
            staged.push(stage_managed_daemon_plist(plist_path, bytes)?);
        }
        // These files may contain user environment values: all are exclusive
        // 0600 stages, no values enter argv/logs, and every exit removes them.
        // NSData option 0 writes directly into our existing private output;
        // no Foundation atomic-write temporary is created with default modes.
        const SCRIPT: &str = r#"ObjC.import('Foundation');
function run(a){
var original=$.NSData.dataWithContentsOfFile($(a[0]));
if(ObjC.unwrap(original)==null)throw new Error('read failed');
var old=$.NSPropertyListSerialization.propertyListWithDataOptionsFormatError(original,0,null,null);
if(ObjC.unwrap(old)==null||!old.isKindOfClass($.NSDictionary))return JSON.stringify({unparseable:true});
var expected=$.NSDictionary.dictionaryWithContentsOfFile($(a[1]));
if(ObjC.unwrap(expected)==null)throw new Error('invalid expected plist');
['Program','RootDirectory','BundleProgram'].forEach(function(k){if(ObjC.unwrap(old.objectForKey($(k)))!=null)throw new Error('execution override');});
var merged=old.mutableCopy;var matches=true;
['Label','ProgramArguments','RunAtLoad','KeepAlive','ThrottleInterval','StandardOutPath','StandardErrorPath'].forEach(function(k){
var before=old.objectForKey($(k));var after=expected.objectForKey($(k));
function typed(v){return $.NSPropertyListSerialization.dataWithPropertyListFormatOptionsError($.NSArray.arrayWithObject(v),$.NSPropertyListXMLFormat_v1_0,0,null);}
if(ObjC.unwrap(before)==null||!typed(before).isEqualToData(typed(after)))matches=false;
merged.setObjectForKey(after,$(k));});
if(ObjC.unwrap(old.objectForKey($('ProcessType'))) === 'Background'){
merged.setObjectForKey($('Adaptive'),$('ProcessType'));matches=false;}
if(!matches){var data=$.NSPropertyListSerialization.dataWithPropertyListFormatOptionsError(merged,$.NSPropertyListXMLFormat_v1_0,0,null);
if(ObjC.unwrap(data)==null||!data.writeToFileOptionsError($(a[2]),0,null))throw new Error('serialize failed');}
return JSON.stringify({matches:matches});}"#;
        let mut command = std::process::Command::new("/usr/bin/osascript");
        command.args(["-l", "JavaScript", "-e", SCRIPT]);
        command.args(&staged);
        let csq_core::cli_deps::cli_shim::ProbeOutcome::Ok(output) =
            csq_core::cli_deps::cli_shim::probe_command(command)
        else {
            anyhow::bail!("managed_plist_merge_failed");
        };
        let response: serde_json::Value =
            serde_json::from_slice(&output).context("managed_plist_merge_response_invalid")?;
        if response
            .get("unparseable")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            return Err(UnparseableManagedPlist.into());
        }
        let matches = response
            .get("matches")
            .and_then(serde_json::Value::as_bool)
            .context("managed_plist_merge_response_invalid")?;
        if matches {
            return Ok(original);
        }
        let metadata =
            std::fs::symlink_metadata(&staged[2]).context("managed_plist_merge_output_missing")?;
        use std::os::unix::fs::PermissionsExt;
        if !metadata.file_type().is_file()
            || metadata.len() > LIMIT
            || metadata.permissions().mode() & 0o077 != 0
        {
            anyhow::bail!("managed_plist_merge_output_invalid");
        }
        read_bounded(&staged[2])
    })();
    for path in staged {
        let _ = std::fs::remove_file(path);
    }
    result
}

#[cfg(target_os = "macos")]
fn run_managed_launchctl_command(command: std::process::Command) -> Result<()> {
    // A private binary fixture must fail before the canonical lifecycle executor,
    // even if a regression bypasses its absent-job guard. Never compiled into
    // production builds, and deliberately not a swallowable Result error.
    #[cfg(feature = "test-utils")]
    if std::env::var_os("CSQ_TEST_FORBID_MANAGED_LAUNCHCTL").is_some() {
        panic!("fixture_forbidden_managed_launchctl_mutation");
    }
    use csq_core::cli_deps::cli_shim::ProbeOutcome;
    match csq_core::cli_deps::cli_shim::probe_command(command) {
        ProbeOutcome::Ok(_) => Ok(()),
        ProbeOutcome::TimedOut => anyhow::bail!("managed_launchctl_timed_out"),
        _ => anyhow::bail!("managed_launchctl_failed"),
    }
}

#[cfg(target_os = "macos")]
fn managed_daemon_launchctl_command(
    operation: &str,
    plist_path: &Path,
    euid: u32,
) -> Result<std::process::Command> {
    let mut command = std::process::Command::new("/bin/launchctl");
    match operation {
        // A disk plist's mutable Label must never choose the loaded service to
        // stop. Target only this user's canonical managed-daemon service.
        "bootout" => {
            command
                .arg("bootout")
                .arg(format!("gui/{euid}/{LAUNCHD_LABEL}"));
        }
        "load" => {
            command.arg("load").arg(plist_path);
        }
        _ => anyhow::bail!("managed_plist_operation_unsupported"),
    }
    Ok(command)
}

/// The production install/repair flow with only launchd operations injected.
#[cfg(all(target_os = "macos", test))]
fn ensure_managed_daemon_plist_with(
    plist_path: &Path,
    expected: impl AsRef<[u8]>,
    job_state: impl FnMut() -> ManagedJobState,
    launchctl: impl FnMut(&str, &Path) -> Result<()>,
) -> Result<ManagedPlistOutcome> {
    ensure_managed_daemon_plist_with_operations(
        plist_path,
        expected,
        job_state,
        launchctl,
        managed_daemon_rollback_identity_checker(),
        |_from, to, writer| writer.replace(to).map_err(Into::into),
    )
}

#[cfg(target_os = "macos")]
fn managed_daemon_rollback_identity_checker() -> impl FnMut(&Path, bool) -> bool {
    let policy = if crate::BUILD_EDITION == "enterprise" {
        csq_core::cli_deps::cli_shim::SignerPolicy::PinTrustedTeam
    } else {
        csq_core::cli_deps::cli_shim::SignerPolicy::AnySignature
    };
    managed_daemon_rollback_identity_checker_with(
        read_loaded_managed_identity,
        csq_core::sessions::ancestor_start,
        move |program| {
            csq_core::cli_deps::cli_shim::installed_cli_signature_verifies(program, &policy)
        },
    )
}

/// Preserve the production identity policy while allowing sandbox observations.
/// A dormant job needs no executable verification before bootout, but every
/// rollback reload starts code and therefore requires current verification.
#[cfg(target_os = "macos")]
fn managed_daemon_rollback_identity_checker_with(
    mut loaded_identity: impl FnMut() -> Option<LoadedManagedIdentity>,
    mut generation: impl FnMut(u32) -> Option<u64>,
    mut verify: impl FnMut(&Path) -> bool,
) -> impl FnMut(&Path, bool) -> bool {
    let mut rollback_program: Option<PathBuf> = None;
    move |snapshot, restoring| {
        if restoring {
            return rollback_program
                .as_ref()
                .is_some_and(|program| verify(program));
        }
        let Some(config) = read_managed_rollback_config(snapshot) else {
            return false;
        };
        let Some(loaded) = loaded_identity() else {
            return false;
        };
        let mut first = Some(loaded);
        if !managed_rollback_identity_matches_with(
            &config,
            || first.take().or_else(&mut loaded_identity),
            &mut generation,
            &mut verify,
        ) {
            return false;
        }
        rollback_program = Some(config.program);
        true
    }
}

#[cfg(target_os = "macos")]
fn read_managed_rollback_config(plist_path: &Path) -> Option<ManagedRollbackConfig> {
    const SCRIPT: &str = r#"ObjC.import('Foundation');function run(a){
var d=$.NSDictionary.dictionaryWithContentsOfFile($(a[0]));if(ObjC.unwrap(d)==null)throw new Error('invalid plist');var result={};
['Label','ProgramArguments','Program','RootDirectory','BundleProgram','EnvironmentVariables','WorkingDirectory','RunAtLoad','KeepAlive','ThrottleInterval','ProcessType','StandardOutPath','StandardErrorPath'].forEach(function(k){var v=d.objectForKey($(k));if(ObjC.unwrap(v)!=null)result[k]=ObjC.deepUnwrap(v);});return JSON.stringify(result);}"#;
    let mut command = std::process::Command::new("/usr/bin/osascript");
    command
        .args(["-l", "JavaScript", "-e", SCRIPT])
        .arg(plist_path);
    match csq_core::cli_deps::cli_shim::probe_command(command) {
        csq_core::cli_deps::cli_shim::ProbeOutcome::Ok(output) => {
            managed_rollback_config_from_json(&output)
        }
        _ => None,
    }
}

#[cfg(all(target_os = "macos", test))]
fn managed_plist_has_canonical_label_from_json(output: &[u8]) -> bool {
    managed_rollback_config_from_json(output).is_some()
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedRollbackConfig {
    program: PathBuf,
    arguments: Vec<String>,
    environment: Option<serde_json::Map<String, serde_json::Value>>,
    working_directory: Option<PathBuf>,
}

#[cfg(target_os = "macos")]
fn managed_rollback_config_from_json(output: &[u8]) -> Option<ManagedRollbackConfig> {
    let value: serde_json::Value = serde_json::from_slice(output).ok()?;
    let object = value.as_object()?;
    if object.iter().any(|(key, value)| {
        !match key.as_str() {
            "Label" | "ProgramArguments" => true,
            "RunAtLoad" => value.is_boolean(),
            "KeepAlive" => {
                value.is_boolean()
                    || value.as_object().is_some_and(|conditions| {
                        conditions.len() == 1
                            && conditions
                                .get("SuccessfulExit")
                                .is_some_and(serde_json::Value::is_boolean)
                    })
            }
            // Keep the supported interval within a nonnegative signed 32-bit
            // seconds range; reject floats, negative values and wider integers.
            "ThrottleInterval" => value
                .as_u64()
                .is_some_and(|seconds| seconds <= i32::MAX as u64),
            "ProcessType" => matches!(
                value.as_str(),
                Some("Background" | "Standard" | "Adaptive" | "Interactive")
            ),
            "StandardOutPath" | "StandardErrorPath" => value.as_str().is_some_and(|path| {
                Path::new(path).is_absolute() && !path.chars().any(char::is_control)
            }),
            "EnvironmentVariables" => value
                .as_object()
                .is_some_and(|values| values.values().all(serde_json::Value::is_string)),
            "WorkingDirectory" => value.as_str().is_some_and(|path| {
                Path::new(path).is_absolute() && !path.chars().any(char::is_control)
            }),
            "Program" | "RootDirectory" | "BundleProgram" => false,
            _ => true,
        }
    }) {
        return None;
    }
    if object.get("Label")?.as_str()? != LAUNCHD_LABEL {
        return None;
    }
    let arguments: Vec<String> = object
        .get("ProgramArguments")?
        .as_array()?
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect::<Option<_>>()?;
    if arguments.len() != 4 || arguments[1..] != ["daemon", "start", "--supervised"] {
        return None;
    }
    let program = PathBuf::from(&arguments[0]);
    if !program.is_absolute() || arguments[0].chars().any(char::is_control) {
        return None;
    }
    let environment = object
        .get("EnvironmentVariables")
        .and_then(serde_json::Value::as_object)
        .cloned();
    let working_directory = object
        .get("WorkingDirectory")
        .and_then(serde_json::Value::as_str)
        .map(PathBuf::from);
    Some(ManagedRollbackConfig {
        program,
        arguments,
        environment,
        working_directory,
    })
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LoadedManagedIdentity {
    pid: u32,
    config: ManagedRollbackConfig,
}

#[cfg(target_os = "macos")]
fn loaded_managed_identity_from_json(output: &[u8]) -> Option<LoadedManagedIdentity> {
    let value: serde_json::Value = serde_json::from_slice(output).ok()?;
    if !value.get("found")?.as_bool()? {
        return None;
    }
    for key in ["hasRootDirectory", "hasBundleProgram"] {
        if value.get(key)?.as_bool()? {
            return None;
        }
    }
    // launchd retains a loaded job after a clean stop or failed spawn. Absence
    // of PID is explicit dormant-job evidence, not a metadata probe failure.
    let pid = match value.get("PID") {
        None => 0,
        Some(value) => u32::try_from(value.as_u64()?).ok()?,
    };
    let mut disk_shape = serde_json::json!({ "Label": value.get("Label")?, "ProgramArguments": value.get("ProgramArguments")? });
    for key in ["EnvironmentVariables", "WorkingDirectory"] {
        if value.get(format!("has{key}"))?.as_bool()? {
            disk_shape[key] = value.get(key)?.clone();
        } else if value.get(key).is_some() {
            return None;
        }
    }
    let config = managed_rollback_config_from_json(&serde_json::to_vec(&disk_shape).ok()?)?;
    if value.get("Program")?.as_str()? != config.arguments[0] {
        return None;
    }
    Some(LoadedManagedIdentity { pid, config })
}

#[cfg(target_os = "macos")]
fn read_loaded_managed_identity() -> Option<LoadedManagedIdentity> {
    const SCRIPT: &str = r#"ObjC.import('ServiceManagement');ObjC.import('Foundation');ObjC.import('CoreFoundation');
var ref=$.SMJobCopyDictionary($.kSMDomainUserLaunchd,$('foundation.terrene.csq'));var result={found:false};
try{var d=ObjC.castRefToObject(ref);var u=ObjC.unwrap(d);if(u!==null&&u!==undefined){result.found=true;
['Label','Program','ProgramArguments','PID'].forEach(function(k){var v=d.objectForKey($(k));var u=ObjC.unwrap(v);if(u!==null&&u!==undefined)result[k]=ObjC.deepUnwrap(v);});
['EnvironmentVariables','WorkingDirectory','RootDirectory','BundleProgram'].forEach(function(k){var v=d.objectForKey($(k));var u=ObjC.unwrap(v);result['has'+k]=(u!==null&&u!==undefined);if((k==='EnvironmentVariables'||k==='WorkingDirectory')&&result['has'+k])result[k]=ObjC.deepUnwrap(v);});}}
finally{if(result.found)$.CFRelease(ref);}JSON.stringify(result);"#;
    let mut command = std::process::Command::new("/usr/bin/osascript");
    command.args(["-l", "JavaScript", "-e", SCRIPT]);
    match csq_core::cli_deps::cli_shim::probe_command(command) {
        csq_core::cli_deps::cli_shim::ProbeOutcome::Ok(output) => {
            loaded_managed_identity_from_json(&output)
        }
        _ => None,
    }
}

/// Read-only canonical loaded-job observation. A failed query, malformed
/// metadata or absent job stays unknown; this never starts/stops a service.
#[cfg(target_os = "macos")]
pub(crate) fn managed_daemon_dormant() -> Option<bool> {
    managed_daemon_dormant_with(read_loaded_managed_identity)
}

#[cfg(target_os = "macos")]
fn managed_daemon_dormant_with(
    loaded: impl FnOnce() -> Option<LoadedManagedIdentity>,
) -> Option<bool> {
    loaded().map(|identity| identity.pid == 0)
}

#[cfg(target_os = "macos")]
fn managed_rollback_identity_matches_with(
    config: &ManagedRollbackConfig,
    mut loaded: impl FnMut() -> Option<LoadedManagedIdentity>,
    mut generation: impl FnMut(u32) -> Option<u64>,
    verify: impl FnOnce(&Path) -> bool,
) -> bool {
    let Some(first) = loaded() else { return false };
    if &first.config != config {
        return false;
    }
    if first.pid == 0 {
        // Never use disk bytes alone to authorize bootout; both loaded samples
        // must describe this exact canonical job and still have no live PID.
        return loaded().is_some_and(|second| second == first);
    }
    let Some(start) = generation(first.pid).filter(|start| *start != 0) else {
        return false;
    };
    if !verify(&config.program) {
        return false;
    }
    loaded().is_some_and(|second| second == first && generation(second.pid) == Some(start))
}

#[cfg(target_os = "macos")]
fn ensure_managed_daemon_plist_with_operations(
    plist_path: &Path,
    expected: impl AsRef<[u8]>,
    mut job_state: impl FnMut() -> ManagedJobState,
    mut launchctl: impl FnMut(&str, &Path) -> Result<()>,
    mut rollback_identity: impl FnMut(&Path, bool) -> bool,
    mut atomic_replace: impl FnMut(
        &Path,
        &Path,
        csq_core::platform::fs::WrittenPrivateFile,
    ) -> Result<()>,
) -> Result<ManagedPlistOutcome> {
    let original = match std::fs::read(plist_path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => anyhow::bail!("managed_plist_read_failed"),
    };
    let expected = expected.as_ref();
    let content_matches = original.as_deref() == Some(expected);
    let drifted = original.is_some();
    let mut needs_bootout = false;

    // Matching disk bytes do not establish that launchd loaded the job: a
    // previous rejected CLI may have been booted out while retaining its plist.
    if drifted {
        match job_state() {
            ManagedJobState::Loaded if content_matches => {
                return Ok(ManagedPlistOutcome::AlreadyCurrent)
            }
            ManagedJobState::Loaded => needs_bootout = true,
            ManagedJobState::Unloaded => {}
            // Do not risk an already-loaded error followed by removal of a
            // previously valid plist when the state probe itself was uncertain.
            ManagedJobState::Unknown => anyhow::bail!("managed_plist_job_state_unknown"),
        }
    }

    if !content_matches {
        if let Some(parent) = plist_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "could not create LaunchAgents directory at {}",
                    parent.display()
                )
            })?;
        }
    }

    let mut rollback = if needs_bootout {
        let bytes = original
            .as_deref()
            .context("managed_plist_rollback_unavailable")?;
        let staged = stage_managed_daemon_plist_written(plist_path, bytes)?;
        // Decode the preserved snapshot, not mutable on-disk metadata. Never
        // reload an arbitrary Label after a repair error.
        if !rollback_identity(&staged.0, false) {
            anyhow::bail!("managed_plist_rollback_identity_unknown");
        }
        Some(staged)
    } else {
        None
    };

    let mut candidate = if !content_matches {
        Some(stage_managed_daemon_plist_written(plist_path, expected)?)
    } else {
        None
    };

    let mut booted_out = false;
    let mut load_attempted = false;
    let repair = (|| -> Result<()> {
        if needs_bootout {
            if let Err(error) = launchctl("bootout", plist_path) {
                // Killing a timed-out launchctl client does not cancel launchd's
                // operation. A failed command can already have removed the job.
                let after = job_state();
                if after == ManagedJobState::Unknown {
                    return Err(error.context("managed_plist_bootout_state_unknown"));
                }
                booted_out = after == ManagedJobState::Unloaded;
                return Err(error.context("could not boot out canonical managed daemon service"));
            }
            booted_out = true;
        }
        if let Some(candidate) = candidate.take() {
            atomic_replace(&candidate.0, plist_path, candidate.1)
                .context("replace managed daemon plist")?;
        }
        load_attempted = true;
        launchctl("load", plist_path).context("could not load managed daemon plist")?;
        // Executor success alone does not establish that launchd admitted the
        // job. Require the bounded native observation before claiming success.
        if job_state() != ManagedJobState::Loaded {
            anyhow::bail!("managed_plist_load_unconfirmed");
        }
        Ok(())
    })();
    let repair = match repair {
        Err(primary) if booted_out => {
            let restored = (|| -> Result<()> {
                let original = original
                    .as_deref()
                    .context("managed_plist_rollback_unavailable")?;
                let rollback = rollback
                    .take()
                    .context("managed_plist_rollback_unavailable")?;
                // A failed rename (e.g. an immutable destination) may have
                // preserved the old bytes; do not require another rename then.
                if !std::fs::read(plist_path).is_ok_and(|bytes| bytes == original) {
                    atomic_replace(&rollback.0, plist_path, rollback.1)
                        .context("restore managed daemon plist")?;
                }
                if !rollback_identity(&rollback.0, true) {
                    anyhow::bail!("managed_plist_rollback_executable_unverifiable");
                }
                launchctl("load", plist_path).context("reload previous managed daemon plist")?;
                if job_state() != ManagedJobState::Loaded {
                    anyhow::bail!("managed_plist_rollback_load_unconfirmed");
                }
                Ok(())
            })();
            Err(primary.context(if restored.is_ok() {
                "managed_plist_restored_after_failed_repair"
            } else {
                "managed_plist_restoration_failed"
            }))
        }
        Err(primary) => {
            // Preserve the historical new-install/unloaded retry policy. A
            // loaded job whose bootout failed keeps its original plist.
            if load_attempted {
                let _ = std::fs::remove_file(plist_path);
            }
            Err(primary)
        }
        Ok(()) => Ok(()),
    };
    drop(candidate);
    drop(rollback);
    repair?;

    Ok(if drifted {
        ManagedPlistOutcome::Repaired
    } else {
        ManagedPlistOutcome::Installed
    })
}

#[cfg(target_os = "macos")]
fn stage_managed_daemon_plist(plist_path: &Path, bytes: &[u8]) -> Result<PathBuf> {
    // Merge-only staging is later rewritten by Foundation, never published.
    let staged = csq_core::platform::fs::unique_tmp_path(plist_path);
    csq_core::platform::fs::write_new_private_synced(&staged, bytes)
        .context("stage managed daemon plist")?;
    Ok(staged)
}

/// Candidate and rollback bytes may retain user environment secrets. Preserve
/// the synced private writer through publication and owned cleanup.
#[cfg(target_os = "macos")]
fn stage_managed_daemon_plist_written(
    plist_path: &Path,
    bytes: &[u8],
) -> Result<(PathBuf, csq_core::platform::fs::WrittenPrivateFile)> {
    let staged = csq_core::platform::fs::unique_tmp_path(plist_path);
    let writer = csq_core::platform::fs::write_new_private_synced_retained(&staged, bytes)
        .context("stage managed daemon plist")?;
    Ok((staged, writer))
}

/// Separates observed job removal from actual disk removal and an absent no-op.
#[cfg(all(target_os = "macos", any(feature = "cli", test)))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagedUninstallOutcome {
    NotInstalled,
    PlistRemoved,
    JobUnloaded { plist_removed: bool },
}

#[cfg(all(target_os = "macos", any(feature = "cli", test)))]
pub(crate) fn managed_uninstall_output(
    outcome: ManagedUninstallOutcome,
    plist_path: &Path,
) -> String {
    if outcome == ManagedUninstallOutcome::NotInstalled {
        return "csq daemon service not installed.".to_owned();
    }
    let mut output = "csq daemon service uninstalled.".to_owned();
    if matches!(
        outcome,
        ManagedUninstallOutcome::PlistRemoved
            | ManagedUninstallOutcome::JobUnloaded {
                plist_removed: true
            }
    ) {
        output.push_str(&format!("\n  Removed: {}", plist_path.display()));
    }
    output
}

/// Composed uninstall entrypoint: callers cannot replace native observation/execution.
#[cfg(all(target_os = "macos", feature = "cli"))]
pub(crate) fn uninstall_managed_daemon_plist() -> Result<(ManagedUninstallOutcome, PathBuf)> {
    let plist_path = launchd_plist_path()?;
    // SAFETY: geteuid takes no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let outcome = platform_uninstall_with(
        &plist_path,
        euid,
        managed_launchd_job_state,
        run_managed_launchctl_command,
    )?;
    Ok((outcome, plist_path))
}

#[cfg(all(target_os = "macos", any(feature = "cli", test)))]
fn platform_uninstall_with(
    plist_path: &Path,
    euid: u32,
    mut job_state: impl FnMut() -> ManagedJobState,
    mut execute: impl FnMut(std::process::Command) -> Result<()>,
) -> Result<ManagedUninstallOutcome> {
    let mut job_unloaded = false;
    match job_state() {
        ManagedJobState::Unknown => anyhow::bail!("managed_uninstall_job_state_unknown"),
        ManagedJobState::Unloaded => {}
        ManagedJobState::Loaded => {
            // Disk absence (or a foreign on-disk Label) does not choose which
            // service to stop, and does not establish that it is absent.
            let result = execute(managed_daemon_launchctl_command(
                "bootout", plist_path, euid,
            )?);
            if job_state() != ManagedJobState::Unloaded {
                return Err(result
                    .err()
                    .unwrap_or_else(|| anyhow::anyhow!("managed_uninstall_still_loaded"))
                    .context("managed_uninstall_absence_unconfirmed"));
            }
            result.context("managed_uninstall_bootout_failed_after_unload")?;
            job_unloaded = true;
        }
    }
    // Preserve retry state on command failure or any uncertain/loaded probe.
    let plist_removed = match std::fs::remove_file(plist_path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => anyhow::bail!("managed_uninstall_remove_failed"),
    };
    Ok(if job_unloaded {
        ManagedUninstallOutcome::JobUnloaded { plist_removed }
    } else if plist_removed {
        ManagedUninstallOutcome::PlistRemoved
    } else {
        ManagedUninstallOutcome::NotInstalled
    })
}

#[cfg(test)]
mod tests {
    #[cfg(all(target_os = "macos", feature = "test-utils"))]
    #[test]
    fn l2_fixture_tripwire_panics_before_owned_command_spawn() {
        let _env = csq_core::platform::test_env::lock();
        struct RestoreFlag(Option<std::ffi::OsString>);
        impl Drop for RestoreFlag {
            fn drop(&mut self) {
                match &self.0 {
                    Some(value) => std::env::set_var("CSQ_TEST_FORBID_MANAGED_LAUNCHCTL", value),
                    None => std::env::remove_var("CSQ_TEST_FORBID_MANAGED_LAUNCHCTL"),
                }
            }
        }
        let _restore = RestoreFlag(std::env::var_os("CSQ_TEST_FORBID_MANAGED_LAUNCHCTL"));
        std::env::set_var("CSQ_TEST_FORBID_MANAGED_LAUNCHCTL", "1");
        let fixture = tempfile::TempDir::new().unwrap();
        let canary = fixture.path().join("child-spawned");
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", "printf spawned > \"$CSQ_L2_CANARY\""])
            .env_clear()
            .env("HOME", fixture.path())
            .env("CSQ_BASE_DIR", fixture.path().join("base"))
            .env("PATH", "/usr/bin:/bin")
            .env("CSQ_L2_CANARY", &canary);
        let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            super::run_managed_launchctl_command(command)
        }));
        let panic = stopped
            .expect_err("tripwire must panic before executing even an owned harmless command");
        let message = panic
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic.downcast_ref::<String>().map(String::as_str));
        assert_eq!(
            message,
            Some("fixture_forbidden_managed_launchctl_mutation")
        );
        assert!(!canary.exists(), "tripwire must run before process spawn");
    }

    #[test]
    fn cli_managed_install_admission_precedes_all_fixture_writes() {
        use csq_core::cli_deps::cli_shim::InstalledCliVerification::{
            Invalid, Unverifiable, Verified,
        };
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("managed.plist");
        for (exists, verified) in [
            (false, Verified("csq 2.21.0 (community)".into())),
            (true, Invalid),
            (true, Unverifiable),
            (true, Verified("csq 2.21.0 (enterprise)".into())),
        ] {
            let result = super::ensure_managed_daemon_plist_admitted(
                exists,
                &verified,
                "csq 2.21.0 (community)",
                || {
                    std::fs::write(&path, b"fixture").unwrap();
                    Ok(())
                },
            );
            assert!(result.is_err(), "unadmitted candidate must be refused");
            assert!(!path.exists(), "admission must precede writes");
        }
        super::ensure_managed_daemon_plist_admitted(
            true,
            &Verified("csq 2.21.0 (community)".into()),
            "csq 2.21.0 (community)",
            || {
                std::fs::write(&path, b"fixture").unwrap();
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"fixture");
    }

    #[cfg(feature = "cli")]
    #[test]
    fn launchd_fixture_override_cannot_redirect_release_policy() {
        let fixture = "csq.fixture.doctor.release-policy";
        assert_eq!(
            super::managed_launchd_probe_label_for_build(Some(fixture.into()), false),
            super::LAUNCHD_LABEL
        );
        assert_eq!(
            super::managed_launchd_probe_label_for_build(Some(fixture.into()), true),
            fixture
        );
        // Release must ignore even invalid/non-fixture input without probing it.
        assert_eq!(
            super::managed_launchd_probe_label_for_build(Some("invalid".into()), false),
            super::LAUNCHD_LABEL
        );
    }

    mod stale_managed_plist {
        use super::super::{inspect_managed_daemon_plist_with, StaleManagedPlistOutcome};
        use csq_core::cli_deps::cli_shim::InstalledCliVerification;
        use std::path::{Path, PathBuf};

        #[cfg(target_os = "macos")]
        fn seed_fixture_rollback_cli(base: &Path) {
            use std::os::unix::fs::PermissionsExt;
            let executable = base.join("old-csq");
            std::fs::write(&executable, "fixture-trusted-cli").unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        #[cfg(target_os = "macos")]
        fn fixture_rollback_identity(snapshot: &Path, restoring: bool) -> bool {
            use super::super::{LoadedManagedIdentity, ManagedRollbackConfig};
            use std::os::unix::fs::PermissionsExt;
            let program = snapshot.parent().unwrap().join("old-csq");
            let verify = |path: &Path| {
                std::fs::symlink_metadata(path).is_ok_and(|metadata| {
                    metadata.file_type().is_file() && metadata.permissions().mode() & 0o111 != 0
                }) && std::fs::read(path).is_ok_and(|bytes| bytes == b"fixture-trusted-cli")
            };
            if restoring {
                return verify(&program);
            }
            let Some(config) = super::super::read_managed_rollback_config(snapshot) else {
                return false;
            };
            // Independently specified loaded-job fixture; never derive its argv
            // from the disk snapshot or query the developer's launchd domain.
            let loaded = LoadedManagedIdentity {
                pid: 471,
                config: ManagedRollbackConfig {
                    arguments: vec![
                        program.to_string_lossy().into_owned(),
                        "daemon".into(),
                        "start".into(),
                        "--supervised".into(),
                    ],
                    program,
                    environment: None,
                    working_directory: None,
                },
            };
            super::super::managed_rollback_identity_matches_with(
                &config,
                || Some(loaded.clone()),
                |_| Some(123456),
                verify,
            )
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn rejected_refresh_retains_loaded_symlink_plist_and_truthful_receipt() {
            use csq_core::cli_deps::cli_shim::{self, ShimOutcome, SignerPolicy};
            use csq_core::cli_deps::cli_shim_refresh::{
                refresh_cli_and_record_with, RefreshContext,
            };
            use std::os::unix::fs::PermissionsExt;
            let _env = csq_core::platform::test_env::lock();
            let fixture = tempfile::TempDir::new().unwrap();
            let executable = fixture.path().join("working-csq");
            std::fs::write(&executable, "fixture executable").unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
            let program = fixture.path().join("csq-link");
            std::os::unix::fs::symlink(&executable, &program).unwrap();
            let plist = fixture.path().join("managed.plist");
            let original =
                super::super::build_launchd_plist(&program, &fixture.path().join("daemon.log"));
            std::fs::write(&plist, &original).unwrap();
            let loaded = std::cell::Cell::new(true);
            let receipt = refresh_cli_and_record_with(
                RefreshContext {
                    base_dir: fixture.path(),
                    source: Some(&executable),
                    target: Some(&program),
                    expected_version_line: "csq 2.21.0 (enterprise)",
                },
                |_, _| Ok(ShimOutcome::Rejected("fixture_signer_untrusted")),
                |target| {
                    cli_shim::installed_cli_verification(target, &SignerPolicy::PinTrustedTeam)
                },
                |target, verified, failed| {
                    super::super::repair_managed_daemon_plist_after_refresh_with(
                        program.exists(),
                        verified,
                        failed,
                        "csq 2.21.0 (enterprise)",
                        || {
                            inspect_managed_daemon_plist_with(
                                target,
                                verified,
                                || super::super::read_managed_daemon_program(&plist),
                                |_| panic!("same path reuses final verification"),
                                || super::super::ManagedJobState::Loaded,
                            )
                        },
                        || {
                            loaded.set(false);
                            Ok(super::super::ManagedPlistOutcome::Repaired)
                        },
                        || panic!("rejected refresh must not query dormancy"),
                    )
                },
            )
            .unwrap();
            assert!(
                loaded.get(),
                "rejected refresh must preserve the loaded job"
            );
            assert_eq!(std::fs::read_to_string(&plist).unwrap(), original);
            assert_eq!(receipt.outcome, "fixture_signer_untrusted");
            assert_eq!(receipt.plist_decision, "skipped_unverifiable");
            assert_eq!(receipt.stale_plist_decision, "retained_unverifiable");
            assert_eq!(receipt.verified_version_line, None);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn matching_owned_keys_with_no_pid_preserves_job_and_records_dormant_receipt() {
            use super::super::*;
            use csq_core::cli_deps::cli_shim::{InstalledCliVerification, ShimOutcome};
            use csq_core::cli_deps::cli_shim_refresh::{
                refresh_cli_and_record_with, RefreshContext,
            };
            let _env = csq_core::platform::test_env::lock();
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let program = fixture.path().join("csq");
            let log = fixture.path().join("log");
            let original = user_customized_plist(&program, &log);
            std::fs::write(&program, "fixture admitted CLI").unwrap();
            std::fs::write(&plist, &original).unwrap();
            let metadata = serde_json::json!({
                "found": true, "Label": LAUNCHD_LABEL, "Program": program,
                "ProgramArguments": [program, "daemon", "start", "--supervised"],
                "hasEnvironmentVariables": true, "EnvironmentVariables": {"CSQ_FIXTURE_ONLY": "fixture-value"},
                "hasWorkingDirectory": true, "WorkingDirectory": "/fixture/project",
                "hasRootDirectory": false, "hasBundleProgram": false,
            });
            let identity =
                loaded_managed_identity_from_json(&serde_json::to_vec(&metadata).unwrap()).unwrap();
            assert_eq!(identity.pid, 0);
            let receipt = refresh_cli_and_record_with(
                RefreshContext {
                    base_dir: fixture.path(),
                    source: Some(&program),
                    target: Some(&program),
                    expected_version_line: "csq 2.21.0 (enterprise)",
                },
                |_, _| Ok(ShimOutcome::NoOp),
                |_| InstalledCliVerification::Verified("csq 2.21.0 (enterprise)".into()),
                |_, verified, failed| {
                    repair_managed_daemon_plist_after_refresh_with(
                        true,
                        verified,
                        failed,
                        "csq 2.21.0 (enterprise)",
                        || StaleManagedPlistOutcome::RetainedVerified,
                        || {
                            let result = ensure_managed_daemon_plist_at(
                                &plist,
                                &program,
                                &log,
                                471,
                                || ManagedJobState::Loaded,
                                |_| panic!("intentional clean stop must not restart"),
                            )?;
                            assert_eq!(result, ManagedPlistOutcome::AlreadyCurrent);
                            Ok(result)
                        },
                        || managed_daemon_dormant_with(|| Some(identity.clone())),
                    )
                },
            )
            .unwrap();
            assert_eq!(receipt.plist_decision, "daemon_dormant");
            let persisted: serde_json::Value = serde_json::from_slice(
                &std::fs::read(fixture.path().join("cli-shim-refresh.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(persisted["plist_decision"], "daemon_dormant");
            assert_eq!(std::fs::read_to_string(&plist).unwrap(), original);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn unknown_dormant_probe_never_claims_stopped_managed_job() {
            use super::super::*;
            assert_eq!(managed_daemon_dormant_with(|| None), None);
            let result = repair_managed_daemon_plist_after_refresh_with(
                true,
                &InstalledCliVerification::Verified("csq 2.21.0 (enterprise)".into()),
                false,
                "csq 2.21.0 (enterprise)",
                || StaleManagedPlistOutcome::RetainedVerified,
                || Ok(ManagedPlistOutcome::AlreadyCurrent),
                || None,
            );
            assert_eq!(result.0, "already_current");
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn rejected_refresh_with_invalid_disk_program_never_enters_repair() {
            let loaded = std::cell::Cell::new(true);
            let result = super::super::repair_managed_daemon_plist_after_refresh_with(
                true,
                &InstalledCliVerification::Invalid,
                true,
                "csq 2.21.0 (enterprise)",
                || StaleManagedPlistOutcome::RetainedInvalid,
                || {
                    loaded.set(false);
                    Ok(super::super::ManagedPlistOutcome::Repaired)
                },
                || panic!("rejected refresh must not query dormancy"),
            );
            assert!(loaded.get());
            assert_eq!(
                result,
                ("skipped_unverifiable".into(), "retained_invalid".into())
            );
        }

        #[test]
        fn missing_plist_never_verifies_or_boots_out() {
            let result = inspect_managed_daemon_plist_with(
                None,
                &InstalledCliVerification::Unverifiable,
                || Ok(None),
                |_| panic!("absent plist must not probe an executable"),
                || super::super::ManagedJobState::Loaded,
            );
            assert_eq!(result, StaleManagedPlistOutcome::NoPlist);
            assert_eq!(result.as_str(), "no_plist");
        }

        #[test]
        fn verified_program_retains_existing_job() {
            let program = PathBuf::from("/fixture/working-csq");
            let result = inspect_managed_daemon_plist_with(
                None,
                &InstalledCliVerification::Unverifiable,
                || Ok(Some(program.clone())),
                |path| {
                    assert_eq!(path, program);
                    InstalledCliVerification::Verified("csq 2.20.2 (enterprise)".into())
                },
                || super::super::ManagedJobState::Loaded,
            );
            assert_eq!(result, StaleManagedPlistOutcome::RetainedVerified);
        }

        #[test]
        fn broken_or_missing_disk_program_retains_existing_job() {
            for program in ["/fixture/broken-csq", "/fixture/missing-csq"] {
                let result = inspect_managed_daemon_plist_with(
                    None,
                    &InstalledCliVerification::Unverifiable,
                    || Ok(Some(PathBuf::from(program))),
                    |path| {
                        assert_eq!(path, Path::new(program));
                        InstalledCliVerification::Invalid
                    },
                    || super::super::ManagedJobState::Loaded,
                );
                assert_eq!(result, StaleManagedPlistOutcome::RetainedInvalid);
                assert_eq!(result.as_str(), "retained_invalid");
            }
        }

        #[test]
        fn different_program_is_verified_even_when_shim_is_good() {
            let shim = Path::new("/fixture/new-csq");
            let old_program = PathBuf::from("/fixture/old-csq");
            let result = inspect_managed_daemon_plist_with(
                Some(shim),
                &InstalledCliVerification::Verified("csq 2.20.2 (enterprise)".into()),
                || Ok(Some(old_program.clone())),
                |path| {
                    assert_eq!(path, old_program);
                    assert_ne!(path, shim);
                    InstalledCliVerification::Invalid
                },
                || super::super::ManagedJobState::Loaded,
            );
            assert_eq!(result, StaleManagedPlistOutcome::RetainedInvalid);
        }

        #[test]
        fn same_program_reuses_final_verification_for_all_states() {
            let program = Path::new("/fixture/csq");
            for (verification, expected) in [
                (
                    InstalledCliVerification::Verified("csq 2.20.2".into()),
                    StaleManagedPlistOutcome::RetainedVerified,
                ),
                (
                    InstalledCliVerification::Invalid,
                    StaleManagedPlistOutcome::RetainedInvalid,
                ),
                (
                    InstalledCliVerification::Unverifiable,
                    StaleManagedPlistOutcome::RetainedUnverifiable,
                ),
            ] {
                let result = inspect_managed_daemon_plist_with(
                    Some(program),
                    &verification,
                    || Ok(Some(program.to_path_buf())),
                    |_| panic!("same path must reuse final caller verification"),
                    || super::super::ManagedJobState::Loaded,
                );
                assert_eq!(result, expected);
            }
        }

        #[test]
        fn inconclusive_program_probe_retains_job() {
            let result = inspect_managed_daemon_plist_with(
                None,
                &InstalledCliVerification::Unverifiable,
                || Ok(Some(PathBuf::from("/fixture/csq"))),
                |_| InstalledCliVerification::Unverifiable,
                || super::super::ManagedJobState::Loaded,
            );
            assert_eq!(result, StaleManagedPlistOutcome::RetainedUnverifiable);
        }

        #[test]
        fn read_error_retains_job_without_verifying() {
            let result = inspect_managed_daemon_plist_with(
                None,
                &InstalledCliVerification::Unverifiable,
                || anyhow::bail!("fixture read error"),
                |_| panic!("failed read must not probe guessed path"),
                || super::super::ManagedJobState::Loaded,
            );
            assert_eq!(result, StaleManagedPlistOutcome::ReadFailed);
        }

        #[test]
        fn invalid_disk_program_is_inspected_without_lifecycle_change() {
            let result = inspect_managed_daemon_plist_with(
                None,
                &InstalledCliVerification::Unverifiable,
                || Ok(Some(PathBuf::from("/fixture/broken-csq"))),
                |_| InstalledCliVerification::Invalid,
                || super::super::ManagedJobState::Loaded,
            );
            assert_eq!(result, StaleManagedPlistOutcome::RetainedInvalid);
            assert_eq!(result.as_str(), "retained_invalid");
        }

        #[test]
        fn only_explicit_service_not_found_establishes_unloaded_state() {
            use super::super::{managed_job_state_from_probe, ManagedJobState};
            use csq_core::cli_deps::cli_shim::ProbeOutcome;
            assert_eq!(
                managed_job_state_from_probe(ProbeOutcome::Ok(0)),
                ManagedJobState::Loaded
            );
            assert_eq!(
                managed_job_state_from_probe(ProbeOutcome::Ok(113)),
                ManagedJobState::Unloaded
            );
            for probe in [
                ProbeOutcome::Ok(1),
                ProbeOutcome::TimedOut,
                ProbeOutcome::Unavailable,
                ProbeOutcome::Signaled(9),
            ] {
                assert_eq!(
                    managed_job_state_from_probe(probe),
                    ManagedJobState::Unknown
                );
            }
        }

        #[test]
        fn unknown_job_state_retains_broken_program_without_bootout() {
            let result = inspect_managed_daemon_plist_with(
                None,
                &InstalledCliVerification::Unverifiable,
                || Ok(Some(PathBuf::from("/fixture/broken-csq"))),
                |_| InstalledCliVerification::Invalid,
                || super::super::ManagedJobState::Unknown,
            );
            assert_eq!(result, StaleManagedPlistOutcome::RetainedUnverifiable);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn matching_unloaded_plist_is_reloaded_after_cli_repair() {
            use super::super::{
                ensure_managed_daemon_plist_with, ManagedJobState, ManagedPlistOutcome,
            };
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let program = fixture.path().join("csq");
            let expected = super::super::build_launchd_plist(&program, &fixture.path().join("log"));
            std::fs::write(&plist, &expected).unwrap();
            let loaded = std::cell::Cell::new(false);
            let stopped = inspect_managed_daemon_plist_with(
                Some(&program),
                &InstalledCliVerification::Invalid,
                || Ok(Some(program.clone())),
                |_| panic!("same program must reuse verification"),
                || {
                    if loaded.get() {
                        ManagedJobState::Loaded
                    } else {
                        ManagedJobState::Unloaded
                    }
                },
            );
            assert_eq!(stopped, StaleManagedPlistOutcome::AlreadyUnloaded);
            let repaired = ensure_managed_daemon_plist_with(
                &plist,
                &expected,
                || {
                    if loaded.get() {
                        ManagedJobState::Loaded
                    } else {
                        ManagedJobState::Unloaded
                    }
                },
                |operation, path| {
                    assert_eq!(operation, "load");
                    assert_eq!(path, plist);
                    loaded.set(true);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(repaired, ManagedPlistOutcome::Repaired);
            assert!(loaded.get());
            assert_eq!(std::fs::read_to_string(&plist).unwrap(), expected);
            let current = ensure_managed_daemon_plist_with(
                &plist,
                &expected,
                || ManagedJobState::Loaded,
                |_, _| panic!("loaded matching plist must stay untouched"),
            )
            .unwrap();
            assert_eq!(current, ManagedPlistOutcome::AlreadyCurrent);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn already_unloaded_broken_program_can_install_good_replacement() {
            use super::super::{
                ensure_managed_daemon_plist_with, ManagedJobState, ManagedPlistOutcome,
            };
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let old = fixture.path().join("broken-old-csq");
            let new = fixture.path().join("working-new-csq");
            let log = fixture.path().join("log");
            std::fs::write(&plist, super::super::build_launchd_plist(&old, &log)).unwrap();
            // A prior attempt already booted this old program out. This attempt
            // must permit installation rather than fail on a second bootout.
            let stopped = inspect_managed_daemon_plist_with(
                Some(&new),
                &InstalledCliVerification::Verified("csq 2.20.2".into()),
                || Ok(Some(old.clone())),
                |path| {
                    assert_eq!(path, old);
                    InstalledCliVerification::Invalid
                },
                || ManagedJobState::Unloaded,
            );
            assert_eq!(stopped, StaleManagedPlistOutcome::AlreadyUnloaded);
            assert_eq!(stopped.as_str(), "already_unloaded");
            let expected = super::super::build_launchd_plist(&new, &log);
            let mut operations = Vec::new();
            let state = std::cell::Cell::new(ManagedJobState::Unloaded);
            let result = ensure_managed_daemon_plist_with(
                &plist,
                &expected,
                || state.get(),
                |operation, _| {
                    operations.push(operation.to_string());
                    state.set(ManagedJobState::Loaded);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(result, ManagedPlistOutcome::Repaired);
            assert_eq!(operations, ["load"]);
            assert_eq!(std::fs::read_to_string(&plist).unwrap(), expected);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn matching_unloaded_plist_load_failure_is_not_success() {
            use super::super::{ensure_managed_daemon_plist_with, ManagedJobState};
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            std::fs::write(&plist, "matching plist").unwrap();
            let result = ensure_managed_daemon_plist_with(
                &plist,
                "matching plist",
                || ManagedJobState::Unloaded,
                |operation, _| {
                    assert_eq!(operation, "load");
                    anyhow::bail!("fixture load failed")
                },
            );
            assert!(result.is_err());
            assert!(
                !plist.exists(),
                "failed load must retain removal/retry policy"
            );
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn unknown_job_state_preserves_matching_plist_without_loading() {
            use super::super::{ensure_managed_daemon_plist_with, ManagedJobState};
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            std::fs::write(&plist, "matching plist").unwrap();
            let result = ensure_managed_daemon_plist_with(
                &plist,
                "matching plist",
                || ManagedJobState::Unknown,
                |_, _| panic!("uncertain state must not risk unloading/loading"),
            );
            assert!(result.is_err());
            assert_eq!(std::fs::read_to_string(&plist).unwrap(), "matching plist");
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn unknown_job_state_preserves_different_broken_program_through_repair() {
            use super::super::{ensure_managed_daemon_plist_with, ManagedJobState};
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let old = fixture.path().join("broken-old-csq");
            let new = fixture.path().join("working-new-csq");
            let log = fixture.path().join("log");
            let original = super::super::build_launchd_plist(&old, &log);
            std::fs::write(&plist, &original).unwrap();
            let stopped = inspect_managed_daemon_plist_with(
                Some(&new),
                &InstalledCliVerification::Verified("csq 2.20.2 (enterprise)".into()),
                || Ok(Some(old.clone())),
                |_| InstalledCliVerification::Invalid,
                || ManagedJobState::Unknown,
            );
            assert_eq!(stopped, StaleManagedPlistOutcome::RetainedUnverifiable);
            let expected = super::super::build_launchd_plist(&new, &log);
            let result = ensure_managed_daemon_plist_with(
                &plist,
                &expected,
                || ManagedJobState::Unknown,
                |_, _| panic!("unknown drifted job must not be unloaded or loaded"),
            );
            assert!(result.is_err());
            assert_eq!(std::fs::read_to_string(&plist).unwrap(), original);
        }

        #[cfg(target_os = "macos")]
        fn user_customized_plist(program: &Path, log: &Path) -> String {
            super::super::build_launchd_plist(program, log)
                .replace("<string>Adaptive</string>", "<string>Interactive</string>")
                .replace("</dict>\n</plist>", r#"<key>Nice</key><integer>3</integer>
<key>EnvironmentVariables</key><dict><key>CSQ_FIXTURE_ONLY</key><string>fixture-value</string></dict>
<key>WorkingDirectory</key><string>/fixture/project</string>
<key>UserData</key><data>YWJj</data><key>UserDate</key><date>2025-01-01T00:00:00Z</date>
</dict>
</plist>"#)
        }

        #[cfg(target_os = "macos")]
        fn m1_dormant_rollback_flow(signature_valid: bool) {
            use super::super::*;
            let _env = csq_core::platform::test_env::lock();
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let old_program = fixture.path().join("old-csq");
            let new_program = fixture.path().join("new-csq");
            let log = fixture.path().join("log");
            let original = build_launchd_plist(&old_program, &log);
            std::fs::write(&plist, &original).unwrap();
            // This loaded-job observation is independently specified; it is
            // never read from the host or derived from the mutable disk plist.
            let loaded = LoadedManagedIdentity {
                pid: 0,
                config: ManagedRollbackConfig {
                    program: old_program.clone(),
                    arguments: vec![
                        old_program.to_string_lossy().into_owned(),
                        "daemon".into(),
                        "start".into(),
                        "--supervised".into(),
                    ],
                    environment: None,
                    working_directory: None,
                },
            };
            let verification_count = std::cell::Cell::new(0);
            let checker = managed_daemon_rollback_identity_checker_with(
                || Some(loaded.clone()),
                |_| panic!("dormant job has no live generation"),
                |program| {
                    assert_eq!(program, old_program);
                    assert_eq!(
                        std::fs::read_to_string(&plist).unwrap(),
                        original,
                        "rollback bytes must be restored before signature verification"
                    );
                    verification_count.set(verification_count.get() + 1);
                    signature_valid
                },
            );
            let state = std::cell::Cell::new(ManagedJobState::Loaded);
            let mut operations = Vec::new();
            let error = ensure_managed_daemon_plist_at_with_identity(
                &plist,
                &new_program,
                &log,
                471,
                || state.get(),
                |command| {
                    assert_eq!(command.get_program(), "/bin/launchctl");
                    let args: Vec<_> = command
                        .get_args()
                        .map(|arg| arg.to_string_lossy().into_owned())
                        .collect();
                    match args[0].as_str() {
                        "bootout" => {
                            state.set(ManagedJobState::Unloaded);
                            assert_eq!(args, ["bootout", "gui/471/foundation.terrene.csq"]);
                            assert_eq!(
                                verification_count.get(),
                                0,
                                "dormant bootout must not need an executable signature"
                            );
                        }
                        "load" if operations.len() == 1 => {
                            assert_eq!(verification_count.get(), 0);
                            assert_eq!(
                                read_managed_daemon_program(&plist).unwrap(),
                                Some(new_program.clone())
                            );
                            operations.push(args[0].clone());
                            anyhow::bail!("fixture_candidate_load_failed");
                        }
                        "load" => {
                            assert!(signature_valid, "invalid dormant rollback must never load");
                            assert_eq!(verification_count.get(), 1);
                            assert_eq!(
                                read_managed_daemon_program(&plist).unwrap(),
                                Some(old_program.clone())
                            );
                        }
                        other => panic!("unexpected operation: {other}"),
                    }
                    if args[0] == "load" {
                        state.set(ManagedJobState::Loaded);
                    }
                    operations.push(args[0].clone());
                    Ok(())
                },
                checker,
            )
            .unwrap_err();
            assert_eq!(std::fs::read_to_string(&plist).unwrap(), original);
            assert_eq!(verification_count.get(), 1);
            assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
            if signature_valid {
                assert_eq!(operations, ["bootout", "load", "load"]);
                assert_eq!(
                    error.to_string(),
                    "managed_plist_restored_after_failed_repair"
                );
            } else {
                assert_eq!(operations, ["bootout", "load"]);
                assert_eq!(error.to_string(), "managed_plist_restoration_failed");
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn m1_dormant_rollback_rejects_invalid_signature_after_restoring_bytes() {
            m1_dormant_rollback_flow(false);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn m1_dormant_rollback_reloads_valid_signature_after_restoring_bytes() {
            m1_dormant_rollback_flow(true);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn m2_malformed_unloaded_plist_repairs_production_flow() {
            use super::super::*;
            let _env = csq_core::platform::test_env::lock();
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let program = fixture.path().join("csq");
            let log = fixture.path().join("log");
            let original = "<plist><dict><key>truncated";
            std::fs::write(&plist, original).unwrap();
            let expected = build_launchd_plist(&program, &log);
            let mut observations = 0;
            let state = std::cell::Cell::new(ManagedJobState::Unloaded);
            let mut operations = Vec::new();
            let outcome = ensure_managed_daemon_plist_at_with_identity(
                &plist,
                &program,
                &log,
                471,
                || {
                    observations += 1;
                    state.get()
                },
                |command| {
                    assert_eq!(command.get_program(), "/bin/launchctl");
                    let args: Vec<_> = command
                        .get_args()
                        .map(|arg| arg.to_string_lossy().into_owned())
                        .collect();
                    assert_eq!(
                        args,
                        ["load".to_owned(), plist.to_string_lossy().into_owned()]
                    );
                    assert_eq!(std::fs::read_to_string(&plist).unwrap(), expected);
                    operations.push(args[0].clone());
                    state.set(ManagedJobState::Loaded);
                    Ok(())
                },
                |_, _| panic!("definitely absent job has no rollback identity"),
            )
            .unwrap();
            assert_eq!(outcome, ManagedPlistOutcome::Repaired);
            assert_eq!(
                observations, 3,
                "absence is checked before fallback and repair, then loading is confirmed"
            );
            assert_eq!(operations, ["load"]);
            assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn m2_malformed_loaded_or_unknown_plist_remains_unchanged() {
            use super::super::*;
            let _env = csq_core::platform::test_env::lock();
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let original = b"<plist><dict><key>truncated";
            for state in [ManagedJobState::Loaded, ManagedJobState::Unknown] {
                std::fs::write(&plist, original).unwrap();
                let error = ensure_managed_daemon_plist_at_with_identity(
                    &plist,
                    &fixture.path().join("csq"),
                    &fixture.path().join("log"),
                    471,
                    || state,
                    |_| panic!("unconfirmed absence must never repair"),
                    |_, _| panic!("parse failure must not inspect loaded identity"),
                )
                .unwrap_err();
                assert!(error.is::<UnparseableManagedPlist>());
                assert_eq!(std::fs::read(&plist).unwrap(), original);
                assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn m2_unloaded_execution_overrides_still_refused() {
            use super::super::*;
            let _env = csq_core::platform::test_env::lock();
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let program = fixture.path().join("csq");
            let log = fixture.path().join("log");
            for key in ["Program", "RootDirectory", "BundleProgram"] {
                let original = build_launchd_plist(&program, &log).replace(
                    "</dict>\n</plist>",
                    &format!("<key>{key}</key><string>/fixture/override</string></dict>\n</plist>"),
                );
                std::fs::write(&plist, &original).unwrap();
                let error = ensure_managed_daemon_plist_at_with_identity(
                    &plist,
                    &program,
                    &log,
                    471,
                    || panic!("execution override must not be admitted as parse failure"),
                    |_| panic!("execution override must never load"),
                    |_, _| panic!("execution override must never inspect identity"),
                )
                .unwrap_err();
                assert!(!error.is::<UnparseableManagedPlist>());
                assert_eq!(std::fs::read_to_string(&plist).unwrap(), original);
                assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn m2_unreadable_input_does_not_fallback() {
            use super::super::*;
            use std::os::unix::fs::PermissionsExt;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            std::fs::write(&plist, "malformed").unwrap();
            std::fs::set_permissions(&plist, std::fs::Permissions::from_mode(0o000)).unwrap();
            let result = ensure_managed_daemon_plist_at_with_identity(
                &plist,
                &fixture.path().join("csq"),
                &fixture.path().join("log"),
                471,
                || panic!("read failure must not be admitted as parse failure"),
                |_| panic!("read failure must not load"),
                |_, _| panic!("read failure must not inspect identity"),
            );
            std::fs::set_permissions(&plist, std::fs::Permissions::from_mode(0o600)).unwrap();
            let error = result.unwrap_err();
            assert!(!error.is::<UnparseableManagedPlist>());
            assert_eq!(error.to_string(), "managed_plist_merge_read_failed");
            assert_eq!(std::fs::read_to_string(&plist).unwrap(), "malformed");
            assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn m2_non_regular_or_oversized_inputs_do_not_fallback() {
            use super::super::*;
            use std::os::unix::fs::symlink;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let program = fixture.path().join("csq");
            let log = fixture.path().join("log");
            let target = fixture.path().join("target");
            std::fs::write(&target, "malformed").unwrap();
            symlink(&target, &plist).unwrap();
            for kind in ["symlink", "directory", "oversized"] {
                match kind {
                    "directory" => {
                        std::fs::remove_file(&plist).unwrap();
                        std::fs::create_dir(&plist).unwrap();
                    }
                    "oversized" => {
                        std::fs::remove_dir(&plist).unwrap();
                        std::fs::write(&plist, vec![b'x'; 1024 * 1024 + 1]).unwrap();
                    }
                    _ => {}
                }
                let error = ensure_managed_daemon_plist_at_with_identity(
                    &plist,
                    &program,
                    &log,
                    471,
                    || panic!("invalid input must not reach fallback job probe"),
                    |_| panic!("invalid input must not load"),
                    |_, _| panic!("invalid input must not inspect identity"),
                )
                .unwrap_err();
                assert!(!error.is::<UnparseableManagedPlist>());
                assert_eq!(std::fs::read_to_string(&target).unwrap(), "malformed");
                match kind {
                    "symlink" => assert!(std::fs::symlink_metadata(&plist)
                        .unwrap()
                        .file_type()
                        .is_symlink()),
                    "directory" => assert!(plist.is_dir()),
                    "oversized" => {
                        assert_eq!(std::fs::metadata(&plist).unwrap().len(), 1024 * 1024 + 1)
                    }
                    _ => unreachable!(),
                }
                assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 2);
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn h1_background_migration_reloads_production_flow() {
            use super::super::*;
            let _env = csq_core::platform::test_env::lock();
            let fixture = tempfile::TempDir::new().unwrap();
            seed_fixture_rollback_cli(fixture.path());
            let plist = fixture.path().join("managed.plist");
            let program = fixture.path().join("old-csq");
            let log = fixture.path().join("log");
            let original = build_launchd_plist(&program, &log)
                .replace("<string>Adaptive</string>", "<string>Background</string>");
            std::fs::write(&plist, &original).unwrap();
            let state = std::cell::Cell::new(ManagedJobState::Loaded);
            let mut operations = Vec::new();
            let outcome = ensure_managed_daemon_plist_at_with_identity(
                &plist,
                &program,
                &log,
                471,
                || state.get(),
                |command| {
                    assert_eq!(command.get_program(), "/bin/launchctl");
                    let args: Vec<_> = command
                        .get_args()
                        .map(|arg| arg.to_string_lossy().into_owned())
                        .collect();
                    match args[0].as_str() {
                        "bootout" => {
                            state.set(ManagedJobState::Unloaded);
                            assert_eq!(args, ["bootout", "gui/471/foundation.terrene.csq"]);
                            assert_eq!(std::fs::read_to_string(&plist).unwrap(), original);
                        }
                        "load" => {
                            assert_eq!(
                                args,
                                ["load".to_owned(), plist.to_string_lossy().into_owned()]
                            );
                            let updated = std::fs::read_to_string(&plist).unwrap();
                            assert!(updated.contains("<string>Adaptive</string>"));
                            assert!(!updated.contains("<string>Background</string>"));
                        }
                        other => panic!("unexpected operation: {other}"),
                    }
                    if args[0] == "load" {
                        state.set(ManagedJobState::Loaded);
                    }
                    operations.push(args[0].clone());
                    Ok(())
                },
                fixture_rollback_identity,
            )
            .unwrap();
            assert_eq!(outcome, ManagedPlistOutcome::Repaired);
            assert_eq!(operations, ["bootout", "load"]);
            assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 2);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn h1_interactive_process_type_preserves_production_flow_bytes() {
            use super::super::*;
            let _env = csq_core::platform::test_env::lock();
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let program = fixture.path().join("csq");
            let log = fixture.path().join("log");
            for process_type in ["Interactive", "Standard", "Adaptive"] {
                let original = build_launchd_plist(&program, &log).replace(
                    "<string>Adaptive</string>",
                    &format!("<string>{process_type}</string>"),
                );
                std::fs::write(&plist, &original).unwrap();
                let outcome = ensure_managed_daemon_plist_at_with_identity(
                    &plist,
                    &program,
                    &log,
                    471,
                    || ManagedJobState::Loaded,
                    |_| panic!("user process type must not restart"),
                    |_, _| panic!("unchanged plist must not inspect loaded identity"),
                )
                .unwrap();
                assert_eq!(outcome, ManagedPlistOutcome::AlreadyCurrent);
                assert_eq!(std::fs::read(&plist).unwrap(), original.as_bytes());
                assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn user_key_only_plist_difference_does_not_restart_production_job() {
            use super::super::*;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let program = fixture.path().join("csq");
            let log = fixture.path().join("log");
            let original = user_customized_plist(&program, &log);
            std::fs::write(&plist, &original).unwrap();
            for binary in [false, true] {
                std::fs::write(&plist, &original).unwrap();
                if binary {
                    let mut command = std::process::Command::new("/usr/bin/plutil");
                    command.args(["-convert", "binary1", "--"]).arg(&plist);
                    assert!(matches!(
                        csq_core::cli_deps::cli_shim::probe_command(command),
                        csq_core::cli_deps::cli_shim::ProbeOutcome::Ok(_)
                    ));
                }
                let bytes = std::fs::read(&plist).unwrap();
                let result = ensure_managed_daemon_plist_at(
                    &plist,
                    &program,
                    &log,
                    471,
                    || ManagedJobState::Loaded,
                    |_| panic!("user-key-only differences must never restart"),
                )
                .unwrap();
                assert_eq!(result, ManagedPlistOutcome::AlreadyCurrent);
                assert_eq!(std::fs::read(&plist).unwrap(), bytes);
                assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn owned_key_repair_preserves_user_environment_and_plist_types() {
            use super::super::*;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let log = fixture.path().join("log");
            let original = user_customized_plist(&fixture.path().join("old"), &log);
            std::fs::write(&plist, &original).unwrap();
            let program = fixture.path().join("new");
            let state = std::cell::Cell::new(ManagedJobState::Unloaded);
            let result = ensure_managed_daemon_plist_at(
                &plist,
                &program,
                &log,
                471,
                || state.get(),
                |command| {
                    assert_eq!(command.get_program(), "/bin/launchctl");
                    assert_eq!(
                        command.get_args().next(),
                        Some(std::ffi::OsStr::new("load"))
                    );
                    state.set(ManagedJobState::Loaded);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(result, ManagedPlistOutcome::Repaired);
            let config = read_managed_rollback_config(&plist).unwrap();
            assert_eq!(config.program, program);
            assert_eq!(
                config.environment.unwrap()["CSQ_FIXTURE_ONLY"],
                "fixture-value"
            );
            assert_eq!(
                config.working_directory.unwrap(),
                PathBuf::from("/fixture/project")
            );
            let updated = std::fs::read_to_string(&plist).unwrap();
            for retained in [
                "Interactive",
                "<key>Nice</key>",
                "<integer>3</integer>",
                "<key>UserData</key>",
                "YWJj",
                "<date>2025-01-01T00:00:00Z</date>",
            ] {
                assert!(
                    updated.contains(retained),
                    "typed user key missing: {retained}"
                );
            }
            assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn loaded_user_environment_must_match_canonical_rollback_snapshot() {
            use super::super::*;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let program = fixture.path().join("old");
            std::fs::write(
                &plist,
                user_customized_plist(&program, &fixture.path().join("log")),
            )
            .unwrap();
            let config = read_managed_rollback_config(&plist).unwrap();
            let mut metadata = serde_json::json!({
                "found": true, "Label": LAUNCHD_LABEL, "Program": program,
                "ProgramArguments": [program, "daemon", "start", "--supervised"], "PID": 471,
                "hasEnvironmentVariables": true, "EnvironmentVariables": {"CSQ_FIXTURE_ONLY": "fixture-value"},
                "hasWorkingDirectory": true, "WorkingDirectory": "/fixture/project",
                "hasRootDirectory": false, "hasBundleProgram": false,
            });
            let loaded =
                loaded_managed_identity_from_json(&serde_json::to_vec(&metadata).unwrap()).unwrap();
            assert!(managed_rollback_identity_matches_with(
                &config,
                || Some(loaded.clone()),
                |_| Some(123),
                |_| true
            ));
            metadata["EnvironmentVariables"]["CSQ_FIXTURE_ONLY"] =
                serde_json::json!("conflicting-value");
            let conflicting =
                loaded_managed_identity_from_json(&serde_json::to_vec(&metadata).unwrap()).unwrap();
            assert!(!managed_rollback_identity_matches_with(
                &config,
                || Some(conflicting.clone()),
                |_| Some(123),
                |_| true
            ));
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn owned_numeric_types_are_repaired_despite_equal_nsnumber_values() {
            use super::super::*;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let program = fixture.path().join("csq");
            let log = fixture.path().join("log");
            let expected = build_launchd_plist(&program, &log);
            for (before, after) in [
                (
                    "<key>RunAtLoad</key>\n\t<true/>",
                    "<key>RunAtLoad</key>\n\t<integer>1</integer>",
                ),
                (
                    "<key>SuccessfulExit</key>\n\t\t<false/>",
                    "<key>SuccessfulExit</key>\n\t\t<integer>0</integer>",
                ),
                ("<integer>10</integer>", "<real>10</real>"),
            ] {
                assert!(expected.contains(before));
                let original = expected.replace(before, after);
                std::fs::write(&plist, &original).unwrap();
                let merged = merge_managed_daemon_plist(&plist, &expected).unwrap();
                assert_ne!(
                    merged,
                    original.as_bytes(),
                    "owned plist types must be repaired"
                );
                assert!(read_managed_rollback_config_from_bytes_for_test(
                    &plist, &merged
                ));
                assert_eq!(std::fs::read_to_string(&plist).unwrap(), original);
                assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
            }
        }

        #[cfg(target_os = "macos")]
        fn read_managed_rollback_config_from_bytes_for_test(path: &Path, bytes: &[u8]) -> bool {
            let staged = super::super::stage_managed_daemon_plist(path, bytes).unwrap();
            let valid = super::super::read_managed_rollback_config(&staged).is_some();
            std::fs::remove_file(staged).unwrap();
            valid
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn merge_refuses_execution_override_and_cleans_private_stages() {
            use super::super::*;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let expected =
                build_launchd_plist(&fixture.path().join("new"), &fixture.path().join("log"));
            let mut cases = vec!["invalid plist".to_string()];
            for key in ["Program", "RootDirectory", "BundleProgram"] {
                cases.push(expected.replace(
                    "</dict>\n</plist>",
                    &format!("<key>{key}</key><string>/fixture/foreign</string></dict>\n</plist>"),
                ));
            }
            for original in cases {
                std::fs::write(&plist, &original).unwrap();
                assert!(merge_managed_daemon_plist(&plist, &expected).is_err());
                assert_eq!(std::fs::read_to_string(&plist).unwrap(), original);
                assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn production_managed_install_wires_absolute_launchctl_command() {
            use super::super::*;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let state = std::cell::Cell::new(ManagedJobState::Unloaded);
            let mut observations = 0;
            let result = ensure_managed_daemon_plist_at(
                &plist,
                &fixture.path().join("csq"),
                &fixture.path().join("log"),
                471,
                || {
                    observations += 1;
                    state.get()
                },
                |command| {
                    assert_eq!(command.get_program(), "/bin/launchctl");
                    assert_eq!(
                        command
                            .get_args()
                            .map(std::ffi::OsStr::to_owned)
                            .collect::<Vec<_>>(),
                        [
                            std::ffi::OsString::from("load"),
                            plist.as_os_str().to_owned()
                        ]
                    );
                    state.set(ManagedJobState::Loaded);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(result, ManagedPlistOutcome::Installed);
            assert_eq!(
                observations, 1,
                "new install requires only the post-load confirmation"
            );
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn l2_missing_unloaded_service_is_not_installed_without_execution() {
            use super::super::*;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("missing.plist");
            let outcome = platform_uninstall_with(
                &plist,
                471,
                || ManagedJobState::Unloaded,
                |_| panic!("absent job must never execute a lifecycle command"),
            )
            .unwrap();
            assert_eq!(outcome, ManagedUninstallOutcome::NotInstalled);
            assert_eq!(
                managed_uninstall_output(outcome, &plist),
                "csq daemon service not installed."
            );
            assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 0);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn l2_existing_unloaded_plist_records_actual_removal() {
            use super::super::*;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            std::fs::write(&plist, "installed disk bytes").unwrap();
            let outcome = platform_uninstall_with(
                &plist,
                471,
                || ManagedJobState::Unloaded,
                |_| panic!("unloaded job needs no lifecycle command"),
            )
            .unwrap();
            assert_eq!(outcome, ManagedUninstallOutcome::PlistRemoved);
            assert!(!plist.exists());
            assert_eq!(
                managed_uninstall_output(outcome, &plist),
                format!(
                    "csq daemon service uninstalled.\n  Removed: {}",
                    plist.display()
                )
            );
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn l2_loaded_service_without_plist_records_only_job_removal() {
            use super::super::*;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("missing.plist");
            let state = std::cell::Cell::new(ManagedJobState::Loaded);
            let mut executions = 0;
            let outcome = platform_uninstall_with(
                &plist,
                471,
                || state.get(),
                |command| {
                    executions += 1;
                    assert_eq!(command.get_program(), "/bin/launchctl");
                    assert_eq!(
                        command.get_args().collect::<Vec<_>>(),
                        ["bootout", "gui/471/foundation.terrene.csq"]
                    );
                    state.set(ManagedJobState::Unloaded);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(executions, 1);
            assert_eq!(
                outcome,
                ManagedUninstallOutcome::JobUnloaded {
                    plist_removed: false
                }
            );
            assert_eq!(
                managed_uninstall_output(outcome, &plist),
                "csq daemon service uninstalled."
            );
            assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 0);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn l2_loaded_service_with_plist_records_both_removals() {
            use super::super::*;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            std::fs::write(&plist, "installed disk bytes").unwrap();
            let state = std::cell::Cell::new(ManagedJobState::Loaded);
            let outcome = platform_uninstall_with(
                &plist,
                471,
                || state.get(),
                |_| {
                    state.set(ManagedJobState::Unloaded);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(
                outcome,
                ManagedUninstallOutcome::JobUnloaded {
                    plist_removed: true
                }
            );
            assert!(!plist.exists());
            assert_eq!(
                managed_uninstall_output(outcome, &plist),
                format!(
                    "csq daemon service uninstalled.\n  Removed: {}",
                    plist.display()
                )
            );
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn l2_remove_failure_preserves_retry_state_without_success_outcome() {
            use super::super::*;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            std::fs::create_dir(&plist).unwrap();
            let error = platform_uninstall_with(
                &plist,
                471,
                || ManagedJobState::Unloaded,
                |_| panic!("unloaded job needs no lifecycle command"),
            )
            .unwrap_err();
            assert_eq!(error.to_string(), "managed_uninstall_remove_failed");
            assert!(plist.is_dir());
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn production_uninstall_targets_canonical_service_and_confirms_absence() {
            use super::super::*;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("foreign.plist");
            std::fs::write(&plist, "foreign Label must not choose service").unwrap();
            let state = std::cell::Cell::new(ManagedJobState::Loaded);
            let calls = std::cell::Cell::new(0);
            platform_uninstall_with(
                &plist,
                471,
                || state.get(),
                |command| {
                    calls.set(calls.get() + 1);
                    assert_eq!(command.get_program(), "/bin/launchctl");
                    assert_eq!(
                        command.get_args().collect::<Vec<_>>(),
                        ["bootout", "gui/471/foundation.terrene.csq"]
                    );
                    state.set(ManagedJobState::Unloaded);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(calls.get(), 1);
            assert!(!plist.exists());
            // An absent disk plist still cannot hide a loaded managed service.
            state.set(ManagedJobState::Loaded);
            platform_uninstall_with(
                &plist,
                471,
                || state.get(),
                |_| {
                    calls.set(calls.get() + 1);
                    state.set(ManagedJobState::Unloaded);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(calls.get(), 2);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn uninstall_failure_and_unknown_state_preserve_plist_for_retry() {
            use super::super::*;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            for after in [
                ManagedJobState::Loaded,
                ManagedJobState::Unknown,
                ManagedJobState::Unloaded,
            ] {
                std::fs::write(&plist, "original").unwrap();
                let state = std::cell::Cell::new(ManagedJobState::Loaded);
                assert!(platform_uninstall_with(
                    &plist,
                    471,
                    || state.get(),
                    |_| {
                        state.set(after);
                        anyhow::bail!("fixture timeout")
                    }
                )
                .is_err());
                assert_eq!(std::fs::read_to_string(&plist).unwrap(), "original");
            }
            assert!(platform_uninstall_with(
                &plist,
                471,
                || ManagedJobState::Unknown,
                |_| panic!("unknown state cannot boot out")
            )
            .is_err());
            platform_uninstall_with(
                &plist,
                471,
                || ManagedJobState::Unloaded,
                |_| panic!("unloaded state needs no command"),
            )
            .unwrap();
            assert!(!plist.exists());
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn managed_repair_bootout_command_targets_only_canonical_service() {
            use super::super::managed_daemon_launchctl_command;
            // Neither a mutable disk Label nor its pathname may select the
            // service to stop. Exercise the same factory production executes.
            let fixture = tempfile::TempDir::new().unwrap();
            let foreign = fixture.path().join("foreign.plist");
            std::fs::write(&foreign, "<key>Label</key><string>fixture.foreign</string>").unwrap();
            for path in [&foreign, &fixture.path().join("missing.plist")] {
                let command = managed_daemon_launchctl_command("bootout", path, 471).unwrap();
                assert_eq!(command.get_program(), "/bin/launchctl");
                let arguments: Vec<_> = command.get_args().map(|arg| arg.to_owned()).collect();
                assert_eq!(
                    arguments,
                    ["bootout", "gui/471/foundation.terrene.csq"].map(std::ffi::OsString::from)
                );
            }
            let command = managed_daemon_launchctl_command("load", &foreign, 471).unwrap();
            let arguments: Vec<_> = command.get_args().map(|arg| arg.to_owned()).collect();
            assert_eq!(
                arguments,
                [std::ffi::OsString::from("load"), foreign.into_os_string()]
            );
            assert!(managed_daemon_launchctl_command("unload", fixture.path(), 471).is_err());
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn n1_successful_load_without_observed_job_never_installs_or_repairs() {
            use super::super::*;
            let _env = csq_core::platform::test_env::lock();
            for prior in ["missing", "matching", "drifted"] {
                for after in [ManagedJobState::Unloaded, ManagedJobState::Unknown] {
                    let fixture = tempfile::TempDir::new().unwrap();
                    let plist = fixture.path().join("managed.plist");
                    let program = fixture.path().join("new");
                    let log = fixture.path().join("log");
                    match prior {
                        "matching" => {
                            std::fs::write(&plist, build_launchd_plist(&program, &log)).unwrap()
                        }
                        "drifted" => std::fs::write(
                            &plist,
                            build_launchd_plist(&fixture.path().join("old"), &log),
                        )
                        .unwrap(),
                        _ => {}
                    }
                    let state = std::cell::Cell::new(ManagedJobState::Unloaded);
                    let mut operations = Vec::new();
                    let error = ensure_managed_daemon_plist_at_with_identity(
                        &plist,
                        &program,
                        &log,
                        471,
                        || state.get(),
                        |command| {
                            assert_eq!(command.get_program(), "/bin/launchctl");
                            let args: Vec<_> = command
                                .get_args()
                                .map(|a| a.to_string_lossy().into_owned())
                                .collect();
                            assert_eq!(
                                args,
                                ["load".to_owned(), plist.to_string_lossy().into_owned()]
                            );
                            operations.push(args[0].clone());
                            state.set(after);
                            Ok(()) // genuine false-success executor condition
                        },
                        |_, _| panic!("an absent job has no rollback identity"),
                    )
                    .unwrap_err();
                    assert_eq!(
                        error.root_cause().to_string(),
                        "managed_plist_load_unconfirmed"
                    );
                    assert_eq!(operations, ["load"]);
                    assert!(
                        !plist.exists(),
                        "existing failed-load retry policy must remain"
                    );
                    assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 0);
                }
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn n1_observed_loaded_confirms_real_install_and_repair_flow() {
            use super::super::*;
            let _env = csq_core::platform::test_env::lock();
            for prior in ["missing", "matching", "drifted"] {
                let fixture = tempfile::TempDir::new().unwrap();
                let plist = fixture.path().join("managed.plist");
                let program = fixture.path().join("new");
                let log = fixture.path().join("log");
                match prior {
                    "matching" => {
                        std::fs::write(&plist, build_launchd_plist(&program, &log)).unwrap()
                    }
                    "drifted" => std::fs::write(
                        &plist,
                        build_launchd_plist(&fixture.path().join("old"), &log),
                    )
                    .unwrap(),
                    _ => {}
                }
                let state = std::cell::Cell::new(ManagedJobState::Unloaded);
                let mut observations = 0;
                let outcome = ensure_managed_daemon_plist_at_with_identity(
                    &plist,
                    &program,
                    &log,
                    471,
                    || {
                        observations += 1;
                        state.get()
                    },
                    |command| {
                        assert_eq!(command.get_program(), "/bin/launchctl");
                        assert_eq!(
                            command.get_args().next(),
                            Some(std::ffi::OsStr::new("load"))
                        );
                        state.set(ManagedJobState::Loaded);
                        Ok(())
                    },
                    |_, _| panic!("an absent job has no rollback identity"),
                )
                .unwrap();
                assert_eq!(
                    outcome,
                    if prior == "missing" {
                        ManagedPlistOutcome::Installed
                    } else {
                        ManagedPlistOutcome::Repaired
                    }
                );
                assert_eq!(observations, if prior == "missing" { 1 } else { 2 });
                let config = read_managed_rollback_config(&plist).unwrap();
                assert_eq!(config.program, program);
                assert_eq!(
                    config.arguments,
                    [
                        program.to_string_lossy().into_owned(),
                        "daemon".into(),
                        "start".into(),
                        "--supervised".into()
                    ]
                );
                if prior != "drifted" {
                    assert_eq!(
                        std::fs::read_to_string(&plist).unwrap(),
                        build_launchd_plist(&program, &log)
                    );
                }
                assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn n1_rollback_load_without_observed_job_reports_restoration_failed() {
            use super::super::*;
            let _env = csq_core::platform::test_env::lock();
            for restored_state in [
                ManagedJobState::Unloaded,
                ManagedJobState::Unknown,
                ManagedJobState::Loaded,
            ] {
                let fixture = tempfile::TempDir::new().unwrap();
                let plist = fixture.path().join("managed.plist");
                let program = fixture.path().join("new");
                let log = fixture.path().join("log");
                let original = build_launchd_plist(&fixture.path().join("old"), &log);
                std::fs::write(&plist, &original).unwrap();
                let state = std::cell::Cell::new(ManagedJobState::Loaded);
                let mut operations = Vec::new();
                let error = ensure_managed_daemon_plist_at_with_identity(
                    &plist,
                    &program,
                    &log,
                    471,
                    || state.get(),
                    |command| {
                        let op = command
                            .get_args()
                            .next()
                            .unwrap()
                            .to_string_lossy()
                            .into_owned();
                        operations.push(op.clone());
                        assert_eq!(command.get_program(), "/bin/launchctl");
                        if op == "bootout" {
                            state.set(ManagedJobState::Unloaded);
                            return Ok(());
                        }
                        assert_eq!(op, "load");
                        if std::fs::read_to_string(&plist).unwrap() != original {
                            anyhow::bail!("n1_primary_load_failure");
                        }
                        state.set(restored_state);
                        Ok(()) // rollback command succeeded; observation decides
                    },
                    |_, _| true, // private loaded identity fixture, no host query
                )
                .unwrap_err();
                assert_eq!(
                    error.to_string(),
                    if restored_state == ManagedJobState::Loaded {
                        "managed_plist_restored_after_failed_repair"
                    } else {
                        "managed_plist_restoration_failed"
                    }
                );
                assert_eq!(error.root_cause().to_string(), "n1_primary_load_failure");
                assert_eq!(operations, ["bootout", "load", "load"]);
                assert_eq!(std::fs::read_to_string(&plist).unwrap(), original);
                assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn n1_unobserved_candidate_load_enters_rollback_and_preserves_primary() {
            use super::super::*;
            let _env = csq_core::platform::test_env::lock();
            for candidate_state in [ManagedJobState::Unloaded, ManagedJobState::Unknown] {
                let fixture = tempfile::TempDir::new().unwrap();
                let plist = fixture.path().join("managed.plist");
                let program = fixture.path().join("new");
                let log = fixture.path().join("log");
                let original = build_launchd_plist(&fixture.path().join("old"), &log);
                std::fs::write(&plist, &original).unwrap();
                let state = std::cell::Cell::new(ManagedJobState::Loaded);
                let mut operations = Vec::new();
                let error = ensure_managed_daemon_plist_at_with_identity(
                    &plist,
                    &program,
                    &log,
                    471,
                    || state.get(),
                    |command| {
                        assert_eq!(command.get_program(), "/bin/launchctl");
                        let op = command
                            .get_args()
                            .next()
                            .unwrap()
                            .to_string_lossy()
                            .into_owned();
                        operations.push(op.clone());
                        if op == "bootout" {
                            state.set(ManagedJobState::Unloaded);
                        } else {
                            state.set(if std::fs::read_to_string(&plist).unwrap() == original {
                                ManagedJobState::Loaded
                            } else {
                                candidate_state
                            });
                        }
                        Ok(())
                    },
                    |_, _| true,
                )
                .unwrap_err();
                assert_eq!(
                    error.to_string(),
                    "managed_plist_restored_after_failed_repair"
                );
                assert_eq!(
                    error.root_cause().to_string(),
                    "managed_plist_load_unconfirmed"
                );
                assert_eq!(operations, ["bootout", "load", "load"]);
                assert_eq!(std::fs::read_to_string(&plist).unwrap(), original);
                assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn drifted_loaded_plist_requires_successful_bootout_before_rewrite() {
            use super::super::{
                ensure_managed_daemon_plist_with_operations, ManagedJobState, ManagedPlistOutcome,
            };
            let _env = csq_core::platform::test_env::lock();
            let fixture = tempfile::TempDir::new().unwrap();
            seed_fixture_rollback_cli(fixture.path());
            let plist = fixture.path().join("managed.plist");
            let log = fixture.path().join("daemon.log");
            let original = super::super::build_launchd_plist(&fixture.path().join("old-csq"), &log);
            let expected = super::super::build_launchd_plist(&fixture.path().join("new-csq"), &log);
            std::fs::write(&plist, &original).unwrap();
            let result = ensure_managed_daemon_plist_with_operations(
                &plist,
                &expected,
                || ManagedJobState::Loaded,
                |operation, path| {
                    assert_eq!(operation, "bootout");
                    let staged: Vec<_> = std::fs::read_dir(fixture.path())
                        .unwrap()
                        .map(|entry| entry.unwrap().path())
                        .filter(|candidate| {
                            candidate != path && candidate.file_name().unwrap() != "old-csq"
                        })
                        .collect();
                    assert_eq!(
                        staged.len(),
                        2,
                        "replacement and rollback are staged before bootout"
                    );
                    assert!(staged
                        .iter()
                        .any(|path| std::fs::read_to_string(path).unwrap() == expected));
                    assert!(staged
                        .iter()
                        .any(|path| std::fs::read_to_string(path).unwrap() == original));
                    anyhow::bail!("fixture bootout failed")
                },
                fixture_rollback_identity,
                |_from, to, writer| writer.replace(to).map_err(Into::into),
            );
            assert!(result.is_err());
            assert_eq!(std::fs::read_to_string(&plist).unwrap(), original);
            assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 2);
            let state = std::cell::Cell::new(ManagedJobState::Loaded);
            let mut operations = Vec::new();
            let result = ensure_managed_daemon_plist_with_operations(
                &plist,
                &expected,
                || state.get(),
                |operation, _| {
                    state.set(if operation == "load" {
                        ManagedJobState::Loaded
                    } else {
                        ManagedJobState::Unloaded
                    });
                    operations.push(operation.to_string());
                    Ok(())
                },
                fixture_rollback_identity,
                |_from, to, writer| writer.replace(to).map_err(Into::into),
            )
            .unwrap();
            assert_eq!(result, ManagedPlistOutcome::Repaired);
            assert_eq!(operations, ["bootout", "load"]);
            assert_eq!(std::fs::read_to_string(&plist).unwrap(), expected);
        }

        #[cfg(target_os = "macos")]
        fn failed_managed_repair_restores_loaded_job_and_original_plist(fail_replace: bool) {
            use super::super::{ensure_managed_daemon_plist_with_operations, ManagedJobState};
            let _env = csq_core::platform::test_env::lock();
            let fixture = tempfile::TempDir::new().unwrap();
            seed_fixture_rollback_cli(fixture.path());
            let plist = fixture.path().join("managed.plist");
            let log = fixture.path().join("daemon.log");
            let original = super::super::build_launchd_plist(&fixture.path().join("old-csq"), &log);
            let expected = super::super::build_launchd_plist(&fixture.path().join("new-csq"), &log);
            std::fs::write(&plist, &original).unwrap();
            let loaded = std::cell::Cell::new(true);
            let operations = std::cell::RefCell::new(Vec::new());
            let replace_calls = std::cell::Cell::new(0);
            let result = ensure_managed_daemon_plist_with_operations(
                &plist,
                &expected,
                || {
                    if loaded.get() {
                        ManagedJobState::Loaded
                    } else {
                        ManagedJobState::Unloaded
                    }
                },
                |operation, path| {
                    operations.borrow_mut().push(operation.to_owned());
                    if operation == "bootout" {
                        loaded.set(false);
                        return Ok(());
                    }
                    assert_eq!(operation, "load");
                    let bytes = std::fs::read_to_string(path)?;
                    if bytes == expected {
                        anyhow::bail!("fixture_new_load_failed");
                    }
                    assert_eq!(bytes, original);
                    loaded.set(true);
                    Ok(())
                },
                fixture_rollback_identity,
                |from, to, writer| {
                    replace_calls.set(replace_calls.get() + 1);
                    if fail_replace && std::fs::read_to_string(from)? == expected {
                        anyhow::bail!("fixture_replace_failed");
                    }
                    writer.replace(to).map_err(Into::into)
                },
            );
            assert!(
                result.is_err(),
                "restoration must not turn failed repair into success"
            );
            assert!(
                loaded.get(),
                "failed repair must restore the originally loaded job"
            );
            assert_eq!(std::fs::read_to_string(&plist).unwrap(), original);
            let operations = operations.into_inner();
            assert_eq!(operations.first().map(String::as_str), Some("bootout"));
            assert_eq!(operations.last().map(String::as_str), Some("load"));
            assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 2);
            assert_eq!(replace_calls.get(), if fail_replace { 1 } else { 2 });
            let primary = result.unwrap_err().root_cause().to_string();
            assert_eq!(
                primary,
                if fail_replace {
                    "fixture_replace_failed"
                } else {
                    "fixture_new_load_failed"
                }
            );
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn failed_managed_repair_replace_restores_loaded_job() {
            failed_managed_repair_restores_loaded_job_and_original_plist(true);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn failed_managed_repair_load_restores_loaded_job() {
            failed_managed_repair_restores_loaded_job_and_original_plist(false);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn unknown_rollback_identity_keeps_loaded_job_without_lifecycle_operations() {
            use super::super::{ensure_managed_daemon_plist_with_operations, ManagedJobState};
            let _env = csq_core::platform::test_env::lock();
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let original = super::super::build_launchd_plist(
                &fixture.path().join("old-csq"),
                &fixture.path().join("log"),
            )
            .replace("foundation.terrene.csq", "fixture.foreign-job");
            std::fs::write(&plist, &original).unwrap();
            let result = ensure_managed_daemon_plist_with_operations(
                &plist,
                "new plist",
                || ManagedJobState::Loaded,
                |_, _| panic!("unknown rollback identity must not stop or reload a job"),
                fixture_rollback_identity,
                |_, _, _| panic!("unknown rollback identity must preserve disk bytes"),
            );
            assert_eq!(
                result.unwrap_err().to_string(),
                "managed_plist_rollback_identity_unknown"
            );
            assert_eq!(std::fs::read_to_string(&plist).unwrap(), original);
            assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn bootout_timeout_after_unload_restores_original_job() {
            use super::super::*;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let original =
                build_launchd_plist(&fixture.path().join("old"), &fixture.path().join("log"));
            let expected =
                build_launchd_plist(&fixture.path().join("new"), &fixture.path().join("log"));
            std::fs::write(&plist, &original).unwrap();
            let state = std::cell::Cell::new(ManagedJobState::Loaded);
            let mut operations = Vec::new();
            let error = ensure_managed_daemon_plist_with_operations(
                &plist,
                &expected,
                || state.get(),
                |operation, _| {
                    operations.push(operation.to_owned());
                    if operation == "bootout" {
                        state.set(ManagedJobState::Unloaded);
                        anyhow::bail!("fixture bootout timed out after unloading");
                    }
                    assert_eq!(std::fs::read_to_string(&plist).unwrap(), original);
                    state.set(ManagedJobState::Loaded);
                    Ok(())
                },
                |_, _| true,
                |from, to, _| std::fs::rename(from, to).map_err(Into::into),
            )
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                "managed_plist_restored_after_failed_repair"
            );
            assert_eq!(operations, ["bootout", "load"]);
            assert_eq!(state.get(), ManagedJobState::Loaded);
            assert_eq!(std::fs::read_to_string(&plist).unwrap(), original);
            assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn bootout_timeout_unknown_state_preserves_original_and_reports_uncertainty() {
            use super::super::*;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            std::fs::write(&plist, "original").unwrap();
            let state = std::cell::Cell::new(ManagedJobState::Loaded);
            let error = ensure_managed_daemon_plist_with_operations(
                &plist,
                "new",
                || state.get(),
                |operation, _| {
                    assert_eq!(operation, "bootout");
                    state.set(ManagedJobState::Unknown);
                    anyhow::bail!("timeout")
                },
                |_, _| true,
                |_, _, _| panic!("uncertain job must not rewrite"),
            )
            .unwrap_err();
            assert_eq!(error.to_string(), "managed_plist_bootout_state_unknown");
            assert_eq!(std::fs::read_to_string(&plist).unwrap(), "original");
            assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn restoration_failure_preserves_primary_repair_error_and_original_plist() {
            use super::super::{ensure_managed_daemon_plist_with_operations, ManagedJobState};
            let _env = csq_core::platform::test_env::lock();
            let fixture = tempfile::TempDir::new().unwrap();
            seed_fixture_rollback_cli(fixture.path());
            let plist = fixture.path().join("managed.plist");
            let original = super::super::build_launchd_plist(
                &fixture.path().join("old-csq"),
                &fixture.path().join("log"),
            );
            std::fs::write(&plist, &original).unwrap();
            let loads = std::cell::Cell::new(0);
            let result = ensure_managed_daemon_plist_with_operations(
                &plist,
                "new plist",
                || ManagedJobState::Loaded,
                |operation, _| {
                    if operation == "bootout" {
                        return Ok(());
                    }
                    assert_eq!(operation, "load");
                    loads.set(loads.get() + 1);
                    anyhow::bail!(if loads.get() == 1 {
                        "fixture_new_load_failed"
                    } else {
                        "fixture_restore_load_failed"
                    });
                },
                fixture_rollback_identity,
                |_from, to, writer| writer.replace(to).map_err(Into::into),
            );
            let error = result.unwrap_err();
            assert_eq!(error.to_string(), "managed_plist_restoration_failed");
            assert_eq!(error.root_cause().to_string(), "fixture_new_load_failed");
            assert_eq!(loads.get(), 2);
            assert_eq!(std::fs::read_to_string(&plist).unwrap(), original);
            assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 2);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn loaded_dormant_job_with_missing_program_is_repaired() {
            use super::super::*;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let old = fixture.path().join("deleted-old-csq");
            let log = fixture.path().join("log");
            let original = build_launchd_plist(&old, &log);
            std::fs::write(&plist, &original).unwrap();
            let expected = build_launchd_plist(&fixture.path().join("new-csq"), &log);
            let mut value = serde_json::json!({
                "found": true, "Label": LAUNCHD_LABEL, "Program": old,
                "ProgramArguments": [old, "daemon", "start", "--supervised"],
                "hasEnvironmentVariables": false, "hasWorkingDirectory": false,
                "hasRootDirectory": false, "hasBundleProgram": false,
            });
            for pid in [None, Some(serde_json::json!(0))] {
                if let Some(pid) = pid {
                    value["PID"] = pid;
                }
                let loaded =
                    loaded_managed_identity_from_json(&serde_json::to_vec(&value).unwrap())
                        .unwrap();
                assert_eq!(loaded.pid, 0);
                let state = std::cell::Cell::new(ManagedJobState::Loaded);
                let mut operations = Vec::new();
                std::fs::write(&plist, &original).unwrap();
                let result = ensure_managed_daemon_plist_with_operations(
                    &plist,
                    &expected,
                    || state.get(),
                    |operation, _| {
                        state.set(if operation == "load" {
                            ManagedJobState::Loaded
                        } else {
                            ManagedJobState::Unloaded
                        });
                        operations.push(operation.to_owned());
                        Ok(())
                    },
                    |snapshot, restoring| {
                        if restoring {
                            return true;
                        }
                        let config = read_managed_rollback_config(snapshot).unwrap();
                        managed_rollback_identity_matches_with(
                            &config,
                            || Some(loaded.clone()),
                            |_| panic!("dormant job has no generation"),
                            |_| false,
                        )
                    },
                    |from, to, _| std::fs::rename(from, to).map_err(Into::into),
                )
                .unwrap();
                assert_eq!(result, ManagedPlistOutcome::Repaired);
                assert_eq!(operations, ["bootout", "load"]);
                assert_eq!(std::fs::read_to_string(&plist).unwrap(), expected);
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn dormant_identity_rejects_live_transition_and_malformed_pid() {
            use super::super::*;
            let value = serde_json::json!({
                "found": true, "Label": LAUNCHD_LABEL, "Program": "/fixture/csq",
                "ProgramArguments": ["/fixture/csq", "daemon", "start", "--supervised"],
                "PID": 0, "hasEnvironmentVariables": false, "hasWorkingDirectory": false,
                "hasRootDirectory": false, "hasBundleProgram": false,
            });
            let first =
                loaded_managed_identity_from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
            let mut second = first.clone();
            second.pid = 471;
            let mut samples = [first.clone(), second].into_iter();
            assert!(!managed_rollback_identity_matches_with(
                &first.config,
                || samples.next(),
                |_| Some(123),
                |_| true
            ));
            for pid in [
                serde_json::json!(null),
                serde_json::json!("0"),
                serde_json::json!(-1),
                serde_json::json!(4294967296_u64),
            ] {
                let mut malformed = value.clone();
                malformed["PID"] = pid;
                assert!(loaded_managed_identity_from_json(
                    &serde_json::to_vec(&malformed).unwrap()
                )
                .is_none());
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn rollback_identity_rejects_conflicting_loaded_executable_or_generation() {
            use super::super::{
                managed_rollback_identity_matches_with, LoadedManagedIdentity,
                ManagedRollbackConfig,
            };
            let config = ManagedRollbackConfig {
                program: PathBuf::from("/fixture/csq"),
                environment: None,
                working_directory: None,
                arguments: vec![
                    "/fixture/csq".into(),
                    "daemon".into(),
                    "start".into(),
                    "--supervised".into(),
                ],
            };
            let matching = LoadedManagedIdentity {
                pid: 471,
                config: config.clone(),
            };
            assert!(managed_rollback_identity_matches_with(
                &config,
                || Some(matching.clone()),
                |_| Some(123456),
                |_| true
            ));
            let conflicting = LoadedManagedIdentity {
                pid: 471,
                config: ManagedRollbackConfig {
                    program: PathBuf::from("/fixture/other-csq"),
                    environment: None,
                    working_directory: None,
                    arguments: vec![
                        "/fixture/other-csq".into(),
                        "daemon".into(),
                        "start".into(),
                        "--supervised".into(),
                    ],
                },
            };
            assert!(!managed_rollback_identity_matches_with(
                &config,
                || Some(conflicting.clone()),
                |_| Some(123456),
                |_| true
            ));
            let mut starts = [123456, 123457].into_iter();
            assert!(!managed_rollback_identity_matches_with(
                &config,
                || Some(matching.clone()),
                |_| starts.next(),
                |_| true
            ));
            assert!(!managed_rollback_identity_matches_with(
                &config,
                || Some(matching.clone()),
                |_| Some(0),
                |_| true
            ));
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn loaded_rollback_metadata_requires_typed_fields_and_no_execution_overrides() {
            let good = serde_json::json!({
                "found": true, "Label": "foundation.terrene.csq", "Program": "/fixture/csq",
                "ProgramArguments": ["/fixture/csq", "daemon", "start", "--supervised"], "PID": 471,
                "hasEnvironmentVariables": false, "hasWorkingDirectory": false,
                "hasRootDirectory": false, "hasBundleProgram": false,
            });
            assert!(super::super::loaded_managed_identity_from_json(
                &serde_json::to_vec(&good).unwrap()
            )
            .is_some());
            for (key, value) in [
                ("Program", serde_json::json!("/fixture/foreign")),
                ("PID", serde_json::json!("471")),
                ("hasEnvironmentVariables", serde_json::json!(true)),
                ("hasWorkingDirectory", serde_json::json!(null)),
            ] {
                let mut invalid = good.clone();
                invalid[key] = value;
                assert!(super::super::loaded_managed_identity_from_json(
                    &serde_json::to_vec(&invalid).unwrap()
                )
                .is_none());
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn rollback_config_rejects_program_override() {
            let config = serde_json::json!({
                "Label": "foundation.terrene.csq",
                "Program": "/fixture/foreign-executable",
                "ProgramArguments": ["/fixture/csq", "daemon", "start", "--supervised"],
            });
            assert!(!super::super::managed_plist_has_canonical_label_from_json(
                &serde_json::to_vec(&config).unwrap(),
            ));
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn rollback_config_rejects_unsupported_execution_options() {
            for (key, value) in [
                ("EnvironmentVariables", serde_json::json!({"TEST": 1})),
                ("WorkingDirectory", serde_json::json!("relative/project")),
                ("RootDirectory", serde_json::json!("/fixture/other-root")),
            ] {
                let mut config = serde_json::json!({
                    "Label": "foundation.terrene.csq",
                    "ProgramArguments": ["/fixture/csq", "daemon", "start", "--supervised"],
                });
                config[key] = value;
                assert!(
                    !super::super::managed_plist_has_canonical_label_from_json(
                        &serde_json::to_vec(&config).unwrap(),
                    ),
                    "unsupported {key} must refuse rollback"
                );
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn rollback_config_rejects_malformed_supported_values() {
            for (key, value) in [
                ("RunAtLoad", serde_json::json!("true")),
                ("KeepAlive", serde_json::json!("garbage")),
                ("KeepAlive", serde_json::json!({})),
                ("KeepAlive", serde_json::json!({"SuccessfulExit": "false"})),
                (
                    "KeepAlive",
                    serde_json::json!({"SuccessfulExit": false, "Crashed": true}),
                ),
                ("ThrottleInterval", serde_json::json!(-1)),
                ("ThrottleInterval", serde_json::json!(1.5)),
                ("ThrottleInterval", serde_json::json!(2147483648_u64)),
                ("ProcessType", serde_json::json!("Foreground")),
                ("ProcessType", serde_json::json!(null)),
                ("StandardOutPath", serde_json::json!({})),
                ("StandardOutPath", serde_json::json!("relative/log")),
                (
                    "StandardErrorPath",
                    serde_json::json!("/fixture/log\nother"),
                ),
                ("StandardErrorPath", serde_json::json!(false)),
            ] {
                let mut config = serde_json::json!({
                    "Label": "foundation.terrene.csq",
                    "ProgramArguments": ["/fixture/csq", "daemon", "start", "--supervised"],
                });
                config[key] = value;
                assert!(
                    !super::super::managed_plist_has_canonical_label_from_json(
                        &serde_json::to_vec(&config).unwrap(),
                    ),
                    "malformed {key} must refuse rollback"
                );
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn rollback_config_accepts_supported_optional_values() {
            for process_type in ["Background", "Standard", "Adaptive", "Interactive"] {
                for keep_alive in [
                    serde_json::json!(false),
                    serde_json::json!(true),
                    serde_json::json!({"SuccessfulExit": false}),
                    serde_json::json!({"SuccessfulExit": true}),
                ] {
                    let config = serde_json::json!({
                        "Label": "foundation.terrene.csq",
                        "ProgramArguments": ["/fixture/csq", "daemon", "start", "--supervised"],
                        "RunAtLoad": true, "KeepAlive": keep_alive,
                        "ThrottleInterval": 2147483647, "ProcessType": process_type,
                        "StandardOutPath": "/fixture/log with spaces",
                        "StandardErrorPath": "/fixture/stderr",
                    });
                    assert!(super::super::managed_plist_has_canonical_label_from_json(
                        &serde_json::to_vec(&config).unwrap(),
                    ));
                }
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn rollback_config_rejects_malformed_daemon_arguments() {
            for arguments in [
                serde_json::json!(["/fixture/csq", "daemon", "start"]),
                serde_json::json!(["/fixture/csq", "daemon", "stop", "--supervised"]),
                serde_json::json!(["/fixture/csq", "daemon", "start", 1]),
                serde_json::json!(["csq", "daemon", "start", "--supervised"]),
            ] {
                let config = serde_json::json!({
                    "Label": "foundation.terrene.csq", "ProgramArguments": arguments,
                });
                assert!(!super::super::managed_plist_has_canonical_label_from_json(
                    &serde_json::to_vec(&config).unwrap(),
                ));
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn system_plutil_reads_actual_program_with_escaped_characters() {
            use super::super::read_managed_daemon_program;
            let fixture = tempfile::TempDir::new().unwrap();
            let plist = fixture.path().join("managed.plist");
            let program = fixture.path().join("path with spaces & <> \" ' /csq");
            let xml = super::super::build_launchd_plist(&program, &fixture.path().join("log"));
            std::fs::write(&plist, xml).unwrap();
            assert_eq!(read_managed_daemon_program(&plist).unwrap(), Some(program));
            std::fs::write(&plist, "malformed plist").unwrap();
            assert!(read_managed_daemon_program(&plist).is_err());
            assert!(
                read_managed_daemon_program(&fixture.path().join("missing.plist"))
                    .unwrap()
                    .is_none()
            );
        }
    }
}
