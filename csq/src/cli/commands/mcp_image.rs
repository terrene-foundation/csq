//! Native image capture; declared source metadata is not binary/publisher attestation.
use csq_core::messaging::image_report::{
    BuildIdentity, ChildIdentity, FileIdentity, ImageReport, LoadedImage, SessionIdentity,
};
#[cfg(unix)]
use csq_core::messaging::{
    image_report::{self, Availability, Edition, ImageSurface, LoadedKind, Platform, SourceState},
    model::Surface,
};
#[cfg(unix)]
use csq_core::sessions;

#[cfg(unix)]
fn compiled_build() -> Option<BuildIdentity> {
    let revision = option_env!("CSQ_IMAGE_REVISION")
        .filter(|v| !v.is_empty())
        .map(str::to_owned);
    let source_state = match option_env!("CSQ_IMAGE_SOURCE_STATE") {
        Some("clean") if revision.is_some() => SourceState::Clean,
        Some("dirty") if revision.is_some() => SourceState::Dirty,
        Some("unknown") | None | Some("clean" | "dirty") => SourceState::Unknown,
        _ => return None,
    };
    Some(BuildIdentity {
        edition: match crate::BUILD_EDITION {
            "community" => Edition::Community,
            "enterprise" => Edition::Enterprise,
            _ => return None,
        },
        version: env!("CARGO_PKG_VERSION").into(),
        target: option_env!("CSQ_IMAGE_TARGET")?.into(),
        availability: if source_state == SourceState::Clean {
            Availability::Available
        } else {
            Availability::Unavailable
        },
        source_state,
        revision,
    })
}
#[cfg(unix)]
pub(super) fn file_identity(meta: &std::fs::Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    if !meta.is_file() {
        return None;
    }
    Some(FileIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
        size: meta.len(),
        mtime_sec: meta.mtime(),
        mtime_nsec: u32::try_from(meta.mtime_nsec()).ok()?,
        ctime_sec: meta.ctime(),
        ctime_nsec: u32::try_from(meta.ctime_nsec()).ok()?,
    })
}
#[cfg(unix)]
pub(super) fn loaded(pid: u32) -> Option<FileIdentity> {
    #[cfg(target_os = "linux")]
    {
        if pid <= 1 {
            return None;
        }
        // The numeric OS proc executable link is an independent observation, not a report path.
        file_identity(
            &std::fs::File::open(format!("/proc/{pid}/exe"))
                .ok()?
                .metadata()
                .ok()?,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}
#[cfg(unix)]
pub(super) fn capture() -> Option<ImageReport> {
    let who = super::sessions_messages::resolve_verified().ok()?;
    let owner = who.as_recipient();
    let owner_exact = owner.started_exact?;
    let pid = std::process::id();
    let child_start = sessions::ancestor_start(pid)?;
    if sessions::ancestor_start(owner.pid)? != owner_exact {
        return None;
    }
    let first = loaded(pid);
    let platform = if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else {
        Platform::Other
    };
    let report = ImageReport::new(
        platform,
        ChildIdentity {
            pid,
            start_exact: child_start,
        },
        SessionIdentity {
            pid: owner.pid,
            started_at: owner.started_at,
            start_exact: owner_exact,
            surface: match owner.surface {
                Surface::ClaudeCode => ImageSurface::ClaudeCode,
                Surface::Codex => ImageSurface::Codex,
            },
            handle_sha256: who.handle_dir_hash().into(),
        },
        compiled_build()?,
        LoadedImage {
            kind: if first.is_some() {
                LoadedKind::LinuxProcExe
            } else {
                LoadedKind::Unavailable
            },
            identity: first.clone(),
        },
    )
    .ok()?;
    if sessions::ancestor_start(pid)? != child_start
        || sessions::ancestor_start(owner.pid)? != owner_exact
        || loaded(pid) != first
    {
        return None;
    }
    // Diagnostic publication is best effort and cannot replace any messaging outcome.
    let _ = image_report::publish(&who, &report);
    Some(report)
}

#[cfg(not(unix))]
pub(super) fn capture() -> Option<ImageReport> {
    None
}

use serde::Serialize;
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Coverage {
    #[cfg(unix)]
    Complete,
    #[cfg(unix)]
    Limited,
    Unavailable,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum State {
    #[cfg(unix)]
    SameImage,
    #[cfg(unix)]
    DifferentImage,
    Undetermined,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Reason {
    #[cfg(unix)]
    None,
    #[cfg(any(unix, test))]
    NoObservedSessions,
    #[cfg(unix)]
    ReportUnavailable,
    #[cfg(unix)]
    MalformedReport,
    #[cfg(unix)]
    UnsafeReport,
    #[cfg(unix)]
    ReportLimit,
    #[cfg(unix)]
    ProcessVisibility,
    #[cfg(unix)]
    IdentityMismatch,
    #[cfg(unix)]
    ImageChanged,
    PlatformUnavailable,
    #[cfg(unix)]
    BuildUnavailable,
    #[cfg(unix)]
    InstalledUnavailable,
}
#[derive(Debug, Serialize)]
pub(super) struct Row {
    state: State,
    reason: Reason,
    #[serde(skip_serializing_if = "Option::is_none")]
    child: Option<ChildIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<SessionIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    build: Option<BuildIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reported_loaded: Option<LoadedImage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_loaded: Option<FileIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    installed: Option<FileIdentity>,
}
#[derive(Debug, Serialize)]
pub(super) struct Images {
    coverage: Coverage,
    rows: Vec<Row>,
}
impl Row {
    fn unknown(reason: Reason) -> Self {
        Self {
            state: State::Undetermined,
            reason,
            child: None,
            session: None,
            build: None,
            reported_loaded: None,
            observed_loaded: None,
            installed: None,
        }
    }
}
#[cfg(unix)]
#[derive(Clone, PartialEq, Eq)]
struct Observation {
    session: SessionIdentity,
    loaded: Option<FileIdentity>,
    installed: Option<FileIdentity>,
}
#[cfg(unix)]
fn observe(
    listings: &[(sessions::CliKind, sessions::Listing)],
    path: &std::path::Path,
    child: &ChildIdentity,
    installed: &impl Fn() -> Option<FileIdentity>,
) -> Option<Observation> {
    if listings.len() != 2
        || listings
            .iter()
            .any(|(_, l)| l.incomplete || l.restricted || !l.unreadable_pids.is_empty())
    {
        return None;
    }
    if sessions::ancestor_start(child.pid)? != child.start_exact {
        return None;
    }
    let mut found = None;
    for (kind, listing) in listings {
        let ancestry = |owner| {
            sessions::ancestor_path_with(
                owner,
                child.pid,
                &sessions::parent_pid,
                &sessions::ancestor_start,
            )
        };
        let Ok(owner) = sessions::resolve_caller(
            *kind,
            &listing.sessions,
            &listing.unreadable_pids,
            listing.visibility(),
            path.to_str(),
            &ancestry,
            &sessions::is_session_hop,
            &sessions::process_start_time,
        ) else {
            continue;
        };
        let verified = owner.verified().ok()?;
        let (info, exact) =
            sessions::session_info_exact_for_pid_kind(*kind, owner.pid()).ok()??;
        if exact == 0
            || info.pid != owner.pid()
            || info.started_at != Some(owner.started_at())
            || info.config_dir.canonicalize().ok()? != path
            || verified.handle_dir() != path
        {
            return None;
        }
        let observation = Observation {
            session: SessionIdentity {
                pid: owner.pid(),
                started_at: owner.started_at(),
                start_exact: exact,
                surface: match kind {
                    sessions::CliKind::Claude => ImageSurface::ClaudeCode,
                    sessions::CliKind::Codex => ImageSurface::Codex,
                },
                handle_sha256: verified.handle_dir_hash().into(),
            },
            loaded: loaded(child.pid),
            installed: installed(),
        };
        if sessions::ancestor_start(owner.pid())? != exact
            || sessions::ancestor_start(child.pid)? != child.start_exact
            || found.is_some()
        {
            return None;
        }
        found = Some(observation);
    }
    found
}
#[cfg(unix)]
fn compare(report: ImageReport, before: Option<Observation>, after: Option<Observation>) -> Row {
    let mut row = Row {
        state: State::Undetermined,
        reason: Reason::ProcessVisibility,
        child: Some(report.child().clone()),
        session: Some(report.session().clone()),
        build: Some(report.build().clone()),
        reported_loaded: Some(report.loaded().clone()),
        observed_loaded: before.as_ref().and_then(|o| o.loaded.clone()),
        installed: before.as_ref().and_then(|o| o.installed.clone()),
    };
    let (Some(before), Some(after)) = (before, after) else {
        return row;
    };
    row.reason = if &before.session != report.session() || before.session != after.session {
        Reason::IdentityMismatch
    } else if !cfg!(target_os = "linux") || report.loaded().identity.is_none() {
        Reason::PlatformUnavailable
    } else if before.loaded.is_none() || after.loaded.is_none() {
        Reason::ProcessVisibility
    } else if before.loaded != after.loaded || report.loaded().identity != before.loaded {
        Reason::ImageChanged
    } else if report.build().availability != Availability::Available {
        Reason::BuildUnavailable
    } else if before.installed.is_none() || before.installed != after.installed {
        Reason::InstalledUnavailable
    } else {
        row.state = if before.loaded == before.installed {
            State::SameImage
        } else {
            State::DifferentImage
        };
        Reason::None
    };
    row
}
#[cfg(unix)]
fn collect_handles(
    handles: Vec<std::path::PathBuf>,
    incomplete: bool,
    observer: &impl Fn(&std::path::Path, &ChildIdentity) -> Option<Observation>,
) -> Images {
    let incomplete = incomplete || handles.len() > 32;
    let mut result = Images {
        coverage: if incomplete {
            Coverage::Limited
        } else {
            Coverage::Complete
        },
        rows: Vec::new(),
    };
    if handles.is_empty() {
        result.coverage = if incomplete {
            Coverage::Limited
        } else {
            Coverage::Unavailable
        };
        result.rows.push(Row::unknown(if incomplete {
            Reason::ProcessVisibility
        } else {
            Reason::NoObservedSessions
        }));
        return result;
    }
    for path in handles.into_iter().take(32) {
        if result.rows.len() == 128 {
            result.coverage = Coverage::Limited;
            break;
        }
        match image_report::read_reports_observed(&path, &|child| observer(&path, child)) {
            Ok(rows) if !rows.is_empty() => {
                for observed in rows {
                    if result.rows.len() == 128 {
                        result.coverage = Coverage::Limited;
                        break;
                    }
                    result
                        .rows
                        .push(compare(observed.report, observed.before, observed.after));
                }
            }
            Ok(_) => result.rows.push(Row::unknown(Reason::ReportUnavailable)),
            Err(error) => {
                result.coverage = Coverage::Limited;
                result.rows.push(Row::unknown(match error {
                    image_report::ReportError::Malformed => Reason::MalformedReport,
                    image_report::ReportError::Unsafe => Reason::UnsafeReport,
                    image_report::ReportError::Limit => Reason::ReportLimit,
                    _ => Reason::ReportUnavailable,
                }));
            }
        }
    }
    result
}
pub(super) fn collect(installed: &impl Fn() -> Option<FileIdentity>) -> Images {
    #[cfg(unix)]
    {
        let listings: Vec<_> = [sessions::CliKind::Claude, sessions::CliKind::Codex]
            .into_iter()
            .filter_map(|kind| sessions::try_list_detailed_kind(kind).map(|table| (kind, table)))
            .collect();
        let mut incomplete = listings.len() != 2
            || listings
                .iter()
                .any(|(_, l)| l.incomplete || l.restricted || !l.unreadable_pids.is_empty());
        let mut handles = std::collections::BTreeSet::new();
        let mut raw_handles = std::collections::BTreeSet::new();
        'discover: for (_, table) in &listings {
            for session in &table.sessions {
                if raw_handles.contains(&session.config_dir) {
                    continue;
                }
                if raw_handles.len() == 32 {
                    incomplete = true;
                    break 'discover;
                }
                raw_handles.insert(session.config_dir.clone());
                match session.config_dir.canonicalize() {
                    Ok(path) => {
                        handles.insert(path);
                    }
                    Err(_) => incomplete = true,
                }
            }
        }
        collect_handles(handles.into_iter().collect(), incomplete, &|path, child| {
            observe(&listings, path, child, installed)
        })
    }
    #[cfg(not(unix))]
    {
        let _ = installed;
        Images {
            coverage: Coverage::Unavailable,
            rows: vec![Row::unknown(Reason::PlatformUnavailable)],
        }
    }
}
pub(super) fn text_lines(images: &Images) -> Result<Vec<String>, serde_json::Error> {
    let coverage = serde_json::to_string(&images.coverage)?;
    let mut text = vec![format!(
        "MCP executable-file identity: coverage {}",
        coverage.trim_matches('"')
    )];
    for row in &images.rows {
        let state = serde_json::to_string(&row.state)?;
        let reason = serde_json::to_string(&row.reason)?;
        text.push(format!(
            "  child {}: {} ({})",
            row.child
                .as_ref()
                .map_or_else(|| "unavailable".into(), |c| c.pid.to_string()),
            state.trim_matches('"'),
            reason.trim_matches('"')
        ));
    }
    Ok(text)
}

#[cfg(test)]
pub(super) fn empty_fixture() -> Images {
    Images {
        coverage: Coverage::Unavailable,
        rows: vec![Row::unknown(Reason::NoObservedSessions)],
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    #[test]
    fn native_build_carrier_is_compiled_and_ignores_runtime_overrides() {
        let _lock = csq_core::platform::test_env::lock();
        let keys = [
            "CSQ_IMAGE_REVISION",
            "CSQ_IMAGE_SOURCE_STATE",
            "CSQ_IMAGE_TARGET",
        ];
        struct Restore(Vec<(&'static str, Option<std::ffi::OsString>)>);
        impl Drop for Restore {
            fn drop(&mut self) {
                for (key, value) in &self.0 {
                    // SAFETY: workspace environment guard outlives this restore.
                    unsafe {
                        match value {
                            Some(v) => std::env::set_var(key, v),
                            None => std::env::remove_var(key),
                        }
                    }
                }
            }
        }
        let _restore = Restore(
            keys.iter()
                .map(|&key| (key, std::env::var_os(key)))
                .collect(),
        );
        for key in keys {
            // SAFETY: workspace guard serializes this independent first runtime value.
            unsafe { std::env::set_var(key, "first-runtime-value") };
        }
        let before = compiled_build().expect("validated build script must supply target");
        for key in keys {
            // SAFETY: mutation is serialized by the workspace environment guard.
            unsafe { std::env::set_var(key, "runtime-override-must-not-be-consumed") };
        }
        assert_eq!(
            compiled_build(),
            Some(before.clone()),
            "runtime override must not replace compiled image metadata"
        );
        assert_eq!(before.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(before.target, env!("CSQ_IMAGE_TARGET"));
        assert_eq!(
            before.revision.as_deref(),
            option_env!("CSQ_IMAGE_REVISION").filter(|v| !v.is_empty())
        );
    }
    fn diagnostic_report(child: u32) -> ImageReport {
        ImageReport::new(
            Platform::Linux,
            ChildIdentity {
                pid: child,
                start_exact: 43,
            },
            SessionIdentity {
                pid: 44,
                started_at: 45,
                start_exact: 46,
                surface: ImageSurface::Codex,
                handle_sha256: "a".repeat(64),
            },
            BuildIdentity {
                edition: Edition::Community,
                version: "1.2.3".into(),
                target: "x86_64-unknown-linux-gnu".into(),
                source_state: SourceState::Clean,
                availability: Availability::Available,
                revision: Some("b".repeat(40)),
            },
            LoadedImage {
                kind: LoadedKind::LinuxProcExe,
                identity: Some(FileIdentity {
                    dev: 1,
                    ino: 2,
                    size: 3,
                    mtime_sec: 4,
                    mtime_nsec: 0,
                    ctime_sec: 5,
                    ctime_nsec: 0,
                }),
            },
        )
        .unwrap()
    }
    fn evidence(report: &ImageReport) -> Observation {
        Observation {
            session: report.session().clone(),
            loaded: report.loaded().identity.clone(),
            installed: report.loaded().identity.clone(),
        }
    }
    #[test]
    fn doctor_image_comparison_requires_all_exact_independent_brackets() {
        let report = diagnostic_report(42);
        let observed = evidence(&report);
        let row = compare(
            report.clone(),
            Some(observed.clone()),
            Some(observed.clone()),
        );
        if !cfg!(target_os = "linux") {
            assert_eq!(row.state, State::Undetermined);
            assert_eq!(row.reason, Reason::PlatformUnavailable);
            return;
        }
        assert_eq!(row.state, State::SameImage);
        let mut changed = observed.clone();
        changed.loaded.as_mut().unwrap().ino += 1;
        let row = compare(report.clone(), Some(observed.clone()), Some(changed));
        assert_eq!(
            row.reason,
            Reason::ImageChanged,
            "changed live tuple must refuse a positive image verdict"
        );
        let mut wrong_owner = observed.clone();
        wrong_owner.session.start_exact += 1;
        assert_eq!(
            compare(report.clone(), Some(wrong_owner.clone()), Some(wrong_owner)).reason,
            Reason::IdentityMismatch,
            "wrong exact owner must not pass diagnostic binding"
        );
        assert_eq!(
            compare(report.clone(), None, Some(observed.clone())).reason,
            Reason::ProcessVisibility
        );
        let mut different = observed.clone();
        different.installed.as_mut().unwrap().ino += 1;
        assert_eq!(
            compare(report.clone(), Some(different.clone()), Some(different)).state,
            State::DifferentImage
        );
        let mut missing = observed.clone();
        missing.installed = None;
        assert_eq!(
            compare(report.clone(), Some(missing.clone()), Some(missing)).reason,
            Reason::InstalledUnavailable
        );
        let mut target_changed = observed.clone();
        target_changed.installed.as_mut().unwrap().ino += 1;
        assert_eq!(
            compare(report.clone(), Some(observed.clone()), Some(target_changed)).reason,
            Reason::InstalledUnavailable
        );
        let mut build = report.build().clone();
        build.source_state = SourceState::Dirty;
        build.availability = Availability::Unavailable;
        let unknown = ImageReport::new(
            Platform::Linux,
            report.child().clone(),
            report.session().clone(),
            build,
            report.loaded().clone(),
        )
        .unwrap();
        assert_eq!(
            compare(unknown, Some(observed.clone()), Some(observed)).reason,
            Reason::BuildUnavailable
        );
    }
    fn private_fixture() -> tempfile::TempDir {
        // Sibling launch fixtures mutate and delete process TMPDIR under their
        // own env lock. These read-only fixtures do not share that lock.
        let root =
            std::env::var_os(crate::cli::commands::tmpdir_outlives_test_support::SANDBOX_ENV)
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
        tempfile::TempDir::new_in(root).unwrap()
    }
    fn private_reports(count: usize) -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = private_fixture();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let reports = dir.path().join(".csq-mcp-images");
        std::fs::create_dir(&reports).unwrap();
        std::fs::set_permissions(&reports, std::fs::Permissions::from_mode(0o700)).unwrap();
        for i in 0..count {
            let report = diagnostic_report(42 + i as u32);
            let path = reports.join(format!("{}-43.json", report.child().pid));
            std::fs::write(&path, report.encode().unwrap()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        dir
    }
    #[test]
    fn doctor_image_discovery_and_read_caps_remain_explicit_and_read_only() {
        use std::os::unix::fs::PermissionsExt;
        let empty = collect_handles(vec![], false, &|_, _| None);
        assert_eq!(empty.coverage, Coverage::Unavailable);
        assert_eq!(empty.rows[0].reason, Reason::NoObservedSessions);
        let fixture = private_reports(1);
        let path = fixture.path().canonicalize().unwrap();
        let before = std::fs::read(path.join(".csq-mcp-images/42-43.json")).unwrap();
        let one = collect_handles(vec![path.clone()], false, &|_, child| {
            Some(evidence(&diagnostic_report(child.pid)))
        });
        assert_eq!(one.rows.len(), 1);
        assert_eq!(one.coverage, Coverage::Complete);
        assert_eq!(
            std::fs::read(path.join(".csq-mcp-images/42-43.json")).unwrap(),
            before
        );
        assert_eq!(
            std::fs::read_dir(path.join(".csq-mcp-images"))
                .unwrap()
                .count(),
            1
        );
        let text = text_lines(&one).unwrap();
        let wire = serde_json::to_value(&one).unwrap();
        assert!(text[0].contains(wire["coverage"].as_str().unwrap()));
        assert!(text[1].contains(wire["rows"][0]["state"].as_str().unwrap()));
        assert!(text[1].contains(wire["rows"][0]["reason"].as_str().unwrap()));
        let missing = private_fixture();
        std::fs::set_permissions(missing.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let unknown = collect_handles(
            vec![missing.path().canonicalize().unwrap()],
            false,
            &|_, _| None,
        );
        assert_eq!(unknown.rows[0].reason, Reason::ReportUnavailable);
        assert!(!missing.path().join(".csq-mcp-images").exists());
        let directories: Vec<_> = (0..33).map(|_| private_reports(1)).collect();
        let calls = std::cell::Cell::new(0);
        let limited = collect_handles(
            directories
                .iter()
                .map(|d| d.path().canonicalize().unwrap())
                .collect(),
            false,
            &|_, child| {
                calls.set(calls.get() + 1);
                Some(evidence(&diagnostic_report(child.pid)))
            },
        );
        assert_eq!(limited.coverage, Coverage::Limited);
        assert_eq!(
            limited.rows.len(),
            32,
            "thirty-third candidate handle must not be read"
        );
        assert_eq!(calls.get(), 64);
        let directories: Vec<_> = (0..17).map(|_| private_reports(8)).collect();
        let calls = std::cell::Cell::new(0);
        let limited = collect_handles(
            directories
                .iter()
                .map(|d| d.path().canonicalize().unwrap())
                .collect(),
            false,
            &|_, child| {
                calls.set(calls.get() + 1);
                Some(evidence(&diagnostic_report(child.pid)))
            },
        );
        assert_eq!(
            limited.rows.len(),
            128,
            "row cap must stop before another handle read"
        );
        assert_eq!(limited.coverage, Coverage::Limited);
        assert_eq!(calls.get(), 256);
    }
    #[test]
    fn doctor_image_fixture_outlives_transient_process_tmpdir() {
        use crate::cli::commands::tmpdir_outlives_test_support::{
            spawn_outlives_child, CHILD_ENV, SANDBOX_ENV,
        };
        const EXACT: &str = "cli::commands::mcp_image::tests::doctor_image_fixture_outlives_transient_process_tmpdir";
        const WITNESS: &str = "doctor-image-fixture-survived-transient-tmpdir";
        if std::env::var_os(CHILD_ENV).is_none() {
            spawn_outlives_child(EXACT, WITNESS);
            return;
        }
        let sandbox = std::env::var_os(SANDBOX_ENV).expect("owned child sandbox");
        let transient = tempfile::TempDir::new_in(&sandbox).unwrap();
        std::env::set_var("TMPDIR", transient.path());
        let fixture = private_reports(1);
        let missing = private_fixture();
        drop(transient);
        let path = fixture.path().canonicalize().unwrap();
        assert!(missing.path().canonicalize().unwrap().is_dir());
        let expected = std::fs::read(path.join(".csq-mcp-images/42-43.json")).unwrap();
        let collected = collect_handles(vec![path.clone()], false, &|_, child| {
            Some(evidence(&diagnostic_report(child.pid)))
        });
        assert_eq!(collected.coverage, Coverage::Complete);
        assert_eq!(
            std::fs::read(path.join(".csq-mcp-images/42-43.json")).unwrap(),
            expected
        );
        println!("{WITNESS}");
    }
}
