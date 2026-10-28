use super::*;
#[cfg(unix)]
fn fixture() -> (tempfile::TempDir, PathBuf, LaunchTicket) {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap().join("accounts");
    let handle = base.join("term-fixture");
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&handle).unwrap();
    fs::set_permissions(&handle, fs::Permissions::from_mode(0o700)).unwrap();
    let ticket = prepare_exec(&handle).expect("own process capture on supported Unix");
    (temp, base, ticket)
}
/// A second capture of an already-prepared handle re-runs the full syscall gauntlet
/// (store lock, `/proc` reads, mkdirat + writes) while the rest of this suite drives
/// the same host; a transient refusal here must not surface as a bare `None`. Every
/// iteration is a real `prepare_exec` attempt and the cap makes a persistent failure
/// LOUD, naming the window. Same shape as the accepted `mutate_until_ctime_advances`
/// sibling in `usage::aggregator`.
#[cfg(unix)]
fn prepare_exec_until_observed(handle: &Path) -> LaunchTicket {
    const BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
    let start = std::time::Instant::now();
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        if let Some(ticket) = prepare_exec(handle) {
            return ticket;
        }
        assert!(
            start.elapsed() <= BUDGET,
            "second incarnation never captured within {BUDGET:?} ({attempts} attempts)"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}
#[test]
fn filtered_absence_and_invalid_pid_are_never_positive_end() {
    assert_eq!(probe_process(0), ProcessProbe::Unknown);
    assert_eq!(probe_process(u32::MAX), ProcessProbe::Unknown);
    assert_eq!(ended_by(ProcessProbe::Unknown, 4), None);
    assert_eq!(ended_by(ProcessProbe::Present(4), 4), None);
    assert_eq!(
        ended_by(ProcessProbe::Present(5), 4),
        Some("incarnation_replaced")
    );
}
#[cfg(unix)]
#[test]
fn positive_gone_writes_end_but_unknown_never_does() {
    let (_temp, base, ticket) = fixture();
    let d = private::store(&base, false)
        .unwrap()
        .child(&ticket.generation, false)
        .unwrap();
    let launch: Launch = d.read("launch").unwrap().unwrap();
    assert!(!reconcile_end(&d, &launch, ProcessProbe::Unknown).unwrap());
    assert!(d.read::<End>("ended").unwrap().is_none());
    assert!(reconcile_end(&d, &launch, ProcessProbe::Gone).unwrap());
    let end: End = d.read("ended").unwrap().unwrap();
    assert_eq!(end.reason, "raw_esrch");
}
#[cfg(unix)]
#[test]
fn strict_binding_rejects_cross_project_fallback_and_changed_incarnation() {
    use std::os::unix::fs::PermissionsExt;
    let (temp, base, ticket) = fixture();
    let d = private::store(&base, false)
        .unwrap()
        .child(&ticket.generation, false)
        .unwrap();
    let mut l: Launch = d.read("launch").unwrap().unwrap();
    // Isolated synthetic project/scratch; never vendor or host scratch evidence.
    l.cwd = PathBuf::from("/synthetic-project");
    let tmp = fs::canonicalize(temp.path()).unwrap().join("synthetic-tmp");
    fs::create_dir(&tmp).unwrap();
    let root = tmp.join(format!("claude-{}", l.uid));
    let project = root.join("-synthetic-project");
    let id = "00000000-0000-4000-8000-000000000000";
    let scratch = project.join(id);
    fs::create_dir_all(&scratch).unwrap();
    for p in [&root, &project, &scratch] {
        fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut row = super::super::rows::SessionRowData {
        pid: l.pid,
        started_at: 1,
        surface: "claude-code",
        session_id: Some(id.into()),
        name: None,
        cwd: l.cwd.clone(),
        handle_dir: l.handle.clone(),
        account_slot: None,
        tty: None,
        terminal_title: None,
        scratch_dir: Some(scratch.clone()),
    };
    assert!(
        checked_binding(&l, &row, &tmp, &|_| ProcessProbe::Present(l.exact))
            .unwrap()
            .is_some()
    );
    assert!(
        checked_binding(&l, &row, &tmp, &|_| ProcessProbe::Present(l.exact + 1))
            .unwrap()
            .is_none()
    );
    row.scratch_dir = Some(root.join("different-project").join(id));
    assert!(
        checked_binding(&l, &row, &tmp, &|_| ProcessProbe::Present(l.exact))
            .unwrap()
            .is_none()
    );
}
#[cfg(unix)]
#[test]
fn foreign_boot_record_does_not_starve_independent_current_observation() {
    let (_temp, base, first) = fixture();
    let second = prepare_exec_until_observed(&base.join("term-fixture"));
    let root = private::store(&base, false).unwrap();
    let d1 = root.child(&first.generation, false).unwrap();
    let mut old: Launch = d1.read("launch").unwrap().unwrap();
    old.boot = "foreign-boot".into();
    fs::write(
        base.join("session-lifecycle")
            .join(&first.generation)
            .join("launch"),
        serde_json::to_vec(&old).unwrap(),
    )
    .unwrap();
    let d2 = root.child(&second.generation, false).unwrap();
    let mut reused: Launch = d2.read("launch").unwrap().unwrap();
    reused.exact += 1;
    fs::write(
        base.join("session-lifecycle")
            .join(&second.generation)
            .join("launch"),
        serde_json::to_vec(&reused).unwrap(),
    )
    .unwrap();
    assert!(reconcile_owned(&base, None).is_err());
    assert!(d1.read::<End>("ended").unwrap().is_none());
    assert_eq!(
        d2.read::<End>("ended").unwrap().unwrap().reason,
        "incarnation_replaced"
    );
}
#[cfg(unix)]
#[test]
fn actual_child_identity_and_successful_direct_wait_are_persisted() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let (temp, base, _self_ticket) = fixture();
    let mut child = Command::new("/bin/sh")
        .env_clear()
        .env("HOME", temp.path())
        .env("CSQ_BASE_DIR", &base)
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", temp.path())
        .arg("-c")
        .arg("read -r fixture_line; exit 0")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let ticket = capture_child(&base.join("term-fixture"), &child);
    // Release the controlled child before assertions, including capture-failure branches.
    child.stdin.take().unwrap().write_all(b"fixture\n").unwrap();
    let status = child.wait().unwrap();
    let ticket = ticket.expect("managed actualchild capture");
    waited(Some(&ticket), &status);
    let d = private::store(&base, false)
        .unwrap()
        .child(&ticket.generation, false)
        .unwrap();
    // `waited` persists the direct-wait evidence best-effort (its store write is
    // deliberately swallowed by `mark`); a transient failure of that write can drop
    // it. Re-issue the contract call until the event is observed;
    // re-writing is inert once present (O_EXCL), and the cap keeps a persistent miss
    // LOUD. The persisted-identity assertions below are unchanged.
    {
        const BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
        let start = std::time::Instant::now();
        let mut attempts = 0u32;
        while d.read::<End>("ended").unwrap().is_none() {
            attempts += 1;
            assert!(
                start.elapsed() <= BUDGET,
                "direct-wait evidence never observed within {BUDGET:?} ({attempts} attempts)"
            );
            waited(Some(&ticket), &status);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    let launch: Launch = d.read("launch").unwrap().unwrap();
    assert_eq!(launch.pid, child.id());
    assert_ne!(launch.pid, std::process::id());
    assert_eq!(launch.units, start_units());
    assert_eq!(
        d.read::<End>("ended").unwrap().unwrap().reason,
        "direct_wait"
    );
}

#[cfg(unix)]
#[test]
fn claude_root_normalization_reads_actual_fixture_registry_not_double_prefix() {
    use std::os::unix::fs::DirBuilderExt;
    let temp = tempfile::tempdir().unwrap();
    let home = fs::canonicalize(temp.path()).unwrap();
    let claude = home.join(".claude");
    let registry = claude.join("sessions");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&registry)
        .unwrap();
    let id = "00000000-0000-4000-8000-000000000000";
    let stamp = now().unwrap();
    fs::write(
        registry.join("123.json"),
        serde_json::to_vec(&serde_json::json!({"pid":123,"sessionId":id,"startedAt":stamp*1000}))
            .unwrap(),
    )
    .unwrap();
    let info:super::super::SessionInfo=serde_json::from_value(serde_json::json!({"pid":123,"cwd":"/synthetic","config_dir":home.join("accounts/term-fixture"),"started_at":stamp})).unwrap();
    let ctx = super::super::rows::RowContext {
        base_dir: home.join("accounts"),
        home: registry_home(&claude).unwrap().to_owned(),
        tmp_root: home.join("fixture-tmp"),
        uid: Some(unsafe { libc::geteuid() }),
        now_secs: stamp,
    };
    let rows = super::super::rows::enrich_kind(super::super::CliKind::Claude, vec![info], &ctx);
    assert_eq!(rows[0].session_id.as_deref(), Some(id));
    assert!(registry_home(&home.join("custom-root")).is_none());
}
