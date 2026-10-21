// Real MCP Backend and handle_line route with owned filesystem/process registry seams.
mod clock_admission_provider_tests {
    use super::*;
    use std::cell::Cell;
    use std::os::fd::AsRawFd;
    fn invoke_with_clock(
        root: &Path,
        pid: u32,
        arguments: Value,
        now: &dyn Fn() -> Result<u64, DirectiveError>,
    ) -> (bool, Value) {
        let fs = real_fs();
        let live = |_: &Recipient| Liveness::Live;
        let me = || Ok(caller(root, pid));
        let resolve = |p: u32, start: u64| {
            let row = registry(root)
                .entries
                .into_iter()
                .find(|r| r.pid == p && r.started_at == start)
                .expect("fixture resolver must find its owned registry row");
            Ok(Recipient {
                pid: row.pid,
                started_at: row.started_at,
                surface: Surface::Codex,
                started_exact: Some(START),
            })
        };
        let sessions = || Ok(registry(root));
        let set_name = |_: &VerifiedSession, _: Option<&str>| Ok(());
        let wake = |_: &Recipient| "codex_woken";
        let be = Backend {
            base_dir: root,
            now,
            fs: &fs,
            live: &live,
            caller: &me,
            resolve: &resolve,
            sessions: &sessions,
            set_name: &set_name,
            wake: &wake,
        };
        let line = json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"send","arguments":arguments}}).to_string();
        let response = handle_line(&be, &line).unwrap();
        assert!(
            response.get("error").is_none(),
            "real backend must reach tools/call"
        );
        let out = &response["result"];
        let text = out["content"][0]["text"].as_str().unwrap();
        (
            out["isError"].as_bool().unwrap(),
            serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.into())),
        )
    }

    fn admitted(file: &std::fs::File) -> bool {
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) }, 0);
            false
        } else {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            true
        }
    }
    #[test]
    fn actual_mcp_refreshes_under_guard_and_keeps_original_key_receipt() {
        let _env = crate::platform::test_env::lock();
        let owned = TempDir::new().unwrap();
        let root = owned.path();
        let _home = HomeGuard::install(root);
        write_registry(root, true);
        request::initialize(root, NOW + 10, &real_fs()).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(store::store_dir(root).join(".lock"))
            .unwrap();
        let held = Cell::new(0);
        let capture = Cell::new(0);
        let now = || {
            if admitted(&file) {
                held.set(held.get() + 1);
                Ok(NOW + 10)
            } else {
                capture.set(capture.get() + 1);
                Ok(NOW)
            }
        };
        let key = request::mint(NOW);
        let args = arguments("clock admission body", Some(&key));
        let (failed, receipt) = invoke_with_clock(root, 100, args.clone(), &now);
        assert!(
            !failed,
            "actual MCP route must refresh a capture ten seconds behind admitted authority"
        );
        let (failed, replay) = invoke_with_clock(root, 100, args, &now);
        assert!(!failed);
        assert_eq!(
            replay["id"], receipt["id"],
            "original canonical key must replay the same receipt"
        );
        assert_eq!(
            count_records(root),
            1,
            "fresh admission must not duplicate publication"
        );
        let ledger: Value = serde_json::from_slice(
            &std::fs::read(store::store_dir(root).join("requests/ledger.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            ledger["clock"],
            NOW + 10,
            "ledger UTC must come from honest admitted observation"
        );
        let id = receipt["id"].as_str().unwrap();
        let record: Value = serde_json::from_slice(
            &std::fs::read(store::store_dir(root).join(format!("{id}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(record["from"]["pid"], 100);
        assert_eq!(record["from"]["started_exact"], START);
        assert!(
            held.get() > 0,
            "actual MCP backend must consume provider while original lock is held"
        );
        assert!(
            capture.get() > 0,
            "fixture must exercise pre-admission capture separately"
        );
    }
    #[test]
    fn actual_mcp_rejects_successive_honest_sample_rollback() {
        let _env = crate::platform::test_env::lock();
        let owned = TempDir::new().unwrap();
        let root = owned.path();
        let _home = HomeGuard::install(root);
        write_registry(root, true);
        request::initialize(root, NOW, &real_fs()).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(store::store_dir(root).join(".lock"))
            .unwrap();
        let held = Cell::new(0);
        let now = || {
            if admitted(&file) {
                let n = held.get();
                held.set(n + 1);
                Ok(match n {
                    0 => NOW + 10,
                    1 => NOW + 15,
                    _ => NOW + 14,
                })
            } else {
                Ok(NOW)
            }
        };
        let key = request::mint(NOW);
        let (failed, error) = invoke_with_clock(
            root,
            100,
            arguments("strict provider sequence", Some(&key)),
            &now,
        );
        assert!(
            failed,
            "successive honest observation rollback must refuse even above original captured UTC"
        );
        let text = error.as_str().unwrap();
        assert!(text.contains("cause=clock"));
        assert!(
            text.contains(&format!("idempotency_key={key}")),
            "uncertainty must preserve original recovery key"
        );
        assert_eq!(
            count_records(root),
            0,
            "rollback before prepare must not publish a new record"
        );
        assert_eq!(
            held.get(),
            3,
            "fixture reaches replay, begin and prepare provider observations"
        );
    }
}
