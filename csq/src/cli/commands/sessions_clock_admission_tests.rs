// Native CLI complete send helper route; process and wall callbacks are explicit test seams.
mod clock_admission_provider_tests {
    use super::*;
    use std::cell::Cell;
    use std::os::fd::AsRawFd;
    #[test]
    fn native_send_helper_refreshes_after_lock_and_replays_original_key() {
        let w = world();
        let me = request::pin_test_session(w.a(), 5_000);
        request::initialize(w.base.path(), T0 + 10, &real_fs()).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(w.base.path().join("messages/.lock"))
            .unwrap();
        let held = Cell::new(0);
        let outside = Cell::new(0);
        let wall = || {
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                outside.set(outside.get() + 1);
                assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) }, 0);
            } else {
                assert_eq!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::WouldBlock
                );
                held.set(held.get() + 1);
            }
            Ok(T0 + 10)
        };
        let key = request::mint(T0);
        let run = || {
            send_result_with_admission_clock(
                w.base.path(),
                &|| Ok(T0.into()),
                Some(&wall),
                &real_fs(),
                &live,
                &|| Ok(me.clone()),
                &no_names,
                &to_rcp(200, Surface::Codex),
                &|_| Delivery::QueuedOnly,
                "200:5000",
                "native clock body",
                None,
                &key,
                true,
            )
        };
        let receipt = run().expect(
            "native CLI helper must consume fresh admitted provider beyond two-second policy",
        );
        let replay = run().unwrap();
        assert_eq!(receipt.id, replay.id);
        let ledger: serde_json::Value = serde_json::from_slice(
            &std::fs::read(w.base.path().join("messages/requests/ledger.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(ledger["clock"], T0 + 10);
        let count = std::fs::read_dir(w.base.path().join("messages"))
            .unwrap()
            .map(Result::unwrap)
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.strip_suffix(".json").is_some_and(|s| s.len() == 36))
            })
            .count();
        assert_eq!(
            count, 1,
            "native same-key retry must preserve one original publication"
        );
        let record: serde_json::Value = serde_json::from_slice(
            &std::fs::read(w.base.path().join(format!("messages/{}.json", receipt.id))).unwrap(),
        )
        .unwrap();
        assert_eq!(record["from"]["pid"], 100);
        assert_eq!(record["from"]["started_exact"], 5_000);
        assert!(
            held.get() > 0,
            "native wall provider must be consumed after admission"
        );
        assert_eq!(
            outside.get(),
            0,
            "native admission wall callback must not run before actual original guard"
        );
    }

    // The real send helper and shared runtime retry adapter use owned authority.
    fn logical_clock_send(
        w: &World,
        key: &str,
        samples: &[u64],
        capture_samples: &[u64],
    ) -> (Result<MessageReceipt, DirectiveError>, usize, usize) {
        let me = request::pin_test_session(w.a(), 5_000);
        let reads = Cell::new(0);
        let attempts = Cell::new(0);
        let capture_reads = Cell::new(0);
        let started = std::time::Instant::now();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(w.base.path().join("messages/.lock"))
            .unwrap();
        let wall = || {
            // SAFETY: the owned file descriptor stays live; these are valid flock flags.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                // SAFETY: unlock the probe lock on the same live owned descriptor.
                assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) }, 0);
                let n = capture_reads.get();
                capture_reads.set(n + 1);
                Ok(capture_samples[n.min(capture_samples.len() - 1)])
            } else {
                assert_eq!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::WouldBlock
                );
                let n = reads.get();
                reads.set(n + 1);
                Ok(samples[n.min(samples.len() - 1)])
            }
        };
        let result =
            request::with_key(Ok(T0), Some(key), |_, key| {
                csq_core::messaging::request_retry::run_with_admission_clock(
                    true,
                    key,
                    &wall,
                    |key| {
                        let path = w.base.path().join("messages/requests/ledger.json");
                        let before = std::fs::read(&path).unwrap();
                        let recovered = request::recover_existing_for_retry(
                            w.base.path(),
                            T0,
                            &real_fs(),
                            &me,
                            key,
                            Some(Intent::Send {
                                target: "200:5000",
                                parent: None,
                                body: "logical clock body",
                                wake: true,
                            }),
                        )?;
                        assert_eq!(std::fs::read(&path).unwrap(), before,
                        "retry recovery must preserve authority bytes even after clock rollback");
                        Ok(recovered.map(|(r, to)| receipt_dto(&r).with_to(to.pid, to.started_at)))
                    },
                    |key, admitted, capture| {
                        attempts.set(attempts.get() + 1);
                        send_result_with_admission_clock(
                            w.base.path(),
                            &|| request::clock(T0, started, capture()),
                            Some(admitted),
                            &real_fs(),
                            &live,
                            &|| Ok(me.clone()),
                            &no_names,
                            &to_rcp(200, Surface::Codex),
                            &|_| Delivery::QueuedOnly,
                            "200:5000",
                            "logical clock body",
                            None,
                            key,
                            true,
                        )
                    },
                )
            });
        (result, reads.get(), attempts.get())
    }

    fn logical_clock_records(w: &World) -> Vec<std::path::PathBuf> {
        std::fs::read_dir(w.base.path().join("messages"))
            .unwrap()
            .map(Result::unwrap)
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.strip_suffix(".json").is_some_and(|s| s.len() == 36))
            })
            .map(|e| e.path())
            .collect()
    }

    #[test]
    fn native_retry_rejects_logical_admitted_rollback_before_publication() {
        let w = world();
        request::initialize(w.base.path(), T0, &real_fs()).unwrap();
        let key = request::mint(T0);
        let (result, reads, _) = logical_clock_send(&w, &key, &[T0 + 10, T0 + 15, T0 + 14], &[T0]);
        let error =
            result.expect_err("logical admitted rollback must survive native retry contexts");
        assert_eq!(error.cause, Some(Cause::Clock));
        assert!(error.message.contains(&format!("idempotency_key={key}")));
        assert!(
            logical_clock_records(&w).is_empty(),
            "rollback must not become retry publication"
        );
        assert_eq!(
            reads, 3,
            "native retry must not re-read UTC after latched rollback"
        );
    }

    #[test]
    fn native_retry_recovers_verified_receipt_after_postpublication_rollback() {
        let w = world();
        request::initialize(w.base.path(), T0, &real_fs()).unwrap();
        let key = request::mint(T0);
        let (result, reads, attempts) =
            logical_clock_send(&w, &key, &[T0 + 10, T0 + 15, T0 + 20, T0 + 19], &[T0]);
        let receipt =
            result.expect("positive read-only recovery must survive admitted clock rollback");
        assert_eq!(
            attempts, 1,
            "verified positive recovery must avoid a second publication attempt"
        );
        assert_eq!(reads, 4);
        let records = logical_clock_records(&w);
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].file_stem().unwrap().to_str().unwrap(),
            receipt.id
        );
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&records[0]).unwrap()).unwrap();
        assert_eq!(record["from"]["pid"], 100);
        assert_eq!(record["from"]["started_exact"], 5_000);
    }

    #[test]
    fn native_retry_rejects_first_admission_below_successful_preflight_capture() {
        let w = world();
        request::initialize(w.base.path(), T0, &real_fs()).unwrap();
        let key = request::mint(T0);
        let (result, reads, _) = logical_clock_send(&w, &key, &[T0 + 9], &[T0 + 10, T0]);
        let error = result
            .expect_err("first admitted sample below captured floor must survive native retries");
        assert_eq!(error.cause, Some(Cause::Clock));
        assert!(error.message.contains(&format!("idempotency_key={key}")));
        assert!(logical_clock_records(&w).is_empty());
        assert_eq!(
            reads, 1,
            "first-admission rollback must not re-read admitted UTC on retry"
        );
    }

    #[test]
    fn native_capture_below_prior_admitted_utc_keeps_healthy_publication() {
        let w = world();
        request::initialize(w.base.path(), T0 + 10, &real_fs()).unwrap();
        let key = request::mint(T0);
        let (result, reads, attempts) = logical_clock_send(&w, &key, &[T0 + 10], &[T0]);
        let receipt =
            result.expect("lower raw capture must preserve healthy admitted floor publication");
        assert_eq!(attempts, 1);
        assert_eq!(
            reads, 4,
            "actual replay/begin/prepare/commit samples must add no provider reads"
        );
        let records = logical_clock_records(&w);
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].file_stem().unwrap().to_str().unwrap(),
            receipt.id
        );
    }
}
