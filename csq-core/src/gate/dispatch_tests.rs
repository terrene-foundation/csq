use super::*;
use crate::gate::matcher::NativeMatcher;
use crate::gate::pin::{Pin, RowAdmissionError};
use crate::gate::registry::{canonical_content_bytes, sha256, PRECEDENCE};
use serde_json::json;
use std::cell::Cell;
use std::collections::VecDeque;
use std::fs;

#[path = "dispatch_native_tests.rs"]
mod native;

#[path = "dispatch_output_tests.rs"]
mod decisions;

fn row(id: &str, order: u64, event: Event) -> Value {
    let kind = match event {
        Event::PreToolUse => "permission-decision",
        Event::PostToolUse => "context-injection",
        Event::UserPromptSubmit => "prompt-gate",
        Event::Stop | Event::SubagentStop => "handback-decision",
        Event::SessionStart => "advisory",
        Event::SessionEnd => "failure-report",
        Event::PreCompact => "compaction-instructions",
    };
    let severity = if matches!(
        event,
        Event::SessionStart | Event::SessionEnd | Event::PreCompact
    ) {
        "advise"
    } else {
        "block"
    };
    json!({"id":id,"order":order,"event":event.as_str(),"matcher":"*", "file":format!(".claude/hooks/{id}.js"),
        "file_sha256":sha256(b"admitted source"),"timeout":1,"source":"repo-local","pool":"repo","deps":[],"surfaces":["claude"],
        "on_incomplete":event.default_policy(),"on_crash":event.default_policy(),"on_timeout":event.default_policy(),
        "contract":{"payload_stdin":{"claude":"cc-hook-json"},
            "protocol":{"kind":kind,"exit_codes":[0,2],"exit_codes_computed":false,
                "decision_fields":["permissionDecision"],"severity":severity},
            "form":"legacy","runtime":"node-subprocess","cwd_scope":"payload",
            "side_effects":{"fs_writes":[],"network":false,"spawns":[],"declared_by":"author"},"idempotent":true,"may_rewrite_input":false}})
}

fn world(
    event: Event,
    mut rows: Vec<Value>,
) -> (tempfile::TempDir, VerifiedRegistry, ParsedPayload) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    fs::create_dir_all(repo.join(".claude/hooks")).unwrap();
    fs::create_dir(repo.join(".claude/hooks/lib")).unwrap();
    fs::write(
        repo.join(".claude/hooks/lib/runtime.js"),
        b"admitted runtime",
    )
    .unwrap();
    // Frozen 1b requires a populated registry. Native-only cases use a valid
    // unselected-event row, so admission stays real and no repository row runs.
    if rows.is_empty() {
        let unselected = if event == Event::SessionStart {
            Event::SessionEnd
        } else {
            Event::SessionStart
        };
        rows.push(row("unselected-fixture", 1, unselected));
    }
    for r in &mut rows {
        r["id"] = crate::gate::registry::stable_row_id(
            r["event"].as_str().unwrap().parse::<Event>().unwrap(),
            r["matcher"].as_str().unwrap_or(""),
            r["file"].as_str().unwrap(),
        )
        .into();
        fs::write(repo.join(r["file"].as_str().unwrap()), b"admitted source").unwrap();
    }
    let defaults: std::collections::BTreeMap<_, _> = Event::ALL
        .into_iter()
        .map(|e| (e.as_str(), e.default_policy()))
        .collect();
    let mut manifest = json!({"$id":"loom.hook-registry/v1","version":"1.0.0","content_sha256":"","content_sha256_scheme":"RFC 8785 JCS",
        "source_sha":"a".repeat(40),"generated_by":"authoring/.claude/bin/emit-hook-registry.mjs","unknown_major_policy":"fail-closed",
        "default_on_incomplete":defaults,
        "precedence":PRECEDENCE,"runtimes":[{"entry":".claude/hooks/lib/runtime.js","entry_sha256":sha256(b"admitted runtime"),"deps":[]}],"hooks":rows});
    manifest["content_sha256"] = sha256(&canonical_content_bytes(&manifest).unwrap()).into();
    fs::write(
        repo.join(".claude/hook-registry.json"),
        manifest.to_string(),
    )
    .unwrap();
    let verified = Pin::capture_operator(&repo).unwrap().verify(&repo).unwrap();
    let process_cwd = dir.path().join("process");
    fs::create_dir(&process_cwd).unwrap();
    let payload = ParsedPayload::parse(
        event,
        Surface::Claude,
        json!({"hook_event_name":event.as_str(),"cwd":repo,"tool_name":"Bash"})
            .to_string()
            .into_bytes(),
        process_cwd,
    )
    .unwrap();
    (dir, verified, payload)
}

fn output(value: Value) -> RowOutput {
    RowOutput {
        stdout: value.to_string().into_bytes(),
        ..RowOutput::default()
    }
}
fn context(event: Event, text: &str) -> RowOutput {
    output(json!({"hookSpecificOutput":{"hookEventName":event.as_str(),"additionalContext":text}}))
}
fn rewrite(value: Value) -> RowOutput {
    output(json!({"hookSpecificOutput":{"hookEventName":"PreToolUse","updatedInput":value}}))
}

struct Runner {
    results: VecDeque<Result<RowOutput, RowFailure>>,
    ids: Vec<String>,
    cwds: Vec<PathBuf>,
    deadlines: Vec<Instant>,
}
impl Runner {
    fn new(results: Vec<Result<RowOutput, RowFailure>>) -> Self {
        Self {
            results: results.into(),
            ids: Vec::new(),
            cwds: Vec::new(),
            deadlines: Vec::new(),
        }
    }
}
impl RowRunner for Runner {
    fn run(&mut self, request: RowRequest<'_>) -> Result<RowOutput, RowFailure> {
        assert_eq!(
            request.source.as_bytes(),
            b"admitted source",
            "runner receives exact admitted bytes"
        );
        self.ids.push(request.row.id.clone());
        self.cwds.push(request.cwd.to_owned());
        self.deadlines.push(request.deadline);
        self.results.pop_front().unwrap()
    }
}
fn run(
    input: &ParsedPayload,
    verified: &VerifiedRegistry,
    runner: &mut dyn RowRunner,
) -> DispatchResult {
    dispatch(
        input,
        verified,
        runner,
        &mut NativeMatcher,
        None,
        Instant::now() + event_budget(input.event),
    )
}

#[test]
fn gate_input_is_bounded_unique_and_event_bound() {
    let cwd = PathBuf::from("/synthetic-absolute-test-cwd");
    let parse =
        |bytes| ParsedPayload::parse(Event::PreToolUse, Surface::Claude, bytes, cwd.clone());
    assert!(matches!(
        parse(vec![b' '; MAX_PAYLOAD_BYTES + 1]),
        Err(InputError::Limit)
    ));
    assert!(matches!(
        parse(br#"{"hook_event_name":"Stop"}"#.to_vec()),
        Err(InputError::EventMismatch)
    ));
    assert!(matches!(
        parse(br#"{"hook_event_name":"Stop","hook_event_name":"PreToolUse"}"#.to_vec()),
        Err(InputError::Malformed)
    ));
    assert!(matches!(
        parse(br#"{"hook_event_name":"PreToolUse","cwd":"relative"}"#.to_vec()),
        Err(InputError::InvalidCwd)
    ));
    assert_eq!(event_budget(Event::SessionEnd), Duration::from_millis(1400));
    assert!(event_budget(Event::PreToolUse) < Duration::from_secs(10));
}

#[test]
fn gate_order_cwd_and_admitted_bytes_are_preserved() {
    let mut a = row("a", 10, Event::PreToolUse);
    a["contract"]["cwd_scope"] = "process".into();
    let (_dir, mut verified, input) = world(
        Event::PreToolUse,
        vec![
            row("z", 20, Event::PreToolUse),
            a,
            row("b", 11, Event::PreToolUse),
        ],
    );
    // Registry admission requires unique order. Exercise defensive stable ties
    // only after a trusted caller constructs a verified-row list with a tie.
    verified.rows[1].row.order = 10;
    let expected: Vec<_> = verified.rows.iter().map(|r| r.row.id.clone()).collect();
    verified.rows.rotate_right(1);
    fs::write(
        input.payload_cwd.join(&verified.rows[0].row.file),
        b"changed after admission",
    )
    .unwrap();
    let mut runner = Runner::new(vec![
        Ok(context(input.event, "a")),
        Ok(context(input.event, "b")),
        Ok(context(input.event, "z")),
    ]);
    let result = run(&input, &verified, &mut runner);
    assert_eq!(runner.ids, expected, "numeric order, defensive stable ties");
    assert_eq!(
        runner.cwds,
        [
            input.process_cwd.clone(),
            input.payload_cwd.clone(),
            input.payload_cwd.clone()
        ]
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["hookSpecificOutput"]["additionalContext"], "a\nb\nz");
    assert!(!result.denied);
}

#[test]
fn gate_actual_deny_survives_advisory_allow_and_silent_rows() {
    let mut advise = row("advise", 20, Event::PreToolUse);
    advise["contract"]["protocol"]["severity"] = "advise".into();
    let (_dir, verified, input) = world(
        Event::PreToolUse,
        vec![row("deny", 10, Event::PreToolUse), advise],
    );
    let mut runner = Runner::new(vec![
        Ok(RowOutput {
            exit_code: 2,
            ..RowOutput::default()
        }),
        Ok(output(
            json!({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}),
        )),
    ]);
    let result = run(&input, &verified, &mut runner);
    assert!(result.denied);
    assert_eq!(result.exit_code, 2);
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(String::from_utf8(result.stderr)
        .unwrap()
        .contains("agent_must_report"));
    let mut runner = Runner::new(vec![
        Ok(RowOutput::default()),
        Ok(output(
            json!({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}),
        )),
    ]);
    assert!(
        run(&input, &verified, &mut runner).denied,
        "advisory metadata cannot downgrade a native deny"
    );
}

#[test]
fn gate_failures_use_admitted_resolved_policies() {
    // The wire contract requires crash/timeout to inherit incomplete policy.
    // Exercise both admitted policies rather than constructing a crash exemption
    // which the registry cannot admit.
    for (event, denied) in [(Event::PreToolUse, true), (Event::SessionEnd, false)] {
        let (_dir, verified, input) = world(event, vec![row("r", 10, event)]);
        for failure in [
            RowFailure::Incomplete,
            RowFailure::Crash,
            RowFailure::Timeout,
            RowFailure::DemotionLedger,
        ] {
            let mut runner = Runner::new(vec![Err(failure)]);
            let result = run(&input, &verified, &mut runner);
            let expected_denied = denied || failure == RowFailure::DemotionLedger;
            assert_eq!(result.denied, expected_denied, "{event:?}/{failure:?}");
            if !expected_denied {
                assert!(result.stdout.is_empty());
                assert!(result.stderr.is_empty());
            }
        }
    }
}

#[test]
fn gate_bad_admission_and_unsupported_matchers_never_run() {
    let (_dir, mut verified, input) =
        world(Event::PreToolUse, vec![row("r", 10, Event::PreToolUse)]);
    verified.rows[0].admission = Err(RowAdmissionError::HashMismatch);
    let mut runner = Runner::new(vec![]);
    assert!(run(&input, &verified, &mut runner).denied);
    assert!(runner.ids.is_empty());
    let (_dir, verified, input) = world(
        Event::PreToolUse,
        vec![{
            let mut r = row("r", 10, Event::PreToolUse);
            r["matcher"] = "(?=Bash)Bash".into();
            r
        }],
    );
    assert!(
        run(&input, &verified, &mut runner).denied,
        "unsupported JS regex is incomplete, never silently a nonmatch"
    );
    assert!(runner.ids.is_empty());
}

#[test]
fn gate_malformed_and_turn_ending_outputs_follow_incomplete_policy() {
    let (_dir, verified, input) = world(Event::PreToolUse, vec![row("r", 10, Event::PreToolUse)]);
    for bytes in [
        b"{".to_vec(),
        json!({"continue":false}).to_string().into_bytes(),
        json!({"stopReason":"stop"}).to_string().into_bytes(),
        json!({"hookSpecificOutput":"bad"}).to_string().into_bytes(),
    ] {
        let mut runner = Runner::new(vec![Ok(RowOutput {
            stdout: bytes,
            ..RowOutput::default()
        })]);
        let result = run(&input, &verified, &mut runner);
        assert!(result.denied);
        let value: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_ne!(value.get("continue"), Some(&Value::Bool(false)));
        assert!(value.get("stopReason").is_none());
    }
}

#[test]
fn gate_equal_rewrites_coalesce_and_conflicts_refuse() {
    let rows = (0..2)
        .map(|index| {
            let mut r = row(&index.to_string(), index + 1, Event::PreToolUse);
            r["contract"]["protocol"]["decision_fields"] = json!(["updatedInput"]);
            r["contract"]["may_rewrite_input"] = true.into();
            r
        })
        .collect();
    let (_dir, verified, input) = world(Event::PreToolUse, rows);
    let mut runner = Runner::new(vec![
        Ok(rewrite(json!({"command":"safe"}))),
        Ok(rewrite(json!({"command":"safe"}))),
    ]);
    let result = run(&input, &verified, &mut runner);
    assert!(!result.denied);
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        value["hookSpecificOutput"]["updatedInput"]["command"],
        "safe"
    );
    let mut runner = Runner::new(vec![
        Ok(rewrite(json!({"command":"safe"}))),
        Ok(rewrite(json!({"command":"other"}))),
    ]);
    let result = run(&input, &verified, &mut runner);
    assert!(result.denied);
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(value["hookSpecificOutput"].get("updatedInput").is_none());
}

#[test]
fn gate_rewrite_requires_explicit_pretool_contract_and_no_deny() {
    let (_dir, verified, input) = world(Event::PreToolUse, vec![row("r", 10, Event::PreToolUse)]);
    let mut runner = Runner::new(vec![Ok(rewrite(json!({"command":"new"})))]);
    assert!(run(&input, &verified, &mut runner).denied);
    let mut r = row("rewrite", 10, Event::PreToolUse);
    r["contract"]["protocol"]["decision_fields"] = json!(["updatedInput"]);
    r["contract"]["may_rewrite_input"] = true.into();
    let (_dir, verified, input) = world(
        Event::PreToolUse,
        vec![r, row("deny", 20, Event::PreToolUse)],
    );
    let mut runner = Runner::new(vec![
        Ok(rewrite(json!({"command":"new"}))),
        Ok(RowOutput {
            exit_code: 2,
            ..RowOutput::default()
        }),
    ]);
    let result = run(&input, &verified, &mut runner);
    assert!(result.denied);
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(value["hookSpecificOutput"].get("updatedInput").is_none());
}

#[test]
fn gate_clips_row_deadline_and_refuses_late_allow() {
    let mut r = row("r", 10, Event::PreToolUse);
    r["timeout"] = 10.into();
    let (_dir, verified, input) = world(Event::PreToolUse, vec![r]);
    let base = Instant::now();
    let clock = Cell::new(base);
    let deadline = base + Duration::from_secs(1);
    struct Late<'a>(&'a Cell<Instant>, Instant);
    impl RowRunner for Late<'_> {
        fn run(&mut self, r: RowRequest<'_>) -> Result<RowOutput, RowFailure> {
            assert_eq!(r.deadline, self.1, "row clipped to overall remainder");
            self.0.set(self.1);
            Ok(RowOutput::default())
        }
    }
    let result = dispatch_with_clock(
        &input,
        &verified,
        &mut Late(&clock, deadline),
        &mut NativeMatcher,
        None,
        (deadline, || clock.get()),
    );
    assert!(
        result.denied,
        "an allow arriving at the deadline is timeout, not verified completion"
    );
}

#[test]
fn gate_expired_overall_budget_never_runs_rows_and_preserves_deny() {
    let (_dir, verified, input) = world(Event::PreToolUse, vec![row("r", 10, Event::PreToolUse)]);
    let deadline = Instant::now();
    let mut runner = Runner::new(vec![]);
    let result = dispatch_with_clock(
        &input,
        &verified,
        &mut runner,
        &mut NativeMatcher,
        None,
        (deadline, || deadline),
    );
    assert!(result.denied);
    assert!(runner.ids.is_empty());
}

#[test]
fn gate_trusted_native_stop_body_is_byte_identical() {
    let (_dir, verified, input) = world(Event::Stop, vec![]);
    let bytes = br#"{ "decision": "block", "reason": "durable unread notice" }"#.to_vec();
    struct Native(Vec<u8>);
    impl NativeHook for Native {
        fn output_bound(&self) -> usize {
            self.0.len()
        }
        fn run(&mut self, _: &ParsedPayload, _: Instant) -> Result<RowOutput, RowFailure> {
            Ok(RowOutput {
                stdout: self.0.clone(),
                ..RowOutput::default()
            })
        }
    }
    let result = dispatch(
        &input,
        &verified,
        &mut Runner::new(vec![]),
        &mut NativeMatcher,
        Some(&mut Native(bytes.clone())),
        Instant::now() + event_budget(input.event),
    );
    assert!(result.denied);
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout, bytes);
}

#[test]
fn gate_trusted_pin_failure_policy_controls_global_refusal() {
    assert!(
        unavailable(Event::Stop).denied,
        "an unreadable pin proves no continue policy"
    );
    assert!(unavailable_with_policy(Event::PostToolUse, FailurePolicy::Deny).denied);
    let result = unavailable_with_policy(Event::Stop, FailurePolicy::Continue);
    assert!(!result.denied);
    assert!(result.stdout.is_empty());
    assert!(result.stderr.is_empty());
}
