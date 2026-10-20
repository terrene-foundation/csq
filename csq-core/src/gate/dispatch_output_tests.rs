use super::*;

#[test]
fn gate_actual_exit_two_survives_continue_policy_deadline() {
    for event in [Event::SessionEnd, Event::PreToolUse] {
        let mut late = row("late", 1, event);
        late["on_timeout"] = "continue".into();
        if event == Event::PreToolUse {
            late["timeout_exemption"] = json!({"reason":"Private test permits late diagnostics without weakening actual denial"});
        }
        // Both policies are admitted from actual 1b metadata. The PreToolUse
        // exception covers timeout handling, never an already observed exit 2.
        let (_dir, verified, input) = world(event, vec![late, row("later", 2, event)]);
        let base = Instant::now();
        let clock = Cell::new(base);
        struct Late<'a> {
            clock: &'a Cell<Instant>,
            calls: usize,
        }
        impl RowRunner for Late<'_> {
            fn run(&mut self, request: RowRequest<'_>) -> Result<RowOutput, RowFailure> {
                self.calls += 1;
                if self.calls == 1 {
                    self.clock.set(request.deadline);
                    Ok(RowOutput {
                        exit_code: 2,
                        // This late rewrite/context must never be admitted.
                        stdout: b"{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"updatedInput\":{\"command\":\"late\"}}}".to_vec(),
                        ..RowOutput::default()
                    })
                } else {
                    Ok(RowOutput::default())
                }
            }
        }
        let mut runner = Late {
            clock: &clock,
            calls: 0,
        };
        let result = dispatch_with_clock(
            &input,
            &verified,
            &mut runner,
            &mut NativeMatcher,
            None,
            (base + Duration::from_secs(3), || clock.get()),
        );
        assert_eq!(runner.calls, 2, "later permissive row must execute");
        assert!(
            result.denied,
            "actual exit 2 must survive Continue timeout policy"
        );
        assert_eq!(result.exit_code, 2);
        assert!(!String::from_utf8(result.stdout)
            .unwrap()
            .contains("updatedInput"));
    }
}

#[test]
fn gate_rewrite_requires_capability_and_protocol_field() {
    for (capability, declared_field) in [(false, false), (false, true), (true, false), (true, true)]
    {
        let mut gate = row("rewrite", 1, Event::PreToolUse);
        gate["contract"]["may_rewrite_input"] = capability.into();
        if declared_field {
            gate["contract"]["protocol"]["decision_fields"] = json!(["updatedInput"]);
        }
        let (_dir, verified, input) = world(Event::PreToolUse, vec![gate]);
        let mut runner = Runner::new(vec![Ok(rewrite(json!({"command":"safe"})))]);
        let result = run(&input, &verified, &mut runner);
        let accepted = capability && declared_field;
        assert_eq!(
            result.denied, !accepted,
            "rewrite requires both capability={capability} and declaration={declared_field}"
        );
        let value: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(
            value["hookSpecificOutput"].get("updatedInput").is_some(),
            accepted
        );
        if accepted {
            assert_eq!(
                value["hookSpecificOutput"]["updatedInput"]["command"],
                "safe"
            );
        }
    }
}

#[test]
fn gate_undeclared_rewrite_retains_actual_exit_two() {
    let mut gate = row("rewrite", 1, Event::PreToolUse);
    gate["contract"]["protocol"]["decision_fields"] = json!(["updatedInput"]);
    let (_dir, mut verified, input) = world(Event::PreToolUse, vec![gate]);
    // PreToolUse admission requires Deny. Exercise a defensive in-memory
    // Continue seam only after valid admission: rejected diagnostics must not
    // discard an actual denial, even if an upstream caller weakens the policy.
    verified.rows[0].row.on_incomplete = FailurePolicy::Continue;
    let mut denied = rewrite(json!({"command":"unsafe"}));
    denied.exit_code = 2;
    denied.stderr = b"actual native denial".to_vec();
    let mut runner = Runner::new(vec![Ok(denied)]);
    let result = run(&input, &verified, &mut runner);
    assert!(
        result.denied,
        "missing rewrite capability cannot erase exit 2"
    );
    assert_eq!(result.exit_code, 2);
    assert!(result.stderr.starts_with(b"actual native denial\n"));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(value["hookSpecificOutput"].get("updatedInput").is_none());
}

#[test]
fn gate_rewrite_capability_does_not_authorize_other_events() {
    let mut gate = row("rewrite", 1, Event::PostToolUse);
    gate["contract"]["may_rewrite_input"] = true.into();
    gate["contract"]["protocol"]["decision_fields"] = json!(["updatedInput"]);
    let (_dir, verified, input) = world(Event::PostToolUse, vec![gate]);
    let mut runner = Runner::new(vec![Ok(output(
        json!({"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedInput":{"command":"unsafe"}}}),
    ))]);
    let result = run(&input, &verified, &mut runner);
    assert!(
        !result.denied,
        "PostToolUse inherits Continue on incomplete"
    );
    assert!(
        result.stdout.is_empty(),
        "non-PreToolUse rewrite must not escape"
    );
}

#[test]
fn gate_actual_exit_two_survives_malformed_continue_policy_output() {
    for event in [Event::PreToolUse, Event::SessionEnd] {
        let (_dir, mut verified, input) =
            world(event, vec![row("gate", 1, event), row("later", 2, event)]);
        // SessionEnd admits Continue natively. The PreToolUse case additionally
        // exercises a defensive in-memory resolved-policy seam: registry policy
        // restrictions must not be the only protection for an actual exit 2.
        verified.rows[0].row.on_incomplete = FailurePolicy::Continue;
        for stdout in [
            b"{".to_vec(),
            json!({"continue":false}).to_string().into_bytes(),
            json!({"stopReason":"turn ended"}).to_string().into_bytes(),
            vec![b'x'; MAX_ROW_OUTPUT_BYTES + 1],
        ] {
            let oversized = stdout.len() > MAX_ROW_OUTPUT_BYTES;
            let later = if event == Event::PreToolUse {
                output(
                    json!({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}),
                )
            } else {
                RowOutput::default()
            };
            let mut runner = Runner::new(vec![
                Ok(RowOutput {
                    exit_code: 2,
                    stdout,
                    stderr: b"native denial diagnostic".to_vec(),
                }),
                Ok(later),
            ]);
            let result = run(&input, &verified, &mut runner);
            assert!(
                result.denied,
                "actual exit 2 survives malformed Continue output"
            );
            assert_eq!(result.exit_code, 2);
            if !oversized {
                assert!(result.stderr.starts_with(b"native denial diagnostic\n"));
            }
            let value: Value = serde_json::from_slice(&result.stdout).unwrap();
            assert_ne!(value.get("continue"), Some(&Value::Bool(false)));
            assert!(value.get("stopReason").is_none());
            if event == Event::PreToolUse {
                assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
            }
        }
    }
}

#[test]
fn gate_permission_ask_survives_later_allow_and_deny_wins() {
    let (_dir, verified, input) = world(
        Event::PreToolUse,
        vec![
            row("a", 10, Event::PreToolUse),
            row("b", 20, Event::PreToolUse),
        ],
    );
    let decision = |name| {
        output(
            json!({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":name}}),
        )
    };
    for (first, second, expected, denied) in [
        ("ask", "allow", "ask", false),
        ("allow", "ask", "ask", false),
        ("ask", "deny", "deny", true),
        ("allow", "allow", "allow", false),
    ] {
        let mut runner = Runner::new(vec![Ok(decision(first)), Ok(decision(second))]);
        let result = run(&input, &verified, &mut runner);
        assert_eq!(result.denied, denied);
        let value: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(value["hookSpecificOutput"]["permissionDecision"], expected);
    }
}

#[test]
fn gate_defer_is_incomplete_under_no_turn_ending_contract() {
    let (_dir, verified, input) = world(Event::PreToolUse, vec![row("r", 10, Event::PreToolUse)]);
    let mut runner = Runner::new(vec![Ok(output(
        json!({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"defer"}}),
    ))]);
    let result = run(&input, &verified, &mut runner);
    assert!(result.denied);
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn gate_deprecated_approve_maps_to_allow_and_block_maps_to_deny() {
    let (_dir, verified, input) = world(
        Event::PreToolUse,
        vec![
            row("a", 10, Event::PreToolUse),
            row("b", 20, Event::PreToolUse),
        ],
    );
    for (legacy, modern, expected) in [
        ("approve", None, "allow"),
        ("approve", Some("ask"), "ask"),
        ("block", Some("allow"), "deny"),
    ] {
        let mut runner = Runner::new(vec![
            Ok(output(json!({"decision":legacy,"reason":"legacy reason"}))),
            Ok(modern.map_or_else(|| context(input.event, "second row context"), |modern| output(
                json!({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":modern}}),
            ))),
        ]);
        let result = run(&input, &verified, &mut runner);
        let value: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(value["hookSpecificOutput"]["permissionDecision"], expected);
        assert_eq!(result.denied, expected == "deny");
    }
}

#[test]
fn gate_subagent_stop_matches_agent_type_and_preserves_block_feedback() {
    let event = Event::SubagentStop;
    let mut gate = row("gate", 1, event);
    gate["matcher"] = "Explore".into();
    let (_dir, verified, mut input) = world(event, vec![gate, row("advice", 2, event)]);
    input.value["agent_type"] = "Explore".into();
    let mut runner = Runner::new(vec![
        Ok(output(
            json!({"decision":"block","reason":"finish the child task"}),
        )),
        Ok(context(event, "additional child feedback")),
    ]);
    let result = run(&input, &verified, &mut runner);
    assert_eq!(runner.ids.len(), 2);
    assert!(result.denied);
    assert_eq!(
        result.exit_code, 0,
        "native Stop-format block remains exit zero"
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        value["decision"], "block",
        "child handback retains block feedback"
    );
    assert_eq!(value["reason"], "finish the child task");
    assert_eq!(value["hookSpecificOutput"]["hookEventName"], "SubagentStop");
    assert_eq!(
        value["hookSpecificOutput"]["additionalContext"],
        "additional child feedback"
    );

    input.value["agent_type"] = "Bash".into();
    let mut runner = Runner::new(vec![Ok(context(event, "only unmatched gate is skipped"))]);
    let result = run(&input, &verified, &mut runner);
    assert_eq!(
        runner.ids.len(),
        1,
        "tool_name cannot select the child agent gate"
    );
    assert!(!result.denied);
}

#[test]
fn gate_null_timeout_uses_overall_deadline() {
    let mut r = row("r", 1, Event::PreToolUse);
    r["timeout"] = Value::Null;
    let (_dir, verified, input) = world(Event::PreToolUse, vec![r]);
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut runner = Runner::new(vec![Ok(RowOutput::default())]);
    let result = dispatch(
        &input,
        &verified,
        &mut runner,
        &mut NativeMatcher,
        None,
        deadline,
    );
    assert!(!result.denied);
    assert_eq!(runner.deadlines, [deadline]);
}

#[test]
fn gate_precompact_plain_instructions_merge_without_json_encoding() {
    let (_dir, verified, input) = world(
        Event::PreCompact,
        vec![
            row("a", 1, Event::PreCompact),
            row("b", 2, Event::PreCompact),
        ],
    );
    let mut runner = Runner::new(vec![
        Ok(RowOutput {
            stdout: b"first instructions".to_vec(),
            ..RowOutput::default()
        }),
        Ok(RowOutput {
            stdout: b"second instructions".to_vec(),
            ..RowOutput::default()
        }),
    ]);
    let result = run(&input, &verified, &mut runner);
    assert!(!result.denied);
    assert_eq!(result.stdout, b"first instructions\nsecond instructions");
}

#[test]
fn gate_exit_code_plain_output_keeps_native_zero_and_two_decisions() {
    let r = row("r", 10, Event::PreToolUse);
    let (_dir, verified, input) = world(Event::PreToolUse, vec![r]);
    let plain = b"hook completed".to_vec();
    let mut runner = Runner::new(vec![Ok(RowOutput {
        stdout: plain.clone(),
        ..RowOutput::default()
    })]);
    let result = run(&input, &verified, &mut runner);
    assert!(!result.denied, "exit-code stdout is not a JSON contract");
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout, plain);
    let mut runner = Runner::new(vec![Ok(RowOutput {
        exit_code: 2,
        stdout: plain,
        stderr: b"refused by native hook".to_vec(),
    })]);
    let result = run(&input, &verified, &mut runner);
    assert!(result.denied);
    assert_eq!(result.exit_code, 2);
    assert_eq!(result.stderr, b"refused by native hook\n");
    for stdout in [b"{".to_vec(), br#"{"continue":false}"#.to_vec()] {
        let mut runner = Runner::new(vec![Ok(RowOutput {
            stdout,
            ..RowOutput::default()
        })]);
        assert!(run(&input, &verified, &mut runner).denied);
    }
}

#[test]
fn gate_plain_and_json_contexts_keep_row_order() {
    let r = row("plain", 10, Event::UserPromptSubmit);
    let (_dir, verified, input) = world(
        Event::UserPromptSubmit,
        vec![r, row("json", 20, Event::UserPromptSubmit)],
    );
    let mut runner = Runner::new(vec![
        Ok(RowOutput {
            stdout: b"first".to_vec(),
            ..RowOutput::default()
        }),
        Ok(context(input.event, "second")),
    ]);
    let result = run(&input, &verified, &mut runner);
    assert!(!result.denied);
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        value["hookSpecificOutput"]["additionalContext"],
        "first\nsecond"
    );
}
