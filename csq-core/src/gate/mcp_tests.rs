use super::*;
use serde_json::json;

fn select(project: Value, settings: Value, trusted: bool) -> Result<Option<Value>, McpError> {
    select_admission(project, settings, trusted).map(|admission| admission.config)
}

fn select_admission(project: Value, settings: Value, trusted: bool) -> Result<Admission, McpError> {
    admit(
        &project,
        &[ScopedSettings {
            source: SettingsSource::User,
            settings: &settings,
        }],
        AdmissionContext {
            persisted_trust: trusted,
            workspace_state: &json!({}),
            higher_precedence_names: &BTreeSet::new(),
        },
    )
}

#[test]
fn unapproved_descriptor_cannot_acquire_explicit_flag_authority() {
    let approved = json!({"type":"stdio","command":"/private/fixture/server","args":["literal argument", "$(not executed)"],"env":{"PROBE_TAG":"approved"}});
    let project = json!({"mcpServers":{"approved":approved,"unapproved":{"command":"/private/fixture/unapproved","args":["must never start"]}}});
    let actual = select(project, json!({"enabledMcpjsonServers":["approved"]}), true)
        .unwrap()
        .unwrap();
    assert_eq!(
        actual,
        json!({"mcpServers":{"approved":approved}}),
        "unapproved project server must never be passed to --mcp-config"
    );
    assert_eq!(
        actual["mcpServers"].as_object().unwrap().len(),
        1,
        "descriptor fixture must admit a real approved server"
    );
}

#[test]
fn untrusted_and_empty_approval_produce_no_extra_config() {
    let project = json!({"mcpServers":{"server":{"command":"fixture-server"}}});
    assert_eq!(
        select(
            project.clone(),
            json!({"enableAllProjectMcpServers":true}),
            false
        )
        .unwrap(),
        None
    );
    assert_eq!(select(project, json!({}), true).unwrap(), None);
}

#[test]
fn disabled_approval_wins_over_named_and_all_approval() {
    let project = json!({"mcpServers":{"a":{"command":"a"},"b":{"command":"b"}}});
    assert_eq!(select(project, json!({"enableAllProjectMcpServers":true,"enabledMcpjsonServers":["a"],"disabledMcpjsonServers":["a"]}), true).unwrap(), Some(json!({"mcpServers":{"b":{"command":"b"}}})));
}

#[test]
fn scope_order_unions_lists_but_last_boolean_wins() {
    let user = json!({"enableAllProjectMcpServers":true,"enabledMcpjsonServers":["user"]});
    let project_settings = json!({"disabledMcpjsonServers":["user"]});
    let local = json!({"enableAllProjectMcpServers":false,"enabledMcpjsonServers":["local"]});
    let sources = [
        ScopedSettings {
            source: SettingsSource::Local,
            settings: &local,
        },
        ScopedSettings {
            source: SettingsSource::User,
            settings: &user,
        },
        ScopedSettings {
            source: SettingsSource::Project,
            settings: &project_settings,
        },
    ];
    let project = json!({"mcpServers":{"user":{"command":"user"},"local":{"command":"local"},"pending":{"command":"pending"}}});
    let actual = admit(
        &project,
        &sources,
        AdmissionContext {
            persisted_trust: true,
            workspace_state: &json!({}),
            higher_precedence_names: &BTreeSet::new(),
        },
    )
    .unwrap();
    assert_eq!(
        actual.config,
        Some(json!({"mcpServers":{"local":{"command":"local"}}}))
    );
}

#[test]
fn workspace_disable_and_higher_precedence_preserve_native_selection() {
    let project = json!({"mcpServers":{"local":{"command":"project-local"},"managed":{"command":"project-managed"},"flag":{"command":"project-flag"},"disabled":{"command":"disabled"},"selected":{"command":"selected"},"computer-use":{"command":"project-builtin"}}});
    let settings = json!({"enableAllProjectMcpServers":true});
    let names = ["local", "managed", "flag"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let actual = admit(
        &project,
        &[ScopedSettings {
            source: SettingsSource::User,
            settings: &settings,
        }],
        AdmissionContext {
            persisted_trust: true,
            workspace_state: &json!({"disabledMcpServers":["disabled"]}),
            higher_precedence_names: &names,
        },
    )
    .unwrap();
    assert_eq!(
        actual.config,
        Some(json!({"mcpServers":{"selected":{"command":"selected"}}}))
    );
}

#[test]
fn native_name_normalization_matches_approvals_without_plugin_aliasing() {
    assert!(same_native_name("a.b", "a_b"));
    assert!(same_native_name("emoji😀", "emoji__"));
    assert!(same_native_name("claude.ai  server", "claude_ai_server"));
    assert!(!same_native_name("plugin:a.b", "plugin:a_b"));
    assert!(!same_native_name("SERVER", "server"));
}

#[test]
fn malformed_inputs_and_duplicate_sources_refuse() {
    let project = json!({"mcpServers":{"server":{"command":"server"}}});
    for settings in [
        json!({"enabledMcpjsonServers":[7]}),
        json!({"enableAllProjectMcpServers":"yes"}),
        json!([]),
    ] {
        assert_eq!(
            select(project.clone(), settings, true),
            Err(McpError::Malformed)
        );
    }
    let settings = json!({});
    let sources = [
        ScopedSettings {
            source: SettingsSource::User,
            settings: &settings,
        },
        ScopedSettings {
            source: SettingsSource::User,
            settings: &settings,
        },
    ];
    assert_eq!(
        admit(
            &project,
            &sources,
            AdmissionContext {
                persisted_trust: true,
                workspace_state: &settings,
                higher_precedence_names: &BTreeSet::new()
            }
        ),
        Err(McpError::DuplicateSource)
    );
    assert_eq!(
        select(
            json!({"mcpServers":{"server":7}}),
            json!({"enableAllProjectMcpServers":true}),
            true
        ),
        Ok(None)
    );
}

#[test]
fn http_descriptor_fields_are_preserved_after_admission_validation() {
    let descriptor = json!({"type":"http","url":"https://fixture.invalid/mcp","headers":{"X-Fixture":"literal"},"headersHelper":"fixture helper"});
    assert_eq!(
        select(
            json!({"mcpServers":{"http":descriptor}}),
            json!({"enabledMcpjsonServers":["http"]}),
            true
        )
        .unwrap(),
        Some(json!({"mcpServers":{"http":descriptor}}))
    );
}

#[test]
fn supported_native_transport_shapes_preserve_original_fields() {
    let stdio = json!({"command":"server", "args":["literal", "${ENV}"], "env":{"TAG":"value"}, "timeout":1.0,"alwaysLoad":true,"bareElicitationCapability":false,"role":"comms","unknown":{"retained":true}});
    let remote = json!({"url":"${NATIVE_EXPANSION}/not-prevalidated", "headers":{"X-Tag":"${ENV}"},"headersHelper":"literal helper", "timeout":9007199254740991_u64,"alwaysLoad":true,"bareElicitationCapability":false,"discoveryCache":true,"role":"comms","request_timeout_ms":400000,"oauth":{"clientId":"id","callbackPort":443,"authServerMetadataUrl":"https://fixture.invalid/metadata","scopes":"scope","xaa":false,"unknown":7},"tools":[{"name":"first","permission_policy":"always_allow"},{"name":"second","permission_policy":"always_ask"},{"name":"third","permission_policy":"always_deny"},{"name":""}],"toolPermissions":{"first":"allow","second":"ask","third":"blocked"},"unknown":{"retained":true}});
    for transport in [
        None,
        Some("stdio"),
        Some("sse"),
        Some("http"),
        Some("streamable-http"),
        Some("ws"),
    ] {
        let mut descriptor = if transport.is_none() || transport == Some("stdio") {
            stdio.clone()
        } else {
            remote.clone()
        };
        if let Some(transport) = transport {
            descriptor["type"] = json!(transport);
        }
        let project = json!({"mcpServers":{"selected":descriptor}});
        assert_eq!(
            select(
                project.clone(),
                json!({"enabledMcpjsonServers":["selected"]}),
                true
            ),
            Ok(Some(project)),
            "admission must preserve the original supported descriptor: {transport:?}"
        );
    }
}

#[test]
fn malformed_original_sibling_warns_before_every_selection_filter() {
    let invalid = [
        json!(7),
        json!({}),
        json!({"command":7}),
        json!({"command":"bad","args":[7]}),
    ];
    let modes = [
        (
            json!({"enabledMcpjsonServers":["selected"]}),
            json!({}),
            BTreeSet::new(),
        ),
        (
            json!({"enableAllProjectMcpServers":true,"disabledMcpjsonServers":["hidden"]}),
            json!({}),
            BTreeSet::new(),
        ),
        (
            json!({"enableAllProjectMcpServers":true}),
            json!({"disabledMcpServers":["hidden"]}),
            BTreeSet::new(),
        ),
        (
            json!({"enableAllProjectMcpServers":true}),
            json!({}),
            ["hidden".to_owned()].into_iter().collect(),
        ),
    ];
    for descriptor in invalid {
        for (index, (settings, state, names)) in modes.iter().enumerate() {
            let project =
                json!({"mcpServers":{"selected":{"command":"valid"},"hidden":descriptor}});
            assert_eq!(
                admit(
                    &project,
                    &[ScopedSettings {
                        source: SettingsSource::User,
                        settings
                    }],
                    AdmissionContext {
                        persisted_trust: true,
                        workspace_state: state,
                        higher_precedence_names: names
                    }
                )
                .unwrap(),
                Admission {
                    config: Some(json!({"mcpServers":{"selected":{"command":"valid"}}})),
                    warnings: vec![ServerWarning {
                        server_name: "\"hidden\"".into(),
                        reason: WarningReason::MalformedDescriptor
                    }]
                },
                "every original descriptor must validate before selection filter {index}"
            );
        }
        for (name, settings, config) in [
            (
                "computer-use",
                json!({"enableAllProjectMcpServers":true}),
                Some(json!({"mcpServers":{"selected":{"command":"valid"}}})),
            ),
            ("hidden", json!({}), None),
        ] {
            let admission = select_admission(
                json!({"mcpServers":{"selected":{"command":"valid"},name:descriptor}}),
                settings,
                true,
            )
            .unwrap();
            assert_eq!(
                admission.config, config,
                "invalid entries must not suppress approved valid siblings"
            );
            assert_eq!(
                admission.warnings,
                vec![ServerWarning {
                    server_name: warning_name(name),
                    reason: WarningReason::MalformedDescriptor
                }],
                "invalid hidden entries must remain visible warnings"
            );
        }
    }
}

fn assert_descriptor_warning(descriptor: Value, reason: WarningReason) {
    let admission = select_admission(
        json!({"mcpServers":{"selected":{"command":"valid"},"bad":descriptor}}),
        json!({"enableAllProjectMcpServers":true}),
        true,
    )
    .unwrap();
    assert_eq!(
        admission.config,
        Some(json!({"mcpServers":{"selected":{"command":"valid"}}})),
        "malformed original descriptor must not suppress the valid approved sibling"
    );
    assert_eq!(
        admission.warnings,
        vec![ServerWarning {
            server_name: "\"bad\"".into(),
            reason
        }],
        "invalid original descriptor must produce a typed warning"
    );
}

#[test]
fn malformed_native_transport_fields_skip_with_warning() {
    for descriptor in [
        json!({"command":""}),
        json!({"command":null}),
        json!({"command":"ok","type":null}),
        json!({"command":"ok","args":null}),
        json!({"command":"ok","args":[false]}),
        json!({"command":"ok","env":{"TAG":1}}),
        json!({"command":"ok","env":[]}),
        json!({"type":"http"}),
        json!({"type":"sse","url":7}),
        json!({"type":"ws","url":null}),
        json!({"type":"http","url":"literal","headers":{"X":false}}),
        json!({"type":"ws","url":"literal","headersHelper":7}),
        json!({"type":"sse","url":"literal","discoveryCache":"yes"}),
    ] {
        assert_descriptor_warning(descriptor, WarningReason::MalformedDescriptor);
    }
    for transport in ["stdio", "http", "sse", "ws", "streamable-http"] {
        let base = json!({"type":transport,"command":"ok","url":"literal"});
        for (field, value) in [
            ("timeout", json!(0)),
            ("timeout", json!(-1)),
            ("timeout", json!(1.5)),
            ("timeout", json!(9007199254740992_u64)),
            ("timeout", json!("1")),
            ("timeout", Value::Null),
            ("alwaysLoad", json!(1)),
            ("bareElicitationCapability", Value::Null),
        ] {
            let mut descriptor = base.clone();
            descriptor[field] = value;
            assert_descriptor_warning(descriptor, WarningReason::MalformedDescriptor);
        }
    }
}

#[test]
fn malformed_native_http_nested_fields_skip_with_warning() {
    for transport in ["http", "streamable-http", "sse"] {
        for (field, value) in [
            ("oauth", json!(false)),
            ("oauth", Value::Null),
            ("oauth", json!({"clientId":7})),
            ("oauth", json!({"callbackPort":0})),
            ("oauth", json!({"callbackPort":1.5})),
            ("oauth", json!({"callbackPort":9007199254740992_u64})),
            (
                "oauth",
                json!({"authServerMetadataUrl":"http://fixture.invalid"}),
            ),
            ("oauth", json!({"authServerMetadataUrl":"https://"})),
            ("oauth", json!({"authServerMetadataUrl":7})),
            ("oauth", json!({"scopes":""})),
            ("oauth", json!({"scopes":[]})),
            ("oauth", json!({"xaa":null})),
            ("tools", json!({})),
            ("tools", json!([7])),
            ("tools", json!([{}])),
            ("tools", json!([{"name":7}])),
            (
                "tools",
                json!([{"name":"tool","permission_policy":"allow"}]),
            ),
            ("toolPermissions", json!([])),
            ("toolPermissions", json!({"tool":"always_allow"})),
            ("toolPermissions", json!({"tool":null})),
        ] {
            let mut descriptor = json!({"type":transport,"url":"literal"});
            descriptor[field] = value;
            assert_descriptor_warning(descriptor, WarningReason::MalformedDescriptor);
        }
    }
}

#[test]
fn native_catch_and_unknown_fields_remain_for_native_parser() {
    for descriptor in [
        json!({"command":"server","role":7,"request_timeout_ms":null,"oauth":false,"headers":false}),
        json!({"type":"http","url":"","role":{"invalid":true},"request_timeout_ms":"invalid","env":7,"unknown":null}),
        json!({"type":"ws","url":"literal","oauth":false,"tools":7,"toolPermissions":false,"discoveryCache":null}),
    ] {
        let project = json!({"mcpServers":{"server":descriptor}});
        assert_eq!(
            select(
                project.clone(),
                json!({"enableAllProjectMcpServers":true}),
                true
            ),
            Ok(Some(project)),
            "native catch and transport-unknown fields must be preserved"
        );
    }
}

#[test]
fn project_unrepresentable_transports_warn_even_when_unapproved() {
    for transport in [
        "sdk",
        "claudeai-proxy",
        "sse-ide",
        "ws-ide",
        "future-transport",
        "",
    ] {
        let admission=select_admission(json!({"mcpServers":{"selected":{"command":"valid"},"hidden":{"type":transport,"name":"host","url":"literal","ideName":"ide","id":"id"}}}),json!({"enabledMcpjsonServers":["selected"]}),true).unwrap();
        assert_eq!(
            admission.config,
            Some(json!({"mcpServers":{"selected":{"command":"valid"}}}))
        );
        assert_eq!(
            admission.warnings,
            vec![ServerWarning {
                server_name: "\"hidden\"".into(),
                reason: WarningReason::UnsupportedTransport
            }],
            "unsupported project transport must warn explicitly: {transport}"
        );
    }
}

#[test]
fn original_server_names_and_admission_limits_refuse() {
    for name in [
        "".to_owned(),
        "__proto__".to_owned(),
        "nul\0name".to_owned(),
        "x".repeat(4097),
    ] {
        let project = json!({"mcpServers":{name.clone():{"command":"server"}}});
        let admission = select_admission(project, json!({}), true).unwrap();
        assert_eq!(admission.config, None);
        assert_eq!(
            admission.warnings,
            vec![ServerWarning {
                server_name: warning_name(&name),
                reason: WarningReason::InvalidName
            }]
        );
    }
    let mut servers = Map::new();
    for index in 0..=MAX_SERVERS {
        servers.insert(index.to_string(), json!({"command":"server"}));
    }
    assert_eq!(
        select(json!({"mcpServers":servers}), json!({}), true),
        Err(McpError::Limit)
    );
    assert_eq!(
        select(
            json!({"mcpServers":{"server":{"command":"server","unknown":"x".repeat(MAX_CONFIG_BYTES)}}}),
            json!({}),
            true
        ),
        Err(McpError::Limit)
    );
}

#[test]
fn descriptor_warnings_are_bounded_one_line_and_exclude_secret_fields() {
    let name = "escape\n\r\t\u{1b}\u{2028}\u{2029}\0".repeat(200);
    let admission = select_admission(
        json!({"mcpServers":{name:{"command":"", "env":{"TOKEN":"private-secret-marker"}}}}),
        json!({"enableAllProjectMcpServers":true}),
        true,
    )
    .unwrap();
    assert_eq!(admission.config, None);
    assert_eq!(admission.warnings.len(), 1);
    let warning = &admission.warnings[0];
    assert_eq!(warning.reason, WarningReason::InvalidName);
    assert!(warning.server_name.is_ascii());
    assert!(warning.server_name.len() <= 128 * 12 + 5);
    assert!(!warning.server_name.chars().any(char::is_control));
    assert!(warning.server_name.ends_with("...\""));
    assert!(!format!("{warning:?}").contains("private-secret-marker"));
}

#[test]
fn untrusted_original_descriptors_warn_without_acquiring_authority() {
    let admission = select_admission(
        json!({"mcpServers":{"valid":{"command":"server"},"bad":{"command":7}}}),
        json!({"enableAllProjectMcpServers":true}),
        false,
    )
    .unwrap();
    assert_eq!(admission.config, None);
    assert_eq!(
        admission.warnings,
        vec![ServerWarning {
            server_name: "\"bad\"".into(),
            reason: WarningReason::MalformedDescriptor,
        }]
    );
}
