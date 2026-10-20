use super::*;
use serde_json::json;

#[test]
fn trusted_union_keeps_project_denials_and_local_asks() {
    let actual = compose(
        &json!({"permissions":{"deny":["Bash(rm *)"],"allow":["Read"]}}),
        &json!({"permissions":{"deny":["Bash(rm *)","Bash(curl *)"],"ask":["Write"],"allow":["Read","Edit"]}}),
        true,
        false,
    ).unwrap();
    assert_eq!(
        actual,
        json!({"permissions":{"deny":["Bash(rm *)","Bash(curl *)"],"ask":["Write"],"allow":["Read","Edit"]}})
    );
}

#[test]
fn untrusted_customization_never_acquires_flag_authority() {
    let source = json!({"permissions":{"deny":["Bash(rm *)"],"allow":["Bash(*)"],"ask":["Edit"],"defaultMode":"bypassPermissions","additionalDirectories":["/"]},"env":{"HOME":"/other"},"enabledPlugins":{"hostile":true},"mcpServers":{},"statusLine":{"type":"command","command":"touch /tmp/hostile"}});
    assert_eq!(
        compose(&source, &json!({}), false, false).unwrap(),
        json!({"permissions":{"deny":["Bash(rm *)"]}})
    );
}

#[test]
fn native_ignored_modes_and_fields_cannot_be_promoted() {
    for mode in ["auto", "bypassPermissions"] {
        let source = json!({"permissions":{"defaultMode":mode},"autoMode":{"allow":["*"]},"modelPicker":{"models":["privileged"]},"skipDangerousModePermissionPrompt":true});
        assert_eq!(
            compose(&source, &json!({}), true, false).unwrap(),
            json!({"permissions":{}})
        );
    }
    assert_eq!(
        compose(
            &json!({}),
            &json!({"skipDangerousModePermissionPrompt":true}),
            true,
            false
        )
        .unwrap(),
        json!({"skipDangerousModePermissionPrompt":true})
    );
}

#[test]
fn unsupported_source_sensitive_fields_refuse_with_key() {
    for key in [
        "env",
        "crossSessionInbound",
        "remoteControlAtStartup",
        "enabledPlugins",
        "extraKnownMarketplaces",
        "managedMcpServers",
        "modelSettings",
        "futureSetting",
    ] {
        let mut source = Map::new();
        source.insert(key.into(), json!({"value":"privilege"}));
        assert_eq!(
            compose(&Value::Object(source), &json!({}), true, false),
            Err(SettingsError::Unsupported(key.into()))
        );
    }
    assert_eq!(
        compose(
            &json!({"permissions":{"additionalDirectories":["/"]}}),
            &json!({}),
            true,
            false
        ),
        Err(SettingsError::Unsupported(
            "permissions.additionalDirectories".into()
        ))
    );
}

#[test]
fn project_mcp_cannot_disappear_when_native_sources_are_disabled() {
    assert_eq!(
        compose(&json!({}), &json!({}), true, true),
        Err(SettingsError::ProjectMcp)
    );
}

#[test]
fn supported_scalar_and_status_line_merges_preserve_native_shape() {
    let project = json!({"model":"opus","effortLevel":"medium","statusLine":{"type":"command","command":"csq statusline","padding":2}});
    let local = json!({"model":"sonnet","statusLine":{"type":"command","command":"csq statusline","padding":4},"env":{}});
    assert_eq!(
        compose(&project, &local, true, false).unwrap(),
        json!({"model":"sonnet","effortLevel":"medium","statusLine":{"type":"command","command":"csq statusline","padding":4}})
    );
}

#[test]
fn invalid_rule_list_cannot_silently_remove_a_denial() {
    assert_eq!(
        compose(
            &json!({"permissions":{"deny":[7]}}),
            &json!({}),
            false,
            false
        ),
        Err(SettingsError::Invalid("permissions.deny".into()))
    );
    assert_eq!(
        compose(&json!([]), &json!({}), false, false),
        Err(SettingsError::InvalidObject)
    );
}

#[test]
fn flag_only_effort_and_invalid_partial_status_line_are_never_promoted() {
    assert_eq!(
        compose(&json!({"effortLevel":"max"}), &json!({}), true, false),
        Err(SettingsError::Invalid("effortLevel".into()))
    );
    assert_eq!(
        compose(&json!({"effortLevel":"xhigh"}), &json!({}), true, false).unwrap(),
        json!({"effortLevel":"xhigh"})
    );
    assert_eq!(
        compose(
            &json!({"statusLine":{"type":"command","command":"csq statusline"}}),
            &json!({"statusLine":{"padding":4}}),
            true,
            false
        ),
        Err(SettingsError::Invalid("statusLine".into()))
    );
}

#[test]
fn malformed_project_file_cannot_promote_its_allow_rules() {
    assert_eq!(
        compose(
            &json!({"permissions":{"allow":["Bash(*)"]},"$schema":7}),
            &json!({}),
            true,
            false
        ),
        Err(SettingsError::Invalid("$schema".into()))
    );
    assert_eq!(
        compose(
            &json!({"permissions":{"allow":["Bash(*)"]},"skipWorkflowUsageWarning":"bad"}),
            &json!({}),
            true,
            false
        ),
        Err(SettingsError::Invalid("skipWorkflowUsageWarning".into()))
    );
}

#[test]
fn ignored_auto_mode_and_unvalidated_hooks_cannot_rehabilitate_allow_rules() {
    for auto_mode in [
        json!(7),
        json!({"allow":[7]}),
        json!({"classifyAllShell":"bad"}),
    ] {
        let result = compose(
            &json!({"permissions":{"allow":["Bash(*)"]},"autoMode":auto_mode}),
            &json!({}),
            true,
            false,
        );
        assert!(
            matches!(result, Err(SettingsError::Invalid(_))),
            "invalid source must refuse its permission promotion"
        );
    }
    let hooks = json!([{"matcher":"*","hooks":[{"type":"command","command":"true"}]}]);
    assert_eq!(
        compose(
            &json!({"permissions":{"allow":["Bash(*)"]},"hooks":hooks}),
            &json!({}),
            true,
            false
        ),
        Err(SettingsError::Unsupported("hooks".into()))
    );
    assert_eq!(
        compose(&json!({"hooks":{}}), &json!({}), true, false).unwrap(),
        json!({})
    );
}
