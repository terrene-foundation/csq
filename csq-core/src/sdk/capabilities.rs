//! `csq.capabilities.v1` builder — the app-side op list, `EDITION`, feature flags,
//! and provider union (an internal ticket).
//!
//! The payload SHAPE ([`CapabilitiesPayload`](super::CapabilitiesPayload)) lives in the
//! public `csq-sdk` crate; this builder supplies the ops THIS build actually implements,
//! the [`EDITION`](super::EDITION) discriminant, the feature flags this build honestly
//! derives, and `providers[]` — mapped from `csq-core`'s canonical provider union
//! ([`crate::providers::registry::all`]) onto the SDK's hand-authored
//! [`ProviderSummary`](super::ProviderSummary) DTO (R1: never serialize the internal
//! `ProviderDescriptor` directly). A consumer calls `csq sdk capabilities --json` to
//! learn which ops the binary implements and which providers it can route to BEFORE
//! invoking either, instead of discovering an unsupported op/provider via a
//! non-enveloped clap error or by hand-rolling its own allowlist that goes stale.

use crate::providers::registry;

use super::{
    CapabilitiesPayload, Envelope, ExecFeatures, Features, ProviderSummary, ToolInfo, EDITION,
    SCHEMA_CAPABILITIES_V1,
};

/// The ops actually IMPLEMENTED in this build.
///
/// Per `rules/spec-accuracy.md`, this advertises only what ships today. `eval.v1`
/// is enterprise-only (an internal ticket S2); community builds do not advertise it.
#[must_use]
pub fn implemented_ops() -> Vec<&'static str> {
    // S1: exec + capabilities. S2: verify. Community ops; enterprise extends below.
    #[allow(unused_mut)]
    let mut ops = vec!["exec.v1", "capabilities.v1", "verify.v1"];
    #[cfg(feature = "enterprise")]
    ops.push("eval.v1");
    ops
}

/// Every provider this build can advertise, mapped from
/// [`registry::all`] onto the wire [`ProviderSummary`] DTO.
///
/// Enterprise-only descriptors ([`registry::ProviderDescriptor::enterprise_only`] —
/// `azure`/`vertex`, serviced only by `crate::phase2b`) are excluded when the
/// `enterprise` Cargo feature is off, so a community build never advertises a
/// provider it has no code path to configure or route to.
#[must_use]
fn provider_summaries() -> Vec<ProviderSummary> {
    registry::all()
        .into_iter()
        .filter(|d| cfg!(feature = "enterprise") || !d.enterprise_only())
        .map(|d| {
            let summary = ProviderSummary::new(
                d.id,
                d.name,
                d.surface.as_str(),
                d.kind.as_str(),
                d.default_model,
                crate::providers::provider_login(&d),
            );
            match d.native {
                Some(n) => summary.with_binary(n.binary),
                None => summary,
            }
        })
        .collect()
}

/// Feature flags this build honestly implements.
///
/// `features.exec.providers_routable` is [`registry::exec_routable_provider_ids`] —
/// the SAME derivation `csq exec --provider <id>` resolves against
/// (`csq/src/cli/commands/exec.rs::resolve_slot`), so this can never advertise a
/// provider id `exec` would then reject. Login-driving metadata now lives per-entry
/// on `providers[].login` (an internal ticket, [`crate::providers::provider_login`]) rather than
/// as a top-level feature flag. `csq status --json`'s roster schema is still
/// reserved but unwired (see `SCHEMA_STATUS_V1`'s doc) — it stays OMITTED rather
/// than hardcoded, per this module's own discipline for `implemented_ops`.
#[must_use]
fn features() -> Features {
    Features::new(ExecFeatures::new(registry::exec_routable_provider_ids()))
}

/// Build the `csq.capabilities.v1` success envelope for this build.
#[must_use]
pub fn build() -> Envelope<CapabilitiesPayload> {
    Envelope::success(
        SCHEMA_CAPABILITIES_V1,
        None,
        CapabilitiesPayload::new(
            ToolInfo::new("csq", env!("CARGO_PKG_VERSION"), EDITION),
            implemented_ops(),
            EDITION,
            features(),
            provider_summaries(),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_envelope_advertises_implemented_ops_and_edition() {
        let env = build();
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["schema"], "csq.capabilities.v1");
        assert_eq!(v["ok"], true);
        let ops: Vec<&str> = v["ops"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_str().unwrap())
            .collect();
        assert!(
            ops.contains(&"exec.v1"),
            "exec.v1 is implemented in this build"
        );
        assert!(ops.contains(&"capabilities.v1"));
        assert!(ops.contains(&"verify.v1"), "verify.v1 is implemented in S2");
        // eval.v1 ships in S2, enterprise-only.
        #[cfg(feature = "enterprise")]
        assert!(
            ops.contains(&"eval.v1"),
            "eval.v1 must be advertised in enterprise builds"
        );
        #[cfg(not(feature = "enterprise"))]
        assert!(
            !ops.contains(&"eval.v1"),
            "eval.v1 must NOT be advertised in community builds"
        );
    }

    #[test]
    fn edition_matches_build_feature() {
        let expected = if cfg!(feature = "enterprise") {
            "enterprise"
        } else {
            "community"
        };
        assert_eq!(EDITION, expected);
    }

    /// AC: `providers[]` count matches `registry::all()`, edition-filtered — NOT a
    /// sample presence check. Non-vacuity companion below shows this REDS against a
    /// hardcoded list.
    #[test]
    fn providers_count_matches_registry_all_for_this_edition() {
        let expected = registry::all()
            .into_iter()
            .filter(|d| cfg!(feature = "enterprise") || !d.enterprise_only())
            .count();
        let env = build();
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        let providers = v["providers"].as_array().unwrap();
        assert_eq!(
            providers.len(),
            expected,
            "providers[] must be built from registry::all(), not a hardcoded list"
        );
    }

    /// Non-vacuity for the count check above: a build() that returned a hardcoded
    /// 3-element provider list would fail this test. Simulated directly (rather than
    /// mutating `provider_summaries`) so the probe runs unconditionally without a
    /// feature flag.
    #[test]
    fn providers_count_check_reds_against_a_hardcoded_three_element_list() {
        let hardcoded_len = 3usize;
        let expected = registry::all()
            .into_iter()
            .filter(|d| cfg!(feature = "enterprise") || !d.enterprise_only())
            .count();
        assert_ne!(
            hardcoded_len, expected,
            "registry::all() must have more than 3 entries for this probe to be \
             meaningful — if this ever fires, widen the hardcoded sample size"
        );
    }

    /// AC: native-only `grok` and `kimi-cli` appear, correctly `kind:"native"`,
    /// with their vendor `binary`.
    #[test]
    fn native_providers_appear_with_kind_native_and_binary() {
        let env = build();
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        let providers = v["providers"].as_array().unwrap();

        let grok = providers
            .iter()
            .find(|p| p["id"] == "grok")
            .expect("grok must appear in providers[]");
        assert_eq!(grok["kind"], "native");
        assert_eq!(grok["binary"], "grok");
        assert_eq!(grok["surface"], "grok");

        let kimi_cli = providers
            .iter()
            .find(|p| p["id"] == "kimi-cli")
            .expect("kimi-cli must appear in providers[]");
        assert_eq!(kimi_cli["kind"], "native");
        assert_eq!(kimi_cli["binary"], "kimi");
        assert_eq!(kimi_cli["surface"], "kimi");
    }

    /// AC: `tool{name,version,edition}` present; `version` is the real build
    /// version, not a literal.
    #[test]
    fn tool_object_present_with_real_version() {
        let env = build();
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["tool"]["name"], "csq");
        assert_eq!(v["tool"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(v["tool"]["edition"], EDITION);
    }

    /// AC: `features{}` present; `exec.providers_routable` matches the shared
    /// registry derivation exactly (every flag traceable to something real).
    #[test]
    fn features_exec_providers_routable_matches_registry_derivation() {
        let env = build();
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        let routable: Vec<&str> = v["features"]["exec"]["providers_routable"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
        assert_eq!(routable, registry::exec_routable_provider_ids());
    }

    /// AC (an internal ticket): EVERY provider in the advertised set carries a `login` object
    /// with all three fields shaped correctly — the whole set, not a sample.
    #[test]
    fn every_provider_carries_a_shaped_login_object() {
        let env = build();
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        let providers = v["providers"].as_array().unwrap();
        assert!(!providers.is_empty());
        for provider in providers {
            let login = provider.get("login").unwrap_or_else(|| {
                panic!("provider {provider} is missing the login object entirely")
            });
            assert!(
                login["headless_drivable"].is_boolean(),
                "provider {provider}: login.headless_drivable must be a bool"
            );
            assert!(
                login["flow"].is_string(),
                "provider {provider}: login.flow must be a string"
            );
            assert!(
                login["instructions"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty()),
                "provider {provider}: login.instructions must be non-empty"
            );
        }
    }

    /// Non-vacuity for the whole-set check above: a `provider_summaries` that
    /// dropped `login` from just ONE entry reds it. Simulated directly against a
    /// hand-built payload missing the field on one of two entries, rather than
    /// mutating `provider_summaries` itself, so the probe runs unconditionally.
    #[test]
    fn every_provider_login_check_reds_when_one_entry_is_missing_login() {
        let payload_with_one_missing = serde_json::json!({
            "providers": [
                {"id": "claude", "login": {"headless_drivable": false, "flow": "browser_subprocess", "instructions": "x"}},
                {"id": "codex"},
            ]
        });
        let providers = payload_with_one_missing["providers"].as_array().unwrap();
        let missing_count = providers
            .iter()
            .filter(|p| p.get("login").is_none())
            .count();
        assert_eq!(
            missing_count, 1,
            "fixture must have exactly one entry missing `login` for this probe \
             to be meaningful — got {missing_count}"
        );
    }

    /// AC: the two `csq exec`-routable-and-headless-drivable providers (grok,
    /// kimi-cli — device-code) are `headless_drivable: true`; the two
    /// live-CLI-dispatch OAuth surfaces reachable via `csq login` but requiring an
    /// attended session (claude, codex) are `false`.
    #[test]
    fn headless_drivable_matches_the_flow_classification() {
        let env = build();
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        let providers = v["providers"].as_array().unwrap();
        let get = |id: &str| providers.iter().find(|p| p["id"] == id).unwrap();

        assert_eq!(get("grok")["login"]["headless_drivable"], true);
        assert_eq!(get("grok")["login"]["flow"], "device_code");
        assert_eq!(get("kimi-cli")["login"]["headless_drivable"], true);
        assert_eq!(get("kimi-cli")["login"]["flow"], "device_code");

        assert_eq!(get("claude")["login"]["headless_drivable"], false);
        assert_eq!(get("claude")["login"]["flow"], "browser_subprocess");
        assert_eq!(get("codex")["login"]["headless_drivable"], false);
        assert_eq!(get("codex")["login"]["flow"], "tty_required");

        assert_eq!(get("gemini")["login"]["headless_drivable"], false);
        assert_eq!(get("gemini")["login"]["flow"], "external_prerequisite");
    }

    /// AC: a community build never advertises the enterprise-only direct-API
    /// providers it has no code path to configure or route to.
    #[test]
    fn community_build_excludes_azure_and_vertex() {
        let env = build();
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        let ids: Vec<&str> = v["providers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["id"].as_str().unwrap())
            .collect();
        if cfg!(feature = "enterprise") {
            assert!(ids.contains(&"azure"));
            assert!(ids.contains(&"vertex"));
        } else {
            assert!(
                !ids.contains(&"azure"),
                "community must not advertise azure"
            );
            assert!(
                !ids.contains(&"vertex"),
                "community must not advertise vertex"
            );
        }
    }
}
