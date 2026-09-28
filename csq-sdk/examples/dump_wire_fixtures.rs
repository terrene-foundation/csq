//! Wire-conformance fixture generator (C3, an internal ticket Track B / INV-30-09).
//!
//! Prints ONE NDJSON line per covered schema — `{"schema": "<name>", "envelope": <the
//! real serialized envelope>}` — built through the SAME public constructors
//! (`Envelope::success` / `Envelope::verdict`, the `with_*` builders) an app uses, with
//! EVERY optional field populated and every `Vec`/`BTreeMap` non-empty. This is the
//! "current serialization" half of `scripts/verify/sdk-wire-conformance.sh`: the gate
//! diffs this binary's live output against the committed golden fixtures under
//! `csq-sdk/tests/wire-fixtures/`, so a rename/removal/retype of an existing field
//! shows up as a structural diff against real, compiled code — not as a hand-maintained
//! claim about the DTOs.
//!
//! Populating every optional field to its non-empty/non-default form is deliberate: a
//! field serialized only when `Some`/non-empty (`#[serde(skip_serializing_if = ...)]`)
//! would otherwise be invisible to a shape-diff run against a "typical" instance, and a
//! rename or removal of exactly that field would go undetected. Every field this crate
//! defines for these four schemas is populated below as of this writing (verified by
//! running the generator and inspecting its output against each struct definition —
//! `cargo run -p csq-sdk --example dump_wire_fixtures`). That coverage is NOT itself
//! mechanically gated: a future optional field added to one of these DTOs without a
//! matching `with_*` call here would silently stay invisible to
//! `scripts/verify/sdk-wire-conformance.sh` (the golden fixture would simply never
//! capture it). Until a coverage check exists, review a diff that adds a `with_*`
//! builder to `envelope.rs` / `verify.rs` / `capabilities.rs` / `models.rs` for the
//! matching call here, and run `sdk-wire-conformance.sh --update` afterward.
//!
//! Coverage: `csq.exec.v1`, `csq.capabilities.v1`, `csq.verify.v1`, and
//! `csq.models.v1`. `csq.status.v1` / `csq.listkeys.v1` / `csq.login.v1` have no
//! DTO here (the app builds them ad hoc). The four `csq.authoring_*` majors DO have payload DTOs in this crate and are NOT covered
//! here: they are in-process SDK capabilities rather than `csq <verb> --json` ops, and no
//! golden fixture has been frozen for them — an uncovered gap, not an inapplicable one.
//! Their status is pinned by two tests in `csq-core/src/sdk/capabilities.rs` —
//! `every_advertised_capability_has_an_executed_path_in_this_build` (all four ARE
//! executable and advertised under `sdk`) and
//! `authoring_capabilities_are_not_advertised_as_cli_ops` (none is in `ops[]`). Their
//! payload vocabulary is governed by `specs/30-sdk-embedding-contract.md` §4.
//! `csq.anchor.v1` /
//! `csq.eval.v1` are enterprise-only (`the enterprise SDK crate`) and out of scope for this
//! generator, which must stay in the PUBLIC (Apache-2.0) crate. Extending coverage:
//! add a new `emit_line` call below plus a matching golden fixture; the gate script
//! enumerates covered schemas from the golden-fixtures directory, so nothing else
//! needs to change.

use std::collections::BTreeMap;

use csq_sdk::{
    CapabilitiesPayload, Completion, Envelope, ExecFeatures, Features, LoginFlow, ModelEntry,
    ModelsPayload, ProviderLogin, ProviderSummary, SdkCapability, SdkSurface, ToolInfo, Usage,
    VerifyFailureDetail, VerifyKeyGap, VerifyPayload,
};
use csq_sdk::{FinishReason, SCHEMA_AUTHORING_SESSION_V1};
use csq_sdk::{SCHEMA_CAPABILITIES_V1, SCHEMA_EXEC_V1, SCHEMA_MODELS_V1, SCHEMA_VERIFY_V1};

/// Serialize one envelope as a single NDJSON line: `{"schema": "...", "envelope": {...}}`.
/// The outer `schema` key is redundant with the envelope's own `schema` field —
/// deliberately: it lets the gate script find each schema's blob with a plain `jq`
/// filter on the OUTER object without first having to parse the (variable-shape)
/// inner envelope, and it stays correct even if a future DTO ever legitimately omits
/// its own top-level `schema` string.
fn emit_line<T: serde::Serialize>(schema: &'static str, env: &Envelope<T>) {
    let inner = env.to_line().expect("hand-authored DTOs always serialize");
    let inner_value: serde_json::Value =
        serde_json::from_str(&inner).expect("emitted envelope is valid JSON");
    let wrapped = serde_json::json!({ "schema": schema, "envelope": inner_value });
    println!(
        "{}",
        serde_json::to_string(&wrapped).expect("wrapper always serializes")
    );
}

fn maximal_exec() -> Envelope<Completion> {
    let completion = Completion::new(
        "the model's output text",
        "claude-opus-4-8",
        "claude",
        FinishReason::ToolUse,
    )
    .with_usage(
        Usage::default()
            .with_input_tokens(120u64)
            .with_output_tokens(48u64)
            .with_cache_creation_input_tokens(16u64)
            .with_cache_read_input_tokens(8u64),
    )
    .with_finish_reason_raw("tool_use".to_string());
    Envelope::success(SCHEMA_EXEC_V1, Some("corr-id-1".to_string()), completion)
}

fn maximal_capabilities() -> Envelope<CapabilitiesPayload> {
    let payload = CapabilitiesPayload::new(
        ToolInfo::new("csq", "2.19.0", "enterprise"),
        vec!["exec.v1", "capabilities.v1", "verify.v1"],
        "enterprise",
        Features::new(ExecFeatures::new(vec!["claude", "gemini", "codex"])),
        vec![ProviderSummary::new(
            "claude",
            "Claude",
            "claude-code",
            "wrapped",
            "opus",
            ProviderLogin::new(
                false,
                LoginFlow::BrowserSubprocess,
                "run `csq login <slot>` from a machine with a reachable local browser",
            ),
        )
        .with_binary("claude-cli")],
    )
    .with_sdk(SdkSurface::new(
        "csq-sdk",
        csq_sdk::CRATE_VERSION,
        vec![SdkCapability::new(
            "authoring_session.v1",
            SCHEMA_AUTHORING_SESSION_V1,
        )],
    ));
    Envelope::success(
        SCHEMA_CAPABILITIES_V1,
        Some("corr-id-2".to_string()),
        payload,
    )
}

fn maximal_verify() -> Envelope<VerifyPayload> {
    let mut levels = BTreeMap::new();
    levels.insert("AUTO_APPROVED".to_string(), 12u64);
    levels.insert("HUMAN_REVIEWED".to_string(), 3u64);
    let payload = VerifyPayload::new("integrity_failure", 40, 2, "enterprise")
        .with_unknown_kind_count(1)
        .with_skipped_truncated_count(5)
        .with_historical_key_gaps(vec![VerifyKeyGap::new("ed25519:aa11", 10, 12, 3)])
        .with_failure_detail(VerifyFailureDetail::new(
            "chain_broken",
            "chain break at seq 41",
        ))
        .with_trust_plane_grade("CONFORMANT")
        .with_verification_level_summary(levels)
        .with_record_verification_level("HUMAN_REVIEWED".to_string());
    Envelope::verdict(
        SCHEMA_VERIFY_V1,
        Some("corr-id-3".to_string()),
        false,
        payload,
    )
}

fn maximal_models() -> Envelope<ModelsPayload> {
    let row = ModelEntry::new("provider", "Provider", "model", "Model", false)
        .with_context_window(1_048_576u64)
        .with_output_limit(8_192u64)
        .with_aliases(vec!["alias".to_string()]);
    Envelope::success(
        SCHEMA_MODELS_V1,
        Some("corr-id-4".to_string()),
        ModelsPayload::new(vec![row]),
    )
}

fn main() {
    emit_line(SCHEMA_EXEC_V1, &maximal_exec());
    emit_line(SCHEMA_CAPABILITIES_V1, &maximal_capabilities());
    emit_line(SCHEMA_VERIFY_V1, &maximal_verify());
    emit_line(SCHEMA_MODELS_V1, &maximal_models());
}
