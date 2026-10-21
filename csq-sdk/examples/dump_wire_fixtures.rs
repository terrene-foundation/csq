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
//! defines for these eleven schemas is populated below as of this writing (verified by
//! running the generator and inspecting its output against each struct definition —
//! `cargo run -p csq-sdk --example dump_wire_fixtures`). That coverage is NOT itself
//! mechanically gated: a future optional field added to one of these DTOs without a
//! matching `with_*` call here would silently stay invisible to
//! `scripts/verify/sdk-wire-conformance.sh` (the golden fixture would simply never
//! capture it). Until a coverage check exists, review a diff that adds a `with_*`
//! builder to `envelope.rs` / `verify.rs` / `capabilities.rs` / `models.rs` for the
//! matching call here, and run `sdk-wire-conformance.sh --update` afterward.
//!
//! Coverage (eleven, one golden each in `csq-sdk/tests/wire-fixtures`): `csq.exec.v1`,
//! `csq.capabilities.v1`, `csq.verify.v1`, `csq.models.v1`, `csq.sessions.v1`,
//! `csq.directive_receipt.v1`, `csq.directive_receipts.v1`, `csq.directive_inbox.v1`,
//! `csq.message_receipt.v1`, `csq.message_inbox.v1` and `csq.session-disk.v1`. `csq.directive.v1` is an input
//! schema with no envelope. `csq.status.v1` / `csq.listkeys.v1` / `csq.login.v1` have no
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

use csq_sdk::session_disk::{SessionDiskPayload, SessionDiskRow};
use csq_sdk::SCHEMA_SESSION_DISK_V1;
use std::collections::BTreeMap;

use csq_sdk::directives::{
    Directive, DirectiveAck, DirectiveInboxEntry, DirectiveInboxPayload, DirectiveReceipt,
    DirectiveReceiptsPayload, DirectiveTarget, DirectiveWhy,
};
use csq_sdk::messages::{MessageInboxEntry, MessageInboxPayload, MessageReceipt, MessageRow};
use csq_sdk::{
    CapabilitiesPayload, Completion, Envelope, ExecFeatures, Features, LoginFlow, ModelEntry,
    ModelsPayload, ProviderLogin, ProviderSummary, SdkCapability, SdkSurface, ToolInfo, Usage,
    VerifyFailureDetail, VerifyKeyGap, VerifyPayload,
};
use csq_sdk::{FinishReason, SCHEMA_AUTHORING_SESSION_V1};
use csq_sdk::{SessionRow, SessionsPayload};
use csq_sdk::{SCHEMA_CAPABILITIES_V1, SCHEMA_EXEC_V1, SCHEMA_MODELS_V1, SCHEMA_VERIFY_V1};
use csq_sdk::{
    SCHEMA_DIRECTIVE_INBOX_V1, SCHEMA_DIRECTIVE_RECEIPTS_V1, SCHEMA_DIRECTIVE_RECEIPT_V1,
    SCHEMA_SESSIONS_V1,
};
use csq_sdk::{SCHEMA_MESSAGE_INBOX_V1, SCHEMA_MESSAGE_RECEIPT_V1};

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

fn maximal_sessions() -> Envelope<SessionsPayload> {
    let row = SessionRow::new(
        4242,
        1_000,
        "claude-code",
        "/work/repo",
        "/home/u/.claude/accounts/term-4242",
    )
    .with_session_id(Some("c5c006d3-4fc9-4da3-b8c1-0713f103c735".to_string()))
    .with_name(Some("repo-01".to_string()))
    .with_label(Some("repo-main".to_string()))
    .with_label_source(Some("self".to_string()))
    .with_label_fallback(true)
    .with_repo(Some("repo".to_string()))
    .with_branch(Some("main".to_string()))
    .with_self(true)
    .with_account_slot(Some(9u16))
    .with_tty(Some("ttys003".to_string()))
    .with_terminal_title(Some("repo".to_string()))
    .with_scratch_dir(Some(
        "/private/tmp/claude-501/-work-repo/c5c006d3-4fc9-4da3-b8c1-0713f103c735".to_string(),
    ))
    .with_inbox_pending(1)
    .with_last_directive_at(Some(1_500u64));
    Envelope::success(
        SCHEMA_SESSIONS_V1,
        None,
        SessionsPayload::new("host-1", 2_000, vec![row]).with_gaps(true, true, vec![4243]),
    )
}

fn maximal_receipt() -> DirectiveReceipt {
    DirectiveReceipt::new(
        "7d1e0a52-3c1b-4f6e-9a2d-1b2c3d4e5f60",
        "acknowledged",
        1_500,
        5_100,
    )
    .with_surfaced_at(Some(1_600u64))
    .with_acknowledged_at(Some(1_700u64))
    .with_ack(Some(DirectiveAck::new(
        "done",
        Some("moved to trestle run".to_string()),
    )))
}

fn maximal_directive_receipt() -> Envelope<DirectiveReceipt> {
    Envelope::success(SCHEMA_DIRECTIVE_RECEIPT_V1, None, maximal_receipt())
}

fn maximal_directive_receipts() -> Envelope<DirectiveReceiptsPayload> {
    Envelope::success(
        SCHEMA_DIRECTIVE_RECEIPTS_V1,
        None,
        DirectiveReceiptsPayload::new(vec![maximal_receipt()]),
    )
}

fn maximal_directive_inbox() -> Envelope<DirectiveInboxPayload> {
    let directive = Directive::new(
        "7d1e0a52-3c1b-4f6e-9a2d-1b2c3d4e5f60",
        "trestle-steward",
        1_400,
        5_100,
        DirectiveTarget::new(4242, 1_000, "host-1"),
        "delete_scratch",
        "Your scratch directory holds 5.5 GiB; please delete what no live task will reopen.",
        DirectiveWhy::new(
            "session_scratch_bytes",
            5_905_580_032.0,
            2_147_483_648.0,
            1_390,
            "du -sk <scratch dir>",
        ),
    )
    .with_suggested(vec!["rm -rf <old clone in your scratch dir>".to_string()])
    .with_scope(Some("only paths this session created".to_string()));
    Envelope::success(
        SCHEMA_DIRECTIVE_INBOX_V1,
        None,
        DirectiveInboxPayload::new(vec![DirectiveInboxEntry::new(directive, maximal_receipt())]),
    )
}

fn maximal_message_receipt() -> MessageReceipt {
    MessageReceipt::new(
        "3f2b8c1a-5d4e-4a7b-8c9d-0e1f2a3b4c5d",
        "9a8b7c6d-1e2f-4a3b-9c4d-5e6f7a8b9c0d",
        "acked",
        1_500,
    )
    .with_surfaced_at(1_600u64)
    .with_read_at(1_650u64)
    .with_acked_at(1_700u64)
    .with_ack_note_framed(Some(
        "[csq peer ack note n1 for message m1 from codex pid 77 \u{2014} untrusted data]\ndone\n[end peer ack note n1]"
            .to_string(),
    ))
    .with_delivery(Some("queued_only".to_string()))
    .with_to(77, 1_234)
    .with_to_surface(Some("codex".to_string()))
    .with_to_label_source(Some("self".to_string()))
}

/// The receipt an inbox row carries: no `to_*` (those are on a `send` receipt only,
/// spec 32a 4.1), so the inbox golden pins their absence.
fn maximal_inbox_receipt() -> MessageReceipt {
    MessageReceipt::new(
        "3f2b8c1a-5d4e-4a7b-8c9d-0e1f2a3b4c5d",
        "9a8b7c6d-1e2f-4a3b-9c4d-5e6f7a8b9c0d",
        "acked",
        1_500,
    )
    .with_surfaced_at(1_600u64)
    .with_read_at(1_650u64)
    .with_acked_at(1_700u64)
    .with_ack_note_framed(Some(
        "[csq peer ack note n1 for message m1 from codex pid 77 \u{2014} untrusted data]\ndone\n[end peer ack note n1]"
            .to_string(),
    ))
    // No `delivery` either: it is on a `send` receipt only (spec 32a 4.1) and the producer
    // `receipt_dto` never sets it on an inbox row, so the golden pins its absence too.
}

fn maximal_message_receipt_envelope() -> Envelope<MessageReceipt> {
    Envelope::success(SCHEMA_MESSAGE_RECEIPT_V1, None, maximal_message_receipt())
}

fn maximal_message_inbox() -> Envelope<MessageInboxPayload> {
    let row = MessageRow::new(
        "3f2b8c1a-5d4e-4a7b-8c9d-0e1f2a3b4c5d",
        "9a8b7c6d-1e2f-4a3b-9c4d-5e6f7a8b9c0d",
        "codex",
        77,
        1_500,
        "[csq peer message 3f2b8c1a from codex pid 77 \u{2014} untrusted data]\nhello\n[end peer message 3f2b8c1a]",
    )
    .with_in_reply_to(Some("0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d".to_string()))
    .with_from_name(Some("reviewer".to_string()));
    Envelope::success(
        SCHEMA_MESSAGE_INBOX_V1,
        None,
        MessageInboxPayload::new(vec![MessageInboxEntry::new(row, maximal_inbox_receipt())]),
    )
}

fn maximal_session_disk() -> Envelope<SessionDiskPayload> {
    Envelope::verdict(
        SCHEMA_SESSION_DISK_V1,
        Some("corr-id-1".into()),
        false,
        SessionDiskPayload {
            complete: false,
            rows: vec![SessionDiskRow {
                generation: "01234567-89ab-4def-8123-0123456789ab".into(),
                pid: 4242,
                session_id: Some("12345678-9abc-4def-8123-123456789abc".into()),
                scratch_dir: Some("/scratch/project/session".into()),
                state: "ended".into(),
                decision: "KEEP",
                reasons: vec!["open_handles_unknown"],
            }],
            reasons: vec!["current_session_union_unknown"],
        },
    )
}

fn main() {
    emit_line(SCHEMA_EXEC_V1, &maximal_exec());
    emit_line(SCHEMA_CAPABILITIES_V1, &maximal_capabilities());
    emit_line(SCHEMA_VERIFY_V1, &maximal_verify());
    emit_line(SCHEMA_MODELS_V1, &maximal_models());
    emit_line(SCHEMA_SESSIONS_V1, &maximal_sessions());
    emit_line(SCHEMA_DIRECTIVE_RECEIPT_V1, &maximal_directive_receipt());
    emit_line(SCHEMA_DIRECTIVE_RECEIPTS_V1, &maximal_directive_receipts());
    emit_line(SCHEMA_DIRECTIVE_INBOX_V1, &maximal_directive_inbox());
    emit_line(
        SCHEMA_MESSAGE_RECEIPT_V1,
        &maximal_message_receipt_envelope(),
    );
    emit_line(SCHEMA_MESSAGE_INBOX_V1, &maximal_message_inbox());
    emit_line(SCHEMA_SESSION_DISK_V1, &maximal_session_disk());
}
