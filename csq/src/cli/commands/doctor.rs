//! `csq doctor` — diagnostic report for troubleshooting.
//!
//! Checks binary version, daemon status, account health, Claude Code
//! installation, settings.json configuration, platform info, and
//! legacy terminal detection (CC sessions using old `config-N` dirs
//! instead of `term-<pid>` handle dirs).
//! Outputs color-coded text by default, or structured JSON with `--json`.

use anyhow::Result;
use csq_core::accounts::profiles::{
    audit_coexistence, label_relocation_sentinel_path, unrecoverable_label_slots, CoexistenceState,
    ConsistencyState, IdentityStoreReport,
};
use csq_core::accounts::{discovery, markers, AccountSource};
use csq_core::cli_deps::{
    min_version, probe, probe_disabled, sanitize_for_display, CliStatus, InstallManager,
    SurfaceCli, WrongBinaryReason,
};
use csq_core::daemon::coc_cache_sweeper;
use csq_core::platform::process::is_pid_alive;
use csq_core::refresh::sentinel as fanout;
use csq_core::types::AccountNum;
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct DoctorReport {
    /// Top-level doctor JSON schema version. The community build reports `19`
    /// and the enterprise build reports `21` — the `mcp_gate_outbox_backlog` field
    /// (v20 #914, gaining the v21 M6 #909 shard-D daemon-aware `state` +
    /// `last_drain_age_secs`) is enterprise-only, so it raises only the enterprise
    /// ceiling (see `DOCTOR_SCHEMA_VERSION` below). The full per-version history (v1–v21,
    /// which version introduced which field, and which fields are
    /// enterprise-only) is the contract in
    /// `specs/13-multi-cli-detection-contract.md` §9 — the single source of
    /// truth. Do NOT re-enumerate it here: the prior inline history drifted
    /// (it stalled at v7 while fields landed through v18), which is exactly the
    /// drift §9 exists to prevent.
    schema_version: u32,
    version: String,
    platform: PlatformInfo,
    /// Claude Code CLI status.  Populated when at least one Anthropic slot
    /// has authenticated credentials; **omitted entirely** (not null) when
    /// no such slot exists (spec/13 §9, R1-L2).
    #[serde(skip_serializing_if = "Option::is_none")]
    claude_code: Option<CliSurfaceInfo>,
    /// Codex CLI status.  Populated when at least one Codex slot has
    /// authenticated credentials; omitted when not (spec/13 §9).
    #[serde(skip_serializing_if = "Option::is_none")]
    codex_cli: Option<CliSurfaceInfo>,
    /// Gemini CLI status.  Populated when at least one Gemini slot has
    /// authenticated credentials; omitted when not (spec/13 §9).
    #[serde(skip_serializing_if = "Option::is_none")]
    gemini_cli: Option<CliSurfaceInfo>,
    /// Authenticated slot counts per surface — NOT serialized in JSON.
    /// Used only by `print_report` for the stale-slot variant (R1-H14).
    #[serde(skip)]
    claude_auth_slots: usize,
    #[serde(skip)]
    codex_auth_slots: usize,
    #[serde(skip)]
    gemini_auth_slots: usize,
    /// Slots whose Gemini binding MARKER exists (spawn-admissible per
    /// `is_gemini_bound_slot` — the daemon WILL run them) but whose
    /// binding does not parse (corrupt / newer-schema). NOT serialized
    /// (mirrors `gemini_auth_slots`); drives the self-legibility row so
    /// the report names the exact slots behind a host-iso warning
    /// instead of delegating to a command that cannot see them
    /// (redteam R3 HIGH-01/MED-01/LOW-02).
    #[serde(skip)]
    gemini_unreadable_slots: Vec<u16>,
    /// Slots whose Codex binding file exists (`is_codex_bound_slot`) and
    /// parses successfully but does NOT carry a Codex-variant payload —
    /// i.e. `is_codex_wrong_variant_bound` returns `true`. These slots
    /// were written with an Anthropic-shape (`claudeAiOauth`) credential
    /// at the Codex-prefixed path (an internal ticket). NOT serialized in JSON
    /// (mirrors `gemini_unreadable_slots`); drives the wrong-variant
    /// row in `print_report` so the operator gets a self-sufficient
    /// remediation hint without delegating to `csq probe --all`
    /// (an internal ticket).
    #[serde(skip)]
    codex_wrong_variant_slots: Vec<u16>,
    js_runtime: JsRuntimeInfo,
    settings: SettingsInfo,
    daemon: DaemonInfo,
    accounts: AccountsInfo,
    broker_failed: BrokerFailedInfo,
    mixed_state_slots: MixedStateInfo,
    terminals: TerminalInfo,
    resurrections: ResurrectionInfo,
    /// PR-CA8b commit 4: spec 08 MED-03 host-isolation surface.
    /// Reports `warning` when a Gemini slot exists AND the parent
    /// env carries production-shaped secrets. Operator-side
    /// mitigation (clean VM) is the load-bearing defense; csq's
    /// surfacing makes the risk visible at decision time.
    host_isolation: HostIsolationStatus,
    /// PR-CA9b T20 / R3/B90: parse-cache sweeper state. Read from
    /// the daemon's persisted state file at
    /// `<base_dir>/coc-cache-sweeper-state.json`; absent when the
    /// daemon has never run a tick on this machine.
    cache_sweeper: CacheSweeperInfo,
    /// M1-8 (an internal ticket A++ Phase 1): A++ identity-store coexistence state.
    /// Present when the layout can be read (always attempted). Absent (`null`)
    /// when the lock cannot be acquired — diagnostic non-fatal fallback.
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_store: Option<IdentityStoreReport>,
    /// M4-11 (an internal ticket Phase 4 release N): compat-bridge surfaces still
    /// emitting v1-era footprints on disk during the v2.6.x downgrade window.
    /// Always emitted; empty `[]` is the canonical post-Phase-4 final state.
    ///
    /// Enumeration values (spec/13 §9):
    /// - `v1_accounts_field_still_present` — retires M4-13 release N+1
    /// - `legacy_canonical_credentials_file_still_written` — retires M4-12 release N+1
    /// - `legacy_canonical_codex_credentials_file_still_written` — retires M4-12 release N+1
    /// - `decimal_marker_content_present` — retires when a future shard makes
    ///   `phase4_gate_check` refuse pure-legacy installs
    legacy_compat_state: Vec<LegacyCompatEntry>,
    /// an internal journal entry (an internal ticket §FD #2 of an internal journal entry): top-level
    /// "phase-4 incomplete" alarm. Present when at least one UUID-mapped
    /// slot in `profiles.json::by_slot` has an identity-keyed file missing
    /// (the same condition that would cause `phase4_gate_check` to refuse
    /// daemon start). Omitted entirely (NOT null) when phase 4 is healthy
    /// — empty alarm is structurally identical to "no alarm needed."
    ///
    /// Surfaces BEFORE the operator attempts `csq daemon start` so they
    /// can run `csq doctor --repair-identities` (auto-heals slots whose
    /// legacy source exists) and/or `csq login N` (slots whose legacy
    /// source is also gone).
    #[serde(skip_serializing_if = "Option::is_none")]
    phase4_incomplete: Option<Phase4IncompleteAlarm>,
    /// RN1-D5 (WBS): rename labels in `profiles.json::accounts[N].email`
    /// whose slot has no `by_slot[N]` UUID — the relocation pass cannot
    /// migrate them because there is no UUID anchor. When RN1-F removes the
    /// `accounts` field, these labels will be silently dropped.
    ///
    /// Only populated AFTER the `label-channel-migrated` sentinel exists
    /// (pre-sentinel = pre-migration; the warning would be noise before the
    /// relocation pass has run). Omitted entirely (NOT null) when empty.
    ///
    /// JSON shape: `[{ "slot": N, "accounts_email": "Work account" }, ...]`.
    /// Text mode: `⚠ N rename label(s) cannot be relocated: slot 3 "Work account" …`
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unrecoverable_label_relocations: Vec<UnrecoverableSlotJson>,
    /// RN1-D R1 (post-RN1 polish): slots that the daemon's Pass-0 identity
    /// mint skipped because the slot's credentials file had no resolvable
    /// `oauthAccount.emailAddress` — the warn-log path at
    /// `csq-core/src/daemon/identity_mint.rs:188-195`. These slots remain
    /// functional but have no UUID anchor in `profiles.json::by_slot`; the
    /// next `csq login N` will mint the identity via `mint_for_login`,
    /// which carries an explicit OAuth-flow email.
    ///
    /// Only populated AFTER the `store-version` sentinel exists (Pass-0 has
    /// run on this host). Slots whose `by_slot[N]` is now present are
    /// excluded — those have already been remediated by a later
    /// `mint_for_login`. Omitted entirely when empty.
    ///
    /// JSON shape: `[{ "slot": N, "reason": "oauth_email_unresolved" }, ...]`.
    /// Text mode: `Pass-0 skip: ⚠ N slot(s) skipped (oauth_email unresolved): slot 3, slot 5`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pass0_skipped_slots: Vec<Pass0SkippedSlot>,

    /// M04 (an internal workspace): signing key presence status.
    ///
    /// Reports whether the Ed25519 audit-trail signing key is present in the
    /// OS keychain. Remediation: run `csq audit init` to generate and store
    /// a new key.
    ///
    /// JSON shape: `"present"` | `"absent"`.
    signing_key: SigningKeyStatus,

    /// M07 (an internal workspace): active audit sink + replication status.
    ///
    /// `active_sink`: name of the configured sink (`"none"` = local-only, the default).
    /// `last_anchor_ts`: ISO-8601 UTC of the last successful anchor, or null.
    /// `pending_count`: records queued in `.pending-<sink>/` awaiting daemon drain.
    /// `replication_drift_count`: drift events detected since last reset.
    ///
    /// JSON shape: `{ active_sink, last_anchor_ts, pending_count, replication_drift_count }`.
    #[serde(skip_serializing_if = "Option::is_none")]
    audit_sink: Option<AuditSinkDoctorInfo>,

    /// M13 (an internal workspace): F-LEDGER-02 orphan intent records.
    ///
    /// Each entry is a pre-op INTENT record on the committed chain whose
    /// `correlation_id` has no matching OUTCOME — the side effect may have
    /// half-completed (a crash/kill between the intent drain and the outcome
    /// append). Omitted from JSON when empty (the common, healthy case).
    ///
    /// JSON shape: `[{ correlation_id, record_id, kind, seq }]`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    audit_orphan_intents: Vec<csq_core::audit::OrphanIntent>,

    /// Historical signing-key gaps detected by the last `verify_chain` scan.
    ///
    /// Non-empty when one or more rotated-out signing keys are no longer in the
    /// keychain. The daemon proceeds to bind in this state (chain-linking was
    /// verified; only per-record signatures for these historical records were
    /// skipped), but the gap is surfaced here so operators can audit the
    /// situation. Omitted from JSON when empty (the healthy, fully-verified case).
    ///
    /// JSON shape: `[{ key_id, first_seq, last_seq, count }]`.
    ///
    /// Note: `key_id` and `seq` values are not secrets; no paths are included.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    audit_historical_key_gaps: Vec<AuditHistoricalKeyGap>,

    /// Audit-chain health state classified from the last `verify_chain` run.
    ///
    /// Mirrors the `AuditHealth` enum the daemon computes at startup.
    ///
    /// `verified`  — chain is intact and all reachable signatures verified.
    /// `degraded`  — chain-linking verified; one or more historical signing keys
    ///               absent from keychain (per-record sigs for those records skipped).
    ///               Daemon is operational; see `audit_historical_key_gaps`.
    /// `broken`    — `verify_chain` returned a fatal error (chain corruption,
    ///               invalid signature, IO failure, etc.). Daemon audit subsystem
    ///               is non-operational until repaired.
    /// `unknown`   — transient: the signing key is present but the credential
    ///               store could not be read this run (`KeychainUnavailable` —
    ///               keychain locked / access-denied; reachable from doctor), OR
    ///               (daemon-startup only) a verify timeout/panic. Audit subsystem
    ///               fail-closed for the run; NOT a durable lockout (the
    ///               `.chain-broken` sentinel is left unchanged). Run
    ///               `csq audit migrate-keys`.
    ///
    /// JSON shape: `{ "status": "verified" | "degraded" | "broken" | "unknown",
    ///               "error_kind": "...", "reason": "..." }` (broken/unknown only).
    ///
    /// Note: no host paths included; `error_kind` is a fixed-vocabulary tag.
    audit_chain_state: csq_core::audit::AuditHealth,
    /// M2 T2.5 — trust-plane conformance grade for the audit chain
    /// (`"COMPATIBLE"` / `"CONFORMANT"` / `"COMPLETE"`). Added in **enterprise**
    /// schema v17.
    ///
    /// **Enterprise edition only.** The schema version is edition-specific
    /// (community `19` / enterprise `22`; see `DOCTOR_SCHEMA_VERSION` + spec 13 §9
    /// for the authoritative current values + full history): this grade field
    /// arrived at v17, so the enterprise build carries it and reports the higher
    /// ceiling, while the community build always emits `None` here and
    /// `skip_serializing_if` omits the field — so the community wire output is
    /// byte-identical to pre-T2.5 (dog/tail model, `rules/independence.md`).
    /// `None` (omitted) when the chain did not verify (`broken`/`unknown`
    /// `audit_chain_state`), or in any community build.
    /// Mirrors the `csq audit verify --json` `trust_plane_grade` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    audit_trust_plane_grade: Option<&'static str>,
    /// M3a — per-level record counts that accompany `audit_trust_plane_grade`.
    /// Present whenever the grade is (never a bare grade — surfacing CONFORMANT
    /// without the level distribution would over-claim on the honest-host
    /// boundary; redteam R1 HIGH, 2026-06-17). **Enterprise only**: the
    /// community build always emits `None`, `skip_serializing_if` omits the
    /// field, so the community `--json` schema stays byte-identical. Keys are
    /// the UPPERCASE canonical wire form (`"AUTO_APPROVED"`, etc.); mirrors the
    /// `csq audit verify --json` `verification_level_summary` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    audit_verification_level_summary: Option<std::collections::BTreeMap<String, u64>>,
    /// Keychain integrity-anchor verdict for this run (a DETECTOR — never bricks
    /// the chain). `confirmed` = file/keychain agree; `unconfirmed` = the anchor
    /// could not be read+compared (keychain locked / absent / legacy — forge-
    /// resistance was file-only; run `csq audit migrate-keys`); `mismatch` =
    /// file/keychain/chain.json disagree (possible tampering — investigate).
    audit_keychain_anchor: csq_core::audit::KeychainAnchorStatus,

    /// Keychain roster-version-floor anchor verdict (a DETECTOR — never bricks).
    /// Added in schema v16 (`#694` item 2).
    /// `confirmed` = chain.json floor matches keychain-anchored floor;
    /// `unconfirmed` = no roster installed yet (chain.json has no floor), OR
    ///   keychain entry absent / unreadable — detection is file-only for now;
    /// `mismatch` = chain.json floor differs from keychain-anchored floor (possible
    ///   rollback tampering — investigate; run `csq audit verify`).
    ///
    /// `None` on installations that have never run `csq audit roster install`.
    /// Always `None` for schema_version < 16 (backward compatibility).
    ///
    /// JSON shape: `{ "audit_roster_floor_anchor": "confirmed" }` (omitted when None).
    #[serde(skip_serializing_if = "Option::is_none")]
    audit_roster_floor_anchor: Option<csq_core::audit::RosterFloorAnchorStatus>,

    /// #787 b2b — the policy-bundle version-floor keychain-anchor cross-check
    /// (DETECTOR posture; enforcement always uses the FILE floor). One of:
    /// `confirmed` (file floor ↔ keychain anchor agree), `unavailable` (no
    /// keychain anchor readable — file-only tamper-detection), `corrupt` (the
    /// floor file exists but is unreadable — the gate fails closed), or
    /// `mismatch (...)` (keychain anchor disagrees with the file floor —
    /// possible on-disk floor tamper/rollback; investigate).
    ///
    /// `None` (omitted) until a policy bundle has been installed
    /// (`csq audit bundle-install`), and ALWAYS `None` in the community edition
    /// (the phase-2b bundle floor is enterprise-only, moat-stripped from the
    /// community tree). A plain string (not the enterprise-only
    /// `BundleFloorAnchor` enum) so the shared `DoctorReport` shape compiles in
    /// both editions.
    #[serde(skip_serializing_if = "Option::is_none")]
    audit_bundle_floor_anchor: Option<String>,

    /// M18 seam: count of events quarantined under `csq-runs/.quarantine/`.
    ///
    /// Non-zero counts indicate frontier-rejected F101-1 provenance events
    /// (malformed JSON, missing fields, bad UUID, timestamp out of skew,
    /// unregistered surface, body too large). Operator action: inspect
    /// quarantine files and, if caused by a loom bug, report upstream.
    /// Cleared by draining the directory after the root cause is fixed.
    ///
    /// `None` when the quarantine directory does not exist (the healthy
    /// initial state — no events have been rejected yet).
    ///
    /// JSON shape: `{ "seam_quarantine_count": 0 }` (omitted when None).
    #[serde(skip_serializing_if = "Option::is_none")]
    seam_quarantine_count: Option<u32>,

    /// M18 seam: count of events parked under `csq-runs/.pending/provenance/`.
    ///
    /// Non-zero counts indicate well-formed F101-1 provenance events whose
    /// `f101_schema_version` is not registered in the production dispatcher
    /// (ADR-B2: empty registry in M18 scaffolding; M18-bind registers the
    /// first decoder arm). Operator action: upgrade csq to a version that
    /// supports the event's schema version, then drain with `csq provenance drain`
    /// (planned for M18-bind). Until M18-bind ships, all real events park here.
    ///
    /// `None` when the pending directory does not exist.
    ///
    /// JSON shape: `{ "seam_pending_provenance_count": 5 }` (omitted when None).
    #[serde(skip_serializing_if = "Option::is_none")]
    seam_pending_provenance_count: Option<u32>,

    /// M20 seam: count of events HELD under
    /// `csq-runs/.pending/provenance-ordered/` awaiting an intra-source
    /// predecessor (F-SEAM-09 counter-gap). A non-zero count is a transient
    /// reconnect-drain state — the held events link when their predecessor
    /// arrives or after the bounded `PREDECESSOR_WAIT_SECS` timeout. A
    /// persistently non-zero count indicates a genuinely-lost predecessor
    /// (the sweep links it with a `predecessor_missing` annotation). No host
    /// paths surfaced — only the count.
    ///
    /// `None` when the held store does not exist.
    ///
    /// JSON shape: `{ "seam_held_predecessor_count": 2 }` (omitted when None).
    #[serde(skip_serializing_if = "Option::is_none")]
    seam_held_predecessor_count: Option<u32>,

    /// M18 seam: surface-registry.json validity check.
    ///
    /// `"ok"` when the registry file is absent (healthy default) or present
    /// and parses successfully. `"seam_registry_invalid"` when the file is
    /// present but fails to load (I/O error, malformed JSON, or >256 entries).
    /// Operator action: inspect `<base>/audit/surface-registry.json` and
    /// repair or remove it.
    ///
    /// JSON shape: `{ "seam_registry_status": "ok" }` (always emitted).
    seam_registry_status: String,

    /// M18 seam: raised when the pending-provenance backlog exceeds 1 000 events.
    ///
    /// `None` when the count is below the threshold (no note needed).
    /// `Some("seam_pending_backlog_high")` when `seam_pending_provenance_count`
    /// exceeds 1 000 — the operator should check whether the registry drain
    /// is running and whether M18-bind has shipped.
    ///
    /// JSON shape: `{ "seam_pending_backlog_note": "seam_pending_backlog_high" }`
    /// (omitted when None).
    #[serde(skip_serializing_if = "Option::is_none")]
    seam_pending_backlog_note: Option<String>,

    /// M19 seam: per-surface provenance capture conformance check.
    ///
    /// Typed state — one of four mutually-exclusive outcomes (Finding D fix):
    /// - `not_configured`: `required-hooks.json` absent — no policy configured.
    /// - `conformant`: policy present, all required surfaces Wired.
    /// - `drift`: policy present, one or more required surfaces Unwired.
    /// - `policy_unreadable`: policy file present but unreadable/unparseable.
    ///
    /// All four states are operator-visible (text-mode prints a line for each).
    /// JSON shape: `{ "seam_capture_conformance": { "state": "...", ... } }`.
    /// Always serialized (never skip_serializing_if) so the state is always
    /// present in `csq doctor --json`.
    seam_capture_conformance: SeamConformanceState,

    /// CU4 (spec 10 §10.8.3): MCP partial-coverage advisory. `warn` is true
    /// when the user has ≥1 CLI-bound MCP server configured AND the capability
    /// layer is enabled — csq's MCP gate covers prompt-edit tool allow/deny
    /// only, not the runtime MCP traffic of the CLIs' own servers. Always
    /// serialized so the state is present in `csq doctor --json`.
    mcp_partial_coverage: McpPartialCoverage,

    /// M6 #914: MCP-gate attestation outbox backlog — enforced `tools/call`
    /// decisions durably queued in `csq-runs/.pending-mcp-gate/` that the daemon
    /// startup drain has not yet landed on the signed audit chain. `Some` with
    /// `warn=true` signals a STUCK backlog (an enforced-but-unrecorded
    /// compliance-record set the operator must clear); `warn=false` is a benign
    /// transient (drains on the next daemon start). `None` when the outbox is
    /// absent or empty — the case for any build a community `csq` produces (the
    /// proxy producer is enterprise-only, so a community build never WRITES the
    /// outbox). The read is edition-agnostic, so a community `csq doctor` run
    /// against a `$HOME` an enterprise `csq-ee` populated will faithfully report
    /// that enterprise-written backlog (count + age are edition-neutral, not
    /// proprietary logic) — the M6 #909 shard-D daemon-aware fields bump only the
    /// enterprise `schema_version` ceiling (v20 → v21), never the community one (v19).
    /// JSON shape: `{ pending_count, oldest_age_secs, state, last_drain_age_secs, warn }`
    /// (omitted when None).
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_gate_outbox_backlog: Option<McpGateOutboxBacklog>,

    /// an internal ticket: custodian-identity canary. Detects the degraded state where
    /// Claude Code has stopped writing `oauthAccount.emailAddress` into a live
    /// Anthropic session's `.claude.json` — the local signal the daemon
    /// custodian's wrong-account gate depends on. Without the field the gate
    /// refuses EVERY token adoption for the account and the credential
    /// refresh war silently returns. NOT serialized in `--json` (drives only
    /// the printed canary line, so it adds no `schema_version` bump / spec-13
    /// §9 contract change); the printed WARN is the operator-facing signal.
    #[serde(skip)]
    custodian_identity_canary: CustodianIdentityCanary,
}

/// CU4 MCP partial-coverage advisory state for `csq doctor` (spec 10 §10.8.3).
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
struct McpPartialCoverage {
    /// True iff `cli_sources` is non-empty AND the capability layer is enabled.
    warn: bool,
    /// CLI surfaces with native MCP servers configured (the advisory's evidence;
    /// e.g. `["claude","gemini"]`). Detected regardless of `warn`.
    cli_sources: Vec<String>,
}

/// M6 #914: MCP-gate attestation outbox backlog surfaced by `csq doctor`.
///
/// The outbox (`csq-runs/.pending-mcp-gate/`) durably queues gated `tools/call`
/// decisions when the live POST to the daemon fails; the startup reconciler
/// drains it onto the signed chain on the next daemon start. A record that
/// lingers means an enforced decision is not yet recorded — a governance gap the
/// operator should see, not just have silently preserved on disk (the #909 fix
/// guarantees no record is LOST; #914 makes a stuck backlog VISIBLE).
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
struct McpGateOutboxBacklog {
    /// `.pending-mcp-gate/*.json` files queued (enforced MCP-gate decisions not
    /// yet on the signed chain). Excludes `.tmp.` in-flight writes and subdirs,
    /// mirroring the drain's own filter.
    pending_count: u32,
    /// Age in seconds of the OLDEST queued file, taken as the max of each file's
    /// `now - mtime`. A file whose mtime is unreadable OR in the future
    /// (`duration_since` errs — clock skew) contributes NO age, so it does not
    /// raise this value; `None` means every counted file's age was unreadable
    /// (never `Some(_)` with `pending_count == 0` — the whole struct is `None`
    /// then). The count axis (`pending_count`) is computed BEFORE the mtime read,
    /// so it always reflects every queued file even when ages are missing — a
    /// backlog can never be fully hidden from `warn` via mtime alone. A genuinely
    /// stuck backlog (daemon not restarting / chain not appendable) carries normal
    /// PAST mtimes, so the age axis fires as intended; a same-user actor forging a
    /// future mtime is out of the threat model (they can delete the file outright).
    oldest_age_secs: Option<u64>,
    /// M6 #909 shard D: the daemon-aware disposition — `stuck` (actionable),
    /// `draining` (daemon up, young backlog), or `pending_daemon_down` (daemon not
    /// draining; drains when it resumes). Replaces #914's fixed-6h age judgment.
    state: McpGateBacklogState,
    /// M6 #909 shard D: seconds since the daemon last ran a drain cycle (the
    /// `.outbox-drain-stamp`), or `None` when no drain has stamped on this base. A
    /// small value ⟺ the daemon is actively draining; a large/absent value ⟺ the
    /// daemon is down — the signal that distinguishes a genuinely-STUCK backlog from
    /// one merely PENDING behind a stopped daemon.
    last_drain_age_secs: Option<u64>,
    /// `true` iff `state == Stuck` — the single operator-actionable axis (chain not
    /// appendable while the daemon drains, OR the count cap exceeded). Retained for
    /// consumers of the pre-shard-D shape; `false` is a benign `draining` /
    /// `pending_daemon_down` transient.
    warn: bool,
}

/// M6 #909 shard D: a drain stamp (`csq-runs/.outbox-drain-stamp`, written by every
/// drain cycle) newer than this (seconds) means the daemon is UP and its continuous
/// drain loop is running. Set to ~3 refresher intervals (the drain rides the 5-min
/// refresher tick), so a stamp within 15 min ⟺ "daemon actively draining", and a
/// staler stamp ⟺ "daemon down / drain not running" (→ PENDING, not a false STUCK
/// alarm during a maintenance window). Replaces #914's fixed 6h wall-clock.
const MCP_GATE_DRAIN_STAMP_FRESH_SECS: u64 = 15 * 60;

/// M6 #909 shard D: with the daemon actively draining (a fresh stamp), a queued file
/// older than this (seconds) is STUCK — the drain has run several cycles and still
/// cannot land the record, so the chain is not appendable (`csq audit verify` /
/// `csq audit init`). ~3 drain cycles; far faster + more accurate than #914's 6h
/// (which had to be generous precisely because it could not tell an up-and-draining
/// daemon from a down one).
const MCP_GATE_OUTBOX_STUCK_AGE_WHILE_DRAINING_SECS: u64 = 15 * 60;

/// #914: a queued-file count above this flips the doctor surface to WARN
/// regardless of age OR daemon state — a large backlog is itself a signal, even
/// behind a down daemon (so an unbounded pending queue is never silently tolerated;
/// M6 #909 shard D keeps this axis unconditional). Mirrors the seam custody soft
/// cap ([`check_seam_pending_backlog`]'s 1 000-file threshold).
const MCP_GATE_OUTBOX_STUCK_COUNT: u32 = 1_000;

/// M19 hook-conformance state for `csq doctor` (Finding D fix).
///
/// Typed enum so that "file absent", "unreadable", "conformant", and "drift"
/// produce distinct operator-visible states — a corrupt/planted policy file
/// can no longer silently disable conformance reporting.
///
/// `required-hooks.json` is a loom-managed or operator-managed file at
/// `<base>/audit/required-hooks.json`: a JSON array of surface-id strings
/// (e.g. `["cc","codex"]`). An empty array `[]` is treated as
/// `NotConfigured` — "no surfaces required" ≡ no requirement set.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
enum SeamConformanceState {
    /// `required-hooks.json` is absent or is an empty `[]`.
    /// No hook-conformance policy is configured for this install.
    NotConfigured,
    /// Policy is present and all required surfaces are Wired.
    Conformant,
    /// Policy is present; `drift` lists required-but-Unwired surfaces.
    Drift {
        /// Required surfaces that are currently Unwired.
        drift: Vec<String>,
    },
    /// Policy file is present but could not be read or parsed.
    /// Operator must inspect `<base>/audit/required-hooks.json`.
    PolicyUnreadable {
        /// Short human-readable reason (no file contents, no secrets).
        reason: String,
    },
}

/// One contiguous run of records whose signatures were skipped because the
/// signing key that produced them is a historical (rotated-out) key absent
/// from the keychain. Surfaces in `csq doctor` under `audit_historical_key_gaps`.
#[derive(Serialize, Debug, Clone)]
struct AuditHistoricalKeyGap {
    /// The `key_id` of the absent historical key (`ed25519:<64 hex chars>`).
    key_id: String,
    /// Sequence number of the first record in this gap run.
    first_seq: u64,
    /// Sequence number of the last record in this gap run.
    last_seq: u64,
    /// Total number of records whose signatures were skipped.
    count: u64,
}

/// Signing key presence status for M04 (`csq doctor`).
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SigningKeyStatus {
    /// Key is present and readable (file store or keychain).
    Present,
    /// Key is absent — run `csq audit init` to generate a new key.
    Absent,
    /// Key is present but not readable right now (locked / ACL-blocked keychain,
    /// no file copy). Run `csq audit migrate-keys` — NOT `audit init`.
    Inaccessible,
}

/// M07 audit-sink doctor surface.
#[derive(Serialize, Debug, Clone)]
struct AuditSinkDoctorInfo {
    /// Active sink name (e.g. `"rekor"`, `"none"`).
    active_sink: String,
    /// ISO-8601 UTC timestamp of the last successful anchor (null when none).
    #[serde(skip_serializing_if = "Option::is_none")]
    last_anchor_ts: Option<String>,
    /// Records queued in `.pending-<sink>/` awaiting daemon drain.
    pending_count: u64,
    /// Drift events detected since last reset.
    replication_drift_count: u64,
}

/// JSON representation of one unrecoverable rename label slot.
///
/// Mirrors `UnrecoverableSlot` from `csq_core::accounts::profiles` but uses
/// serde-friendly field names (`snake_case` matching spec/13 §9 conventions).
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
struct UnrecoverableSlotJson {
    slot: u16,
    accounts_email: String,
}

/// JSON representation of one Pass-0 skipped slot.
///
/// Mirrors the daemon's identity-mint skip path at
/// `csq-core/src/daemon/identity_mint.rs:188-195`. The `reason` field is a
/// closed enumeration: `"oauth_email_unresolved"` is currently the only
/// value emitted, matching the daemon's `error_kind` tag.
///
/// Per spec/13 §9 conventions (snake_case fields).
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
struct Pass0SkippedSlot {
    slot: u16,
    reason: &'static str,
}

/// an internal journal entry: top-level "phase-4 incomplete" alarm payload. Renders
/// near the top of the text-mode doctor report and emits as a structured
/// JSON object when at least one UUID-mapped slot has a missing
/// identity-keyed file. Empty/absent means no alarm needed.
///
/// Detection is the read-only sibling of
/// [`csq_core::daemon::startup_reconciler::phase4_gate_check`] — see
/// [`csq_core::daemon::startup_reconciler::phase4_gate_status`].
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
struct Phase4IncompleteAlarm {
    /// Distinct slot count across the missing-file records. A single
    /// slot missing credentials AND settings counts as one slot here.
    affected_slot_count: usize,
    /// Total missing identity-keyed file records — a single slot can
    /// contribute up to three (credentials / settings / codex creds).
    missing_file_count: usize,
}

/// M4-11 (an internal ticket Phase 4 release N) — one compat-bridge surface that still
/// emits a v1-era footprint on disk. The shape is fixed by spec/13 §9.
///
/// Each variant has a specific, actionable description and a documented
/// remediation milestone (per `tauri-commands.md` MUST Rule 6: every named
/// variant maps to specific UI text). The enumeration is closed by
/// [`LegacyCompatKind`]; renderers / consumers MUST match exhaustively on
/// the `kind` string.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
struct LegacyCompatEntry {
    /// Enumeration value naming the surviving compat-bridge surface.
    /// One of the four spec/13 §9 enumeration kinds (stringified via
    /// [`LegacyCompatKind::as_str`]).
    kind: String,
    /// User-actionable description of the detected footprint, e.g.
    /// `"profiles.json::accounts has 2 non-empty entries (release-N empty-write affordance)"`.
    /// The string is a fixed-vocabulary template per kind — no echo of
    /// user-supplied strings, so no sanitization required at render time.
    evidence: String,
    /// Documented retirement path, e.g. `"M4-13 release N+1"`. Renderers
    /// surface this so operators see the bridge's planned closure window.
    scheduled_for: &'static str,
}

/// M4-11 enumeration of compat-bridge kinds tracked by [`LegacyCompatEntry`].
///
/// Closed enum — adding a variant requires a coordinated spec/13 §9 update
/// per `specs-authority.md` MUST Rule 4 (specs are updated at first instance).
/// Exhaustive matching at every render site catches drift between the spec
/// contract and the implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LegacyCompatKind {
    /// `profiles.json::accounts` has at least one non-empty entry.
    /// Retires M4-13 release N+1 (user-rename channel migration).
    V1AccountsFieldStillPresent,
    /// `credentials/<N>.json` Anthropic legacy-keyed mirror still written
    /// alongside `identities/<UUID>/credentials.json`.
    /// Retires M4-12 release N+1 (downgrade window closure).
    LegacyCanonicalCredentialsFileStillWritten,
    /// `credentials/codex-<N>.json` Codex legacy-keyed mirror still written
    /// alongside `identities/<UUID>/credentials-codex.json`.
    /// Retires M4-12 release N+1 (same shard as the Anthropic retirement).
    LegacyCanonicalCodexCredentialsFileStillWritten,
    /// At least one `config-<N>/.csq-account` marker still carries a
    /// decimal slot id rather than the slot's UUID.
    /// Pure-legacy install where `mint_for_login` has not yet run.
    /// Retires when a future shard makes `phase4_gate_check` refuse
    /// pure-legacy installs.
    DecimalMarkerContentPresent,
}

impl LegacyCompatKind {
    /// Stringified kind — matches spec/13 §9 verbatim. Used both for JSON
    /// emission and for text-mode short tags. Updating a literal here
    /// without updating spec/13 §9 violates `specs-authority.md` MUST Rule 4.
    fn as_str(self) -> &'static str {
        match self {
            LegacyCompatKind::V1AccountsFieldStillPresent => "v1_accounts_field_still_present",
            LegacyCompatKind::LegacyCanonicalCredentialsFileStillWritten => {
                "legacy_canonical_credentials_file_still_written"
            }
            LegacyCompatKind::LegacyCanonicalCodexCredentialsFileStillWritten => {
                "legacy_canonical_codex_credentials_file_still_written"
            }
            LegacyCompatKind::DecimalMarkerContentPresent => "decimal_marker_content_present",
        }
    }

    /// Documented retirement path per spec/13 §9. Returned as `&'static str`
    /// because the value is a fixed milestone label, never user-derived.
    fn scheduled_for(self) -> &'static str {
        match self {
            LegacyCompatKind::V1AccountsFieldStillPresent => "M4-13 release N+1",
            LegacyCompatKind::LegacyCanonicalCredentialsFileStillWritten => "M4-12 release N+1",
            LegacyCompatKind::LegacyCanonicalCodexCredentialsFileStillWritten => {
                "M4-12 release N+1"
            }
            LegacyCompatKind::DecimalMarkerContentPresent => {
                "future shard after phase4_gate_check refuses pure-legacy installs"
            }
        }
    }

    /// Short human-readable tag for the text-mode renderer's
    /// `bridge(s) active — <tag1> (<sched1>), <tag2> (<sched2>)`
    /// line. Per spec/13 §9 the text mode names each surviving kind by
    /// a short tag plus its retirement milestone.
    fn short_tag(self) -> &'static str {
        match self {
            LegacyCompatKind::V1AccountsFieldStillPresent => "v1_accounts_field",
            LegacyCompatKind::LegacyCanonicalCredentialsFileStillWritten => {
                "legacy_credentials_file"
            }
            LegacyCompatKind::LegacyCanonicalCodexCredentialsFileStillWritten => {
                "legacy_codex_credentials_file"
            }
            LegacyCompatKind::DecimalMarkerContentPresent => "decimal_marker",
        }
    }
}

/// Per-surface CLI status emitted by `csq doctor --json`.
///
/// spec/13 §9: `manager` values use the doctor-display names (`"npm"`,
/// `"brew_formula"`, `"brew_cask"`, `"claude_native"`, `"unknown"`) rather
/// than the internal `InstallManager` serde names (`"npm_global"`, etc.).
#[derive(Serialize, Clone)]
pub struct CliSurfaceInfo {
    pub found: bool,
    /// Absolute path to the binary, or `null` when `Missing`.
    ///
    /// **Design-intent operator-facing field.** `csq doctor` is the
    /// diagnostic surface for PATH-shadowed CLI binaries (cc/codex/
    /// gemini); the full resolved path is required so operators can
    /// distinguish shadowing (e.g. `/opt/homebrew/bin/claude` vs
    /// `/Users/<u>/.npm-global/bin/claude`). The Rule 6a binary-smoke
    /// audit MUST exclude this field's JSON output — see
    /// `rules/operator-surface-verification.md` § "Design-intent fields".
    pub path: Option<String>,
    /// Version string (e.g. `"0.130.0"`), or `null`.
    pub version: Option<String>,
    /// Minimum required version string (e.g. `"0.40.0"`).
    pub min_version: String,
    /// `"ok" | "outdated" | "missing" | "wrong_binary" |
    /// "unrecognized_version" | "probe_timed_out" | "probe_disabled"`.
    pub status: String,
    /// `"npm" | "brew_formula" | "brew_cask" | "claude_native" | "unknown"`.
    pub manager: String,
    /// Populated when `status == "wrong_binary"`.
    /// `"install_path_blocklisted" | "prefix_mismatch" | "component_too_large"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrong_binary_reason: Option<WrongBinaryReasonInfo>,
}

/// Structured reason for a `wrong_binary` status, threaded through to the
/// doctor renderer so it can emit the correct per-reason remediation text.
#[derive(Serialize, Clone)]
pub struct WrongBinaryReasonInfo {
    pub kind: String,
    /// For `prefix_mismatch`: the expected prefix string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    /// For `prefix_mismatch`: the sanitized actual output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub got: Option<String>,
    /// For `component_too_large`: the offending segment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub segment: Option<String>,
}

/// PR-CA9b T20 / R3/B90 — surface for the daemon parse-cache sweeper.
/// Mirrors [`csq_core::daemon::coc_cache_sweeper::SweeperSnapshot`]
/// plus a derived `sweep_lag_minutes` computed at doctor-call time.
/// `status` flips to `degraded` when `sweep_partial == true` for >24h
/// per the R4 acceptance bullet.
#[derive(Serialize)]
struct CacheSweeperInfo {
    /// `"ok"`, `"degraded"`, or `"never_run"`.
    status: &'static str,
    last_sweep_at: Option<String>,
    last_sweep_duration_ms: u64,
    sweep_partial: bool,
    sweep_lag_minutes: i64,
    files_swept_last_run: u64,
    files_skipped_last_run: u64,
    cache_sweep_blocked: u64,
}

/// Round-3 R3-M3 + R2-M2 shape: status + count + first-name
/// exemplar are always emitted. `detected_var_names` is empty
/// in default mode and populated only under `--verbose`. Round-2
/// R2-M2: shape-stable across modes (downstream JSON consumers
/// don't have to handle two field-presence shapes).
#[derive(Serialize)]
struct HostIsolationStatus {
    /// `"ok"` or `"warning"`. Round-1 H4 gate: `warning` only
    /// fires when a Gemini slot exists AND production-shaped
    /// secrets are present. cc/codex-only deployments without a
    /// Gemini slot see `ok` even with secrets in env.
    status: &'static str,
    /// Whether at least one Gemini slot is provisioned. The gate
    /// requires this — operators who never use gemini get `ok`.
    gemini_slots_present: bool,
    /// Number of detected production-shaped env-var names (round-2
    /// R2-H3 disclosure-minimization — count + exemplar only by
    /// default).
    detected_count: usize,
    /// Single-name exemplar from the priority-list-first selection
    /// in `csq_core::env::first_exemplar`. Round-3 R3-H7: prefers
    /// EXACT-match list (ANTHROPIC_API_KEY > ... > GITHUB_TOKEN)
    /// over lex-first to surface known-real secrets.
    first_name: Option<String>,
    /// Full set of detected names. Empty `[]` in default mode;
    /// populated under `--verbose` (CLI flag wiring is a follow-
    /// up). Round-2 R2-M2: shape-stable so downstream JSON
    /// consumers see a Vec in both modes.
    detected_var_names: Vec<String>,
}

/// Whether a JS runtime (`node` or `bun`) is available for the
/// Anthropic HTTP subprocess path. `reqwest/rustls` is blocked by
/// Cloudflare's JA3/JA4 fingerprint (an internal journal entry), so the token
/// refresher and usage poller shell out via Node — without one the
/// daemon cannot refresh OAuth tokens or pull quota.
#[derive(Serialize)]
struct JsRuntimeInfo {
    found: bool,
    path: Option<String>,
}

/// One slot that has BOTH a 3P `config-N/settings.json` env block
/// AND a valid OAuth `credentials/N.json`. This is an inconsistent
/// state usually caused by partial recovery: e.g. `csq login N` ran
/// but the pre-existing 3P env block was not stripped, so CC still
/// routes to the 3P endpoint despite having OAuth creds. Resolve by
/// running `csq login N` on a build that includes the automatic
/// unbind (an internal ticket) or manually removing the env block.
#[derive(Serialize)]
struct MixedStateSlot {
    account: u16,
    provider: String,
}

#[derive(Serialize)]
struct MixedStateInfo {
    count: usize,
    entries: Vec<MixedStateSlot>,
}

/// Counts of canonical-credentials resurrection events the daemon
/// has recorded in `.resurrection-log.jsonl`. Non-zero means the
/// refresher found at least one account whose `credentials/N.json`
/// was missing and had to rebuild it from `config-N/.credentials.json`
/// — evidence that something in the write path is orphaning live
/// files without mirroring to canonical. Operators should investigate
/// recent write paths (login, Add Account, imports) when this is > 0.
#[derive(Serialize)]
struct ResurrectionInfo {
    /// Total breadcrumb records found.
    total: usize,
    /// Number of distinct accounts that have been resurrected.
    distinct_accounts: usize,
    /// Unix seconds of the most recent resurrection event, if any.
    last_timestamp_secs: Option<u64>,
    /// Sample of the most recent account IDs (up to 5) for the
    /// operator to start their investigation. Intentionally not
    /// the whole list — if there are hundreds the doctor output
    /// would become unreadable.
    recent_accounts: Vec<u16>,
}

/// Information about running CC terminals (legacy vs modern handle-dir).
#[derive(Serialize)]
struct TerminalInfo {
    /// Number of `term-<pid>` handle dirs with a living PID.
    modern_count: usize,
    /// Number of `config-N` directories that appear to have an active legacy
    /// CC session (credentials file is NOT a symlink, meaning it is a real
    /// file from the pre-handle-dir era).
    legacy_count: usize,
    /// Whether process enumeration was available on this platform.
    /// On Windows this is always false; on Unix it depends on fs access.
    check_available: bool,
}

#[derive(Serialize)]
struct PlatformInfo {
    os: String,
    arch: String,
}

// ClaudeCodeInfo was replaced by CliSurfaceInfo in PR-MCD1.5.

#[derive(Serialize)]
struct SettingsInfo {
    exists: bool,
    statusline_configured: bool,
    statusline_command: Option<String>,
}

#[derive(Serialize)]
struct DaemonInfo {
    /// One of: "healthy", "drifted", "pid_alive_no_socket", "stale", "unhealthy",
    /// "not running", "not supported".
    status: String,
    pid: Option<u32>,
    /// Whether the daemon socket responded to the health check. `None` when
    /// the daemon is not running or the platform does not support detection.
    socket_healthy: Option<bool>,
    /// Populated when the daemon's reported version differs from the CLI's
    /// own `CARGO_PKG_VERSION`, signalling a stale-daemon-after-csq-upgrade
    /// drift. The daemon is alive and serving but its data may be stale; the
    /// remediation is `csq daemon stop && csq daemon start`.
    #[serde(skip_serializing_if = "Option::is_none")]
    version_drift: Option<String>,
}

/// One account whose broker has set the LOGIN-NEEDED sentinel.
#[derive(Serialize)]
struct BrokerFailedEntry {
    account: u16,
    reason: String,
}

/// Summary of broker-failed sentinel files found under
/// `credentials/N.broker-failed`.
#[derive(Serialize)]
struct BrokerFailedInfo {
    /// Number of accounts with a broker-failed sentinel.
    count: usize,
    /// Per-account details (account number + reason tag).
    entries: Vec<BrokerFailedEntry>,
}

#[derive(Serialize)]
struct AccountsInfo {
    total: usize,
    with_credentials: usize,
    expired: usize,
}

pub fn handle(
    base_dir: &Path,
    json: bool,
    slot: Option<u16>,
    repair_identities: bool,
    check_token_owners: bool,
) -> Result<()> {
    if repair_identities {
        return run_repair_identities(base_dir, json);
    }

    if check_token_owners {
        return run_token_owner_check(base_dir, json);
    }

    if let Some(n) = slot {
        let report = build_per_slot_report(base_dir, n)?;
        if json {
            println!("{}", serde_json::to_string(&report)?);
        } else {
            print_per_slot_report(&report);
        }
        return Ok(());
    }

    let report = build_report(base_dir);

    if json {
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }

    print_report(&report);
    Ok(())
}

/// `csq doctor --repair-identities` — one-shot legacy→identity migration.
/// Runs the same `phase4_gate_self_heal` pass the daemon invokes inside
/// `phase4_gate_check`, but as a standalone operator entry point so it
/// can be run BEFORE the daemon starts (the v2.7.3 → v2.7.7+ upgrade
/// scenario where the gate refuses).
///
/// The pass is idempotent and safe to run with the daemon stopped or
/// running — per-slot per-file write contention is bounded to a single
/// `unique_tmp_path → write → secure_file → atomic_replace` sequence,
/// and the heal skips slots whose identity files already exist
/// (`AlreadySeeded`). Origin: an internal journal entry §Follow-up #2.
fn run_repair_identities(base_dir: &Path, json: bool) -> Result<()> {
    use csq_core::daemon::startup_reconciler::{
        phase4_gate_self_heal, Phase4HealFile, Phase4HealOutcome,
    };

    let report = phase4_gate_self_heal(base_dir);

    if json {
        #[derive(Serialize)]
        struct RepairRecordJson {
            slot: u16,
            file: &'static str,
            outcome: &'static str,
            error_kind: Option<String>,
        }
        #[derive(Serialize)]
        struct RepairReportJson {
            schema_version: u32,
            seeded_count: usize,
            unhealed_count: usize,
            records: Vec<RepairRecordJson>,
        }
        let records: Vec<RepairRecordJson> = report
            .records
            .iter()
            .map(|r| {
                let (outcome, error_kind) = match &r.outcome {
                    Phase4HealOutcome::Seeded => ("seeded", None),
                    Phase4HealOutcome::AlreadySeeded => ("already_seeded", None),
                    Phase4HealOutcome::MissingLegacySource => ("missing_legacy_source", None),
                    Phase4HealOutcome::CopyFailed { error_kind } => {
                        ("copy_failed", Some(error_kind.clone()))
                    }
                };
                RepairRecordJson {
                    slot: r.slot,
                    file: match r.file {
                        Phase4HealFile::ClaudeCodeCredentials => "credentials.json",
                        Phase4HealFile::Settings => "settings.json",
                        Phase4HealFile::CodexCredentials => "credentials-codex.json",
                    },
                    outcome,
                    error_kind,
                }
            })
            .collect();
        let json_out = RepairReportJson {
            schema_version: 1,
            seeded_count: report.seeded_count(),
            unhealed_count: report.unhealed_count(),
            records,
        };
        println!("{}", serde_json::to_string(&json_out)?);
        return Ok(());
    }

    // Plain-text rendering: one line per record, summary at the end.
    if report.records.is_empty() {
        println!(
            "csq doctor --repair-identities: no UUID-mapped slots in profiles.json::by_slot \
             — nothing to repair."
        );
        return Ok(());
    }
    for record in &report.records {
        let file = match record.file {
            Phase4HealFile::ClaudeCodeCredentials => "credentials.json",
            Phase4HealFile::Settings => "settings.json",
            Phase4HealFile::CodexCredentials => "credentials-codex.json",
        };
        match &record.outcome {
            Phase4HealOutcome::Seeded => {
                println!("  [seeded]         slot {} {}", record.slot, file);
            }
            Phase4HealOutcome::AlreadySeeded => {
                println!("  [already-seeded] slot {} {}", record.slot, file);
            }
            Phase4HealOutcome::MissingLegacySource => {
                println!(
                    "  [needs login]    slot {} {} (no legacy source; run `csq login {}`)",
                    record.slot, file, record.slot
                );
            }
            Phase4HealOutcome::CopyFailed { error_kind } => {
                println!(
                    "  [FAILED: {}]     slot {} {}",
                    error_kind, record.slot, file
                );
            }
        }
    }
    println!(
        "\n  Healed: {}  Unhealed: {}  Total: {}",
        report.seeded_count(),
        report.unhealed_count(),
        report.records.len()
    );
    if report.unhealed_count() > 0 {
        println!(
            "\n  Remaining unhealed entries require `csq login <N>` per slot. The phase-4 \n  \
             gate will continue to refuse daemon start until every UUID-mapped slot has its \n  \
             identity-keyed credentials/settings/codex files seeded."
        );
    }
    Ok(())
}

// ── `csq doctor --check-token-owners` (an internal ticket contamination detector) ───

/// One Anthropic slot's store-token ownership verdict (JSON shape).
#[derive(Serialize)]
struct TokenOwnerSlot {
    account: u16,
    /// The slot's display label (email) — NOT a filesystem path.
    label: String,
    /// `"owned"` | `"contaminated"` | `"unknown"`.
    status: String,
}

/// `csq doctor --check-token-owners` report.
#[derive(Serialize)]
struct TokenOwnerReport {
    checked: usize,
    contaminated: Vec<u16>,
    unknown: Vec<u16>,
    slots: Vec<TokenOwnerSlot>,
}

/// Build the report from per-slot verdicts. Pure — unit-testable without the
/// network.
fn build_token_owner_report(
    results: &[(u16, String, csq_core::daemon::custodian::SlotOwnership)],
) -> TokenOwnerReport {
    use csq_core::daemon::custodian::SlotOwnership;
    let mut contaminated = Vec::new();
    let mut unknown = Vec::new();
    let mut slots = Vec::with_capacity(results.len());
    for (id, label, verdict) in results {
        let status = match verdict {
            SlotOwnership::Owned => "owned",
            SlotOwnership::Contaminated => {
                contaminated.push(*id);
                "contaminated"
            }
            SlotOwnership::Unknown => {
                unknown.push(*id);
                "unknown"
            }
        };
        slots.push(TokenOwnerSlot {
            account: *id,
            label: label.clone(),
            status: status.into(),
        });
    }
    TokenOwnerReport {
        checked: results.len(),
        contaminated,
        unknown,
        slots,
    }
}

fn print_token_owner_report(r: &TokenOwnerReport) {
    println!(
        "\nToken ownership ({} Anthropic slot(s) checked):",
        r.checked
    );
    if r.contaminated.is_empty() {
        println!("  {} no contaminated slots", ok());
    } else {
        for id in &r.contaminated {
            let label = r
                .slots
                .iter()
                .find(|s| s.account == *id)
                .map(|s| s.label.as_str())
                .unwrap_or("");
            println!(
                "  {} slot {id} ({label}): store token belongs to a DIFFERENT account \
                 — heal with `csq login {id}`",
                fail()
            );
        }
    }
    if !r.unknown.is_empty() {
        println!(
            "  {} {} slot(s) could not be verified (revoked token, no JS runtime, or \
             transport error): {:?}",
            warn(),
            r.unknown.len(),
            r.unknown
        );
    }
}

/// `csq doctor --check-token-owners`: per-Anthropic-slot store-token ownership
/// check. Reuses the daemon's Cloudflare-safe Node transport
/// (`get_bearer_node`) and the `check_slot_store_token_ownership` detector.
/// Read-only — one `GET /api/oauth/profile` per slot, mutates nothing.
fn run_token_owner_check(base_dir: &Path, json: bool) -> Result<()> {
    // Same transport the daemon refresher/custodian use (reqwest is blocked by
    // Cloudflare's JA3/JA4 fingerprint — `discovery_cloudflare_tls_fingerprint`).
    let http_get: csq_core::daemon::usage_poller::HttpGetFn =
        std::sync::Arc::new(|url: &str, token: &str, headers: &[(&str, &str)]| {
            csq_core::http::get_bearer_node(url, token, headers)
        });
    let accounts = discovery::discover_anthropic(base_dir);
    let mut results = Vec::new();
    for a in &accounts {
        if let Ok(slot) = csq_core::types::AccountNum::try_from(a.id) {
            let verdict = csq_core::daemon::custodian::check_slot_store_token_ownership(
                base_dir, slot, &http_get,
            );
            results.push((a.id, a.label.clone(), verdict));
        }
    }
    let report = build_token_owner_report(&results);
    if json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        print_token_owner_report(&report);
    }
    Ok(())
}

/// Per-slot doctor report consumed by
/// `coc-eval/scripts/validate-doctor-json.py`. The validator pins the
/// shape `{status, quota: {utilization}}`; we add `credentials` for
/// human readability without changing the gate contract.
///
/// Origin: PR-CA9 T22a recording-time pre-flight (R2/B78).
#[derive(Serialize, Debug)]
pub struct PerSlotReport {
    /// Slot number echoed back so multi-slot logs are decodable.
    pub slot: u16,
    /// "ok" | "degraded" | "error" — the validator rejects anything
    /// else. "error" when credentials are missing or expired; "ok"
    /// otherwise. "degraded" is reserved for future transient-state
    /// signals (daemon not yet polled, etc.).
    pub status: String,
    pub quota: PerSlotQuota,
    pub credentials: PerSlotCredentials,
}

#[derive(Serialize, Debug)]
pub struct PerSlotQuota {
    /// 5-hour rolling utilization as a percentage (0-100). Reads from
    /// `<base_dir>/quota.json`'s per-account `five_hour` window. When
    /// the daemon has not yet polled the slot, this is 0.0 — callers
    /// MUST treat 0.0 as "no data" rather than "fully fresh".
    pub utilization: f64,
}

#[derive(Serialize, Debug)]
pub struct PerSlotCredentials {
    /// `config-<slot>/.credentials.json` exists.
    pub present: bool,
    /// Tokens are past their `expires_at` timestamp. False when not present.
    pub expired: bool,
}

fn build_per_slot_report(base_dir: &Path, slot: u16) -> Result<PerSlotReport> {
    let num = AccountNum::try_from(slot).map_err(|e| anyhow::anyhow!("invalid slot: {e}"))?;

    // Credential presence + expiry — same shape as `check_accounts`.
    //
    // M4-4: route through identity-keyed credentials when
    // `profiles.json::by_slot` has a UUID for this slot. Slot-id channel:
    // doctor's caller supplies the slot as an operation parameter
    // (channel (c) per `account-terminal-separation.md` MUST Rule 1).
    // M4-12: no UUID → no credential file (numeric path retired).
    let cred_path = csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, num.get())
        .map(|uuid| csq_core::accounts::identity_store::credentials_path_for(base_dir, uuid));
    let mut present = false;
    let mut expired = false;
    if let Some(path) = cred_path.as_deref() {
        if let Ok(content) = std::fs::read_to_string(path) {
            present = true;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                // Real CC creds use `claudeAiOauth.expiresAt` (camelCase, ms).
                if let Some(exp) = val
                    .get("claudeAiOauth")
                    .and_then(|o| o.get("expiresAt"))
                    .and_then(|e| e.as_u64())
                {
                    if exp < now_ms {
                        expired = true;
                    }
                }
            }
        }
    }

    // Quota readout — load quota.json and pull the slot's 5h window.
    let utilization = read_slot_five_hour_pct(base_dir, slot);

    let status = if !present || expired {
        "error".to_string()
    } else {
        "ok".to_string()
    };

    Ok(PerSlotReport {
        slot,
        status,
        quota: PerSlotQuota { utilization },
        credentials: PerSlotCredentials { present, expired },
    })
}

fn read_slot_five_hour_pct(base_dir: &Path, slot: u16) -> f64 {
    use csq_core::quota::QuotaFile;
    let path = base_dir.join("quota.json");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return 0.0;
    };
    let Ok(qf) = serde_json::from_str::<QuotaFile>(&content) else {
        return 0.0;
    };
    qf.get(slot).map(|q| q.five_hour_pct()).unwrap_or(0.0)
}

fn print_per_slot_report(r: &PerSlotReport) {
    println!("slot {}: status={}", r.slot, r.status);
    println!("  quota.utilization: {:.1}%", r.quota.utilization);
    println!(
        "  credentials: present={} expired={}",
        r.credentials.present, r.credentials.expired
    );
}

/// Slots whose Gemini binding marker is spawn-admissible
/// (`is_gemini_bound_slot` — the daemon / `csq run` WILL launch them)
/// but whose binding does not parse. These are invisible to
/// `discover_gemini` (strict parse) and therefore to every
/// listing-based surface (`csq status`, the `Gemini CLI` doctor row,
/// `csq probe --all`) — yet the host-isolation gate correctly counts
/// them. Enumerated here so `print_report` can NAME them with a direct
/// remediation rather than delegate to a command structurally blind to
/// them (redteam R3 HIGH-01/MED-01/LOW-02).
///
/// The whole-`credentials/`-unreadable case yields an EMPTY list (a
/// per-path `symlink_metadata` also fails → `is_gemini_bound_slot` is
/// false), so the row never over-claims a specific slot when presence
/// is merely indeterminate (LOW-02).
fn gemini_unreadable_slots(base_dir: &Path) -> Vec<u16> {
    use csq_core::providers::gemini::provisioning::is_gemini_corrupt_bound;
    (1..=csq_core::types::MAX_ACCOUNTS)
        .filter_map(|n| AccountNum::try_from(n).ok())
        .filter(|&s| is_gemini_corrupt_bound(base_dir, s))
        .map(|s| s.get())
        .collect()
}

/// Slots whose Codex binding file is spawn-admissible
/// (`is_codex_bound_slot`) and parses successfully but does NOT carry a
/// Codex variant — operator wrote an Anthropic-shape credential to the
/// Codex-prefixed path (wrong-variant, an internal ticket / #525). These slots
/// are invisible to quota polling and CLI surface checks yet the daemon
/// WILL attempt to use them. Named directly with a self-sufficient
/// remediation instead of delegating to `csq probe --all`.
fn codex_wrong_variant_slots(base_dir: &Path) -> Vec<u16> {
    use csq_core::providers::codex::provisioning::is_codex_wrong_variant_bound;
    (1..=csq_core::types::MAX_ACCOUNTS)
        .filter_map(|n| AccountNum::try_from(n).ok())
        .filter(|&s| is_codex_wrong_variant_bound(base_dir, s))
        .map(|s| s.get())
        .collect()
}

/// `csq doctor --json` schema version. Per the shared monotonic counter
/// (spec/13 §9), `schema_version` is the highest field-version an edition
/// actually emits. v17 (`audit_trust_plane_grade`) and v18
/// (`audit_verification_level_summary`) are enterprise-only + `skip_serializing_if`,
/// so the community build skipped them (its ceiling was v16). v19
/// (`mcp_partial_coverage`, CU4 #764) ships on BOTH editions, raising the
/// community ceiling 16 → 19. **v20** (`mcp_gate_outbox_backlog`, #914) is the
/// next enterprise-only + `skip_serializing_if` field — it serializes on the
/// enterprise build when the MCP-gate outbox is non-empty. **v21** (M6 #909 shard D)
/// extends that SAME enterprise-only field with the daemon-aware `state`
/// (`stuck` / `draining` / `pending_daemon_down`) + `last_drain_age_secs`,
/// replacing #914's fixed-6h stuck judgment — a shape change to an enterprise-only
/// field, so the enterprise ceiling rises 20 → **21** while the community ceiling
/// stays at **19** (the field is never emitted there — the outbox producer is
/// enterprise-only). **v22** (`audit_bundle_floor_anchor`, #787 b2b) is the next
/// enterprise-only + `skip_serializing_if` field — the policy-bundle floor
/// keychain-anchor DETECTOR verdict, emitted on the enterprise build once a bundle
/// is installed. The enterprise ceiling rises 21 → **22**; the community ceiling
/// stays at **19** (the phase-2b bundle floor is moat-stripped). The `#[cfg]` split
/// carries that edition delta.
#[cfg(feature = "enterprise")]
const DOCTOR_SCHEMA_VERSION: u32 = 22;
#[cfg(not(feature = "enterprise"))]
const DOCTOR_SCHEMA_VERSION: u32 = 19;

/// M2 T2.5 / M3a — trust-plane grade for the `csq doctor` schema, derived
/// from the chain's `AuditHealth` and the M3a `verification_levels_populated`
/// signal. **Enterprise edition only**; the community build compiles this to
/// `None` so the field is omitted.
#[cfg(feature = "enterprise")]
fn doctor_trust_plane_grade(
    health: &csq_core::audit::AuditHealth,
    verification_levels_populated: bool,
) -> Option<&'static str> {
    csq_core::audit::grade_for_audit_health(health, verification_levels_populated)
        .map(|g| g.as_str())
}

#[cfg(not(feature = "enterprise"))]
fn doctor_trust_plane_grade(
    _health: &csq_core::audit::AuditHealth,
    _verification_levels_populated: bool,
) -> Option<&'static str> {
    None
}

/// #787 b2b — project the policy-bundle floor keychain-anchor cross-check into
/// the doctor report. DETECTOR posture: reports the anchor status but never
/// changes the enforced (file) floor. Returns `None` (field omitted) until a
/// bundle has been installed. Enterprise-only; the community variant is always
/// `None` (the phase-2b bundle floor is moat-stripped).
#[cfg(feature = "enterprise")]
fn doctor_bundle_floor_anchor(base_dir: &Path) -> Option<String> {
    use csq_core::phase2b::bundle_floor::{
        bundle_floor_path, effective_bundle_floor, BundleFloorAnchor,
    };
    // Only meaningful once a bundle has been installed (floor file present).
    if !bundle_floor_path(base_dir).exists() {
        return None;
    }
    let chain_id = csq_core::audit::ChainState::load(base_dir)
        .ok()
        .map(|c| c.chain_id);
    match effective_bundle_floor(
        base_dir,
        csq_core::audit::AUDIT_SIGNING_SERVICE_NAME,
        chain_id.as_deref(),
    ) {
        Some((_floor, BundleFloorAnchor::Confirmed)) => Some("confirmed".to_string()),
        Some((_floor, BundleFloorAnchor::Unavailable)) => Some("unavailable".to_string()),
        Some((_floor, BundleFloorAnchor::Mismatch { file, keychain })) => Some(format!(
            "mismatch (file floor {file}, keychain anchor {keychain})"
        )),
        // Floor file exists (gated above) but is unreadable/unparseable — the
        // gate fails closed; surface it as a distinct doctor finding.
        None => Some("corrupt".to_string()),
    }
}

#[cfg(not(feature = "enterprise"))]
fn doctor_bundle_floor_anchor(_base_dir: &Path) -> Option<String> {
    None
}

fn build_report(base_dir: &Path) -> DoctorReport {
    // Compute authenticated slot counts once — used both for suppression
    // and for the stale-slot rendering variant.
    let claude_auth_slots = count_authenticated_slots(base_dir, SurfaceCli::Claude);
    let codex_auth_slots = count_authenticated_slots(base_dir, SurfaceCli::Codex);
    let gemini_auth_slots = count_authenticated_slots(base_dir, SurfaceCli::Gemini);

    let claude_code = if claude_auth_slots > 0 {
        Some(build_surface_info(SurfaceCli::Claude))
    } else {
        None
    };
    let codex_cli = if codex_auth_slots > 0 {
        Some(build_surface_info(SurfaceCli::Codex))
    } else {
        None
    };
    let gemini_cli = if gemini_auth_slots > 0 {
        Some(build_surface_info(SurfaceCli::Gemini))
    } else {
        None
    };

    // M1-8: audit the A++ identity-store coexistence shape.
    // Non-fatal: if the lock cannot be acquired, identity_store is None.
    let identity_store = match audit_coexistence(base_dir) {
        Ok(report) => Some(report),
        Err(e) => {
            tracing::warn!(error_kind = "identity_store_audit_failed", %e, "audit_coexistence failed — identity_store will be null in JSON output");
            None
        }
    };

    // an internal journal entry (§FD #2 of 0041): top-level phase-4-incomplete alarm.
    // Read-only walk of profiles.json::by_slot × three identity files;
    // populated only when at least one (slot, file) is missing — empty
    // status omits the field per its `skip_serializing_if`.
    let phase4_incomplete = build_phase4_incomplete_alarm(base_dir);
    // Run verify_chain once; derive gaps list, health classification, the
    // keychain integrity-anchor verdict, the roster floor anchor verdict, and
    // the M3a verification_levels_populated signal.
    let (
        audit_historical_key_gaps,
        audit_chain_state,
        audit_keychain_anchor,
        audit_roster_floor_anchor,
        audit_verification_levels_populated,
        audit_level_summary_raw,
    ) = check_audit_chain(base_dir);

    // M3a: compute the trust-plane grade once, then attach the per-level
    // disclosure ONLY when the grade is surfaced — a CONFORMANT grade must never
    // appear bare (honest-host boundary; redteam R1 HIGH, 2026-06-17). In the
    // community build the grade is always None, so the summary is omitted too.
    let audit_trust_plane_grade =
        doctor_trust_plane_grade(&audit_chain_state, audit_verification_levels_populated);
    let audit_verification_level_summary = audit_trust_plane_grade.and(audit_level_summary_raw);

    DoctorReport {
        schema_version: DOCTOR_SCHEMA_VERSION,
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: check_platform(),
        claude_code,
        codex_cli,
        gemini_cli,
        claude_auth_slots,
        codex_auth_slots,
        gemini_auth_slots,
        gemini_unreadable_slots: gemini_unreadable_slots(base_dir),
        codex_wrong_variant_slots: codex_wrong_variant_slots(base_dir),
        js_runtime: check_js_runtime(),
        settings: check_settings(),
        daemon: check_daemon(base_dir),
        accounts: check_accounts(base_dir),
        broker_failed: check_broker_failed(base_dir),
        mixed_state_slots: check_mixed_state_slots(base_dir),
        terminals: check_terminals(base_dir),
        resurrections: check_resurrections(base_dir),
        host_isolation: check_host_isolation(base_dir),
        cache_sweeper: check_cache_sweeper(base_dir),
        identity_store,
        legacy_compat_state: check_legacy_compat_state(base_dir),
        phase4_incomplete,
        unrecoverable_label_relocations: check_unrecoverable_label_relocations(base_dir),
        pass0_skipped_slots: check_pass0_skipped_slots(base_dir),
        signing_key: check_signing_key_m04(base_dir),
        audit_sink: check_audit_sink_m07(base_dir),
        audit_orphan_intents: check_audit_orphan_intents_m13(base_dir),
        audit_historical_key_gaps,
        audit_trust_plane_grade,
        audit_verification_level_summary,
        audit_chain_state,
        audit_keychain_anchor,
        audit_roster_floor_anchor,
        audit_bundle_floor_anchor: doctor_bundle_floor_anchor(base_dir),
        seam_quarantine_count: check_seam_custody_count(base_dir, ".quarantine"),
        seam_pending_provenance_count: check_seam_custody_count(
            base_dir,
            csq_core::audit::outbox_paths::SEAM_PROVENANCE_SUBDIR,
        ),
        seam_held_predecessor_count: check_seam_held_predecessor_count(base_dir),
        seam_registry_status: check_seam_registry_status(base_dir),
        seam_pending_backlog_note: check_seam_pending_backlog(base_dir),
        seam_capture_conformance: check_seam_capture_conformance(base_dir),
        mcp_partial_coverage: check_mcp_partial_coverage(base_dir),
        mcp_gate_outbox_backlog: check_mcp_gate_outbox_backlog(base_dir),
        custodian_identity_canary: check_custodian_identity_canary(base_dir),
    }
}

/// CU4 (spec 10 §10.8.3): build the MCP partial-coverage advisory. Detects
/// CLI-bound MCP servers under the user's real `$HOME` (the CLIs read their
/// native config there, independent of `CSQ_BASE_DIR`); `warn` additionally
/// requires the capability layer to be enabled.
fn check_mcp_partial_coverage(base_dir: &Path) -> McpPartialCoverage {
    use csq_core::capability_layer::mcp_coverage::detect_cli_bound_mcp_servers;
    use csq_core::capability_layer::settings::load_capability_layer_toggles;

    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let sources = home
        .as_deref()
        .map(detect_cli_bound_mcp_servers)
        .unwrap_or_default();
    let cli_sources: Vec<String> = sources.iter().map(|s| s.as_str().to_string()).collect();
    let enabled = !load_capability_layer_toggles(base_dir).is_layer_fully_disabled();
    McpPartialCoverage {
        warn: !cli_sources.is_empty() && enabled,
        cli_sources,
    }
}

/// Count files in a seam custody subdirectory under `csq-runs/`.
///
/// Returns `None` when the directory does not exist (healthy initial state).
/// Returns `Some(n)` when the directory exists, where `n` is the number of
/// `.json` files present (0 = directory exists but is empty after a drain).
///
/// No host paths are surfaced — only the count (no PII, no path leakage).
fn check_seam_custody_count(base_dir: &Path, subdir: &str) -> Option<u32> {
    let dir = base_dir.join("csq-runs").join(subdir);
    if !dir.exists() {
        return None;
    }
    let count = std::fs::read_dir(&dir)
        .ok()?
        .flatten()
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "json")
                .unwrap_or(false)
        })
        .count();
    Some(count as u32)
}

/// Count events held under `.pending/provenance-ordered/` awaiting an
/// intra-source predecessor (M20, F-SEAM-09). The held store is a per-surface
/// tree, so this delegates to `reconcile::list_held` (which walks every
/// surface). `None` when the held store does not exist (healthy default).
/// No host paths surfaced — only the count.
fn check_seam_held_predecessor_count(base_dir: &Path) -> Option<u32> {
    let csq_runs = base_dir.join("csq-runs");
    let root = csq_runs.join(".pending").join("provenance-ordered");
    if !root.exists() {
        return None;
    }
    // `now_unix` only affects the per-event age field, not the count.
    let count = csq_core::audit::seam::reconcile::list_held(&csq_runs, 0).len();
    Some(count as u32)
}

/// Attempt to load the surface registry and return its status as a fixed-vocab tag.
///
/// Returns `"ok"` when the file is absent (healthy default) or parses
/// successfully. Returns `"seam_registry_invalid"` when the file is present
/// but fails to load — operator should inspect/repair the file.
fn check_seam_registry_status(base_dir: &Path) -> String {
    use csq_core::audit::seam::registry::SurfaceRegistry;
    match SurfaceRegistry::load(base_dir) {
        Ok(_) => "ok".to_string(),
        Err(_) => "seam_registry_invalid".to_string(),
    }
}

/// M6 #914: inspect the MCP-gate attestation outbox for a stuck backlog.
///
/// Reads `<base>/csq-runs/.pending-mcp-gate/*.json` directly (independent of the
/// daemon — `csq doctor` runs whether or not the daemon is up) and reports the
/// queued count + the OLDEST file's age + the daemon-aware `state` (M6 #909 shard D,
/// via [`classify_mcp_gate_backlog`]). WARNs (`state == Stuck`) when the daemon is
/// draining yet the oldest file persists past
/// [`MCP_GATE_OUTBOX_STUCK_AGE_WHILE_DRAINING_SECS`], or the count exceeds the soft
/// cap ([`MCP_GATE_OUTBOX_STUCK_COUNT`]) — either signals an enforced-but-unrecorded
/// compliance backlog the drain cannot land (chain not appendable).
///
/// Returns `None` when the outbox directory is absent OR empty — the healthy
/// steady state, and ALWAYS the case in the community edition (the proxy
/// producer is enterprise-only). No host paths are surfaced (only count + age),
/// so this is exempt from the operator-surface path-leak class. The directory is
/// resolved by `csq_core::audit::outbox_paths::mcp_gate_outbox_dir` — the single
/// shared full-path helper that both this (community) reader and the
/// enterprise-gated writer (`mcp_gate_outbox::outbox_dir`) call, so neither the
/// subdir name nor the `csq-runs/` prefix can drift between them. Keeps this
/// check edition-agnostic (the community build reads a dir an enterprise
/// `csq-ee` wrote under a shared `$HOME`); parallels the `SEAM_PROVENANCE_SUBDIR`
/// custody count.
fn check_mcp_gate_outbox_backlog(base_dir: &Path) -> Option<McpGateOutboxBacklog> {
    let dir = csq_core::audit::outbox_paths::mcp_gate_outbox_dir(base_dir);
    // Absent dir → None (never written in community; healthy when daemon is up).
    let entries = std::fs::read_dir(&dir).ok()?;
    let now = std::time::SystemTime::now();
    let mut pending_count: u32 = 0;
    let mut oldest_age_secs: Option<u64> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        // Same effective filter as the drain (regular `.json` file, no `.tmp.`
        // in-flight). The drain excludes directories via `!path.is_dir()`; here we
        // require a regular file via `entry.metadata().is_file()` below, which ALSO
        // excludes a symlink — stricter, but the producer (`write_pending`) only
        // ever emits regular files via atomic rename, so the two agree on every
        // real outbox file.
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let fname = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if fname.contains(".tmp.") {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) if m.is_file() => m,
            _ => continue,
        };
        pending_count += 1;
        if let Ok(modified) = meta.modified() {
            if let Ok(age) = now.duration_since(modified) {
                let secs = age.as_secs();
                // Track the OLDEST (largest age) file.
                oldest_age_secs = Some(oldest_age_secs.map_or(secs, |o| o.max(secs)));
            }
        }
    }
    if pending_count == 0 {
        // Dir exists but empty (drained clean) → nothing to report.
        return None;
    }
    // M6 #909 shard D: read the last-drain stamp (shard B) as the daemon-liveness +
    // drain-activity signal, and classify. `now_secs` shares the `now` used for the
    // per-file mtime ages above.
    let now_secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last_drain_secs = csq_core::audit::outbox_paths::read_outbox_drain_stamp(base_dir);
    let last_drain_age_secs = last_drain_secs.map(|s| now_secs.saturating_sub(s));
    let state =
        classify_mcp_gate_backlog(pending_count, oldest_age_secs, last_drain_secs, now_secs);
    Some(McpGateOutboxBacklog {
        pending_count,
        oldest_age_secs,
        state,
        last_drain_age_secs,
        warn: matches!(state, McpGateBacklogState::Stuck),
    })
}

/// M6 #909 shard D: the daemon-aware disposition of a non-empty mcp-gate outbox
/// backlog, replacing #914's fixed-6h wall-clock. Serialized in the doctor JSON
/// (v21). Only `Stuck` is operator-actionable (`warn`); the other two are info.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum McpGateBacklogState {
    /// Operator-actionable. Either the count cap is exceeded, OR the daemon is
    /// actively draining (a fresh drain stamp) yet the backlog persists past a few
    /// drain cycles — the chain is not appendable (`csq audit verify` /
    /// `csq audit init`).
    Stuck,
    /// The daemon is actively draining and the backlog is young — a benign
    /// transient that will drain within a cycle or two. Info.
    Draining,
    /// No fresh drain stamp — the daemon is down (or its drain loop is not running),
    /// so the backlog is merely PENDING until the daemon resumes (it drains on the
    /// next start / tick). Info: no false STUCK alarm during a maintenance window.
    /// The daemon-not-running condition is surfaced separately by the daemon-status
    /// check, and the count cap still escalates to `Stuck` if the backlog grows
    /// unbounded behind a down daemon (`classify_mcp_gate_backlog`).
    PendingDaemonDown,
}

/// Pure daemon-aware backlog classifier (M6 #909 shard D), replacing #914's fixed-6h
/// `mcp_gate_outbox_is_stuck`. The `last_drain_secs` stamp (shard B) is the
/// daemon-liveness + drain-activity signal. Disposition:
///
/// - count > cap → `Stuck` ALWAYS (a large backlog is a problem even behind a down
///   daemon — the one axis that ignores the stamp, so an unbounded pending queue is
///   never silently tolerated).
/// - fresh stamp (daemon draining) + oldest file older than a few drain cycles →
///   `Stuck` (chain not appendable); fresh stamp + young backlog → `Draining`.
/// - stale/absent stamp (daemon down / drain not running) → `PendingDaemonDown`.
///
/// `now_secs` and `last_drain_secs` are Unix epoch seconds; extracted pure so the
/// thresholds are unit-testable without a live daemon or backdated mtimes. Uses
/// `saturating_sub` so a stamp in the future (clock skew) reads as age 0 (fresh),
/// never a giant age — a skewed stamp cannot manufacture a false `Stuck`/`Pending`.
fn classify_mcp_gate_backlog(
    pending_count: u32,
    oldest_age_secs: Option<u64>,
    last_drain_secs: Option<u64>,
    now_secs: u64,
) -> McpGateBacklogState {
    if pending_count > MCP_GATE_OUTBOX_STUCK_COUNT {
        return McpGateBacklogState::Stuck;
    }
    let draining = last_drain_secs
        .is_some_and(|s| now_secs.saturating_sub(s) <= MCP_GATE_DRAIN_STAMP_FRESH_SECS);
    if draining {
        if oldest_age_secs.is_some_and(|a| a > MCP_GATE_OUTBOX_STUCK_AGE_WHILE_DRAINING_SECS) {
            McpGateBacklogState::Stuck
        } else {
            McpGateBacklogState::Draining
        }
    } else {
        McpGateBacklogState::PendingDaemonDown
    }
}

/// Return `Some("seam_pending_backlog_high")` when the pending-provenance
/// directory has more than 1 000 files, `None` otherwise.
///
/// The 1 000-file threshold is the soft warning cap from quarantine.rs
/// (`CUSTODY_CAP_FILES`). The doctor note complements the daemon's WARN log
/// with a visible signal at every `csq doctor` invocation.
fn check_seam_pending_backlog(base_dir: &Path) -> Option<String> {
    let count = check_seam_custody_count(
        base_dir,
        csq_core::audit::outbox_paths::SEAM_PROVENANCE_SUBDIR,
    )?;
    if count > 1_000 {
        Some("seam_pending_backlog_high".to_string())
    } else {
        None
    }
}

/// M19: check provenance capture conformance against `required-hooks.json`.
///
/// Returns a typed `SeamConformanceState` with four distinct outcomes (Finding D):
/// - `NotConfigured`: file absent OR empty `[]` — no policy enforced.
/// - `PolicyUnreadable`: file present but unreadable or unparseable — operator-visible ⚠.
/// - `Conformant`: all required surfaces are Wired.
/// - `Drift { drift }`: one or more required surfaces are Unwired.
///
/// All four states are ALWAYS returned (no silent fallback to None).
/// `required-hooks.json` empty array `[]` is treated as NotConfigured — documented
/// in spec §12.20 (Finding D: "empty = no requirement = NotConfigured").
fn check_seam_capture_conformance(base_dir: &Path) -> SeamConformanceState {
    use csq_core::audit::seam::build_capture_matrix;
    use csq_core::audit::types::CaptureState;

    // LOW-2: cap required-hooks.json reads at 64 KiB.
    // The file is a small JSON array of surface-id strings; any legitimate policy
    // is well under 1 KiB. A cap defends against same-UID DoS via a large planted
    // file. Oversized → PolicyUnreadable (operator-visible ⚠).
    const REQUIRED_HOOKS_READ_CAP: u64 = 64 * 1024; // 64 KiB

    let required_path = base_dir.join("audit").join("required-hooks.json");
    let required_bytes = match std::fs::File::open(&required_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Absent file = no policy configured (healthy default).
            return SeamConformanceState::NotConfigured;
        }
        Err(e) => {
            // File exists but could not be opened — operator-visible error.
            tracing::warn!(
                error_kind = "required_hooks_read_error",
                "M19: could not open required-hooks.json: {e}"
            );
            return SeamConformanceState::PolicyUnreadable {
                reason: "could not read required-hooks.json".to_string(),
            };
        }
        Ok(file) => {
            use std::io::Read as _;
            let mut buf = Vec::new();
            // read cap+1 to detect oversized files without reading the entire thing.
            match file.take(REQUIRED_HOOKS_READ_CAP + 1).read_to_end(&mut buf) {
                Err(e) => {
                    tracing::warn!(
                        error_kind = "required_hooks_read_error",
                        "M19: could not read required-hooks.json: {e}"
                    );
                    return SeamConformanceState::PolicyUnreadable {
                        reason: "could not read required-hooks.json".to_string(),
                    };
                }
                Ok(_) if buf.len() > REQUIRED_HOOKS_READ_CAP as usize => {
                    tracing::warn!(
                        error_kind = "required_hooks_too_large",
                        "M19: required-hooks.json exceeds size cap ({} bytes); treating as unreadable",
                        REQUIRED_HOOKS_READ_CAP
                    );
                    return SeamConformanceState::PolicyUnreadable {
                        reason: "required-hooks.json too large".to_string(),
                    };
                }
                Ok(_) => buf,
            }
        }
    };
    let required: Vec<String> = match serde_json::from_slice(&required_bytes) {
        Ok(v) => v,
        Err(_) => {
            tracing::warn!(
                error_kind = "required_hooks_parse_error",
                "M19: required-hooks.json is not a JSON array of strings"
            );
            return SeamConformanceState::PolicyUnreadable {
                reason: "required-hooks.json is not a JSON array of strings".to_string(),
            };
        }
    };

    // Empty array = "no surfaces required" = NotConfigured.
    // Documented in spec §12.20: `[]` is treated as NotConfigured.
    if required.is_empty() {
        return SeamConformanceState::NotConfigured;
    }

    // Build the current capture matrix.
    // Returns PolicyUnreadable if the surface-registry is malformed;
    // an absent registry falls back to cc/codex/gemini defaults internally.
    let matrix = match build_capture_matrix(base_dir) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(
                error_kind = "capture_matrix_build_error",
                "M19: could not build capture matrix for conformance check: {e}"
            );
            return SeamConformanceState::PolicyUnreadable {
                reason: "could not build capture matrix".to_string(),
            };
        }
    };

    // Collect surfaces that are required but Unwired (or absent from matrix).
    let mut drift = Vec::new();
    for required_surface in &required {
        let is_wired = matrix
            .surfaces
            .iter()
            .any(|s| s.surface == *required_surface && s.capture == CaptureState::Wired);
        if !is_wired {
            drift.push(required_surface.clone());
        }
    }
    drift.sort(); // deterministic output

    if drift.is_empty() {
        SeamConformanceState::Conformant
    } else {
        SeamConformanceState::Drift { drift }
    }
}

/// an internal journal entry: build the optional phase-4-incomplete alarm by calling
/// `csq_core::daemon::startup_reconciler::phase4_gate_status`. Returns
/// `Some` only when at least one UUID-mapped slot has a missing identity
/// file; `None` is the healthy state (no alarm needed).
fn build_phase4_incomplete_alarm(base_dir: &Path) -> Option<Phase4IncompleteAlarm> {
    use csq_core::daemon::startup_reconciler::phase4_gate_status;
    let status = phase4_gate_status(base_dir);
    if !status.is_incomplete() {
        return None;
    }
    Some(Phase4IncompleteAlarm {
        affected_slot_count: status.affected_slot_count(),
        missing_file_count: status.missing.len(),
    })
}

/// RN1-D5 (WBS): build the `unrecoverable_label_relocations` field.
///
/// Returns a non-empty Vec only when the `label-channel-migrated` sentinel
/// exists (meaning the relocation pass has already run) AND at least one slot
/// has `accounts[N].email` (a user rename label) with no `by_slot[N]` UUID.
///
/// Pre-sentinel: returns `[]` — the warning fires only after migration has been
/// attempted; pre-migration the field is absent from JSON output.
///
/// **No side effects.** Read-only filesystem + JSON access.
fn check_unrecoverable_label_relocations(base_dir: &Path) -> Vec<UnrecoverableSlotJson> {
    // Only surface the warning after the one-shot migration has run.
    let sentinel = label_relocation_sentinel_path(base_dir);
    if !sentinel.exists() {
        return Vec::new();
    }
    unrecoverable_label_slots(base_dir)
        .into_iter()
        .map(|s| UnrecoverableSlotJson {
            slot: s.slot,
            accounts_email: s.accounts_email,
        })
        .collect()
}

/// RN1-D R1 (post-RN1 polish): build the `pass0_skipped_slots` field.
///
/// Returns a non-empty Vec only when the `store-version` sentinel exists
/// (Pass-0 has run on this host) AND at least one Anthropic slot has a
/// credentials file whose `oauthAccount.emailAddress` is missing/empty
/// (`AccountInfo.oauth_email == None`) AND has no `by_slot[N]` UUID. That
/// is the exact set Pass-0 would re-skip if the sentinel were deleted —
/// matching the warn-log path at `csq-core/src/daemon/identity_mint.rs:188-195`.
///
/// Pre-sentinel: returns `[]` — Pass-0 has not run on this host yet; a
/// "skip" framing would be premature noise.
///
/// Slots whose `by_slot[N]` IS present are excluded — those have already
/// been minted (most commonly via `mint_for_login` after the operator
/// re-OAuth'd) and are no longer in an operator-actionable "skipped"
/// state.
///
/// **No side effects.** Read-only filesystem + JSON access.
fn check_pass0_skipped_slots(base_dir: &Path) -> Vec<Pass0SkippedSlot> {
    use csq_core::accounts::identity_store::store_version_path;
    use csq_core::accounts::profiles::resolve_slot_to_uuid;
    if !store_version_path(base_dir).exists() {
        return Vec::new();
    }
    discovery::discover_anthropic(base_dir)
        .into_iter()
        .filter(|info| {
            info.oauth_email.is_none() && resolve_slot_to_uuid(base_dir, info.id).is_none()
        })
        .map(|info| Pass0SkippedSlot {
            slot: info.id,
            reason: "oauth_email_unresolved",
        })
        .collect()
}

/// M04 (an internal workspace): check whether the Ed25519 audit-trail
/// signing key is present in the OS keychain.
///
/// Uses the production service name `csq-audit-signing`. Returns
/// [`SigningKeyStatus::Absent`] when `chain.json` is missing or the key is
/// not in the keychain — neither case blocks doctor output. Failure to load
/// chain.json is treated as Absent (the key was never initialised).
fn check_signing_key_m04(base_dir: &Path) -> SigningKeyStatus {
    use csq_core::audit::{
        check_signing_key, SigningKeyStatus as CoreStatus, AUDIT_SIGNING_SERVICE_NAME,
    };
    match check_signing_key(base_dir, AUDIT_SIGNING_SERVICE_NAME) {
        CoreStatus::Present { .. } => SigningKeyStatus::Present,
        CoreStatus::Absent => SigningKeyStatus::Absent,
        CoreStatus::Inaccessible => SigningKeyStatus::Inaccessible,
    }
}

/// M13 (an internal workspace): F-LEDGER-02 orphan-intent scan.
///
/// Returns every pre-op INTENT record on the committed chain with no matching
/// OUTCOME (a crash/kill between the intent drain and the outcome append). A
/// scan error (I/O, or a chain line that does not parse) is non-fatal: it is
/// logged and the field is left empty so doctor still reports the rest — the
/// chain verifier (`csq audit verify`) is the authority on corruption.
fn check_audit_orphan_intents_m13(base_dir: &Path) -> Vec<csq_core::audit::OrphanIntent> {
    match csq_core::audit::scan_orphan_intents(base_dir) {
        Ok(orphans) => orphans,
        Err(e) => {
            tracing::warn!(
                error_kind = "audit_orphan_intent_scan_failed",
                %e,
                "scan_orphan_intents failed — audit_orphan_intents omitted from doctor output"
            );
            Vec::new()
        }
    }
}

/// Return shape of [`check_audit_chain`]: historical-key gaps, the chain-health
/// classification, the keychain + roster-floor anchor verdicts, the M3a
/// `verification_levels_populated` signal, and the M3a per-level disclosure map
/// (`Some` only in the enterprise build; community → `None` → the doctor field
/// is omitted, surfaced beside `audit_trust_plane_grade` so a CONFORMANT grade
/// is never shown bare — honest-host boundary, redteam R1 HIGH 2026-06-17).
/// Factored into an alias to satisfy `clippy::type_complexity`.
type AuditChainCheck = (
    Vec<AuditHistoricalKeyGap>,
    csq_core::audit::AuditHealth,
    csq_core::audit::KeychainAnchorStatus,
    Option<csq_core::audit::RosterFloorAnchorStatus>,
    bool,
    Option<std::collections::BTreeMap<String, u64>>,
);

/// Runs a lightweight `verify_chain` scan (tail 1,000 records) and returns
/// any historical signing-key gaps found.
///
/// Run `verify_chain` once and return both the historical-key gap list and
/// the classified `AuditHealth` — avoids running the verifier twice.
///
/// `AuditHealth` mirrors the daemon's startup classification:
/// - `Verified` — chain-linking clean, all reachable sigs verified. Also
///   returned when no chain exists yet (`verify_chain` returns `Ok(default)`
///   for an absent `csq-runs/` directory).
/// - `Degraded` — chain-linking verified; one or more historical keys absent.
/// - `Broken`   — `verify_chain` returned a fatal `LedgerError`.
/// - `Unknown`  — reachable here when `verify_chain` returns
///   `LedgerError::KeychainUnavailable` (transient keychain access error;
///   `from_verify_result` maps it to `Unknown`); also daemon-startup-only on a
///   verify timeout/panic. The `.chain-broken` sentinel is left unchanged.
fn check_audit_chain(base_dir: &Path) -> AuditChainCheck {
    use csq_core::audit::{verify_chain, AuditHealth, VerifyConfig, AUDIT_SIGNING_SERVICE_NAME};
    // Align to CSQ_AUDIT_VERIFY_LIMIT (daemon default: 10_000) so doctor does
    // not under-report gaps older than 1_000 records. (FIX-2b)
    let record_limit = std::env::var("CSQ_AUDIT_VERIFY_LIMIT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(10_000);
    let cfg = VerifyConfig {
        record_limit,
        keychain_service: AUDIT_SIGNING_SERVICE_NAME.to_string(),
    };

    // Remember whether chain.json existed BEFORE calling verify_chain.
    // verify_chain returns Ok(default) for a genuinely-absent chain, so we
    // use the existence flag to suppress the floor-anchor field in doctor
    // output when no chain has ever been initialised (no roster possible).
    let chain_json_exists = base_dir.join("csq-runs").join("chain.json").exists();

    let result = verify_chain(base_dir, &cfg, None);

    // FIX-1: update the cross-process .chain-broken sentinel. `verify_chain`
    // returns Ok(default) for a genuinely-absent chain (no csq-runs/
    // directory), so Ok always means at least "no corruption found".
    // All Err paths are real failures (incl. Io = corruption or permission
    // error) and set the sentinel.
    // FIX-1/FIX-2: set or clear the .chain-broken sentinel. `from_verify_result`
    // CAN yield Unknown (when the chain returns LedgerError::KeychainUnavailable,
    // a transient keychain access error) — the Unknown arm deliberately leaves
    // the sentinel UNCHANGED (a transient condition must not produce a durable
    // write-lockout). Do NOT collapse it to unreachable!().
    let health = AuditHealth::from_verify_result(&result);
    match &health {
        AuditHealth::Verified | AuditHealth::Degraded { .. } => {
            csq_core::audit::clear_chain_broken(base_dir);
        }
        AuditHealth::Broken { error_kind, .. } => {
            csq_core::audit::set_chain_broken(base_dir, error_kind);
        }
        AuditHealth::Unknown { .. } => {
            // Transient (KeychainUnavailable): leave the sentinel unchanged.
        }
    }

    // M3 §10.5 (W2a): reconcile the born-canonical EATP attestation chain's own
    // `.chain-broken` sentinel (independent fault domain; does not affect the
    // op-chain health reported by `csq doctor`). Inert until the EATP chain
    // exists (`verify_chain_in` returns Ok(default) for an absent `eatp-runs/`).
    {
        use csq_core::audit::ChainKind;
        let eatp = csq_core::audit::verify_chain_in(base_dir, &cfg, None, ChainKind::Eatp);
        csq_core::audit::reconcile_chain_sentinel(base_dir, ChainKind::Eatp.runs_subdir(), &eatp);
    }

    use csq_core::audit::{KeychainAnchorStatus, LedgerError};
    match result {
        Ok(summary) => {
            let gaps: Vec<AuditHistoricalKeyGap> = summary
                .historical_key_gaps
                .iter()
                .map(|g| AuditHistoricalKeyGap {
                    key_id: g.key_id.clone(),
                    first_seq: g.first_seq,
                    last_seq: g.last_seq,
                    count: g.count,
                })
                .collect();
            // Only emit the floor anchor when chain.json existed AND carries a
            // roster_version_floor (i.e. a roster has actually been installed).
            // An initialized-but-rosterless install (chain.json present, floor
            // None) and a no-chain install both omit the field — a Confirmed
            // default would be misleading (nothing to confirm against).
            let floor_anchor = (chain_json_exists && summary.roster_floor_present)
                .then_some(summary.roster_floor_anchor);
            let vl_populated = summary.verification_levels_populated;
            // M3a: the per-level disclosure map. `verification_level_summary` is
            // an enterprise-only field on VerifySummary, so source it under cfg;
            // community returns None → the doctor field is omitted.
            #[cfg(feature = "enterprise")]
            let vl_summary = Some(summary.verification_level_summary.clone());
            #[cfg(not(feature = "enterprise"))]
            let vl_summary = None;
            (
                gaps,
                health,
                summary.keychain_anchor,
                floor_anchor,
                vl_populated,
                vl_summary,
            )
        }
        // KeychainUnavailable is the transient case where the keychain genuinely
        // was NOT read → the truthful anchor verdict is Unconfirmed (not a
        // self-contradictory "chain unverified + anchor confirmed"). For a
        // genuinely-fatal Broken error there is no anchor verdict; default to
        // Confirmed (N/A) — the Broken health line carries the failure.
        Err(LedgerError::KeychainUnavailable { .. }) => (
            Vec::new(),
            health,
            KeychainAnchorStatus::Unconfirmed,
            None,
            false,
            None,
        ),
        Err(_) => (
            Vec::new(),
            health,
            KeychainAnchorStatus::Confirmed,
            None,
            false,
            None,
        ),
    }
}

/// M07 (an internal workspace): reads `audit-sink.json` and the on-disk
/// anchor state to surface the active-sink diagnostics.
///
/// Returns `None` when the sink is `"none"` (local-only default) so the
/// `audit_sink` field is absent from the JSON output when not relevant.
fn check_audit_sink_m07(base_dir: &Path) -> Option<AuditSinkDoctorInfo> {
    use csq_core::audit::{AuditSinkConfig, SinkDoctorSnapshot};
    let cfg = AuditSinkConfig::load(base_dir).unwrap_or_default();
    if cfg.sink == "none" {
        // H3: if sink is "none" but we have evidence of prior anchoring, warn.
        // Evidence: any `anchor-state-<name>.json` file with a `last_anchor_ts`.
        let prior = detect_prior_anchor_activity(base_dir);
        if let Some((prior_sink, prior_ts)) = prior {
            // Surface a synthetic "disabled" entry so the doctor text renderer
            // shows the warning row instead of silently omitting the field.
            return Some(AuditSinkDoctorInfo {
                active_sink: format!("none (was: {prior_sink} — witness disabled)"),
                last_anchor_ts: Some(prior_ts),
                pending_count: 0,
                replication_drift_count: 0,
            });
        }
        // Truly never had a sink — omit the field per workspace-owner decision §5.
        return None;
    }
    let snap = SinkDoctorSnapshot::load(base_dir, &cfg.sink);
    Some(AuditSinkDoctorInfo {
        active_sink: snap.active_sink,
        last_anchor_ts: snap.last_anchor_ts,
        pending_count: snap.pending_count,
        replication_drift_count: snap.replication_drift_count,
    })
}

/// H3 + MED-1: detects prior anchor activity when sink is now "none".
///
/// **Two-layer detection** per `account-terminal-separation.md` MUST Rule 1
/// (source from the authoritative channel):
///
/// 1. **Sidecar layer**: scan `base_dir` for any `anchor-state-<name>.json`
///    with a non-null `last_anchor_ts`. Fast, attacker-writable (same-UID).
/// 2. **Chain layer (MED-1)**: if the sidecar was deleted, scan the committed
///    chain for any `ReplicationAck` / `ReplicationFailed` record. The chain
///    is tamper-evident — erasing an anchor-outcome record breaks the hash
///    chain that `verify_chain` (run at daemon pre-bind) rejects. This layer
///    fires even when all sidecars are absent.
///
/// Returns `(sink_name, last_anchor_ts)` from the sidecar when available, or
/// `(sink_name_from_chain, "<chain-scan>")` as the timestamp sentinel when
/// only the chain evidence is present (the chain record has no `last_anchor_ts`
/// equivalent, so we use the sentinel string to indicate detection origin).
fn detect_prior_anchor_activity(base_dir: &Path) -> Option<(String, String)> {
    // Layer 1: sidecar scan (fast path).
    let sidecar = detect_prior_anchor_via_sidecar(base_dir);
    if sidecar.is_some() {
        return sidecar;
    }

    // Layer 2: chain scan — authoritative, tamper-evident (MED-1 fix).
    // Cite: account-terminal-separation.md MUST Rule 1 — "source from the
    // authoritative channel."
    if let Some(sink_name) = csq_core::audit::scan_chain_for_anchor_outcome(base_dir) {
        return Some((sink_name, "<chain-scan>".to_string()));
    }

    None
}

/// Inner sidecar scanner extracted from the original `detect_prior_anchor_activity`.
/// Scans `base_dir` for any `anchor-state-<name>.json` with a non-null
/// `last_anchor_ts`. Returns `(sink_name, ts)` on first match.
fn detect_prior_anchor_via_sidecar(base_dir: &Path) -> Option<(String, String)> {
    let entries = std::fs::read_dir(base_dir).ok()?;
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with("anchor-state-") || !name_str.ends_with(".json") {
            continue;
        }
        let sink_name = name_str
            .strip_prefix("anchor-state-")
            .and_then(|s| s.strip_suffix(".json"))
            .unwrap_or("")
            .to_string();
        if sink_name.is_empty() || sink_name == "none" {
            continue;
        }
        let raw = match std::fs::read_to_string(entry.path()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let v: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(ts) = v.get("last_anchor_ts").and_then(|t| t.as_str()) {
            return Some((sink_name, ts.to_string()));
        }
    }
    None
}

/// M4-11 (an internal ticket Phase 4 release N): assemble the `legacy_compat_state`
/// field by surveying compat-bridge surfaces on disk.
///
/// Four spec/13 §9 enumeration kinds are surveyed independently. Any
/// detected footprint surfaces as a [`LegacyCompatEntry`]; the empty
/// `Vec` is the canonical post-Phase-4 final state.
///
/// **No side effects.** Read-only filesystem traversal — no daemon IPC,
/// no `unique_tmp_path`, no credential reads (only marker + directory
/// structure inspection). Safe to call from `csq doctor` without holding
/// any lock.
///
/// **Failure tolerance.** Each kind's detector returns an empty Vec on
/// filesystem error rather than propagating — doctor is a diagnostic
/// tool and MUST emit a report even when individual checks fail. The
/// `identity_store` field already encodes the load-bearing "is the
/// layout readable at all" signal; this field is informational.
fn check_legacy_compat_state(base_dir: &Path) -> Vec<LegacyCompatEntry> {
    let mut entries: Vec<LegacyCompatEntry> = Vec::new();

    // (1) v1_accounts_field_still_present
    if let Some(entry) = detect_v1_accounts_field(base_dir) {
        entries.push(entry);
    }

    // (2) legacy_canonical_credentials_file_still_written (Anthropic mirror)
    if let Some(entry) = detect_legacy_canonical_anthropic(base_dir) {
        entries.push(entry);
    }

    // (3) legacy_canonical_codex_credentials_file_still_written (Codex mirror)
    if let Some(entry) = detect_legacy_canonical_codex(base_dir) {
        entries.push(entry);
    }

    // (4) decimal_marker_content_present
    if let Some(entry) = detect_decimal_marker(base_dir) {
        entries.push(entry);
    }

    entries
}

/// M4-11 detector (kind 1): emit `v1_accounts_field_still_present` when
/// `profiles.json::accounts` carries at least one non-empty entry.
///
/// The v1 `accounts` field is empty-write in M4-9 production code paths
/// but two channels still populate it: (a) `update_email` (the desktop
/// `Rename account` flow — the SOLE remaining production writer per
/// M4-9), and (b) a v2.6.x downgrade re-save. Either way is a real
/// signal worth surfacing during the release N window.
///
/// Returns `None` on file-not-found / parse error — diagnostic
/// non-fatal fallback. The `identity_store` audit field carries the
/// load-bearing "profiles.json broken" signal.
fn detect_v1_accounts_field(base_dir: &Path) -> Option<LegacyCompatEntry> {
    let path = csq_core::accounts::profiles::profiles_path(base_dir);
    let profiles = csq_core::accounts::profiles::load(&path).ok()?;
    // M4-13: accounts field removed from ProfilesFile struct; read from
    // extra["accounts"] via the helper. If the key doesn't exist or is
    // empty, no legacy entries remain.
    let count = csq_core::accounts::profiles::legacy_accounts_email_map(&profiles).len();
    if count == 0 {
        return None;
    }
    let kind = LegacyCompatKind::V1AccountsFieldStillPresent;
    Some(LegacyCompatEntry {
        kind: kind.as_str().to_string(),
        evidence: format!(
            "profiles.json::accounts has {count} non-empty entr{} (release-N empty-write affordance)",
            if count == 1 { "y" } else { "ies" }
        ),
        scheduled_for: kind.scheduled_for(),
    })
}

/// M4-11 detector (kind 2): emit
/// `legacy_canonical_credentials_file_still_written` when at least one
/// `<base>/credentials/<N>.json` file exists. The pattern matches the
/// Anthropic-keyed canonical from `cred_file::canonical_path` — a
/// strict `<digits>.json` filename, excluding the `codex-` and
/// `gemini-` prefixes that share the directory.
///
/// Returns `None` when the `credentials/` directory is absent or
/// empty of matching entries.
fn detect_legacy_canonical_anthropic(base_dir: &Path) -> Option<LegacyCompatEntry> {
    let creds_dir = base_dir.join("credentials");
    let entries = std::fs::read_dir(&creds_dir).ok()?;
    let mut count: usize = 0;
    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        // Anthropic canonical: `<N>.json` where N is u16. Reject
        // `codex-<N>.json` and `gemini-<N>.json` via prefix; accept
        // only when stripping `.json` leaves a pure-decimal stem.
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        if stem.parse::<u16>().is_ok() {
            count += 1;
        }
    }
    if count == 0 {
        return None;
    }
    let kind = LegacyCompatKind::LegacyCanonicalCredentialsFileStillWritten;
    Some(LegacyCompatEntry {
        kind: kind.as_str().to_string(),
        evidence: format!(
            "credentials/<N>.json mirror written alongside identities/<UUID>/credentials.json ({count} file{})",
            if count == 1 { "" } else { "s" }
        ),
        scheduled_for: kind.scheduled_for(),
    })
}

/// M4-11 detector (kind 3): emit
/// `legacy_canonical_codex_credentials_file_still_written` when at
/// least one `<base>/credentials/codex-<N>.json` file exists.
///
/// Returns `None` when the `credentials/` directory is absent or
/// empty of matching entries.
fn detect_legacy_canonical_codex(base_dir: &Path) -> Option<LegacyCompatEntry> {
    let creds_dir = base_dir.join("credentials");
    let entries = std::fs::read_dir(&creds_dir).ok()?;
    let mut count: usize = 0;
    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let Some(rest) = name.strip_prefix("codex-") else {
            continue;
        };
        let Some(stem) = rest.strip_suffix(".json") else {
            continue;
        };
        if stem.parse::<u16>().is_ok() {
            count += 1;
        }
    }
    if count == 0 {
        return None;
    }
    let kind = LegacyCompatKind::LegacyCanonicalCodexCredentialsFileStillWritten;
    Some(LegacyCompatEntry {
        kind: kind.as_str().to_string(),
        evidence: format!(
            "credentials/codex-<N>.json mirror written alongside identities/<UUID>/credentials-codex.json ({count} file{})",
            if count == 1 { "" } else { "s" }
        ),
        scheduled_for: kind.scheduled_for(),
    })
}

/// M4-11 detector (kind 4): emit `decimal_marker_content_present` when
/// at least one `<base>/config-<N>/.csq-account` marker carries a decimal
/// slot id AND the slot has NO identity-store entry — i.e. a genuine
/// pre-migration ("pure-legacy") footprint.
///
/// Detection sweeps every `config-<N>` directory under `base_dir`, skips
/// any slot that is recovery-backed per
/// [`csq_core::accounts::profiles::is_slot_recovery_backed`] (`by_slot` ∪
/// `by_slot_identity` ∪ regular-file `credentials/gemini-<N>.json` marker —
/// those are MODERN identity-store accounts whose marker content is
/// cosmetic), and reads the remaining markers
/// via [`markers::read_identity_marker`], which returns `IdentityMarker {
/// numeric: Some(_), uuid: None }` for the decimal-content shape and
/// `IdentityMarker { numeric: None, uuid: Some(_) }` for the post-M4-7
/// UUID shape. The decimal-content shape is informational (M4-7 reader is
/// tolerant of both formats).
///
/// #578: the identity-store skip prevents two false-positive classes —
/// 3P API-key slots (decimal by design, `by_slot_identity = "apikey:*"`)
/// and modern OAuth slots whose marker simply never got rewritten by a
/// login/swap flow. The detector now fires only for slots with no map
/// entry at all, which aligns it with its documented retirement
/// condition (`phase4_gate_check` refusing pure-legacy installs).
///
/// Returns `None` when no `config-<N>` dirs exist, every marker is
/// already UUID-shaped or missing, or every decimal-marked slot is an
/// identity-store member.
fn detect_decimal_marker(base_dir: &Path) -> Option<LegacyCompatEntry> {
    // #578: a slot recovery-backed by ANY identity channel is a MODERN
    // account, regardless of its `.csq-account` marker content. For a
    // `config-<N>` dir the slot derives from the dir NAME and the identity
    // from a channel (`by_slot` UUID for OAuth, `by_slot_identity` for 3P
    // API-key / codex / gemini, OR a regular-file `credentials/gemini-<N>.json`
    // binding marker for the pre-backfill Gemini window), so the marker's
    // decimal-vs-UUID content is cosmetic — the M4-7 reader is tolerant of
    // both. Only a slot with NO channel at all is a genuine pre-migration
    // ("pure-legacy") footprint worth flagging. Without this guard the
    // detector false-positives on (a) 3P API-key slots, which carry decimal
    // ids BY DESIGN (`by_slot_identity = "apikey:*"`), and (b) modern OAuth
    // slots whose marker simply never got rewritten by a login/swap flow.
    // The full union lives in `is_slot_recovery_backed` (one source of
    // truth shared with audit_coexistence + legacy_count).
    let profiles =
        csq_core::accounts::profiles::load(&csq_core::accounts::profiles::profiles_path(base_dir))
            .unwrap_or_else(|_| csq_core::accounts::profiles::ProfilesFile::empty());

    let entries = std::fs::read_dir(base_dir).ok()?;
    let mut count: usize = 0;
    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        // Match config-<N> only (skip config-codex-<N>, term-<pid>, etc.).
        let Some(rest) = name.strip_prefix("config-") else {
            continue;
        };
        let Ok(slot) = rest.parse::<u16>() else {
            continue;
        };
        // Skip identity-store members (#578) via the SINGLE authoritative
        // recovery-backed predicate (by_slot ∪ by_slot_identity ∪
        // regular-file gemini-<N>.json marker). Shared with
        // `audit_coexistence` + the `legacy_count` heuristic so the three
        // keep-sets cannot drift (reconciler-cleanup-parity Rule 4).
        if csq_core::accounts::profiles::is_slot_recovery_backed(base_dir, &profiles, slot) {
            continue;
        }
        let dir = entry.path();
        if let Some(im) = markers::read_identity_marker(&dir) {
            if im.numeric.is_some() && im.uuid.is_none() {
                count += 1;
            }
        }
    }
    if count == 0 {
        return None;
    }
    let kind = LegacyCompatKind::DecimalMarkerContentPresent;
    Some(LegacyCompatEntry {
        kind: kind.as_str().to_string(),
        evidence: format!(
            "config-<N>/.csq-account contains a decimal slot id ({count} marker{})",
            if count == 1 { "" } else { "s" }
        ),
        scheduled_for: kind.scheduled_for(),
    })
}

/// Build `CliSurfaceInfo` for a surface, handling the probe-disabled case.
fn build_surface_info(cli: SurfaceCli) -> CliSurfaceInfo {
    if probe_disabled() {
        let m = min_version(cli);
        CliSurfaceInfo {
            found: false,
            path: None,
            version: None,
            min_version: format!("{}.{}.{}", m.major, m.minor, m.patch),
            status: "probe_disabled".into(),
            manager: "unknown".into(),
            wrong_binary_reason: None,
        }
    } else {
        cli_status_to_surface_info(&probe(cli), cli)
    }
}

/// PR-CA9b T20 / R3/B90 — read the daemon's persisted sweeper state
/// from `<base_dir>/coc-cache-sweeper-state.json` and surface it
/// for `csq doctor --json`. When the file is missing (daemon has
/// never run a tick on this host) we return `never_run` with zeroed
/// counters; doctor consumers should not treat that as an error.
fn check_cache_sweeper(base_dir: &Path) -> CacheSweeperInfo {
    let state_path = coc_cache_sweeper::state_file_path(base_dir);
    let snap = match coc_cache_sweeper::read_state_file(&state_path) {
        Some(s) => s,
        None => {
            return CacheSweeperInfo {
                status: "never_run",
                last_sweep_at: None,
                last_sweep_duration_ms: 0,
                sweep_partial: false,
                sweep_lag_minutes: 0,
                files_swept_last_run: 0,
                files_skipped_last_run: 0,
                cache_sweep_blocked: 0,
            };
        }
    };

    let lag_minutes = snap
        .last_sweep_at
        .as_deref()
        .and_then(parse_iso8601_unix_minutes_ago)
        .unwrap_or(0);

    // R4/B90 acceptance: sweep_partial=true for >24h ⇒ degraded.
    let status: &'static str = if snap.sweep_partial && lag_minutes > 24 * 60 {
        "degraded"
    } else {
        "ok"
    };

    CacheSweeperInfo {
        status,
        last_sweep_at: snap.last_sweep_at,
        last_sweep_duration_ms: snap.last_sweep_duration_ms,
        sweep_partial: snap.sweep_partial,
        sweep_lag_minutes: lag_minutes,
        files_swept_last_run: snap.files_swept_last_run,
        files_skipped_last_run: snap.files_skipped_last_run,
        cache_sweep_blocked: snap.cache_sweep_blocked,
    }
}

/// Parses an ISO-8601 UTC timestamp like `2026-05-03T18:30:00Z` and
/// returns "minutes ago" relative to the system clock. Stdlib-only —
/// we do not pull in `chrono` for one timestamp parse.
fn parse_iso8601_unix_minutes_ago(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    if bytes.len() < 20 || bytes[19] != b'Z' {
        return None;
    }
    let year: i64 = std::str::from_utf8(&bytes[0..4]).ok()?.parse().ok()?;
    let month: u32 = std::str::from_utf8(&bytes[5..7]).ok()?.parse().ok()?;
    let day: u32 = std::str::from_utf8(&bytes[8..10]).ok()?.parse().ok()?;
    let hour: u32 = std::str::from_utf8(&bytes[11..13]).ok()?.parse().ok()?;
    let minute: u32 = std::str::from_utf8(&bytes[14..16]).ok()?.parse().ok()?;
    let second: u32 = std::str::from_utf8(&bytes[17..19]).ok()?.parse().ok()?;
    // Civil-time → unix seconds (Howard Hinnant algorithm, stdlib-only).
    let m = month as i64;
    let y = year - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + (day as i64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let unix = days * 86_400 + (hour as i64) * 3_600 + (minute as i64) * 60 + (second as i64);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some(((now - unix).max(0)) / 60)
}

/// PR-CA8b commit 4: spec 08 MED-03 host-isolation surface.
///
/// Production caller. Reads `std::env::vars()` and dispatches to
/// `check_host_isolation_with_env` for the testable path.
fn check_host_isolation(base_dir: &Path) -> HostIsolationStatus {
    let names: Vec<String> = std::env::vars().map(|(k, _v)| k).collect();
    check_host_isolation_with_env(base_dir, names.iter().map(|s| s.as_str()))
}

/// PR-CA8b commit 4: testable variant — accepts the env-var-name
/// iterator explicitly so tests can pass synthetic env without
/// mutating `std::env` (which would race across tests).
///
/// Round-1 H4 gate: `warning` requires BOTH a provisioned Gemini
/// slot AND production-shaped secrets in the parent env. Operators
/// who never use Gemini get `ok` regardless of env shape — the
/// warning is action-relevant only when a Gemini spawn could
/// actually expose secrets.
fn check_host_isolation_with_env<'a, I>(base_dir: &Path, env_var_names: I) -> HostIsolationStatus
where
    I: IntoIterator<Item = &'a str>,
{
    use std::collections::BTreeSet;

    // Detect production-shaped env-var names via the shared
    // heuristic in csq_core::env.
    let detected: BTreeSet<String> = env_var_names
        .into_iter()
        .filter(|k| csq_core::env::looks_like_production_secret(k))
        .map(|k| k.to_string())
        .collect();
    let detected_count = detected.len();
    let first_name = csq_core::env::first_exemplar(&detected).map(|s| s.to_string());

    // Presence predicate for the spec-08 MED-03 SECURITY gate. The
    // gate warns when a Gemini spawn could read the operator's real
    // `$HOME` secrets, so "a Gemini slot exists" MUST mean "a Gemini
    // spawn can be admitted". That is decided by the daemon's IPC gate
    // and `csq run` via `is_gemini_bound_slot` — marker file
    // `credentials/gemini-<N>.json` exists (one `symlink_metadata`, NO
    // JSON parse, NO schema check; see `daemon::server` gemini IPC
    // admission). Keying the gate off the SAME predicate guarantees it
    // can never disagree with what actually admits a spawn.
    //
    // Deliberately NOT `discover_gemini` (the listing path):
    // `discover_gemini` strict-parses the binding and drops malformed
    // / old-schema / symlinked markers — but the daemon would still
    // spawn those slots, so a listing-based gate would silently
    // suppress the warning for exactly the corrupt-binding hosts that
    // most need it. Security doctrine (`csq_core::env`: "false-
    // negatives are not acceptable") → fail TOWARD warn: an unreadable
    // `credentials/` dir is slot-presence-INDETERMINATE, not "no slot".
    //
    // Regression (journal): the original predicate scanned
    // `providers/<N>/binding.json` — a DEAD path no production code
    // writes (`binding_path` is `credentials/gemini-<N>.json`, proven
    // by `provisioning::tests::binding_path_is_credentials_gemini_n_json`)
    // — so the MED-03 warning was silently suppressed on every host.
    use csq_core::providers::gemini::provisioning::is_gemini_bound_slot;
    let creds_dir_indeterminate = match std::fs::read_dir(base_dir.join("credentials")) {
        Ok(_) => false,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true, // EACCES/EMFILE/EIO → cannot prove absence
    };
    let gemini_slots_present = creds_dir_indeterminate
        || (1..=csq_core::types::MAX_ACCOUNTS)
            .filter_map(|n| AccountNum::try_from(n).ok())
            .any(|slot| is_gemini_bound_slot(base_dir, slot));

    // Round-1 H4 gate.
    let status = if gemini_slots_present && detected_count > 0 {
        "warning"
    } else {
        "ok"
    };

    HostIsolationStatus {
        status,
        gemini_slots_present,
        detected_count,
        first_name,
        // Default mode: empty list (round-2 R2-M2 disclosure-min).
        // Verbose-mode wiring is a follow-up.
        detected_var_names: Vec::new(),
    }
}

/// Probes for a `node` or `bun` binary using the same two-stage
/// resolver as the HTTP client (PATH + known install locations).
/// The daemon cannot refresh tokens or poll quota without one, so
/// `not found` is reported as a WARN.
fn check_js_runtime() -> JsRuntimeInfo {
    match csq_core::http::js_runtime_path() {
        Some(p) => JsRuntimeInfo {
            found: true,
            // `js_runtime_path()` returns a `String`, so we use
            // `redact_home_prefix` directly rather than the `&Path`-typed
            // `redact_path` helper.
            path: Some(csq_core::cli_deps::sanitize::redact_home_prefix(&p)),
        },
        None => JsRuntimeInfo {
            found: false,
            path: None,
        },
    }
}

/// Finds slots whose `config-N/settings.json` carries a 3P env block
/// AND whose `credentials/N.json` is a valid OAuth credential.
///
/// This is a mixed-state slot — on `csq run N` CC will route to the
/// 3P endpoint because `env.ANTHROPIC_BASE_URL` wins over OAuth, so
/// the OAuth credential sits unused. `csq login N` on a post-PR-#130
/// build auto-strips the 3P env block; older installs leave the slot
/// stuck.
fn check_mixed_state_slots(base_dir: &Path) -> MixedStateInfo {
    let third_party = discovery::discover_per_slot_third_party(base_dir);
    let mut entries: Vec<MixedStateSlot> = Vec::new();

    for slot in third_party {
        let Ok(num) = AccountNum::try_from(slot.id) else {
            continue;
        };
        // M4-4 / M4-12: route through identity-keyed credentials.
        // No UUID → no canonical file (numeric path retired).
        // Slot-id channel: caller-supplied slot (channel (c)).
        let canonical = csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, num.get())
            .map(|uuid| csq_core::accounts::identity_store::credentials_path_for(base_dir, uuid));
        // Only flag when the OAuth file is parseable. A missing or
        // unparseable credential isn't "mixed state" — other doctor
        // checks surface that (`expired`, `broker_failed`).
        if canonical
            .as_deref()
            .map(|p| csq_core::credentials::load(p).is_ok())
            .unwrap_or(false)
        {
            let provider = match &slot.source {
                AccountSource::ThirdParty { provider } => provider.clone(),
                _ => "third-party".to_string(),
            };
            entries.push(MixedStateSlot {
                account: slot.id,
                provider,
            });
        }
    }

    entries.sort_by_key(|e| e.account);
    MixedStateInfo {
        count: entries.len(),
        entries,
    }
}

/// Reads `{base_dir}/.resurrection-log.jsonl` and summarizes it.
///
/// Each line is an object emitted by the refresher when it had to
/// rebuild a canonical credential file from its live sibling. Any
/// non-zero count means at least one OAuth slot's canonical went
/// missing — a symptom of a broken write path. The operator should
/// investigate login / Add Account / import flows that touched the
/// affected accounts.
fn check_resurrections(base_dir: &Path) -> ResurrectionInfo {
    let path = base_dir.join(".resurrection-log.jsonl");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => {
            return ResurrectionInfo {
                total: 0,
                distinct_accounts: 0,
                last_timestamp_secs: None,
                recent_accounts: Vec::new(),
            };
        }
    };

    let mut total = 0usize;
    let mut last_ts: Option<u64> = None;
    let mut distinct: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();
    // Keep the last 5 account IDs in insertion order for the recent
    // sample. We don't guarantee chronological order of the file
    // beyond "appended" — appender is single-threaded inside the
    // daemon refresher so this is safe in practice.
    let mut recent: std::collections::VecDeque<u16> = std::collections::VecDeque::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        total += 1;
        if let Some(ts) = val.get("timestamp_secs").and_then(|v| v.as_u64()) {
            last_ts = Some(last_ts.map_or(ts, |prev| prev.max(ts)));
        }
        if let Some(acct) = val
            .get("account")
            .and_then(|v| v.as_u64())
            .and_then(|n| u16::try_from(n).ok())
        {
            distinct.insert(acct);
            recent.push_back(acct);
            while recent.len() > 5 {
                recent.pop_front();
            }
        }
    }

    ResurrectionInfo {
        total,
        distinct_accounts: distinct.len(),
        last_timestamp_secs: last_ts,
        recent_accounts: recent.into_iter().collect(),
    }
}

fn check_platform() -> PlatformInfo {
    PlatformInfo {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
    }
}

/// Convert `InstallManager` to the doctor JSON display string.
///
/// spec/13 §9 uses shorter names than the internal serde (`"npm"` not
/// `"npm_global"`; `"claude_native"` not `"claude_native_installer"`).
fn manager_display(m: InstallManager) -> &'static str {
    match m {
        InstallManager::NpmGlobal => "npm",
        InstallManager::BrewFormula => "brew_formula",
        InstallManager::BrewCask => "brew_cask",
        InstallManager::ClaudeNativeInstaller => "claude_native",
        InstallManager::Unknown => "unknown",
    }
}

/// Build a `CliSurfaceInfo` from a `CliStatus` for JSON output.
fn cli_status_to_surface_info(status: &CliStatus, cli: SurfaceCli) -> CliSurfaceInfo {
    let min = min_version(cli);
    let min_str = format!("{}.{}.{}", min.major, min.minor, min.patch);

    match status {
        CliStatus::Ok {
            version,
            path,
            manager,
        } => CliSurfaceInfo {
            found: true,
            path: Some(sanitize_for_display(&path.to_string_lossy())),
            version: Some(format!(
                "{}.{}.{}",
                version.major, version.minor, version.patch
            )),
            min_version: min_str,
            status: "ok".into(),
            manager: manager_display(*manager).into(),
            wrong_binary_reason: None,
        },
        CliStatus::Outdated {
            version,
            path,
            manager,
            ..
        } => CliSurfaceInfo {
            found: true,
            path: Some(sanitize_for_display(&path.to_string_lossy())),
            version: Some(format!(
                "{}.{}.{}",
                version.major, version.minor, version.patch
            )),
            min_version: min_str,
            status: "outdated".into(),
            manager: manager_display(*manager).into(),
            wrong_binary_reason: None,
        },
        CliStatus::WrongBinary { path, reason, .. } => {
            let reason_info = match reason {
                WrongBinaryReason::InstallPathBlocklisted { .. } => WrongBinaryReasonInfo {
                    kind: "install_path_blocklisted".into(),
                    expected: None,
                    got: None,
                    segment: None,
                },
                WrongBinaryReason::PrefixMismatch { expected, got } => WrongBinaryReasonInfo {
                    kind: "prefix_mismatch".into(),
                    expected: Some((*expected).into()),
                    got: Some(sanitize_for_display(got)),
                    segment: None,
                },
                WrongBinaryReason::ComponentTooLarge { segment } => WrongBinaryReasonInfo {
                    kind: "component_too_large".into(),
                    expected: None,
                    got: None,
                    segment: Some(sanitize_for_display(segment)),
                },
            };
            CliSurfaceInfo {
                found: true,
                path: Some(sanitize_for_display(&path.to_string_lossy())),
                version: None,
                min_version: min_str,
                status: "wrong_binary".into(),
                manager: "unknown".into(),
                wrong_binary_reason: Some(reason_info),
            }
        }
        CliStatus::Missing => CliSurfaceInfo {
            found: false,
            path: None,
            version: None,
            min_version: min_str,
            status: "missing".into(),
            manager: "unknown".into(),
            wrong_binary_reason: None,
        },
        CliStatus::UnrecognizedVersion { path, manager, .. } => CliSurfaceInfo {
            found: true,
            path: Some(sanitize_for_display(&path.to_string_lossy())),
            version: None,
            min_version: min_str,
            status: "unrecognized_version".into(),
            manager: manager_display(*manager).into(),
            wrong_binary_reason: None,
        },
        CliStatus::ProbeTimedOut { path, .. } => CliSurfaceInfo {
            found: true,
            path: Some(sanitize_for_display(&path.to_string_lossy())),
            version: None,
            min_version: min_str,
            status: "probe_timed_out".into(),
            manager: "unknown".into(),
            wrong_binary_reason: None,
        },
    }
}

/// Count authenticated slots (has `.credentials.json`) for a surface.
fn count_authenticated_slots(base_dir: &Path, cli: SurfaceCli) -> usize {
    match cli {
        SurfaceCli::Claude => discovery::discover_anthropic(base_dir)
            .into_iter()
            .filter(|a| a.has_credentials)
            .count(),
        SurfaceCli::Codex => discovery::discover_codex(base_dir)
            .into_iter()
            .filter(|a| a.has_credentials)
            .count(),
        SurfaceCli::Gemini => discovery::discover_gemini(base_dir)
            .into_iter()
            .filter(|a| a.has_credentials)
            .count(),
        // SurfaceCli is #[non_exhaustive]; future variants return 0.
        _ => 0,
    }
}

fn check_settings() -> SettingsInfo {
    let claude_home = super::claude_home().ok();

    let settings_path = claude_home.as_ref().map(|h| h.join("settings.json"));

    let (exists, statusline_configured, statusline_command) = match settings_path {
        Some(ref path) if path.exists() => match std::fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(val) => {
                    let cmd = val
                        .get("statusLine")
                        .and_then(|sl| sl.get("command"))
                        .and_then(|c| c.as_str())
                        .map(|s| s.to_string());
                    // Any non-empty command is "configured" — doctor should
                    // not second-guess what script is used, only that one
                    // exists. The old `c.contains("csq")` check rejected
                    // valid wrapper scripts.
                    let configured = cmd.as_ref().is_some_and(|c| !c.trim().is_empty());
                    (true, configured, cmd)
                }
                Err(_) => (true, false, None),
            },
            Err(_) => (true, false, None),
        },
        _ => (false, false, None),
    };

    SettingsInfo {
        exists,
        statusline_configured,
        statusline_command,
    }
}

fn check_daemon(base_dir: &Path) -> DaemonInfo {
    use csq_core::daemon::{detect_daemon, version_drift_reason, DetectResult};
    match detect_daemon(base_dir) {
        DetectResult::Healthy {
            pid,
            daemon_version,
            ..
        } => {
            let drift = version_drift_reason(&daemon_version);
            DaemonInfo {
                status: if drift.is_some() {
                    "drifted".into()
                } else {
                    "healthy".into()
                },
                pid: Some(pid),
                socket_healthy: Some(true),
                version_drift: drift,
            }
        }
        DetectResult::Stale { .. } => DaemonInfo {
            status: "stale".into(),
            pid: None,
            socket_healthy: Some(false),
            version_drift: None,
        },
        DetectResult::Unhealthy { reason } => {
            // PID is alive but the socket did not respond — daemon is up
            // but not serving. The reason string distinguishes "PID alive
            // but socket missing" from other unhealthy cases.
            let pid_alive_no_socket = reason.contains("socket") && reason.contains("missing");
            DaemonInfo {
                status: if pid_alive_no_socket {
                    "pid_alive_no_socket".into()
                } else {
                    "unhealthy".into()
                },
                pid: None,
                socket_healthy: Some(false),
                version_drift: None,
            }
        }
        DetectResult::NotRunning => DaemonInfo {
            status: "not running".into(),
            pid: None,
            socket_healthy: None,
            version_drift: None,
        },
    }
}

fn check_accounts(base_dir: &Path) -> AccountsInfo {
    let accounts = discovery::discover_anthropic(base_dir);
    let total = accounts.len();
    let with_credentials = accounts.iter().filter(|a| a.has_credentials).count();

    // Check for expired tokens
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let mut expired = 0usize;
    for a in &accounts {
        if !a.has_credentials {
            continue;
        }
        let Ok(num) = AccountNum::try_from(a.id) else {
            continue;
        };
        // M4-4: route through identity-keyed credentials when
        // `profiles.json::by_slot` has a UUID for this slot. Slot-id
        // channel: discovery-output parameter (channel (c)).
        // M4-12: no UUID → no credential file (numeric path retired).
        let cred_path = csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, num.get())
            .map(|uuid| csq_core::accounts::identity_store::credentials_path_for(base_dir, uuid));
        if let Some(path) = cred_path.as_deref() {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                    // Real CC creds: `claudeAiOauth.expiresAt` (camelCase, ms).
                    if let Some(exp) = val
                        .get("claudeAiOauth")
                        .and_then(|o| o.get("expiresAt"))
                        .and_then(|e| e.as_u64())
                    {
                        if exp < now_ms {
                            expired += 1;
                        }
                    }
                }
            }
        }
    }

    AccountsInfo {
        total,
        with_credentials,
        expired,
    }
}

/// an internal ticket custodian-identity canary result. Carries the `term-<pid>` tags of
/// live Anthropic-bound handle dirs partitioned by `.claude.json` `oauthAccount`
/// state. `term-<pid>` is a directory basename (no host-path bytes), safe to
/// print (`operator-surface-verification.md`).
#[derive(Debug, Default, Clone)]
struct CustodianIdentityCanary {
    /// `false` when the scan cannot run (non-unix — handle dirs are a unix
    /// symlink construct — or an unreadable base dir).
    check_available: bool,
    /// Live Anthropic-bound dirs whose `.claude.json` is POPULATED but lacks a
    /// usable `oauthAccount.emailAddress` — the format-drift signal. A non-empty
    /// list means the custodian's wrong-account gate is refusing adoptions.
    drift_dirs: Vec<String>,
    /// Live Anthropic-bound dirs whose `.claude.json` is absent/empty — a benign
    /// fresh / not-yet-populated session. Tracked only to distinguish drift from
    /// fresh (an internal ticket AC bullet 2); not alarmed on.
    fresh_dirs: Vec<String>,
}

/// Is `dir` a handle dir bound to an Anthropic account? True when its
/// `.credentials.json` is a symlink resolving through `identities/<uuid>/` (with
/// a NON-EMPTY uuid segment) and ending in `credentials.json` — the exact shape
/// the daemon custodian harvests
/// (`credentials::keychain::harvest_account_candidates`). Excludes Codex
/// (`auth.json`), legacy `config-N` links, and any non-Anthropic link so the
/// canary never false-flags a non-Claude session that legitimately has no
/// `oauthAccount`.
///
/// The `identities/<uuid>/` extraction mirrors the producer's non-empty-segment
/// check rather than a bare `contains("identities/")`, so a future rename of the
/// credential-link shape regresses both predicates in lockstep
/// (`reconciler-cleanup-parity.md` Rule 4 — enumerate the exact names the producer
/// creates; redteam R1 LOW L1/F4).
/// Sort `term-<pid>` handle-dir labels by NUMERIC pid (so `term-999` precedes
/// `term-1000`, not lexicographically) and drop the pid key. Extracted as a pure
/// fn so the numeric ordering is unit-testable without live PIDs (redteam R2
/// testing-specialist F2).
#[cfg(unix)]
fn sorted_dir_names(mut pairs: Vec<(u32, String)>) -> Vec<String> {
    pairs.sort_by_key(|(pid, _)| *pid);
    pairs.into_iter().map(|(_, name)| name).collect()
}

#[cfg(unix)]
fn is_anthropic_bound_handle_dir(dir: &Path) -> bool {
    let Ok(target) = std::fs::read_link(dir.join(".credentials.json")) else {
        return false;
    };
    let s = target.to_string_lossy();
    let has_identity_uuid = s
        .split("identities/")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .is_some_and(|uuid| !uuid.is_empty());
    has_identity_uuid && s.ends_with("credentials.json")
}

/// an internal ticket: scan live Anthropic-bound handle dirs and classify each session's
/// `.claude.json` `oauthAccount.emailAddress` presence. Surfaces the degraded
/// state where Claude Code has stopped writing that field — the local signal the
/// custodian's wrong-account gate depends on. Scoped to LIVE (alive-PID)
/// Anthropic-bound dirs.
///
/// Scope note (redteam R1 F1/L2): this is a SUPERSET of the custodian's harvest
/// scope on one benign edge — the shared `is_pid_alive` treats an EPERM (live but
/// unsignalable) PID as alive, whereas the harvest's raw `kill(pid,0) != 0` skips
/// it. Under csq's same-user threat model a handle-dir PID is always the same UID
/// that owns the 0600 credentials, so EPERM does not arise for these PIDs and the
/// two scopes coincide in practice; where they would diverge, the canary
/// OVER-surfaces (a live-but-unsignalable Anthropic session with real drift is
/// still worth reporting), never under-surfaces.
#[cfg(not(unix))]
fn check_custodian_identity_canary(_base_dir: &Path) -> CustodianIdentityCanary {
    CustodianIdentityCanary::default()
}

#[cfg(unix)]
fn check_custodian_identity_canary(base_dir: &Path) -> CustodianIdentityCanary {
    use csq_core::credentials::claude_json::{classify_oauth_account, OauthAccountState};

    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return CustodianIdentityCanary::default(),
    };

    // (pid, "term-<pid>") pairs so the display list sorts numerically by PID
    // (term-999 before term-1000), not lexicographically (redteam R1 NIT N7).
    let mut drift: Vec<(u32, String)> = Vec::new();
    let mut fresh: Vec<(u32, String)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // Only live term-<pid> handle dirs (the custodian's harvest scope).
        let Some(pid) = name
            .strip_prefix("term-")
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if !is_pid_alive(pid) {
            continue;
        }
        let dir = entry.path();
        if !is_anthropic_bound_handle_dir(&dir) {
            continue;
        }
        match classify_oauth_account(&dir) {
            OauthAccountState::Present => {}
            OauthAccountState::FieldMissing => drift.push((pid, name)),
            OauthAccountState::NotYetPopulated => fresh.push((pid, name)),
        }
    }
    let drift_dirs = sorted_dir_names(drift);
    let fresh_dirs = sorted_dir_names(fresh);
    CustodianIdentityCanary {
        check_available: true,
        drift_dirs,
        fresh_dirs,
    }
}

/// Scans `credentials/N.broker-failed` sentinel files and returns the list of
/// accounts that require re-login.
///
/// The scan uses two approaches combined:
/// 1. Check every account discovered by `discovery::discover_anthropic` —
///    covers accounts whose credential slot exists.
/// 2. Glob `credentials/*.broker-failed` directly — catches sentinel files for
///    accounts whose `credentials/N.json` is missing (total loss case).
///
/// Both sets are unioned and de-duplicated before building the report.
fn check_broker_failed(base_dir: &Path) -> BrokerFailedInfo {
    let mut failed_ids: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();

    // Pass 1: discovered accounts.
    let accounts = discovery::discover_anthropic(base_dir);
    for a in &accounts {
        let Ok(num) = AccountNum::try_from(a.id) else {
            continue;
        };
        if fanout::is_broker_failed(base_dir, num) {
            failed_ids.insert(a.id);
        }
    }

    // Pass 2: filesystem scan of credentials/*.broker-failed to catch
    // accounts not in the discovery list.
    let creds_dir = base_dir.join("credentials");
    if let Ok(entries) = std::fs::read_dir(&creds_dir) {
        for entry in entries.flatten() {
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            let stem = match name.strip_suffix(".broker-failed") {
                Some(s) => s,
                None => continue,
            };
            if let Ok(id) = stem.parse::<u16>() {
                failed_ids.insert(id);
            }
        }
    }

    let entries: Vec<BrokerFailedEntry> = failed_ids
        .iter()
        .filter_map(|&id| {
            let Ok(num) = AccountNum::try_from(id) else {
                return None;
            };
            let reason = fanout::read_broker_failed_reason(base_dir, num).unwrap_or_default();
            let display_reason = if reason.is_empty() {
                "unknown".to_string()
            } else {
                reason
            };
            Some(BrokerFailedEntry {
                account: id,
                reason: display_reason,
            })
        })
        .collect();

    let count = entries.len();
    BrokerFailedInfo { count, entries }
}

/// Detects legacy and modern CC terminals by examining the `base_dir` layout.
///
/// Strategy:
///
/// **Modern terminals** — scan for `term-<pid>` directories. Extract the PID
/// from the name and call `is_pid_alive`. Count those whose PID is still alive.
///
/// **Legacy terminals** — scan for `config-<N>` directories. In the modern
/// handle-dir model the `.credentials.json` inside each `config-N` is always a
/// plain file (the canonical OAuth token store). But the distinguishing
/// characteristic of a *still-active legacy terminal* is that the CC process
/// has `CLAUDE_CONFIG_DIR` pointing directly at a `config-N` path, bypassing
/// the `term-<pid>` layer. We cannot read every running process's environment
/// portably, so we use a best-effort proxy: count `config-N` dirs whose
/// `.credentials.json` is a **real file** (not a symlink). In the handle-dir
/// model this is still the expected layout — `config-N/.credentials.json` is
/// always a real file. To improve signal we also count how many live `term-<pid>`
/// dirs have a symlink pointing into each `config-N`; if no `term-<pid>` has
/// adopted a `config-N`, and the `config-N` has credentials, that `config-N`
/// might be hosting a legacy terminal.
///
/// Because perfect detection would require reading `/proc/*/environ` (Linux) or
/// `proc_pidinfo` (macOS) for every process — which is expensive and may be
/// blocked by SIP — we settle for the simplest reliable proxy:
///
/// - `modern_count` = number of `term-<pid>` dirs with a living PID
/// - `legacy_count` = number of `config-N` dirs that have credentials,
///   are NOT referenced by any living `term-<pid>` symlink, AND are NOT
///   recovery-backed per `is_slot_recovery_backed` (#578 — `by_slot` ∪
///   `by_slot_identity` ∪ gemini marker; an idle but identity-store member
///   account is modern, not legacy; only pre-migration config-N dirs with
///   no identity channel at all are counted)
/// - `check_available` = true on Unix (where we can at least check PIDs)
///
/// On Windows the check is skipped entirely.
fn check_terminals(base_dir: &Path) -> TerminalInfo {
    #[cfg(not(unix))]
    {
        let _ = base_dir;
        return TerminalInfo {
            modern_count: 0,
            legacy_count: 0,
            check_available: false,
        };
    }

    #[cfg(unix)]
    {
        check_terminals_unix(base_dir)
    }
}

#[cfg(unix)]
fn check_terminals_unix(base_dir: &Path) -> TerminalInfo {
    use csq_core::accounts::profiles;
    use std::collections::HashSet;

    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => {
            return TerminalInfo {
                modern_count: 0,
                legacy_count: 0,
                check_available: false,
            };
        }
    };

    // Collect all entries once so we can iterate twice.
    let all_entries: Vec<_> = entries.flatten().collect();

    // R1 H1-DA fix-wave: post-M3-3 modern handle dirs symlink `.credentials.json`
    // through `identities/<UUID>/credentials.json` (identity-keyed) rather than
    // `config-N/.credentials.json` (legacy). The prior implementation only
    // recognized the legacy shape and therefore reported every modern terminal's
    // slot as "legacy". Resolve UUID → slot via `profiles.json::by_slot`
    // (loaded once) before classifying targets; fall back to the legacy
    // config-N component scan for slots that have not yet been minted.
    //
    // Slots adopted by at least one living `term-<pid>` are tracked by slot
    // number (`u16`) — both target shapes ultimately map to the same slot
    // identity for legacy-detection purposes.
    let profiles_file = profiles::load(&profiles::profiles_path(base_dir))
        .unwrap_or_else(|_| profiles::ProfilesFile::empty());
    // Reverse map: UUID string → slot number. Built once so the inner loop is
    // a hash lookup, not a linear scan of `by_slot`.
    let uuid_to_slot: std::collections::HashMap<String, u16> = profiles_file
        .by_slot
        .iter()
        .filter_map(|(slot_str, uuid)| slot_str.parse::<u16>().ok().map(|n| (uuid.to_string(), n)))
        .collect();

    // Pass 1: count living term-<pid> dirs and collect which slot each references.
    let mut modern_count = 0usize;
    let mut adopted_slots: HashSet<u16> = HashSet::new();

    for entry in &all_entries {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };

        if !name.starts_with("term-") {
            continue;
        }

        let pid: u32 = match name.strip_prefix("term-").and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };

        if !is_pid_alive(pid) {
            continue; // orphaned, not a live modern terminal
        }

        modern_count += 1;

        // Resolve symlink target → slot. Handles both identity-keyed
        // (`identities/<UUID>/credentials.json`) and legacy
        // (`config-N/.credentials.json`) shapes.
        let handle_path = entry.path();
        let cred_link = handle_path.join(".credentials.json");
        if let Ok(target) = std::fs::read_link(&cred_link) {
            let components: Vec<String> = target
                .components()
                .filter_map(|c| c.as_os_str().to_str().map(str::to_string))
                .collect();

            // Identity-keyed: …/identities/<UUID>/credentials.json
            if let Some(idx) = components.iter().position(|c| c == "identities") {
                if let Some(uuid_str) = components.get(idx + 1) {
                    if let Some(&slot) = uuid_to_slot.get(uuid_str) {
                        adopted_slots.insert(slot);
                        continue;
                    }
                }
            }

            // Legacy: …/config-<N>/.credentials.json
            if let Some(config_name) = components.iter().find(|c| c.starts_with("config-")) {
                if let Some(slot) = config_name
                    .strip_prefix("config-")
                    .and_then(|s| s.parse::<u16>().ok())
                {
                    adopted_slots.insert(slot);
                }
            }
        }
    }

    // Pass 2: count config-N dirs that have credentials but no living handle dir.
    let mut legacy_count = 0usize;

    for entry in &all_entries {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let slot: u16 = match name.strip_prefix("config-").and_then(|s| s.parse().ok()) {
            Some(n) => n,
            None => continue,
        };

        // Only count config dirs that have real credentials (not empty stubs).
        let cred_path = entry.path().join(".credentials.json");
        if !cred_path.exists() {
            continue;
        }

        // If this slot has been adopted by at least one living term-<pid>,
        // terminals on it are modern and already counted above.
        if adopted_slots.contains(&slot) {
            continue;
        }

        // #578: a slot recovery-backed by ANY identity channel is a MODERN
        // account. An idle modern account (credentials on disk but no live
        // handle dir bound right now) is NOT a legacy terminal — the legacy
        // signal is a PRE-identity-store config-N being driven directly
        // (CLAUDE_CONFIG_DIR=config-N). Counting every unbound-but-migrated
        // account as "legacy" was a constant false positive on hosts that
        // rotate between accounts. We trade away detection of the rare
        // "direct CC session against a migrated config-N" case (unobservable
        // without per-process env inspection, which is expensive /
        // SIP-blocked) for silence on the common idle case. Uses the SAME
        // authoritative predicate as `audit_coexistence` +
        // `detect_decimal_marker` (by_slot ∪ by_slot_identity ∪
        // regular-file gemini-<N>.json marker) so the three keep-sets
        // cannot drift (reconciler-cleanup-parity Rule 4) — this also
        // excludes 3P/Codex/Gemini recovery-backed slots, not just OAuth.
        if profiles::is_slot_recovery_backed(base_dir, &profiles_file, slot) {
            continue;
        }

        // Slot has credentials, no living term-<pid> references it, and it
        // is NOT recovery-backed by any identity channel — a genuine
        // pre-migration footprint. Either a legacy CC session running
        // directly against config-N, or an un-migrated idle account. Count
        // it — the warning is advisory.
        legacy_count += 1;
    }

    TerminalInfo {
        modern_count,
        legacy_count,
        check_available: true,
    }
}

/// Render a single CLI surface row in human-readable format.
///
/// Handles all `CliSurfaceInfo` status variants per the doctor user-flow specs:
/// - `01-doctor-happy-path.md` (ok row)
/// - `04-wrong-binary-on-path.md` (wrong_binary row)
/// - `07-stale-slot-surface-uninstalled.md` (missing with stale slots)
fn render_cli_row(label: &str, surface_name: &str, info: &CliSurfaceInfo, auth_slots: usize) {
    match info.status.as_str() {
        "ok" => {
            let v = info.version.as_deref().unwrap_or("?");
            let p = info.path.as_deref().unwrap_or("?");
            println!(
                "  {label}: {icon} {v}  (min {min})   {p}   ({mgr})",
                icon = ok(),
                min = info.min_version,
                mgr = info.manager,
            );
        }
        "outdated" => {
            let v = info.version.as_deref().unwrap_or("?");
            let p = info.path.as_deref().unwrap_or("?");
            println!(
                "  {label}: {icon} outdated {v} (min {min})   {p}   ({mgr})",
                icon = warn(),
                min = info.min_version,
                mgr = info.manager,
            );
        }
        "missing" => {
            if auth_slots > 0 {
                // Stale-slot variant (R1-H14 / flow 07).
                println!(
                    "  {label}: {icon} missing — but you have {n} {surface_name} slot(s) configured",
                    icon = fail(),
                    n = auth_slots,
                );
                println!("    Slot(s) have credentials but no working binary.");
                println!();
                println!("    Either:");
                println!(
                    "      (a) `csq cli install {surface_name}`         (reinstall — keeps slot)"
                );
                println!("      (b) `csq logout <slot>`                  (remove slot — keeps {surface_name} uninstalled)");
                println!();
                println!("    Until one of these is done, `csq run <slot>` and `csq login <slot>` will fail.");
            } else {
                println!("  {label}: {icon} not found", icon = fail());
            }
        }
        "wrong_binary" => {
            let p = info.path.as_deref().unwrap_or("?");
            println!("  {label}: {icon} wrong binary on PATH", icon = warn());
            println!();
            println!("    Found: {surface_name} at {p}");

            // Dispatch on the reason so the remediation text is accurate.
            let reason_kind = info
                .wrong_binary_reason
                .as_ref()
                .map(|r| r.kind.as_str())
                .unwrap_or("install_path_blocklisted");

            match reason_kind {
                "prefix_mismatch" => {
                    let expected = info
                        .wrong_binary_reason
                        .as_ref()
                        .and_then(|r| r.expected.as_deref())
                        .unwrap_or("?");
                    let got = info
                        .wrong_binary_reason
                        .as_ref()
                        .and_then(|r| r.got.as_deref())
                        .unwrap_or("?");
                    println!("    Reason: `--version` output does not start with `{expected}` (got: `{got}`).");
                    println!();
                    println!("    Run `which -a {surface_name}` to inspect PATH-shadowing.");
                }
                "component_too_large" => {
                    let seg = info
                        .wrong_binary_reason
                        .as_ref()
                        .and_then(|r| r.segment.as_deref())
                        .unwrap_or("?");
                    println!("    Reason: version string is malformed (segment `{seg}` is not valid semver).");
                    println!();
                    println!("    Re-install via `csq cli install {surface_name}` once that subcommand ships,");
                    println!("    or upgrade your CLI through your usual package manager.");
                }
                _ => {
                    // install_path_blocklisted (default)
                    println!("    Reason: install path matches the Homebrew formula, not the npm package csq supports.");
                    println!();
                    println!("    Fix — copy and run this in your terminal:");
                    println!("      brew uninstall {surface_name}");
                    println!();
                    println!("    This removes the Homebrew-formula {surface_name} (a different tool with the same name).");
                    println!("    The npm-installed {surface_name} (which csq supports) stays untouched.");
                }
            }

            println!();
            println!("    After addressing the issue above, re-run `csq doctor` to verify.");
        }
        "unrecognized_version" => {
            let p = info.path.as_deref().unwrap_or("?");
            println!(
                "  {label}: {icon} unrecognized version at {p}",
                icon = warn()
            );
        }
        "probe_timed_out" => {
            let p = info.path.as_deref().unwrap_or("?");
            println!("  {label}: {icon} probe timed out at {p}", icon = warn());
        }
        "probe_disabled" => {
            println!(
                "  {label}: {icon} probe disabled (CSQ_CLI_DEPS_PROBE_DISABLE=1 set)",
                icon = warn()
            );
        }
        other => {
            println!("  {label}: {icon} {other}", icon = warn());
        }
    }
}

/// All user-supplied or third-party-supplied strings that flow into
/// `println!` calls MUST pass through `sanitize_for_display` before
/// being written to the terminal.  This defends against terminal
/// injection via malicious `--version` output, daemon strings, or
/// env-var names embedded in diagnostic output (spec/13 §10).
fn print_report(r: &DoctorReport) {
    println!();
    println!("csq doctor — v{}", r.version);
    println!();

    // Platform
    println!("  Platform:    {} / {}", r.platform.os, r.platform.arch);
    // Build edition (compile-time const from the `enterprise` Cargo feature;
    // community = csq, enterprise = csq-ee). The hardcoded label is
    // injection-safe (no user input). Distinct from the runtime audit dialect.
    println!("  Edition:     {}", crate::edition_label());
    println!();

    // an internal journal entry: top-level phase-4-incomplete alarm. Rendered BEFORE
    // the CLI surface rows so an operator scanning the report sees the
    // impending daemon-start refusal first, with the actionable
    // remediation command on the same screen.
    if let Some(ref alarm) = r.phase4_incomplete {
        render_phase4_incomplete_alarm(alarm);
        println!();
    }

    // CLI surfaces — rendered only when the surface has authenticated slots.
    let any_surface = r.claude_code.is_some() || r.codex_cli.is_some() || r.gemini_cli.is_some();
    if !any_surface {
        println!("  No slots configured. Run `csq login 1` to start.");
    } else {
        if let Some(ref cc) = r.claude_code {
            render_cli_row("Claude Code (claude)", "claude", cc, r.claude_auth_slots);
        }
        if let Some(ref cx) = r.codex_cli {
            render_cli_row("Codex CLI (codex)  ", "codex", cx, r.codex_auth_slots);
        }
        if let Some(ref gm) = r.gemini_cli {
            render_cli_row("Gemini CLI (gemini)", "gemini", gm, r.gemini_auth_slots);
        }
    }
    println!();

    // JS runtime (node/bun) — required for the Cloudflare-bypass
    // HTTP path. Missing runtime = broken token refresh + quota poll.
    let js_icon = if r.js_runtime.found { ok() } else { warn() };
    let js_detail = match &r.js_runtime.path {
        Some(p) => format!("found at {p}"),
        None => "not found — daemon can't refresh tokens or poll quota; install node or bun".into(),
    };
    println!("  JS runtime:  {js_icon} {js_detail}");

    // Settings
    let settings_icon = if r.settings.statusline_configured {
        ok()
    } else if r.settings.exists {
        warn()
    } else {
        fail()
    };
    let settings_detail = if r.settings.statusline_configured {
        format!(
            "statusline configured ({})",
            r.settings.statusline_command.as_deref().unwrap_or("?")
        )
    } else if r.settings.exists {
        "settings.json exists but statusline not configured".into()
    } else {
        "settings.json not found — run `csq install`".into()
    };
    println!("  Settings:    {settings_icon} {settings_detail}");

    // Daemon
    let (daemon_icon, daemon_detail) = match r.daemon.status.as_str() {
        "healthy" => {
            let pid_str = r
                .daemon
                .pid
                .map(|p| format!(" (PID {p})"))
                .unwrap_or_default();
            (ok(), format!("running and healthy{pid_str}"))
        }
        "drifted" => {
            // The daemon answers /api/health but its CARGO_PKG_VERSION
            // does not match this CLI's. Surface the reason verbatim
            // — it already names both versions and the remediation.
            // sanitize_for_display guards against terminal injection via
            // a malicious daemon that returns ESC sequences in its version
            // string (spec/13 §10, M-3).
            let raw =
                r.daemon.version_drift.as_deref().unwrap_or(
                    "version drift detected — run `csq daemon stop && csq daemon start`",
                );
            (warn(), sanitize_for_display(raw))
        }
        "pid_alive_no_socket" => (
            warn(),
            "PID alive but socket unreachable — daemon may be starting up".into(),
        ),
        "stale" => (fail(), "stale PID/socket — run `csq daemon start`".into()),
        "unhealthy" => (
            warn(),
            "daemon unhealthy — socket connect or health check failed".into(),
        ),
        "not running" => (warn(), "not running — run `csq daemon start`".into()),
        _ => (warn(), r.daemon.status.clone()),
    };
    println!("  Daemon:      {daemon_icon} {daemon_detail}");

    // Accounts
    let acct_icon = if r.accounts.with_credentials > 0 && r.accounts.expired == 0 {
        ok()
    } else if r.accounts.expired > 0 {
        warn()
    } else {
        fail()
    };
    let mut acct_detail = format!(
        "{} account(s), {} with credentials",
        r.accounts.total, r.accounts.with_credentials
    );
    if r.accounts.expired > 0 {
        acct_detail.push_str(&format!(", {} expired", r.accounts.expired));
    }
    println!("  Accounts:    {acct_icon} {acct_detail}");

    // Mixed-state slots (3P env block + OAuth creds)
    if r.mixed_state_slots.count > 0 {
        for entry in &r.mixed_state_slots.entries {
            // sanitize provider name: third-party settings could theoretically
            // contain control chars (spec/13 §10, M-3).
            let provider = sanitize_for_display(&entry.provider);
            println!(
                "  Mixed:       {} Slot {} has both {} env and OAuth creds — CC will route via {}. Run `csq login {}` to unbind.",
                warn(),
                entry.account,
                provider,
                provider,
                entry.account,
            );
        }
    }

    // Broker-failed sentinels
    if r.broker_failed.count > 0 {
        for entry in &r.broker_failed.entries {
            // sanitize reason: broker failure reasons may include strings
            // sourced from external services (spec/13 §10, M-3).
            let reason = sanitize_for_display(&entry.reason);
            println!(
                "  Broker:      {} Account {}: LOGIN-NEEDED ({}) — run `csq login {}`",
                fail(),
                entry.account,
                reason,
                entry.account,
            );
        }
    }

    // Custodian-identity canary (an internal ticket). Fires only on FORMAT DRIFT — a live
    // Anthropic session whose `.claude.json` is present with content the
    // wrong-account gate cannot read an `oauthAccount.emailAddress` from (field
    // omitted/renamed/emptied, an unparseable/non-object shape, or a file past the
    // read ceiling). That field is the local identity signal the daemon custodian's
    // gate requires; while the gate cannot read it, it refuses every token adoption
    // and the credential refresh war silently returns. A fresh / not-yet-populated
    // dir (absent/empty file) is NOT alarmed on (benign, self-heals).
    {
        let c = &r.custodian_identity_canary;
        if c.check_available && !c.drift_dirs.is_empty() {
            println!(
                "  Custodian:   {} {} live Claude session(s) [{}] have a .claude.json the account-identity gate can't read oauthAccount.emailAddress from",
                warn(),
                c.drift_dirs.len(),
                c.drift_dirs.join(", "),
            );
            println!(
                "               → the gate will refuse all token adoptions for those accounts (refresh war returns). If this persists across runs, Claude Code changed format — file a csq issue (#833)."
            );
            // Show the fresh/not-yet-populated sessions the discriminator excluded,
            // so the operator can see drift was distinguished from benign fresh dirs
            // (an internal ticket AC bullet 2) rather than a blanket "field absent" alarm.
            if !c.fresh_dirs.is_empty() {
                println!(
                    "               ({} fresh/not-yet-populated session(s) excluded from the count: {})",
                    c.fresh_dirs.len(),
                    c.fresh_dirs.join(", "),
                );
            }
        }
    }

    // Terminals
    let t = &r.terminals;
    if !t.check_available {
        println!("  Terminals:   - check not available on this platform");
    } else if t.legacy_count > 0 {
        let term_icon = warn();
        println!(
            "  Terminals:   {term_icon} {} legacy, {} modern — relaunch legacy terminals with `csq run`",
            t.legacy_count, t.modern_count
        );
    } else if t.modern_count > 0 {
        let term_icon = ok();
        println!(
            "  Terminals:   {term_icon} {} terminal(s) using handle dirs",
            t.modern_count
        );
    } else {
        println!("  Terminals:   - no active terminals detected");
    }

    // PR-CA8b commit 4: spec 08 MED-03 host-isolation surface.
    // Always print the line (so operators see "ok" confirmation
    // when their workstation is clean for Gemini), but use the
    // warn() icon when status == "warning". Round-1 H4 gate
    // ensures the warning fires only when a Gemini slot exists
    // AND production-shaped secrets are present in env.
    let hi = &r.host_isolation;
    let (hi_icon, hi_detail) = match hi.status {
        "warning" => {
            // sanitize_for_display: first_name comes from the shell environment;
            // a malicious env-var name could carry an OSC-52 or CSI sequence
            // (spec/13 §10, M-2).
            let first_name_raw = hi.first_name.as_deref().unwrap_or("<unknown>");
            let first_name = sanitize_for_display(first_name_raw);
            (
                warn(),
                format!(
                    "{} production-shaped env-var name(s) detected (e.g. {}) — Gemini reads $HOME unfiltered; specs/08 MED-03",
                    hi.detected_count,
                    first_name
                ),
            )
        }
        _ => (
            ok(),
            if hi.gemini_slots_present {
                "no production-shaped secrets in env (Gemini slot(s) provisioned)".to_string()
            } else {
                "no Gemini slot — gate inactive".to_string()
            },
        ),
    };
    println!("  Host iso:    {hi_icon} {hi_detail}");

    // Legibility (redteam R2 LOW-01 → R3 HIGH-01/MED-01/LOW-02): the
    // host-iso gate keys off `is_gemini_bound_slot` (marker existence —
    // what admits a spawn), while `gemini_auth_slots` /
    // `Gemini CLI` row / `csq status` / `csq probe --all` all key off
    // `discover_gemini` (strict parse). A slot whose marker exists but
    // whose binding will not parse is spawn-admissible yet invisible to
    // every listing surface — so the operator gets a host-iso warning
    // with no slot to act on, and delegating to `csq probe --all`
    // would NOT help (it shares `discover_gemini`'s blindness). Name
    // the offending slots directly with a self-sufficient remediation.
    // Fires whenever ANY slot is bound-but-unparseable, independent of
    // how many sibling slots are healthy (resolves the multi-slot
    // mixed case), and never on the merely-indeterminate
    // unreadable-`credentials/` case (the list is empty there, so no
    // false slot is named).
    if !r.gemini_unreadable_slots.is_empty() {
        let slots = r
            .gemini_unreadable_slots
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "  Gemini bind: {} slot(s) {slots} have a Gemini binding marker the daemon WILL \
             spawn, but the binding does not parse (corrupt or written by a newer csq) — fix \
             each with `csq logout <N>` then `csq login <N> --provider gemini`",
            warn()
        );
    }

    // an internal ticket: Codex slots where the credential file parsed but contains
    // an Anthropic-shape payload (wrong-variant binding). Mirrors the Gemini
    // unreadable row. Remediation: re-login to the Codex provider.
    if !r.codex_wrong_variant_slots.is_empty() {
        let slots = r
            .codex_wrong_variant_slots
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "  Codex bind:  {} slot(s) {slots} have a wrong-variant Codex credential (an \
             Anthropic-shape token was written to the Codex binding path) — fix each with \
             `csq logout <N>` then `csq login <N> --provider codex`",
            warn()
        );
    }

    // Resurrection forensics — only printed when the daemon has had
    // to rebuild a canonical credential file at least once. Non-zero
    // is always a WARN because it implies a broken write path that
    // the daemon is auto-healing.
    let res = &r.resurrections;
    if res.total > 0 {
        let ts_str = res
            .last_timestamp_secs
            .map(format_utc_date)
            .unwrap_or_else(|| "unknown".into());
        let sample: Vec<String> = res.recent_accounts.iter().map(|a| a.to_string()).collect();
        println!(
            "  Resurrections: {} {} canonical rebuilds across {} account(s) — last at {} — \
             investigate write path (recent: {}). Breadcrumbs: ~/.claude/accounts/.resurrection-log.jsonl",
            warn(),
            res.total,
            res.distinct_accounts,
            ts_str,
            sample.join(", ")
        );
    }

    // M1-8: A++ identity-store coexistence one-liner.
    render_identity_store_line(r.identity_store.as_ref());

    // M4-11: legacy compat state one-liner (spec/13 §9 text-mode contract).
    render_legacy_compat_line(&r.legacy_compat_state);

    // RN1-D5: unrecoverable rename label warning (post-migration only).
    if !r.unrecoverable_label_relocations.is_empty() {
        render_unrecoverable_label_relocations(&r.unrecoverable_label_relocations);
    }

    // RN1-D R1: Pass-0 skipped slots warning (post-sentinel only).
    if !r.pass0_skipped_slots.is_empty() {
        render_pass0_skipped_slots(&r.pass0_skipped_slots);
    }

    // M04 signing key status.
    let (sk_icon, sk_detail) = match r.signing_key {
        SigningKeyStatus::Present => (ok(), "signing key present"),
        SigningKeyStatus::Absent => (
            fail(),
            "signing key absent — run `csq audit init` to generate a key",
        ),
        SigningKeyStatus::Inaccessible => (
            warn(),
            "signing key present but inaccessible (locked / access-denied keychain) — \
             run `csq audit migrate-keys` to make it daemon-readable (do NOT run `audit init`)",
        ),
    };
    println!("  Signing key:   {sk_icon} {sk_detail}");

    // FIX-4: audit chain state line (next to signing key).
    {
        use csq_core::audit::AuditHealth;
        let chain_line = match &r.audit_chain_state {
            AuditHealth::Verified => format!("  Audit chain:   {} verified", ok()),
            AuditHealth::Degraded { gaps } => format!(
                "  Audit chain:   {} DEGRADED ({} historical gap{})",
                warn(),
                gaps.len(),
                if gaps.len() == 1 { "" } else { "s" }
            ),
            AuditHealth::Broken { error_kind, .. } => {
                format!("  Audit chain:   {} BROKEN ({error_kind})", fail())
            }
            AuditHealth::Unknown { reason } => {
                format!("  Audit chain:   {} UNVERIFIED ({reason})", warn())
            }
        };
        println!("{chain_line}");
    }

    // Keychain integrity-anchor verdict (DETECTOR — never bricks the chain).
    {
        use csq_core::audit::KeychainAnchorStatus;
        let anchor_line = match r.audit_keychain_anchor {
            KeychainAnchorStatus::Confirmed => {
                format!(
                    "  Audit anchor:  {} confirmed (file ↔ keychain agree)",
                    ok()
                )
            }
            KeychainAnchorStatus::Unconfirmed => format!(
                "  Audit anchor:  {} UNCONFIRMED — keychain anchor not read this run \
                 (locked / absent); forge-resistance was file-only. Run `csq audit migrate-keys`",
                warn()
            ),
            KeychainAnchorStatus::Mismatch => format!(
                "  Audit anchor:  {} MISMATCH — file / keychain / chain.json disagree; \
                 possible tampering. Run `csq audit verify --full` and investigate",
                fail()
            ),
        };
        println!("{anchor_line}");
    }

    // Roster-version-floor keychain anchor verdict (DETECTOR — never bricks).
    if let Some(floor_anchor) = r.audit_roster_floor_anchor {
        use csq_core::audit::RosterFloorAnchorStatus;
        let floor_line = match floor_anchor {
            RosterFloorAnchorStatus::Confirmed => format!(
                "  Roster floor:  {} confirmed (chain.json ↔ keychain agree)",
                ok()
            ),
            RosterFloorAnchorStatus::Unconfirmed => format!(
                "  Roster floor:  {} UNCONFIRMED — keychain anchor absent or unreadable; \
                 tamper-detection is chain.json-only for now",
                warn()
            ),
            RosterFloorAnchorStatus::Mismatch => format!(
                "  Roster floor:  {} MISMATCH — chain.json floor differs from keychain anchor; \
                 possible rollback tampering — inspect chain.json history; reinstalling the \
                 authentic roster re-anchors the floor",
                fail()
            ),
        };
        println!("{floor_line}");
    }

    // #787 b2b — policy-bundle version-floor keychain-anchor verdict (DETECTOR —
    // enforcement always uses the FILE floor; the anchor is a tamper tripwire).
    if let Some(ref bundle_floor) = r.audit_bundle_floor_anchor {
        let line = if bundle_floor == "confirmed" {
            format!(
                "  Bundle floor:  {} confirmed (file floor ↔ keychain anchor agree)",
                ok()
            )
        } else if bundle_floor == "unavailable" {
            format!(
                "  Bundle floor:  {} UNAVAILABLE — keychain anchor absent or unreadable; \
                 tamper-detection is file-floor-only for now",
                warn()
            )
        } else if bundle_floor == "corrupt" {
            format!(
                "  Bundle floor:  {} CORRUPT — the policy-bundle floor file is unreadable; \
                 the gate fails closed. Re-run `csq audit bundle-install` to rewrite the floor",
                fail()
            )
        } else {
            // "mismatch (file floor N, keychain anchor M)"
            format!(
                "  Bundle floor:  {} MISMATCH — {bundle_floor}; possible on-disk floor \
                 tamper/rollback. Enforcement uses the file floor; reinstalling the authentic \
                 bundle re-anchors it",
                fail()
            )
        };
        println!("{line}");
    }

    // M07 audit sink status.
    if let Some(ref sink_info) = r.audit_sink {
        let (sink_icon, pending_note) =
            if sink_info.pending_count == 0 && sink_info.replication_drift_count == 0 {
                (ok(), String::new())
            } else {
                let warn = warn();
                let note = format!(
                    " (pending: {}, drift: {})",
                    sink_info.pending_count, sink_info.replication_drift_count
                );
                (warn, note)
            };
        let last_anchor = sink_info.last_anchor_ts.as_deref().unwrap_or("never");
        println!(
            "  Audit sink:    {sink_icon} {} — last anchor: {last_anchor}{pending_note}",
            sink_info.active_sink
        );
    }

    // M13 — F-LEDGER-02 orphan intent records (an op recorded its intent but
    // never its outcome — a crash/kill mid-operation). Printed only when present.
    if !r.audit_orphan_intents.is_empty() {
        println!(
            "  Audit intents: {} {} orphan intent record(s) — an operation may have \
             half-completed (intent recorded, no outcome).",
            warn(),
            r.audit_orphan_intents.len()
        );
        for o in &r.audit_orphan_intents {
            println!(
                "                   - {} (seq {}, correlation {})",
                o.kind, o.seq, o.correlation_id
            );
        }
    }

    // M19 — provenance capture conformance (text-mode summary line).
    // ALL four states print a line (Finding D fix: never silent).
    match &r.seam_capture_conformance {
        SeamConformanceState::NotConfigured => {
            // Info line — no policy means no requirement, but operators should
            // know the loom requirement set has not been relayed.
            println!(
                "  Prov capture:  {} not configured — no required-hooks.json \
                 (loom requirement set not relayed; capture requirements unverified)",
                info()
            );
        }
        SeamConformanceState::Conformant => {
            println!(
                "  Prov capture:  {} hook conformance ok (all required surfaces wired)",
                ok()
            );
        }
        SeamConformanceState::Drift { drift } => {
            println!(
                "  Prov capture:  {} hook drift — required surfaces unwired: {}",
                warn(),
                drift.join(", ")
            );
        }
        SeamConformanceState::PolicyUnreadable { reason } => {
            println!(
                "  Prov capture:  {} policy unreadable — inspect \
                 <base>/audit/required-hooks.json ({reason})",
                warn()
            );
        }
    }

    // CU4 (spec 10 §10.8.3) — MCP partial-coverage advisory. Prints only when
    // the user has CLI-bound MCP servers AND the capability layer is enabled.
    if r.mcp_partial_coverage.warn {
        println!(
            "  MCP coverage:  {} partial — CLI-bound MCP servers configured ({}); \
             csq's capability-layer gate covers prompt-edit tool allow/deny only, \
             not runtime MCP traffic from these servers (spec 10 §10.8.3)",
            warn(),
            r.mcp_partial_coverage.cli_sources.join(", ")
        );
    }

    // M6 #914 — MCP-gate attestation outbox backlog. Printed only when the
    // outbox is non-empty (None in the community edition — never written there).
    if let Some(ref backlog) = r.mcp_gate_outbox_backlog {
        let age_note = match backlog.oldest_age_secs {
            Some(secs) => format!(", oldest {}", fmt_age_secs(secs)),
            None => String::new(),
        };
        // M6 #909 shard D: three daemon-aware dispositions replace the fixed-6h
        // warn/info split. Only `Stuck` is operator-actionable.
        match backlog.state {
            McpGateBacklogState::Stuck => {
                println!(
                    "  MCP gate outbox: {} {} decision(s) stuck{} — enforced MCP-gate \
                     decisions not yet on the audit chain; the daemon is draining but \
                     cannot land them — repair/initialise the chain (`csq audit verify` \
                     / `csq audit init`)",
                    warn(),
                    backlog.pending_count,
                    age_note
                );
            }
            McpGateBacklogState::Draining => {
                println!(
                    "  MCP gate outbox: {} {} decision(s) queued{} — the daemon is \
                     draining them onto the audit chain",
                    info(),
                    backlog.pending_count,
                    age_note
                );
            }
            McpGateBacklogState::PendingDaemonDown => {
                let drain_note = match backlog.last_drain_age_secs {
                    Some(secs) => format!("last drain {} ago", fmt_age_secs(secs)),
                    None => "no drain has run".to_string(),
                };
                println!(
                    "  MCP gate outbox: {} {} decision(s) pending{} — the daemon is not \
                     draining ({}); they drain when it next runs (`csq daemon start`)",
                    info(),
                    backlog.pending_count,
                    age_note,
                    drain_note
                );
            }
        }
    }

    println!();
}

/// Compact human-readable age from a second count: `45s`, `12m`, `6h`, `3d`.
/// Used by the #914 MCP-gate outbox backlog line so the operator sees "oldest
/// 8h" rather than a raw second count.
fn fmt_age_secs(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 60 * 60 {
        format!("{}m", secs / 60)
    } else if secs < 24 * 60 * 60 {
        format!("{}h", secs / (60 * 60))
    } else {
        format!("{}d", secs / (24 * 60 * 60))
    }
}

/// M4-11: render the legacy-compat-state one-liner in text mode.
///
/// Empty array renders `Legacy compat: ✓ none (Phase 4 final state)`.
/// Non-empty renders
/// `Legacy compat: ⚠ <count> bridge(s) active — <tag1> (<sched1>), <tag2> (<sched2>)`
/// per spec/13 §9.
///
/// Each tag/scheduled pair is sourced from [`LegacyCompatKind::short_tag`]
/// and [`LegacyCompatKind::scheduled_for`] via the kind round-trip
/// [`kind_from_str`] — unknown kinds (drift between spec/13 §9 and this
/// renderer) render their literal `kind` string with `(unknown_schedule)`
/// so the operator notices the spec ↔ impl drift rather than a silent
/// fallback.
fn render_legacy_compat_line(entries: &[LegacyCompatEntry]) {
    if entries.is_empty() {
        println!("  Legacy compat: {} none (Phase 4 final state)", ok());
        return;
    }
    let parts: Vec<String> = entries
        .iter()
        .map(|e| {
            match kind_from_str(&e.kind) {
                Some(k) => format!("{} ({})", k.short_tag(), k.scheduled_for()),
                // Drift between spec and impl — surface the raw kind so
                // the operator sees the inconsistency rather than a
                // silently dropped entry.
                None => format!("{} (unknown_schedule)", sanitize_for_display(&e.kind)),
            }
        })
        .collect();
    let count = entries.len();
    println!(
        "  Legacy compat: {} {} bridge(s) active — {}",
        warn(),
        count,
        parts.join(", ")
    );
}

/// RN1-D5: render the unrecoverable-rename-label warning block.
///
/// Text format (per WBS RN1-D5 requirement):
/// ```text
///   ⚠ 2 rename label(s) cannot be relocated: slot 3 "Work account", slot 5 "Backup"
///     (no by_slot UUID — log in again to mint UUIDs and re-run csq doctor)
/// ```
fn render_unrecoverable_label_relocations(slots: &[UnrecoverableSlotJson]) {
    let n = slots.len();
    let slot_list: Vec<String> = slots
        .iter()
        .map(|s| format!("slot {} {:?}", s.slot, s.accounts_email))
        .collect();
    println!(
        "  Label reloc:   {} {} rename label(s) cannot be relocated: {}",
        warn(),
        n,
        slot_list.join(", ")
    );
    println!(
        "                 (no by_slot UUID — log in again to mint UUIDs and re-run csq doctor)"
    );
}

/// RN1-D R1 (post-RN1 polish): render the Pass-0 skip warning block.
///
/// Text format:
/// ```text
///   Pass-0 skip:   ⚠ 2 slot(s) skipped (oauth_email unresolved): slot 3, slot 5
///                  (log in again to mint identity UUIDs and re-run csq doctor)
/// ```
fn render_pass0_skipped_slots(slots: &[Pass0SkippedSlot]) {
    let n = slots.len();
    let slot_list: Vec<String> = slots.iter().map(|s| format!("slot {}", s.slot)).collect();
    println!(
        "  Pass-0 skip:   {} {} slot(s) skipped (oauth_email unresolved): {}",
        warn(),
        n,
        slot_list.join(", ")
    );
    println!("                 (log in again to mint identity UUIDs and re-run csq doctor)");
}

/// M4-11: parse a `kind` string back into [`LegacyCompatKind`] for the
/// renderer's short-tag lookup. Returns `None` for any string outside
/// the closed enumeration — see [`render_legacy_compat_line`] for the
/// drift-surfacing behavior in that case.
fn kind_from_str(s: &str) -> Option<LegacyCompatKind> {
    match s {
        "v1_accounts_field_still_present" => Some(LegacyCompatKind::V1AccountsFieldStillPresent),
        "legacy_canonical_credentials_file_still_written" => {
            Some(LegacyCompatKind::LegacyCanonicalCredentialsFileStillWritten)
        }
        "legacy_canonical_codex_credentials_file_still_written" => {
            Some(LegacyCompatKind::LegacyCanonicalCodexCredentialsFileStillWritten)
        }
        "decimal_marker_content_present" => Some(LegacyCompatKind::DecimalMarkerContentPresent),
        _ => None,
    }
}

/// M1-8: render the identity-store one-liner in text mode.
///
/// Examples:
///   `Identity store: legacy-only (no Phase 1 daemon-mint observed yet)`
///   `Identity store: coexisting (3 identities, 3 legacy slots, consistent)`
///   `Identity store: coexisting (3 identities, 3 legacy slots, INCONSISTENT: OrphanLegacySlot(4))`
/// an internal journal entry: render the top-level phase-4-incomplete alarm. Two
/// lines: a `fail()` header naming the impending daemon refusal, and a
/// remediation hint pointing at `csq doctor --repair-identities`. The
/// counts are pre-computed by `build_phase4_incomplete_alarm`.
fn render_phase4_incomplete_alarm(alarm: &Phase4IncompleteAlarm) {
    let slot_word = if alarm.affected_slot_count == 1 {
        "slot"
    } else {
        "slots"
    };
    let file_word = if alarm.missing_file_count == 1 {
        "identity file"
    } else {
        "identity files"
    };
    println!(
        "  Phase 4:     {} INCOMPLETE — {} {} affected ({} {} missing); daemon will refuse to start",
        fail(),
        alarm.affected_slot_count,
        slot_word,
        alarm.missing_file_count,
        file_word,
    );
    println!(
        "               Remediation: run `csq doctor --repair-identities` (auto-heals from legacy sources where present;"
    );
    println!(
        "               re-run `csq login <N>` for any slot whose legacy source is also gone)."
    );
}

/// Builds the `(detail)` text for the `Identity store:` doctor line — a pure
/// function so the render is unit-testable (the caller `println!`s it).
///
/// CRITICAL (binary-smoke finding): the `consistency` Vec is rendered for EVERY
/// state, including `LegacyOnly`. `audit_coexistence` surfaces
/// `CurrentAccountDrift` for all states (HIGH-2); a prior version hardcoded the
/// LegacyOnly detail and silently dropped those findings, so `csq doctor`'s
/// icon flipped to ⚠ but never NAMED the drift on a LegacyOnly host. Both the
/// state-specific prefix AND the consistency label must appear.
fn identity_store_detail(r: &IdentityStoreReport) -> String {
    let consistency_label = if r.consistency.is_empty() {
        "consistent".to_string()
    } else {
        let parts: Vec<String> = r
            .consistency
            .iter()
            .map(|c| match c {
                ConsistencyState::SlotCountMismatch { legacy, identity } => {
                    format!("SlotCountMismatch (legacy={legacy}, identity={identity})")
                }
                ConsistencyState::OrphanIdentity { uuid } => format!("OrphanIdentity({uuid})"),
                ConsistencyState::OrphanLegacySlot { slot } => format!("OrphanLegacySlot({slot})"),
                ConsistencyState::MissingCredentialsAtUuidPath { uuid } => {
                    format!("MissingCredentialsAtUuidPath({uuid})")
                }
                ConsistencyState::MissingSettingsAtUuidPath { uuid } => {
                    format!("MissingSettingsAtUuidPath({uuid})")
                }
                ConsistencyState::CurrentAccountDrift { slot, cached } => {
                    format!("CurrentAccountDrift(slot={slot}, cached={cached}) — run `csq repair`")
                }
            })
            .collect();
        format!("INCONSISTENT: {}", parts.join("; "))
    };

    match r.state {
        CoexistenceState::LegacyOnly => {
            if r.consistency.is_empty() {
                "no Phase 1 daemon-mint observed yet".to_string()
            } else {
                format!("no Phase 1 daemon-mint observed yet, {consistency_label}")
            }
        }
        CoexistenceState::Coexisting | CoexistenceState::IdentityOnly => {
            format!(
                "{} identities, {} legacy slots, {}",
                r.identity_count, r.profile_slot_count, consistency_label
            )
        }
    }
}

fn render_identity_store_line(report: Option<&IdentityStoreReport>) {
    let Some(r) = report else {
        println!("  Identity store: - audit unavailable (lock contention)");
        return;
    };

    let state_label = match r.state {
        CoexistenceState::LegacyOnly => "legacy-only",
        CoexistenceState::Coexisting => "coexisting",
        CoexistenceState::IdentityOnly => "identity-only",
    };

    // `consistency` is a list — an empty list is the consistent signal,
    // a non-empty list carries every detected issue kind, rendered in
    // `audit_coexistence`'s collection order (not a severity ranking).
    let detail = identity_store_detail(r);

    let icon = if r.consistency.is_empty() {
        ok()
    } else {
        warn()
    };

    println!("  Identity store: {icon} {state_label} ({detail})");
}

/// Formats a Unix epoch second count as `YYYY-MM-DD HH:MM:SS UTC`.
///
/// Hand-rolled because bringing in `chrono` or `time` for a single
/// print statement is excess baggage. The daemon stamps timestamps
/// with `SystemTime::now().duration_since(UNIX_EPOCH)` so valid
/// values are always non-negative and within the i64 range.
fn format_utc_date(secs: u64) -> String {
    let days = secs / 86_400;
    let time_of_day = secs % 86_400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;

    // Civil from days algorithm (Howard Hinnant, "date algorithms",
    // public domain). Converts days-since-1970-01-01 into Y/M/D.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

fn ok() -> &'static str {
    "\x1b[32m✓\x1b[0m"
}

fn warn() -> &'static str {
    "\x1b[33m⚠\x1b[0m"
}

fn fail() -> &'static str {
    "\x1b[31m✗\x1b[0m"
}

fn info() -> &'static str {
    "\x1b[36mℹ\x1b[0m"
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn build_token_owner_report_partitions_verdicts() {
        use csq_core::daemon::custodian::SlotOwnership;
        let results = vec![
            (1u16, "a@x.com".to_string(), SlotOwnership::Owned),
            (2u16, "b@x.com".to_string(), SlotOwnership::Contaminated),
            (3u16, "c@x.com".to_string(), SlotOwnership::Unknown),
        ];
        let r = build_token_owner_report(&results);
        assert_eq!(r.checked, 3);
        assert_eq!(r.contaminated, vec![2]);
        assert_eq!(r.unknown, vec![3]);
        // JSON status strings are stable + machine-parseable.
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"status\":\"contaminated\""));
        assert!(json.contains("\"status\":\"owned\""));
        assert!(json.contains("\"status\":\"unknown\""));
        // The label is echoed verbatim (it's an email, not a path).
        assert!(json.contains("b@x.com"));
    }

    #[test]
    fn build_token_owner_report_empty_is_clean() {
        let r = build_token_owner_report(&[]);
        assert_eq!(r.checked, 0);
        assert!(r.contaminated.is_empty());
        assert!(r.unknown.is_empty());
    }

    // ── helpers ───────────────────────────────────────────────────────────

    /// Create a minimal `config-<N>` directory with a real `.credentials.json`.
    fn make_config(base: &std::path::Path, n: u16) -> std::path::PathBuf {
        let dir = base.join(format!("config-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".credentials.json"), "{}").unwrap();
        dir
    }

    /// Create a `term-<pid>` handle directory with a symlink to config-N's
    /// .credentials.json. Uses an absolute target path so the component
    /// extraction in check_terminals_unix works reliably.
    #[cfg(unix)]
    fn make_handle_dir_with_symlink(base: &std::path::Path, pid: u32, config_name: &str) {
        let handle = base.join(format!("term-{pid}"));
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(handle.join(".live-pid"), pid.to_string()).unwrap();
        // Absolute path target so component scan finds "config-N"
        let target = base.join(config_name).join(".credentials.json");
        std::os::unix::fs::symlink(&target, handle.join(".credentials.json")).unwrap();
    }

    /// Create a `term-<pid>` handle directory with an identity-keyed symlink
    /// to `identities/<UUID>/credentials.json` (the post-M3-3 modern shape).
    /// Used by R1 H1-DA regression tests.
    #[cfg(unix)]
    fn make_handle_dir_with_identity_symlink(base: &std::path::Path, pid: u32, uuid: &str) {
        let handle = base.join(format!("term-{pid}"));
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(handle.join(".live-pid"), pid.to_string()).unwrap();
        let identity_dir = base.join("identities").join(uuid);
        std::fs::create_dir_all(&identity_dir).unwrap();
        let target = identity_dir.join("credentials.json");
        std::fs::write(&target, "{}").unwrap();
        std::os::unix::fs::symlink(&target, handle.join(".credentials.json")).unwrap();
    }

    /// Write a minimal `profiles.json` containing a slot→UUID mapping so
    /// `check_terminals_unix`'s identity-keyed resolution can find the slot.
    #[cfg(unix)]
    fn make_profiles_with_slot_uuid(base: &std::path::Path, slot: u16, uuid: &str) {
        use csq_core::accounts::profiles;
        let path = profiles::profiles_path(base);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let json =
            format!(r#"{{"by_slot":{{"{slot}":"{uuid}"}},"by_email":{{}},"profiles":{{}}}}"#);
        std::fs::write(&path, json).unwrap();
    }

    // ── check_terminals tests (Unix only) ─────────────────────────────────

    // ── cache_sweeper tests (PR-CA9b T20 / R3/B90) ────────────────────────

    #[test]
    fn cache_sweeper_reports_never_run_when_state_file_absent() {
        let tmp = TempDir::new().unwrap();
        let info = check_cache_sweeper(tmp.path());
        assert_eq!(info.status, "never_run");
        assert!(info.last_sweep_at.is_none());
        assert_eq!(info.files_swept_last_run, 0);
        assert!(!info.sweep_partial);
    }

    #[test]
    fn doctor_json_surfaces_sweeper_state_after_sweep_runs() {
        let tmp = TempDir::new().unwrap();
        // Pre-populate the sweeper state file as if a tick had run.
        let state_path = coc_cache_sweeper::state_file_path(tmp.path());
        let snap = coc_cache_sweeper::SweeperSnapshot {
            last_sweep_at: Some("2026-05-03T10:00:00Z".into()),
            last_sweep_duration_ms: 1234,
            sweep_partial: false,
            sweep_lag_minutes: 0,
            files_swept_last_run: 42,
            files_skipped_last_run: 7,
            cache_sweep_blocked: 0,
        };
        coc_cache_sweeper::write_state_file(&state_path, &snap).unwrap();

        let info = check_cache_sweeper(tmp.path());
        assert_eq!(info.status, "ok");
        assert_eq!(info.files_swept_last_run, 42);
        assert_eq!(info.files_skipped_last_run, 7);
        assert_eq!(info.last_sweep_duration_ms, 1234);
        // Doctor surfaces the persisted timestamp verbatim.
        assert_eq!(info.last_sweep_at.as_deref(), Some("2026-05-03T10:00:00Z"));
    }

    #[test]
    #[cfg(unix)]
    fn no_dirs_reports_zero() {
        // Arrange
        let tmp = TempDir::new().unwrap();

        // Act
        let info = check_terminals(tmp.path());

        // Assert
        assert!(info.check_available);
        assert_eq!(info.modern_count, 0);
        assert_eq!(info.legacy_count, 0);
    }

    #[test]
    #[cfg(unix)]
    fn config_dir_without_credentials_not_counted_as_legacy() {
        // Arrange: config dir exists but has no .credentials.json
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("config-1")).unwrap();

        // Act
        let info = check_terminals(tmp.path());

        // Assert: no credentials means not a legacy terminal
        assert_eq!(info.legacy_count, 0);
    }

    #[test]
    #[cfg(unix)]
    fn config_dir_with_credentials_but_no_handle_counted_as_legacy() {
        // Arrange: config-1 has credentials, no term-<pid> adopts it
        let tmp = TempDir::new().unwrap();
        make_config(tmp.path(), 1);

        // Act
        let info = check_terminals(tmp.path());

        // Assert: one legacy, zero modern
        assert_eq!(info.legacy_count, 1);
        assert_eq!(info.modern_count, 0);
    }

    /// #578 regression: an IDLE but identity-store-member account
    /// (`config-N` has credentials, `profiles.json::by_slot` has a UUID for
    /// slot N, but no live `term-<pid>` is bound to it right now) is MODERN,
    /// not legacy. The prior heuristic counted every unbound config-N as
    /// "legacy", producing a constant false-positive on hosts that rotate
    /// between accounts (e.g. 8 OAuth accounts, only 3 with a terminal open).
    #[test]
    #[cfg(unix)]
    fn idle_by_slot_member_account_not_counted_as_legacy() {
        let tmp = TempDir::new().unwrap();
        // config-1: credentials + by_slot UUID, NO handle dir → modern idle.
        make_config(tmp.path(), 1);
        make_profiles_with_slot_uuid(tmp.path(), 1, "00000000-0000-0000-0000-000000000001");

        let info = check_terminals(tmp.path());

        assert_eq!(
            info.legacy_count, 0,
            "an idle account present in by_slot is MODERN (#578), not legacy"
        );
        assert_eq!(info.modern_count, 0, "no live handle dir → zero modern");
    }

    /// #578 regression companion: a `config-N` with credentials and NO
    /// `by_slot` entry (genuine pre-identity-store install) IS still counted
    /// as legacy — the refinement narrows the predicate, it does not disable
    /// it. Guards against over-correction that would silence the real signal.
    #[test]
    #[cfg(unix)]
    fn pre_migration_config_without_by_slot_still_counted_as_legacy() {
        let tmp = TempDir::new().unwrap();
        // config-1: credentials, NO profiles.json at all → pre-migration.
        make_config(tmp.path(), 1);

        let info = check_terminals(tmp.path());

        assert_eq!(
            info.legacy_count, 1,
            "a config-N with creds and no by_slot UUID is genuine legacy (#578)"
        );
    }

    /// #578 redteam follow-up (deep-analyst MED-1): `legacy_count` MUST use
    /// the SAME recovery-backed keep-set as `detect_decimal_marker` /
    /// `audit_coexistence` — `by_slot` ∪ `by_slot_identity` ∪ gemini marker
    /// — not `by_slot` alone. A 3P API-key / Codex slot (recovery-backed via
    /// `by_slot_identity`, no `by_slot` UUID) with `config-N/.credentials.json`
    /// and no live terminal must NOT be flagged as a legacy terminal.
    #[test]
    #[cfg(unix)]
    fn idle_by_slot_identity_member_not_counted_as_legacy() {
        use csq_core::accounts::profiles;
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        // config-9: credentials present, but the slot is recovery-backed via
        // by_slot_identity (3P API key), NOT by_slot. No live handle dir.
        make_config(base, 9);
        let pp = profiles::profiles_path(base);
        std::fs::create_dir_all(pp.parent().unwrap()).unwrap();
        std::fs::write(
            &pp,
            r#"{"by_slot":{},"by_slot_identity":{"9":"apikey:deepseek"},"by_email":{},"profiles":{}}"#,
        )
        .unwrap();

        let info = check_terminals(base);

        assert_eq!(
            info.legacy_count, 0,
            "a by_slot_identity (3P) recovery-backed slot is MODERN, not legacy (#578 MED-1)"
        );
    }

    /// #578 redteam follow-up (deep-analyst MED-2): the gemini binding-marker
    /// channel (regular-file `credentials/gemini-<N>.json`) is the third
    /// recovery channel. A slot backed ONLY by that marker (pre-backfill
    /// Gemini window — no `by_slot`, no `by_slot_identity`) must NOT be
    /// flagged as a legacy terminal.
    #[test]
    #[cfg(unix)]
    fn idle_gemini_marker_backed_slot_not_counted_as_legacy() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        make_config(base, 9);
        // Regular-file gemini binding marker for slot 9, no profiles maps.
        let creds = base.join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("gemini-9.json"), "{}").unwrap();

        let info = check_terminals(base);

        assert_eq!(
            info.legacy_count, 0,
            "a gemini-marker recovery-backed slot is MODERN, not legacy (#578 MED-2)"
        );
    }

    #[test]
    #[cfg(unix)]
    fn living_handle_dir_counts_as_modern_and_suppresses_legacy() {
        // Arrange: config-1 with credentials, adopted by a term-1
        // (PID 1 = init/launchd — always alive on Unix)
        let tmp = TempDir::new().unwrap();
        make_config(tmp.path(), 1);
        make_handle_dir_with_symlink(tmp.path(), 1, "config-1");

        // Act
        let info = check_terminals(tmp.path());

        // Assert: PID 1 is alive → one modern terminal; config-1 is adopted
        // so not counted as legacy.
        assert_eq!(info.modern_count, 1);
        assert_eq!(info.legacy_count, 0);
    }

    #[test]
    #[cfg(unix)]
    fn dead_handle_dir_not_counted_as_modern() {
        // Arrange: config-1 with credentials, term-999999999 pointing at it
        let tmp = TempDir::new().unwrap();
        make_config(tmp.path(), 1);
        make_handle_dir_with_symlink(tmp.path(), 999_999_999, "config-1");

        // Act
        let info = check_terminals(tmp.path());

        // Assert: dead PID → zero modern; config-1 not adopted → one legacy.
        assert_eq!(info.modern_count, 0);
        assert_eq!(info.legacy_count, 1);
    }

    /// R1 H1-DA fix-wave regression: post-M3-3 modern handle dirs symlink
    /// `.credentials.json` through `identities/<UUID>/credentials.json` rather
    /// than `config-N/.credentials.json`. The prior implementation only scanned
    /// the `config-N` shape and therefore reported every modern terminal's slot
    /// as "legacy". The rewrite resolves UUID → slot via `profiles.json::by_slot`.
    #[test]
    #[cfg(unix)]
    fn living_handle_dir_with_identity_symlink_counts_as_modern() {
        // Arrange: config-1 has credentials; profiles.json maps slot 1 → UUID;
        // term-1 (PID 1 = init/launchd, always alive) symlinks to identity path.
        let tmp = TempDir::new().unwrap();
        make_config(tmp.path(), 1);
        let uuid = "00000000-0000-0000-0000-000000000001";
        make_profiles_with_slot_uuid(tmp.path(), 1, uuid);
        make_handle_dir_with_identity_symlink(tmp.path(), 1, uuid);

        // Act
        let info = check_terminals(tmp.path());

        // Assert: identity-keyed symlink → modern; slot 1 adopted → NOT legacy.
        assert_eq!(info.modern_count, 1);
        assert_eq!(
            info.legacy_count, 0,
            "M3-3 identity-keyed symlinks MUST resolve to the adopted slot, \
             not be reported as legacy"
        );
    }

    /// R1 H1-DA fix-wave regression: identity-keyed symlink whose UUID has no
    /// entry in `profiles.json::by_slot` (e.g. orphaned identity dir).  We
    /// still count the handle dir as modern (PID alive, .credentials.json link
    /// present) but cannot attribute the slot — so the underlying config-N
    /// stays in the legacy bucket if it has credentials.
    #[test]
    #[cfg(unix)]
    fn identity_symlink_without_profiles_mapping_does_not_suppress_legacy() {
        let tmp = TempDir::new().unwrap();
        make_config(tmp.path(), 1);
        // No profiles.json mapping for this UUID — orphan identity.
        make_handle_dir_with_identity_symlink(
            tmp.path(),
            1,
            "deadbeef-dead-dead-dead-deaddeaddead",
        );

        let info = check_terminals(tmp.path());
        // PID 1 is alive → handle dir counted as modern.
        assert_eq!(info.modern_count, 1);
        // No UUID → slot mapping → config-1 stays in legacy bucket.
        assert_eq!(info.legacy_count, 1);
    }

    #[test]
    #[cfg(unix)]
    fn mixed_layout_detected_correctly() {
        // Arrange:
        //   config-1 — adopted by living term-1 (PID 1 = init/launchd)
        //   config-2 — no living handle dir → legacy
        //   term-999999999 — dead PID (orphan, adopts config-1 but is dead)
        let tmp = TempDir::new().unwrap();
        make_config(tmp.path(), 1);
        make_config(tmp.path(), 2);
        // Living handle for config-1
        make_handle_dir_with_symlink(tmp.path(), 1, "config-1");
        // Dead orphaned handle for config-1
        make_handle_dir_with_symlink(tmp.path(), 999_999_999, "config-1");

        // Act
        let info = check_terminals(tmp.path());

        // Assert
        assert_eq!(info.modern_count, 1); // only PID 1 is alive
        assert_eq!(info.legacy_count, 1); // config-2 has no living adopter
    }

    // ── TerminalInfo JSON serialization ───────────────────────────────────

    /// Helper: build a minimal DoctorReport with specific terminal info.
    fn make_report(terminals: TerminalInfo) -> DoctorReport {
        DoctorReport {
            schema_version: DOCTOR_SCHEMA_VERSION,
            version: "0.0.0".into(),
            platform: PlatformInfo {
                os: "test".into(),
                arch: "x86_64".into(),
            },
            claude_code: None,
            codex_cli: None,
            gemini_cli: None,
            claude_auth_slots: 0,
            codex_auth_slots: 0,
            gemini_auth_slots: 0,
            gemini_unreadable_slots: Vec::new(),
            codex_wrong_variant_slots: Vec::new(),
            js_runtime: JsRuntimeInfo {
                found: false,
                path: None,
            },
            settings: SettingsInfo {
                exists: false,
                statusline_configured: false,
                statusline_command: None,
            },
            daemon: DaemonInfo {
                status: "not running".into(),
                pid: None,
                socket_healthy: None,
                version_drift: None,
            },
            accounts: AccountsInfo {
                total: 0,
                with_credentials: 0,
                expired: 0,
            },
            broker_failed: BrokerFailedInfo {
                count: 0,
                entries: Vec::new(),
            },
            mixed_state_slots: MixedStateInfo {
                count: 0,
                entries: Vec::new(),
            },
            terminals,
            resurrections: ResurrectionInfo {
                total: 0,
                distinct_accounts: 0,
                last_timestamp_secs: None,
                recent_accounts: Vec::new(),
            },
            host_isolation: HostIsolationStatus {
                status: "ok",
                gemini_slots_present: false,
                detected_count: 0,
                first_name: None,
                detected_var_names: Vec::new(),
            },
            cache_sweeper: CacheSweeperInfo {
                status: "never_run",
                last_sweep_at: None,
                last_sweep_duration_ms: 0,
                sweep_partial: false,
                sweep_lag_minutes: 0,
                files_swept_last_run: 0,
                files_skipped_last_run: 0,
                cache_sweep_blocked: 0,
            },
            identity_store: None,
            legacy_compat_state: Vec::new(),
            phase4_incomplete: None,
            unrecoverable_label_relocations: Vec::new(),
            pass0_skipped_slots: Vec::new(),
            signing_key: SigningKeyStatus::Absent,
            audit_sink: None,
            audit_orphan_intents: Vec::new(),
            audit_historical_key_gaps: Vec::new(),
            audit_trust_plane_grade: doctor_trust_plane_grade(
                &csq_core::audit::AuditHealth::Verified,
                false,
            ),
            // Test fixture has no leveled chain → grade is COMPATIBLE (no
            // summary). The grade↔summary co-presence invariant is asserted by
            // `doctor_grade_surface_includes_level_summary` (M3a AC-7, doctor).
            audit_verification_level_summary: None,
            // No chain on disk → verify_chain returns Ok(default) → Verified.
            // (Unknown IS reachable in production via KeychainUnavailable; this
            // test fixture just has no chain, so Verified.)
            audit_chain_state: csq_core::audit::AuditHealth::Verified,
            audit_keychain_anchor: csq_core::audit::KeychainAnchorStatus::Confirmed,
            // No roster installed in test fixtures → None (omitted from JSON).
            audit_roster_floor_anchor: None,
            audit_bundle_floor_anchor: None,
            // M18 seam: no custody dirs in test fixtures.
            seam_quarantine_count: None,
            seam_pending_provenance_count: None,
            seam_held_predecessor_count: None,
            seam_registry_status: "ok".to_string(),
            seam_pending_backlog_note: None,
            // M19: no required-hooks.json in test fixtures → NotConfigured.
            seam_capture_conformance: SeamConformanceState::NotConfigured,
            mcp_partial_coverage: McpPartialCoverage {
                warn: false,
                cli_sources: Vec::new(),
            },
            mcp_gate_outbox_backlog: None,
            custodian_identity_canary: CustodianIdentityCanary::default(),
        }
    }

    // ============================================================
    // #787 b2b — policy-bundle floor keychain-anchor doctor projection
    // ============================================================

    /// No policy bundle installed (no floor file) → the field is omitted.
    #[cfg(feature = "enterprise")]
    #[test]
    fn bundle_floor_anchor_absent_when_no_bundle() {
        let tmp = TempDir::new().unwrap();
        assert!(
            doctor_bundle_floor_anchor(tmp.path()).is_none(),
            "no floor file → None (field omitted)"
        );
    }

    /// A present-but-unparseable floor file → `corrupt` (the gate fails closed;
    /// doctor surfaces it as a distinct finding).
    #[cfg(feature = "enterprise")]
    #[test]
    fn bundle_floor_anchor_corrupt_when_floor_unreadable() {
        use csq_core::phase2b::bundle_floor::bundle_floor_path;
        let tmp = TempDir::new().unwrap();
        let p = bundle_floor_path(tmp.path());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"garbage").unwrap();
        assert_eq!(
            doctor_bundle_floor_anchor(tmp.path()).as_deref(),
            Some("corrupt"),
            "corrupt floor file → \"corrupt\""
        );
    }

    /// A valid floor with no readable keychain anchor → `unavailable`
    /// (no chain initialized → no anchor tripwire; file floor stands alone).
    #[cfg(feature = "enterprise")]
    #[test]
    fn bundle_floor_anchor_unavailable_without_keychain_anchor() {
        use csq_core::phase2b::bundle_floor::write_bundle_floor;
        csq_core::audit::key_custody::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        write_bundle_floor(tmp.path(), 5).unwrap();
        assert_eq!(
            doctor_bundle_floor_anchor(tmp.path()).as_deref(),
            Some("unavailable"),
            "floor present, no chain/keychain anchor → \"unavailable\""
        );
    }

    /// A keychain anchor that DISAGREES with the file floor → `mismatch (...)`
    /// — the tamper tripwire the b1 LOW folded into doctor. Enforcement still
    /// uses the FILE floor; doctor reports the disagreement.
    #[cfg(feature = "enterprise")]
    #[test]
    fn bundle_floor_anchor_mismatch_is_projected() {
        use csq_core::phase2b::bundle_floor::write_bundle_floor;
        csq_core::audit::key_custody::init_mock_keyring();
        let tmp = TempDir::new().unwrap();
        // doctor reads the chain id from ChainState — initialize one so the
        // keychain anchor (written under the same chain id) is discoverable.
        // Keychain isolation: the mock keyring is process-global keyed by
        // (service, chain_id); "chain-doctor-b2b" MUST stay unique across every
        // test in this binary that writes to AUDIT_SIGNING_SERVICE_NAME, or a
        // sibling's floor write would poison this mismatch assertion.
        let chain_id = "chain-doctor-b2b";
        csq_core::audit::ChainState::new(chain_id)
            .save(tmp.path())
            .unwrap();
        csq_core::phase2b::bundle_floor::write_bundle_floor_to_keychain(
            csq_core::audit::AUDIT_SIGNING_SERVICE_NAME,
            chain_id,
            20,
        );
        write_bundle_floor(tmp.path(), 3).unwrap();
        let got = doctor_bundle_floor_anchor(tmp.path());
        assert_eq!(
            got.as_deref(),
            Some("mismatch (file floor 3, keychain anchor 20)"),
            "file 3 vs anchor 20 → mismatch projection; got {got:?}"
        );
    }

    // ============================================================
    // PR-CA8b commit 4 — host-isolation gate (round-1 H4)
    // ============================================================

    /// Provision a Gemini slot exactly the way production does — a
    /// canonical `GeminiBinding` written via `write_binding` to
    /// `credentials/gemini-<N>.json` (NOT the obsolete
    /// `providers/<N>/binding.json` path the host-iso predicate
    /// scanned before the journal regression fix). `code_assist_oauth`
    /// mode mirrors the real on-host state of slot 13 that exposed
    /// the dead-path bug.
    fn provision_canonical_gemini_slot(base: &std::path::Path, slot_id: u16) {
        use csq_core::providers::gemini::provisioning::{write_binding, AuthMode, GeminiBinding};
        use csq_core::types::AccountNum;
        let binding = GeminiBinding::new(AuthMode::CodeAssistOAuth, "auto");
        write_binding(base, AccountNum::try_from(slot_id).unwrap(), &binding).unwrap();
        // The canonical path must NOT create a `providers/` tree —
        // assert the regression invariant at the fixture itself.
        assert!(
            !base.join("providers").exists(),
            "canonical Gemini provisioning must not touch providers/ (dead path)"
        );
    }

    /// PR-CA8b R1-H4: cc/codex-only deployment (no Gemini slot)
    /// gets `ok` even when production-shaped secrets are in env.
    /// The gate requires BOTH conditions; either alone → `ok`.
    /// Uses `check_host_isolation_with_env` to pass synthetic env
    /// without mutating the real `std::env` (which would race
    /// against other tests per `.claude/rules/testing.md` Rule 6).
    #[test]
    fn csq_doctor_reports_host_isolation_ok_when_no_gemini_slots_even_with_secrets() {
        let tmp = TempDir::new().unwrap();
        // Synthetic env with a production-shaped secret. No
        // gemini slot provisioned — base_dir is empty.
        let env = ["PATH", "HOME", "ANTHROPIC_API_KEY"];
        let status = check_host_isolation_with_env(tmp.path(), env.iter().copied());

        assert!(
            !status.gemini_slots_present,
            "no slot provisioned must report false"
        );
        assert!(
            status.detected_count > 0,
            "ANTHROPIC_API_KEY must trigger detection"
        );
        assert_eq!(
            status.status, "ok",
            "no Gemini slot must gate to ok regardless of env"
        );
    }

    /// PR-CA8b R1-H4: clean env with a Gemini slot → `ok`.
    #[test]
    fn csq_doctor_reports_host_isolation_ok_when_gemini_slot_and_clean_env() {
        let tmp = TempDir::new().unwrap();
        // Canonical Gemini slot: binding at credentials/gemini-1.json,
        // the SAME path `discover_gemini` / `csq status` / the daemon
        // use. (Was `providers/1/binding.json` — a dead path; see the
        // regression note in `check_host_isolation_with_env`.)
        provision_canonical_gemini_slot(tmp.path(), 1);

        // Synthetic clean env — no production-shaped names.
        let env = ["PATH", "HOME", "USER", "TERM", "LANG"];
        let status = check_host_isolation_with_env(tmp.path(), env.iter().copied());

        assert!(
            status.gemini_slots_present,
            "canonical credentials/gemini-1.json must register as gemini slot present"
        );
        assert_eq!(
            status.detected_count, 0,
            "clean env must report no detected names"
        );
        assert_eq!(
            status.status, "ok",
            "clean env + gemini slot must gate to ok"
        );
    }

    /// PR-CA8b R1-H4 + R2-H3: Gemini slot + secrets in env →
    /// `warning` with first-name exemplar.
    #[test]
    fn csq_doctor_reports_host_isolation_warning_when_gemini_slot_and_secrets() {
        let tmp = TempDir::new().unwrap();
        // Canonical Gemini slot (credentials/gemini-1.json).
        provision_canonical_gemini_slot(tmp.path(), 1);

        let env = ["PATH", "HOME", "ANTHROPIC_API_KEY", "GITHUB_TOKEN"];
        let status = check_host_isolation_with_env(tmp.path(), env.iter().copied());

        assert!(status.gemini_slots_present);
        assert_eq!(status.detected_count, 2);
        assert_eq!(status.status, "warning");
        // Round-3 R3-H7 priority: ANTHROPIC_API_KEY is first in
        // EXACT_PRIORITY so it surfaces as the exemplar even when
        // GITHUB_TOKEN is also present.
        assert_eq!(
            status.first_name.as_deref(),
            Some("ANTHROPIC_API_KEY"),
            "exemplar must prefer EXACT-priority list over lex-first"
        );
    }

    /// Regression (journal — `csq doctor` "no Gemini slot" vs
    /// `csq status` showing slot 13 as a live gemini oauth slot).
    ///
    /// Reproduces the EXACT on-host state that exposed the bug: a
    /// `code_assist_oauth` binding at `credentials/gemini-13.json`
    /// and NO `providers/` tree anywhere. The old predicate scanned
    /// `providers/<N>/binding.json` — a path no production code
    /// writes — so it returned `gemini_slots_present == false` for
    /// every real Gemini slot, silently suppressing the spec-08
    /// MED-03 host-isolation warning when production secrets were in
    /// env. Asserts the gate now fires on the canonical path AND
    /// that the dead path is genuinely absent in the fixture.
    #[test]
    fn host_isolation_gate_fires_for_canonical_gemini_slot_without_providers_path() {
        let tmp = TempDir::new().unwrap();
        provision_canonical_gemini_slot(tmp.path(), 13);

        // The dead path the old predicate keyed off must NOT exist —
        // this is the production reality the bug missed.
        assert!(
            !tmp.path()
                .join("providers")
                .join("13")
                .join("binding.json")
                .exists(),
            "fixture must reproduce the no-providers/ on-host state"
        );

        // Clean env + canonical gemini slot → ok (slot detected, no
        // secrets to warn about).
        let clean = ["PATH", "HOME", "USER", "TERM", "LANG"];
        let s_clean = check_host_isolation_with_env(tmp.path(), clean.iter().copied());
        assert!(
            s_clean.gemini_slots_present,
            "canonical credentials/gemini-13.json MUST be detected (regression: \
             old providers/<N>/binding.json scan returned false here)"
        );
        assert_eq!(s_clean.status, "ok", "clean env + slot → ok");

        // Production secrets in env + canonical gemini slot → warning
        // (this is the spec-08 MED-03 case the bug silently suppressed
        // for the entire identity-store / credentials-keyed layout).
        let dirty = ["PATH", "HOME", "ANTHROPIC_API_KEY"];
        let s_dirty = check_host_isolation_with_env(tmp.path(), dirty.iter().copied());
        assert!(s_dirty.gemini_slots_present);
        assert!(
            s_dirty.detected_count > 0,
            "ANTHROPIC_API_KEY must be detected"
        );
        assert_eq!(
            s_dirty.status, "warning",
            "spec-08 MED-03: gemini slot + production secrets MUST warn"
        );
    }

    /// Redteam R1 MED-02 (substantive): the MED-03 gate MUST track
    /// what admits a Gemini SPAWN (`is_gemini_bound_slot` — marker
    /// existence), NOT the strict-parse listing (`discover_gemini`).
    /// A malformed `credentials/gemini-<N>.json` is dropped by
    /// `discover_gemini` but the daemon's IPC gate still spawns it —
    /// so a listing-based gate would silently suppress the security
    /// warning for exactly the corrupt-binding host. Proves the gate
    /// fires here AND that the discarded `discover_gemini`-based fix
    /// would NOT have.
    #[test]
    fn host_isolation_warns_for_malformed_binding_that_discover_gemini_drops() {
        let tmp = TempDir::new().unwrap();
        let creds = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        // Marker file exists but is unparseable → is_gemini_bound_slot
        // = true (spawn admissible), discover_gemini = drops it.
        std::fs::write(creds.join("gemini-7.json"), b"{ not valid json").unwrap();

        // Structural preconditions (redteam R2 (d) — do not couple the
        // proof solely to discover_gemini's behavior): the marker IS
        // spawn-admissible AND its binding genuinely fails to parse.
        let slot7 = csq_core::types::AccountNum::try_from(7).unwrap();
        assert!(
            csq_core::providers::gemini::provisioning::is_gemini_bound_slot(tmp.path(), slot7),
            "precondition: marker MUST be spawn-admissible (daemon would run it)"
        );
        assert!(
            csq_core::providers::gemini::provisioning::read_binding(tmp.path(), slot7).is_err(),
            "precondition: the binding MUST genuinely fail to parse"
        );
        assert!(
            csq_core::accounts::discovery::discover_gemini(tmp.path()).is_empty(),
            "precondition: discover_gemini MUST drop the malformed marker \
             (this is why a listing-based gate would have suppressed the warning)"
        );

        let env = ["PATH", "HOME", "ANTHROPIC_API_KEY"];
        let status = check_host_isolation_with_env(tmp.path(), env.iter().copied());

        assert!(
            status.gemini_slots_present,
            "spawn-admissible marker MUST count as a Gemini slot for the \
             security gate even when its binding does not parse"
        );
        assert_eq!(
            status.status, "warning",
            "spec-08 MED-03: corrupt-binding host with secrets is the case \
             that MOST needs the warning — it MUST NOT be suppressed"
        );
    }

    /// Redteam R1 MED-1: an unreadable `credentials/` dir is
    /// slot-presence-INDETERMINATE. Security doctrine
    /// (`csq_core::env`: false-negatives unacceptable) → fail TOWARD
    /// warn rather than silently report "no Gemini slot" when slot
    /// presence cannot be proven.
    #[cfg(unix)]
    #[test]
    fn host_isolation_fails_toward_warn_when_credentials_dir_unreadable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let creds = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        // 0o000 → read_dir yields EACCES (≠ NotFound) → indeterminate.
        std::fs::set_permissions(&creds, std::fs::Permissions::from_mode(0o000)).unwrap();

        let env = ["PATH", "HOME", "ANTHROPIC_API_KEY"];
        let status = check_host_isolation_with_env(tmp.path(), env.iter().copied());

        // Restore perms BEFORE asserting so TempDir cleanup never
        // fails regardless of assertion outcome.
        std::fs::set_permissions(&creds, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            status.gemini_slots_present,
            "unreadable credentials/ → presence INDETERMINATE → MUST be \
             treated as present (fail toward warn), not silently absent"
        );
        assert_eq!(
            status.status, "warning",
            "indeterminate slot presence + production secrets MUST warn"
        );
    }

    /// Redteam R3 HIGH-01 / MED-01 / LOW-02: the self-legibility row
    /// must NAME the offending slot(s) directly (not delegate to
    /// `csq probe --all`, which shares `discover_gemini`'s blindness),
    /// must fire even when healthy sibling slots exist (multi-slot
    /// mixed case), and must NOT name a slot when presence is merely
    /// indeterminate (unreadable `credentials/`).
    #[test]
    fn gemini_unreadable_slots_names_only_corrupt_slots_across_topologies() {
        // Mixed: slot 3 healthy (parses), slot 7 marker present but
        // unparseable. MED-01: a healthy sibling must NOT mask slot 7.
        let mixed = TempDir::new().unwrap();
        provision_canonical_gemini_slot(mixed.path(), 3);
        let creds = mixed.path().join("credentials");
        std::fs::write(creds.join("gemini-7.json"), b"{ not json").unwrap();
        assert_eq!(
            gemini_unreadable_slots(mixed.path()),
            vec![7],
            "MED-01: must name ONLY the corrupt slot, even with a healthy sibling"
        );

        // All-healthy: empty (row must not fire on a clean gemini host).
        let healthy = TempDir::new().unwrap();
        provision_canonical_gemini_slot(healthy.path(), 3);
        assert!(
            gemini_unreadable_slots(healthy.path()).is_empty(),
            "healthy gemini slot MUST NOT be reported as unreadable"
        );

        // No credentials dir at all: empty.
        let bare = TempDir::new().unwrap();
        assert!(gemini_unreadable_slots(bare.path()).is_empty());

        // LOW-02: unreadable credentials/ → presence INDETERMINATE.
        // `is_gemini_bound_slot` cannot stat any path → empty list, so
        // the row never over-claims a specific slot (the host-iso
        // warning still fires conservatively via the indeterminate
        // branch — that is the correct, separate signal).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let opaque = TempDir::new().unwrap();
            let c = opaque.path().join("credentials");
            std::fs::create_dir_all(&c).unwrap();
            std::fs::write(c.join("gemini-5.json"), b"{ not json").unwrap();
            std::fs::set_permissions(&c, std::fs::Permissions::from_mode(0o000)).unwrap();
            let got = gemini_unreadable_slots(opaque.path());
            std::fs::set_permissions(&c, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(
                got.is_empty(),
                "LOW-02: indeterminate presence MUST NOT name a specific slot"
            );
        }
    }

    /// an internal ticket: `codex_wrong_variant_slots` populator returns the slot
    /// number(s) for any slot whose `credentials/codex-<N>.json` file
    /// parses successfully but carries an Anthropic-shape payload
    /// (`is_codex_wrong_variant_bound` == true). Mirrors the
    /// `gemini_unreadable_slots` regression test shape.
    ///
    /// Fixture shape matches #520's `write_wrong_variant_codex` helper:
    /// an Anthropic `claudeAiOauth` JSON payload written to the
    /// Codex-prefixed credential path. Synthetic-token discipline:
    /// `sk-ant-oat01-x` (live OAuth prefix + 1-char suffix, <20-char
    /// synthetic budget), `rt` refresh, `4102444800000` (year-2100 ms
    /// literal per `feedback_no_test_timebombs`).
    #[test]
    fn doctor_codex_wrong_variant_slots_populated_for_wrong_variant_binding() {
        use csq_core::credentials::file::canonical_path_for;
        use csq_core::providers::catalog::Surface;
        use csq_core::types::AccountNum;
        use tempfile::TempDir;

        // Arrange — one wrong-variant Codex binding at slot 6.
        let base = TempDir::new().unwrap();
        let slot = AccountNum::try_from(6u16).unwrap();
        let path = canonical_path_for(base.path(), slot, Surface::Codex);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            br#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","refreshToken":"rt","expiresAt":4102444800000,"scopes":[]}}"#,
        )
        .unwrap();

        // Act
        let slots = codex_wrong_variant_slots(base.path());

        // Assert — slot 6 is reported; no other slots appear.
        assert_eq!(
            slots,
            vec![6],
            "wrong-variant Codex binding at slot 6 must be reported in codex_wrong_variant_slots"
        );
    }

    /// an internal ticket: `codex_wrong_variant_slots` returns empty for a healthy
    /// (valid Codex-variant) binding and for a base dir with no Codex
    /// credentials at all.
    #[test]
    fn doctor_codex_wrong_variant_slots_empty_for_healthy_and_absent_bindings() {
        use csq_core::credentials::file::{canonical_path_for, save as cred_save};
        use csq_core::credentials::{CodexCredentialFile, CodexTokensFile, CredentialFile};
        use csq_core::providers::catalog::Surface;
        use csq_core::types::AccountNum;
        use std::collections::HashMap;
        use tempfile::TempDir;

        // Arrange — valid Codex binding at slot 2.
        let base = TempDir::new().unwrap();
        let slot = AccountNum::try_from(2u16).unwrap();
        let path = canonical_path_for(base.path(), slot, Surface::Codex);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let creds = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some("uuid-2".into()),
                access_token: "eyJ.codex-2.sig".into(),
                refresh_token: Some("rt_2".into()),
                id_token: None,
                extra: HashMap::new(),
            },
            last_refresh: None,
            extra: HashMap::new(),
        });
        cred_save(&path, &creds).unwrap();

        // Act — healthy binding → empty list.
        let slots_healthy = codex_wrong_variant_slots(base.path());
        assert!(
            slots_healthy.is_empty(),
            "valid Codex binding MUST NOT appear in codex_wrong_variant_slots"
        );

        // Act — bare dir (no credentials at all) → empty list.
        let bare = TempDir::new().unwrap();
        let slots_bare = codex_wrong_variant_slots(bare.path());
        assert!(
            slots_bare.is_empty(),
            "absent Codex binding MUST NOT appear in codex_wrong_variant_slots"
        );
    }

    /// PR-CA8b R2-M2: shape-stable JSON. detected_var_names is
    /// always Vec — empty in default mode, populated in verbose.
    #[test]
    fn csq_doctor_default_omits_detected_var_names_when_status_is_ok() {
        let tmp = TempDir::new().unwrap();
        let env = ["PATH", "HOME"];
        let status = check_host_isolation_with_env(tmp.path(), env.iter().copied());

        // detected_var_names is empty Vec in default mode (always
        // present in JSON, just empty — round-2 R2-M2 shape-stable).
        assert!(
            status.detected_var_names.is_empty(),
            "default mode must emit empty Vec, got {:?}",
            status.detected_var_names
        );
    }

    #[test]
    fn check_resurrections_absent_file_reports_zero() {
        let tmp = TempDir::new().unwrap();
        let info = check_resurrections(tmp.path());
        assert_eq!(info.total, 0);
        assert_eq!(info.distinct_accounts, 0);
        assert!(info.last_timestamp_secs.is_none());
        assert!(info.recent_accounts.is_empty());
    }

    #[test]
    fn check_resurrections_counts_unique_accounts() {
        // Three breadcrumbs across two distinct accounts — distinct
        // count should be 2, total count should be 3, and the recent
        // sample should contain the most recent entries in insertion
        // order.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(".resurrection-log.jsonl");
        std::fs::write(
            &path,
            concat!(
                r#"{"timestamp_secs":1000,"account":3,"event":"canonical_resurrected","live_mtime_secs":950,"live_path":"/a"}"#, "\n",
                r#"{"timestamp_secs":2000,"account":5,"event":"canonical_resurrected","live_mtime_secs":1950,"live_path":"/b"}"#, "\n",
                r#"{"timestamp_secs":3000,"account":3,"event":"canonical_resurrected","live_mtime_secs":2950,"live_path":"/c"}"#, "\n",
            ),
        )
        .unwrap();

        let info = check_resurrections(tmp.path());

        assert_eq!(info.total, 3);
        assert_eq!(info.distinct_accounts, 2, "accounts 3 and 5 are distinct");
        assert_eq!(info.last_timestamp_secs, Some(3000));
        assert_eq!(info.recent_accounts, vec![3, 5, 3]);
    }

    #[test]
    fn check_resurrections_ignores_malformed_lines() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(".resurrection-log.jsonl");
        std::fs::write(
            &path,
            concat!(
                "not json\n",
                r#"{"timestamp_secs":1000,"account":7,"event":"canonical_resurrected","live_mtime_secs":950,"live_path":"/a"}"#, "\n",
                "\n",
                "{ broken\n",
            ),
        )
        .unwrap();

        let info = check_resurrections(tmp.path());
        assert_eq!(info.total, 1, "only the valid line counts");
        assert_eq!(info.recent_accounts, vec![7]);
    }

    #[test]
    fn format_utc_date_round_trips_known_timestamps() {
        // 2026-04-14 02:00:00 UTC
        let s = format_utc_date(1_776_132_000);
        assert_eq!(s, "2026-04-14 02:00:00 UTC");
        // 1970-01-01 00:00:00 UTC
        let epoch = format_utc_date(0);
        assert_eq!(epoch, "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn report_fields_no_active_terminals() {
        // Arrange
        let r = make_report(TerminalInfo {
            modern_count: 0,
            legacy_count: 0,
            check_available: true,
        });

        // Assert: the report struct carries the expected values that drive
        // the "no active terminals" display branch.
        assert_eq!(r.terminals.modern_count, 0);
        assert_eq!(r.terminals.legacy_count, 0);
        assert!(r.terminals.check_available);
    }

    #[test]
    fn report_fields_modern_terminals_only() {
        // Arrange
        let r = make_report(TerminalInfo {
            modern_count: 3,
            legacy_count: 0,
            check_available: true,
        });

        // Assert
        assert_eq!(r.terminals.modern_count, 3);
        assert_eq!(r.terminals.legacy_count, 0);
    }

    #[test]
    fn report_fields_legacy_terminals_present() {
        // Arrange
        let r = make_report(TerminalInfo {
            modern_count: 2,
            legacy_count: 1,
            check_available: true,
        });

        // Assert: legacy_count > 0 is the condition that drives the warning branch
        assert!(r.terminals.legacy_count > 0);
        assert_eq!(r.terminals.modern_count, 2);
    }

    #[test]
    fn report_fields_check_not_available() {
        // Arrange: simulate Windows (check_available = false)
        let r = make_report(TerminalInfo {
            modern_count: 0,
            legacy_count: 0,
            check_available: false,
        });

        // Assert
        assert!(!r.terminals.check_available);
    }

    #[test]
    fn json_output_includes_terminals_field() {
        // Arrange
        let r = make_report(TerminalInfo {
            modern_count: 5,
            legacy_count: 2,
            check_available: true,
        });

        // Act
        let json = serde_json::to_string(&r).unwrap();

        // Assert
        assert!(
            json.contains("\"terminals\""),
            "JSON must include terminals key"
        );
        assert!(
            json.contains("\"modern_count\":5"),
            "JSON must include modern_count"
        );
        assert!(
            json.contains("\"legacy_count\":2"),
            "JSON must include legacy_count"
        );
        assert!(
            json.contains("\"check_available\":true"),
            "JSON must include check_available"
        );
    }

    // ── Daemon version-drift JSON tests ───────────────────────────────────

    /// Drift surfaces in the JSON output as `status: "drifted"` with a
    /// populated `version_drift` reason naming both versions and the
    /// remediation. Pins the contract that scripts grepping the JSON
    /// can detect a stale daemon and route the operator at fix.
    #[test]
    fn json_output_includes_version_drift_when_daemon_drifted() {
        // Arrange
        let mut r = make_report(TerminalInfo {
            modern_count: 0,
            legacy_count: 0,
            check_available: true,
        });
        r.daemon = DaemonInfo {
            status: "drifted".into(),
            pid: Some(12345),
            socket_healthy: Some(true),
            version_drift: Some("daemon v2.5.0 differs from CLI v2.6.1".into()),
        };

        // Act
        let json = serde_json::to_string(&r).unwrap();

        // Assert
        assert!(
            json.contains("\"status\":\"drifted\""),
            "JSON must surface drifted status: {json}"
        );
        assert!(
            json.contains("\"version_drift\":\"daemon v2.5.0 differs from CLI v2.6.1\""),
            "JSON must include version_drift reason: {json}"
        );
    }

    /// `version_drift` is `#[serde(skip_serializing_if = "Option::is_none")]`
    /// so a non-drifted daemon omits the field entirely. Keeps the JSON
    /// stable for downstream tools that don't yet know about the field.
    #[test]
    fn json_output_omits_version_drift_when_daemon_healthy() {
        // Arrange
        let mut r = make_report(TerminalInfo {
            modern_count: 0,
            legacy_count: 0,
            check_available: true,
        });
        r.daemon = DaemonInfo {
            status: "healthy".into(),
            pid: Some(12345),
            socket_healthy: Some(true),
            version_drift: None,
        };

        // Act
        let json = serde_json::to_string(&r).unwrap();

        // Assert
        assert!(
            !json.contains("version_drift"),
            "JSON must NOT include version_drift key when None: {json}"
        );
    }

    // ── Fix 2: statusline check tests ─────────────────────────────────────

    #[test]
    fn statusline_any_non_empty_command_is_configured() {
        // Arrange: a wrapper script that doesn't contain "csq"
        let cmd = Some("statusline-quota.sh".to_string());

        // Act: replicate the check logic
        let configured = cmd.as_ref().is_some_and(|c| !c.trim().is_empty());

        // Assert: non-empty → configured
        assert!(
            configured,
            "any non-empty command should be considered configured"
        );
    }

    #[test]
    fn statusline_empty_command_is_not_configured() {
        // Arrange
        let cmd = Some("   ".to_string());

        // Act
        let configured = cmd.as_ref().is_some_and(|c| !c.trim().is_empty());

        // Assert
        assert!(
            !configured,
            "whitespace-only command should not be configured"
        );
    }

    #[test]
    fn statusline_none_command_is_not_configured() {
        // Arrange
        let cmd: Option<String> = None;

        // Act
        let configured = cmd.as_ref().is_some_and(|c| !c.trim().is_empty());

        // Assert
        assert!(!configured, "None command should not be configured");
    }

    #[test]
    fn statusline_csq_command_still_configured_after_relaxation() {
        // Arrange: original csq command still works under the relaxed check
        let cmd = Some("csq statusline".to_string());

        // Act
        let configured = cmd.as_ref().is_some_and(|c| !c.trim().is_empty());

        // Assert
        assert!(configured);
    }

    // ── Fix 3: broker_failed scanning tests ───────────────────────────────

    #[test]
    fn check_broker_failed_no_sentinels_reports_empty() {
        // Arrange
        let tmp = TempDir::new().unwrap();

        // Act
        let info = check_broker_failed(tmp.path());

        // Assert
        assert_eq!(info.count, 0);
        assert!(info.entries.is_empty());
    }

    #[test]
    fn check_broker_failed_detects_sentinel_files() {
        // Arrange: write two broker-failed sentinel files directly
        let tmp = TempDir::new().unwrap();
        let creds_dir = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("2.broker-failed"), "invalid_grant").unwrap();
        std::fs::write(creds_dir.join("5.broker-failed"), "network").unwrap();

        // Act
        let info = check_broker_failed(tmp.path());

        // Assert
        assert_eq!(info.count, 2, "two sentinels should be detected");
        let ids: Vec<u16> = info.entries.iter().map(|e| e.account).collect();
        assert!(ids.contains(&2), "account 2 should be in entries");
        assert!(ids.contains(&5), "account 5 should be in entries");
    }

    #[test]
    fn check_broker_failed_reads_reason_from_file() {
        // Arrange
        let tmp = TempDir::new().unwrap();
        let creds_dir = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("3.broker-failed"), "rate_limit").unwrap();

        // Act
        let info = check_broker_failed(tmp.path());

        // Assert
        assert_eq!(info.count, 1);
        assert_eq!(info.entries[0].account, 3);
        assert_eq!(info.entries[0].reason, "rate_limit");
    }

    #[test]
    fn check_broker_failed_empty_sentinel_shows_unknown_reason() {
        // Arrange: pre-v2.1 zero-byte sentinel file
        let tmp = TempDir::new().unwrap();
        let creds_dir = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("1.broker-failed"), b"").unwrap();

        // Act
        let info = check_broker_failed(tmp.path());

        // Assert
        assert_eq!(info.count, 1);
        assert_eq!(
            info.entries[0].reason, "unknown",
            "empty file should show 'unknown'"
        );
    }

    #[test]
    fn check_broker_failed_ignores_non_sentinel_files() {
        // Arrange: a .json and a random file in credentials/
        let tmp = TempDir::new().unwrap();
        let creds_dir = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("1.json"), "{}").unwrap();
        std::fs::write(creds_dir.join("random.txt"), "data").unwrap();

        // Act
        let info = check_broker_failed(tmp.path());

        // Assert
        assert_eq!(info.count, 0, "non-sentinel files should not be counted");
    }

    #[test]
    fn check_broker_failed_entries_sorted_by_account_number() {
        // Arrange: write sentinels in reverse order
        let tmp = TempDir::new().unwrap();
        let creds_dir = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("7.broker-failed"), "network").unwrap();
        std::fs::write(creds_dir.join("2.broker-failed"), "invalid_grant").unwrap();
        std::fs::write(creds_dir.join("4.broker-failed"), "rate_limit").unwrap();

        // Act
        let info = check_broker_failed(tmp.path());

        // Assert: entries should be sorted ascending by account number
        assert_eq!(info.count, 3);
        assert_eq!(info.entries[0].account, 2);
        assert_eq!(info.entries[1].account, 4);
        assert_eq!(info.entries[2].account, 7);
    }

    // ── custodian-identity canary tests (an internal ticket) ──────────────────────────

    /// Build a `term-<pid>` handle dir under `base` with an Anthropic-shape
    /// `.credentials.json` symlink (dangling target is fine — `read_link` reads
    /// the target string without following it) and optional `.claude.json` body.
    #[cfg(unix)]
    fn mk_canary_handle_dir(base: &Path, pid: u32, link_name: &str, claude_json: Option<&str>) {
        let handle = base.join(format!("term-{pid}"));
        std::fs::create_dir_all(&handle).unwrap();
        let target = base.join(format!("identities/uuid-{pid}/{link_name}"));
        std::os::unix::fs::symlink(&target, handle.join(".credentials.json")).unwrap();
        if let Some(body) = claude_json {
            std::fs::write(handle.join(".claude.json"), body).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn canary_flags_populated_claude_json_without_oauth_account() {
        // The #833 drift signal: a live Anthropic session whose `.claude.json`
        // is populated but has no oauthAccount.emailAddress.
        let tmp = TempDir::new().unwrap();
        let pid = std::process::id(); // self → alive
        mk_canary_handle_dir(
            tmp.path(),
            pid,
            "credentials.json",
            Some(r#"{"numStartups":3,"userID":"abc"}"#),
        );
        let c = check_custodian_identity_canary(tmp.path());
        assert!(c.check_available);
        assert_eq!(c.drift_dirs, vec![format!("term-{pid}")]);
        assert!(c.fresh_dirs.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn canary_flags_unparseable_claude_json_as_drift() {
        // R1 security-reviewer MEDIUM: an unparseable present `.claude.json` breaks
        // the gate identically to a missing field → must surface as drift through
        // the canary path, not be mistaken for a benign fresh dir.
        let tmp = TempDir::new().unwrap();
        let pid = std::process::id();
        mk_canary_handle_dir(tmp.path(), pid, "credentials.json", Some("not json {"));
        let c = check_custodian_identity_canary(tmp.path());
        assert_eq!(c.drift_dirs, vec![format!("term-{pid}")]);
        assert!(c.fresh_dirs.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn canary_healthy_when_oauth_account_present() {
        let tmp = TempDir::new().unwrap();
        let pid = std::process::id();
        mk_canary_handle_dir(
            tmp.path(),
            pid,
            "credentials.json",
            Some(r#"{"numStartups":3,"oauthAccount":{"emailAddress":"u@x.com"}}"#),
        );
        let c = check_custodian_identity_canary(tmp.path());
        assert!(c.drift_dirs.is_empty());
        assert!(c.fresh_dirs.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn canary_fresh_when_claude_json_absent() {
        let tmp = TempDir::new().unwrap();
        let pid = std::process::id();
        // Absent .claude.json → fresh (not-yet-populated), not drift.
        mk_canary_handle_dir(tmp.path(), pid, "credentials.json", None);
        let c = check_custodian_identity_canary(tmp.path());
        assert!(c.drift_dirs.is_empty());
        assert_eq!(c.fresh_dirs, vec![format!("term-{pid}")]);
    }

    #[cfg(unix)]
    #[test]
    fn canary_fresh_when_claude_json_empty_object() {
        // R2 testing-specialist F4: an empty `{}` .claude.json → fresh through the
        // integration path (not just the classifier unit test), NOT drift.
        let tmp = TempDir::new().unwrap();
        let pid = std::process::id();
        mk_canary_handle_dir(tmp.path(), pid, "credentials.json", Some("{}"));
        let c = check_custodian_identity_canary(tmp.path());
        assert!(c.drift_dirs.is_empty());
        assert_eq!(c.fresh_dirs, vec![format!("term-{pid}")]);
    }

    #[cfg(unix)]
    #[test]
    fn sorted_dir_names_orders_by_numeric_pid_not_lexicographically() {
        // R2 testing-specialist F2: proves the N7 numeric-sort fix. Lexicographic
        // order would give term-100 < term-9 < term-90; numeric gives 9, 90, 100.
        let out = sorted_dir_names(vec![
            (100, "term-100".to_string()),
            (9, "term-9".to_string()),
            (90, "term-90".to_string()),
        ]);
        assert_eq!(out, vec!["term-9", "term-90", "term-100"]);
    }

    #[cfg(unix)]
    #[test]
    fn canary_ignores_codex_bound_dir() {
        // A Codex session (`auth.json` link) legitimately has no oauthAccount —
        // it MUST NOT be flagged as drift.
        let tmp = TempDir::new().unwrap();
        let pid = std::process::id();
        mk_canary_handle_dir(
            tmp.path(),
            pid,
            "auth.json",
            Some(r#"{"numStartups":3,"userID":"abc"}"#),
        );
        let c = check_custodian_identity_canary(tmp.path());
        assert!(c.drift_dirs.is_empty());
        assert!(c.fresh_dirs.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn canary_ignores_dead_pid() {
        // A dir whose PID is not alive is out of the custodian's harvest scope.
        let tmp = TempDir::new().unwrap();
        // 2_000_000_000 is positive as i32 yet above every OS pid ceiling
        // (macOS 99_999, Linux pid_max ≤ 2^22) → deterministically not alive.
        mk_canary_handle_dir(
            tmp.path(),
            2_000_000_000,
            "credentials.json",
            Some(r#"{"numStartups":3,"userID":"abc"}"#),
        );
        let c = check_custodian_identity_canary(tmp.path());
        assert!(c.check_available);
        assert!(c.drift_dirs.is_empty());
        assert!(c.fresh_dirs.is_empty());
    }

    // ── mixed-state slot tests ─────────────────────────────────

    #[test]
    fn check_mixed_state_slots_reports_empty_when_no_slots_mixed() {
        let tmp = TempDir::new().unwrap();
        let info = check_mixed_state_slots(tmp.path());
        assert_eq!(info.count, 0);
        assert!(info.entries.is_empty());
    }

    #[test]
    fn check_mixed_state_slots_flags_oauth_plus_3p_slot() {
        // Arrange: write a 3P env block AND a valid-shape OAuth
        // credential for slot 3. This is the exact state the PR
        // #130 login flow now prevents; older installs can still
        // produce it via manual filesystem edits.
        //
        // M4-12: `check_mixed_state_slots` reads from the UUID-keyed
        // identity path (`identities/<UUID>/credentials.json`) only —
        // numeric path retired. Provision profiles.json + UUID-keyed
        // credential so the doctor reader can locate it.
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path().join("config-3");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.minimax.io/anthropic","ANTHROPIC_AUTH_TOKEN":"sk-fake-minimax-12345"}}"#,
        ).unwrap();

        // M4-12: provision UUID mapping + identity-keyed credential for slot 3.
        let uuid = csq_core::testing::identity_fixtures::fixture_uuid_for_slot(3);
        let profiles_path = csq_core::accounts::profiles::profiles_path(tmp.path());
        let mut profiles = csq_core::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("3".to_string(), uuid);
        csq_core::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        let cred_path = csq_core::accounts::identity_store::credentials_path_for(tmp.path(), uuid);
        std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
        // Minimum-viable OAuth credential — must parse, concrete values don't matter.
        std::fs::write(
            &cred_path,
            r#"{"claudeAiOauth":{"accessToken":"oat-stub","refreshToken":"rt-stub","expiresAt":9999999999999,"scopes":["user:profile"],"subscriptionType":"max"}}"#,
        ).unwrap();

        // Act
        let info = check_mixed_state_slots(tmp.path());

        // Assert
        assert_eq!(info.count, 1, "slot 3 should be flagged");
        assert_eq!(info.entries[0].account, 3);
        assert_eq!(info.entries[0].provider, "MiniMax");
    }

    #[test]
    fn check_mixed_state_slots_ignores_3p_only_slot() {
        // 3P env block without any OAuth credential is the normal
        // MM/Z.AI/Ollama state — must not be flagged.
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path().join("config-3");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"http://localhost:11434","ANTHROPIC_AUTH_TOKEN":"ollama"}}"#,
        ).unwrap();

        let info = check_mixed_state_slots(tmp.path());
        assert_eq!(info.count, 0);
    }

    #[test]
    fn check_mixed_state_slots_ignores_oauth_only_slot() {
        // Pure OAuth slot (no 3P settings) is the normal Anthropic
        // path — must not be flagged.
        let tmp = TempDir::new().unwrap();
        let creds_dir = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(
            creds_dir.join("1.json"),
            r#"{"claudeAiOauth":{"accessToken":"oat-stub","refreshToken":"rt-stub","expiresAt":9999999999999,"scopes":["user:profile"],"subscriptionType":"max"}}"#,
        ).unwrap();

        let info = check_mixed_state_slots(tmp.path());
        assert_eq!(info.count, 0);
    }

    // ── js_runtime test ────────────────────────────────────────

    #[test]
    fn check_js_runtime_returns_consistent_structure() {
        // Can't assume the CI has node/bun installed — just assert
        // the invariant: `found == path.is_some()`. Exhaustive probe
        // logic lives in csq_core::http tests.
        let info = check_js_runtime();
        assert_eq!(info.found, info.path.is_some());
    }

    #[test]
    fn json_output_includes_broker_failed_field() {
        // Arrange
        let r = make_report(TerminalInfo {
            modern_count: 0,
            legacy_count: 0,
            check_available: true,
        });

        // Act
        let json = serde_json::to_string(&r).unwrap();

        // Assert
        assert!(
            json.contains("\"broker_failed\""),
            "JSON must include broker_failed key"
        );
        assert!(
            json.contains("\"count\":0"),
            "JSON must include count field"
        );
    }

    // ── per-slot doctor (--slot N) ────────────────────────────────────────

    fn write_credentials(base: &std::path::Path, slot: u16, expires_at_ms: u64) {
        // M4-12: `build_per_slot_report` and `check_mixed_state_slots` read
        // ONLY from the UUID-keyed identity path `identities/<UUID>/credentials.json`.
        // The numeric mirror `credentials/<N>.json` is retired as a read target.
        //
        // This helper provisions:
        //   1. `profiles.json` with `by_slot[slot] = uuid` so
        //      `resolve_slot_to_uuid` returns the UUID.
        //   2. `identities/<uuid>/credentials.json` with a minimal OAuth
        //      payload at the given `expires_at_ms`.
        //
        // UUID is deterministic via `fixture_uuid_for_slot(slot)` — same
        // derivation as `coexisting_fixture` so tests relying on stable UUIDs
        // across calls stay stable.
        let uuid = csq_core::testing::identity_fixtures::fixture_uuid_for_slot(slot);

        // 1. Write profiles.json — load existing or start empty, add this slot.
        let profiles_path = csq_core::accounts::profiles::profiles_path(base);
        let mut profiles = if profiles_path.exists() {
            csq_core::accounts::profiles::load(&profiles_path)
                .unwrap_or_else(|_| csq_core::accounts::profiles::ProfilesFile::empty())
        } else {
            csq_core::accounts::profiles::ProfilesFile::empty()
        };
        profiles.by_slot.insert(slot.to_string(), uuid);
        csq_core::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // 2. Write credentials.json at the UUID-keyed identity path.
        let cred_path = csq_core::accounts::identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
        let json = serde_json::json!({
            "claudeAiOauth": {
                "accessToken": "tok",
                "refreshToken": "ref",
                "expiresAt": expires_at_ms,
                "scopes": ["user:profile"],
                "subscriptionType": "max",
            }
        });
        std::fs::write(&cred_path, json.to_string()).unwrap();
    }

    fn write_quota(base: &std::path::Path, slot: u16, five_hour_pct: f64) {
        let path = base.join("quota.json");
        let json = serde_json::json!({
            "schema_version": 2,
            "accounts": {
                slot.to_string(): {
                    "surface": "claude-code",
                    "kind": "utilization",
                    "five_hour": {
                        "used_percentage": five_hour_pct,
                        "resets_at": 4_102_444_800u64,
                    },
                    "seven_day": null,
                    "updated_at": 0.0,
                }
            }
        });
        std::fs::write(&path, json.to_string()).unwrap();
    }

    #[test]
    fn per_slot_report_status_ok_when_creds_fresh_and_quota_under_threshold() {
        let tmp = TempDir::new().unwrap();
        let future_ms = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            + 86_400_000) as u64;
        write_credentials(tmp.path(), 4, future_ms);
        write_quota(tmp.path(), 4, 12.5);

        let r = build_per_slot_report(tmp.path(), 4).unwrap();
        assert_eq!(r.slot, 4);
        assert_eq!(r.status, "ok");
        assert_eq!(r.quota.utilization, 12.5);
        assert!(r.credentials.present);
        assert!(!r.credentials.expired);
    }

    #[test]
    fn per_slot_report_status_error_when_credentials_missing() {
        let tmp = TempDir::new().unwrap();
        write_quota(tmp.path(), 5, 0.0);
        let r = build_per_slot_report(tmp.path(), 5).unwrap();
        assert_eq!(r.status, "error");
        assert!(!r.credentials.present);
        assert!(!r.credentials.expired);
    }

    #[test]
    fn per_slot_report_status_error_when_credentials_expired() {
        let tmp = TempDir::new().unwrap();
        write_credentials(tmp.path(), 9, 1_000); // long past
        write_quota(tmp.path(), 9, 4.0);
        let r = build_per_slot_report(tmp.path(), 9).unwrap();
        assert_eq!(r.status, "error");
        assert!(r.credentials.present);
        assert!(r.credentials.expired);
    }

    #[test]
    fn per_slot_report_quota_zero_when_quota_file_missing() {
        let tmp = TempDir::new().unwrap();
        let future_ms = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            + 86_400_000) as u64;
        write_credentials(tmp.path(), 7, future_ms);
        let r = build_per_slot_report(tmp.path(), 7).unwrap();
        assert_eq!(r.status, "ok");
        assert_eq!(r.quota.utilization, 0.0);
    }

    #[test]
    fn per_slot_report_rejects_invalid_slot_number() {
        let tmp = TempDir::new().unwrap();
        let err = build_per_slot_report(tmp.path(), 0).unwrap_err();
        assert!(err.to_string().contains("invalid slot"));
    }

    #[test]
    fn per_slot_report_serializes_to_validator_required_shape() {
        let tmp = TempDir::new().unwrap();
        let future_ms = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            + 86_400_000) as u64;
        write_credentials(tmp.path(), 3, future_ms);
        write_quota(tmp.path(), 3, 42.0);

        let r = build_per_slot_report(tmp.path(), 3).unwrap();
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"quota\":{\"utilization\":42.0}"));
        // The validate-doctor-json.py contract: status + quota.utilization
        // are the load-bearing keys; adding fields is non-breaking.
    }

    // ─── M1-8 / M2-6 doctor tests ────────────────────────────────────────────

    /// an internal journal entry (was M2-6 full): `csq doctor --json` emits the current
    /// `schema_version` on a coexisting layout where all Phase 2 UUID-path
    /// files are present (an empty consistency list). Bumped 4 → 5 by journal
    /// 0042 when the `phase4_incomplete` top-level field landed; 5 → 6 by
    /// RN1-D R1 when the `pass0_skipped_slots` field landed; 6 → 7 when the
    /// `MirrorDriftAtSlot` consistency variant was removed; 7 → 8 when
    /// `identity_store.consistency` became a list of issues.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn doctor_json_emits_current_schema_version() {
        // Hermeticity (test-hermeticity.md MUST 1b): build_report transitively reads
        // CSQ_AUDIT_EDITION; pin a clean community baseline under the shared env lock
        // so this test cannot race a concurrent enterprise-edition setter.
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        use csq_core::accounts::identity_store::identity_path;
        use csq_core::accounts::profiles::{load, profiles_path};
        use csq_core::testing::identity_fixtures::coexisting_fixture;

        // Arrange: coexisting fixture with 3 slots. Seed UUID-keyed
        // credentials.json + settings.json under every identity dir so the
        // M2-6 presence-checks resolve to Consistent.
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let pf = load(&profiles_path(base)).unwrap();
        for &uuid in pf.by_slot.values() {
            let id_dir = identity_path(base, uuid);
            std::fs::write(id_dir.join("credentials.json"), b"{}").unwrap();
            std::fs::write(id_dir.join("settings.json"), b"{}").unwrap();
        }

        // Act: build the report (read-only; no daemon / CLI probe invocations).
        let report = build_report(base);

        // Assert: schema_version is edition-specific — community v19, enterprise
        // v22 (enterprise-only fields: mcp_gate_outbox_backlog v20 #914 + v21 M6
        // #909 shard-D daemon-aware fields + audit_bundle_floor_anchor v22 #787
        // b2b, raising only the enterprise ceiling). Pinned to the build-active
        // const so the test is correct under both feature sets.
        assert_eq!(
            report.schema_version, DOCTOR_SCHEMA_VERSION,
            "schema_version must equal the edition-active DOCTOR_SCHEMA_VERSION \
             (community 19 / enterprise 22)"
        );

        // Assert: identity_store is present and state is Coexisting.
        let is = report
            .identity_store
            .as_ref()
            .expect("identity_store must be present on a coexisting layout");
        assert_eq!(
            is.state,
            CoexistenceState::Coexisting,
            "expected Coexisting state"
        );
        assert_eq!(is.identity_count, 3, "expected 3 identity dirs");
        assert_eq!(is.profile_slot_count, 3, "expected 3 legacy slots");
        assert!(
            is.consistency.is_empty(),
            "expected Consistent (empty vec) after seeding all Phase 2 UUID-path files"
        );

        // Verify the JSON shape: schema_version (edition-active), identity_store
        // key present, state is "Coexisting".
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            json.contains(&format!("\"schema_version\":{DOCTOR_SCHEMA_VERSION}")),
            "JSON must contain schema_version:{DOCTOR_SCHEMA_VERSION}; got: {json}"
        );
        assert!(
            json.contains("\"identity_store\""),
            "JSON must contain identity_store key; got: {json}"
        );
        assert!(
            json.contains("\"Coexisting\""),
            "JSON must contain Coexisting state value; got: {json}"
        );

        // M2 T2.5 — edition-specific grade surface. Enterprise: the field is
        // present and grades COMPATIBLE for a clean fixture chain. Community: the
        // field is omitted entirely (byte-identical pre-T2.5 schema).
        #[cfg(feature = "enterprise")]
        assert!(
            json.contains("\"audit_trust_plane_grade\":\"COMPATIBLE\""),
            "enterprise doctor JSON must carry the trust-plane grade; got: {json}"
        );
        #[cfg(not(feature = "enterprise"))]
        assert!(
            !json.contains("audit_trust_plane_grade"),
            "community doctor JSON must omit the trust-plane grade; got: {json}"
        );
    }

    /// M2-6: text output renders the Phase 2 consistency one-liner correctly
    /// for a Coexisting layout with a Missing* inconsistency.
    ///
    /// Verifies the render path handles the UUID-path Missing* ConsistencyState
    /// variants and formats them as INCONSISTENT: <Variant>(...).
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn doctor_text_renders_phase2_consistency_one_liner() {
        use csq_core::accounts::identity_store::IdentityId;
        use csq_core::accounts::profiles::{
            CoexistenceState, ConsistencyState, IdentityStoreReport,
        };
        use std::io::Write;

        let uuid = IdentityId::new_v4();

        // Test the Phase 2 Missing* variants' render output.
        let cases: &[(ConsistencyState, &str)] = &[
            (
                ConsistencyState::MissingCredentialsAtUuidPath { uuid },
                "MissingCredentialsAtUuidPath",
            ),
            (
                ConsistencyState::MissingSettingsAtUuidPath { uuid },
                "MissingSettingsAtUuidPath",
            ),
        ];

        for (consistency, expected_fragment) in cases {
            // Arrange: synthesise an IdentityStoreReport for a Coexisting layout.
            let report = IdentityStoreReport {
                state: CoexistenceState::Coexisting,
                store_version: 2,
                identity_count: 3,
                profile_slot_count: 3,
                consistency: vec![consistency.clone()],
            };

            // Drive the formatting logic directly (mirrors render_identity_store_line).
            let state_label = match report.state {
                CoexistenceState::LegacyOnly => "legacy-only",
                CoexistenceState::Coexisting => "coexisting",
                CoexistenceState::IdentityOnly => "identity-only",
            };
            let consistency_label = if report.consistency.is_empty() {
                "consistent".to_string()
            } else {
                let parts: Vec<String> = report
                    .consistency
                    .iter()
                    .map(|c| match c {
                        ConsistencyState::SlotCountMismatch { legacy, identity } => {
                            format!("SlotCountMismatch (legacy={legacy}, identity={identity})")
                        }
                        ConsistencyState::OrphanIdentity { uuid } => {
                            format!("OrphanIdentity({uuid})")
                        }
                        ConsistencyState::OrphanLegacySlot { slot } => {
                            format!("OrphanLegacySlot({slot})")
                        }
                        ConsistencyState::MissingCredentialsAtUuidPath { uuid } => {
                            format!("MissingCredentialsAtUuidPath({uuid})")
                        }
                        ConsistencyState::MissingSettingsAtUuidPath { uuid } => {
                            format!("MissingSettingsAtUuidPath({uuid})")
                        }
                        ConsistencyState::CurrentAccountDrift { slot, cached } => {
                            format!("CurrentAccountDrift(slot={slot}, cached={cached}) — run `csq repair`")
                        }
                    })
                    .collect();
                format!("INCONSISTENT: {}", parts.join("; "))
            };
            let detail = format!(
                "{} identities, {} legacy slots, {}",
                report.identity_count, report.profile_slot_count, consistency_label
            );

            let mut output: Vec<u8> = Vec::new();
            writeln!(output, "  Identity store: {state_label} ({detail})").unwrap();

            let text = String::from_utf8(output).unwrap();

            assert!(
                text.contains("Identity store:"),
                "text must contain 'Identity store:'; got: {text}"
            );
            assert!(
                text.contains("coexisting"),
                "text must contain 'coexisting'; got: {text}"
            );
            assert!(
                text.contains("INCONSISTENT"),
                "text must contain 'INCONSISTENT' for Phase 2 variant {expected_fragment}; got: {text}"
            );
            assert!(
                text.contains(expected_fragment),
                "text must contain variant name '{expected_fragment}'; got: {text}"
            );
        }
    }

    /// Binary-smoke regression (workspace an internal workspace): the
    /// extracted `identity_store_detail` MUST surface consistency findings for
    /// a LegacyOnly host too. A prior version hardcoded the LegacyOnly detail
    /// and dropped `CurrentAccountDrift`, so `csq doctor`'s icon flipped to ⚠
    /// but never NAMED the drift on a pre-Pass-0 host — caught by the binary
    /// smoke, not by the unit tests of `audit_coexistence` (which assert the
    /// returned Vec, not the rendered line).
    #[test]
    fn identity_store_detail_surfaces_drift_on_legacy_only() {
        let report = IdentityStoreReport {
            state: CoexistenceState::LegacyOnly,
            store_version: 0,
            identity_count: 0,
            profile_slot_count: 3,
            consistency: vec![ConsistencyState::CurrentAccountDrift { slot: 2, cached: 8 }],
        };
        let detail = identity_store_detail(&report);
        assert!(
            detail.contains("CurrentAccountDrift(slot=2, cached=8)"),
            "LegacyOnly detail must NAME the drift; got: {detail}"
        );
        assert!(
            detail.contains("no Phase 1 daemon-mint observed yet"),
            "LegacyOnly prefix must be retained; got: {detail}"
        );
    }

    #[test]
    fn identity_store_detail_legacy_only_consistent_is_clean() {
        let report = IdentityStoreReport {
            state: CoexistenceState::LegacyOnly,
            store_version: 0,
            identity_count: 0,
            profile_slot_count: 3,
            consistency: vec![],
        };
        assert_eq!(
            identity_store_detail(&report),
            "no Phase 1 daemon-mint observed yet"
        );
    }

    #[test]
    fn identity_store_detail_coexisting_names_finding() {
        let report = IdentityStoreReport {
            state: CoexistenceState::Coexisting,
            store_version: 2,
            identity_count: 7,
            profile_slot_count: 11,
            consistency: vec![ConsistencyState::OrphanLegacySlot { slot: 5 }],
        };
        let detail = identity_store_detail(&report);
        assert!(detail.contains("7 identities, 11 legacy slots"));
        assert!(detail.contains("OrphanLegacySlot(5)"), "got: {detail}");
    }

    // ─── M4-11 doctor tests (Phase 4 release N: schema v4 + legacy_compat_state)

    /// M4-11 acceptance criterion (a) [updated by an internal journal entry]:
    /// `csq doctor --json` emits the current `schema_version`.
    /// Verifies both the struct field and the serialized JSON shape —
    /// downstream consumers (statusline, validate-doctor-json.py, future
    /// tooling) read the JSON, so the JSON-level assertion is the
    /// load-bearing one. an internal journal entry bumped the schema 4 → 5 when
    /// `phase4_incomplete` landed.
    ///
    /// The fixture has no compat-bridge footprint, so
    /// `legacy_compat_state` is empty — the assertion here is scoped to
    /// the schema_version landing. A separate test
    /// (`doctor_emits_legacy_compat_state_field`) verifies the field's
    /// enumeration values on a fixture that triggers all four kinds.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn doctor_json_schema_version_is_current() {
        // Hermeticity (test-hermeticity.md MUST 1b): build_report transitively reads
        // CSQ_AUDIT_EDITION; pin a clean community baseline under the shared env lock
        // so this test cannot race a concurrent enterprise-edition setter.
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        // Act: build the report on an empty base dir (no slots, no
        // credentials, no profiles.json). Doctor MUST still emit a
        // structurally valid report.
        let report = build_report(base);

        // Assert: schema_version equals the edition-active const (community 19 /
        // enterprise 22). Pinned to the const so it stays correct across bumps.
        assert_eq!(
            report.schema_version, DOCTOR_SCHEMA_VERSION,
            "schema_version must equal the edition-active DOCTOR_SCHEMA_VERSION"
        );

        // Assert: serialized JSON contains the literal token. Use
        // `to_string` (compact) so the assertion is robust to pretty-
        // printing whitespace.
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            json.contains(&format!("\"schema_version\":{DOCTOR_SCHEMA_VERSION}")),
            "JSON must contain the edition-active schema_version; got: {json}"
        );

        // Belt-and-suspenders: the field MUST also be present in the
        // JSON output (covered by `legacy_compat_state` test below) —
        // this test only asserts the schema_version invariant.
        assert!(
            json.contains("\"legacy_compat_state\""),
            "schema v6 JSON must include the legacy_compat_state field; got: {json}"
        );
    }

    /// M4-11 acceptance criterion (a): `csq doctor --json` emits the
    /// `legacy_compat_state` field with the correct enumeration values.
    ///
    /// The fixture seeds all four compat-bridge surfaces (per spec/13
    /// §9):
    /// 1. `profiles.json::accounts` with a non-empty entry →
    ///    `v1_accounts_field_still_present`
    /// 2. `credentials/1.json` (Anthropic legacy mirror) →
    ///    `legacy_canonical_credentials_file_still_written`
    /// 3. `credentials/codex-1.json` (Codex legacy mirror) →
    ///    `legacy_canonical_codex_credentials_file_still_written`
    /// 4. `config-2/.csq-account` with decimal `"2"` content →
    ///    `decimal_marker_content_present`
    ///
    /// Verifies all four kinds emit and that the `kind` strings match
    /// spec/13 §9 verbatim. Per `tauri-commands.md` MUST Rule 6, each
    /// named variant must map to a specific, actionable description —
    /// we assert the `evidence` field is non-empty for every entry.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn doctor_emits_legacy_compat_state_field() {
        // Hermeticity (test-hermeticity.md MUST 1b): build_report transitively reads
        // CSQ_AUDIT_EDITION; pin a clean community baseline under the shared env lock
        // so this test cannot race a concurrent enterprise-edition setter.
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        use csq_core::accounts::profiles::{profiles_path, save, AccountProfile, ProfilesFile};

        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        // Seed (1): profiles.json with a non-empty accounts entry.
        let mut pf = ProfilesFile::empty();
        pf.set_profile(
            1,
            AccountProfile {
                email: "test@example.com".to_string(),
                method: "oauth".to_string(),
                extra: Default::default(),
            },
        );
        save(&profiles_path(base), &pf).unwrap();

        // Seed (2): credentials/1.json (Anthropic legacy mirror).
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("1.json"), b"{}").unwrap();

        // Seed (3): credentials/codex-1.json (Codex legacy mirror).
        std::fs::write(creds_dir.join("codex-1.json"), b"{}").unwrap();

        // Seed (4): config-2/.csq-account with decimal content.
        let config2 = base.join("config-2");
        std::fs::create_dir_all(&config2).unwrap();
        std::fs::write(config2.join(".csq-account"), "2").unwrap();

        // Act
        let report = build_report(base);

        // Assert: all four kinds present.
        let kinds: std::collections::HashSet<String> = report
            .legacy_compat_state
            .iter()
            .map(|e| e.kind.clone())
            .collect();
        assert!(
            kinds.contains("v1_accounts_field_still_present"),
            "missing v1_accounts_field_still_present; got: {kinds:?}"
        );
        assert!(
            kinds.contains("legacy_canonical_credentials_file_still_written"),
            "missing legacy_canonical_credentials_file_still_written; got: {kinds:?}"
        );
        assert!(
            kinds.contains("legacy_canonical_codex_credentials_file_still_written"),
            "missing legacy_canonical_codex_credentials_file_still_written; got: {kinds:?}"
        );
        assert!(
            kinds.contains("decimal_marker_content_present"),
            "missing decimal_marker_content_present; got: {kinds:?}"
        );

        // Assert: every entry has a specific, actionable description
        // and a documented retirement path (tauri-commands.md MUST 6).
        for entry in &report.legacy_compat_state {
            assert!(
                !entry.evidence.is_empty(),
                "evidence must be non-empty for kind {}",
                entry.kind
            );
            assert!(
                !entry.scheduled_for.is_empty(),
                "scheduled_for must be non-empty for kind {}",
                entry.kind
            );
        }

        // Assert: serialized JSON shape. The `legacy_compat_state`
        // field is an array of objects with `kind`, `evidence`, and
        // `scheduled_for` keys per spec/13 §9.
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            json.contains("\"legacy_compat_state\""),
            "JSON must contain legacy_compat_state field; got: {json}"
        );
        assert!(
            json.contains("\"v1_accounts_field_still_present\""),
            "JSON must contain v1_accounts_field_still_present; got: {json}"
        );
        assert!(
            json.contains("\"legacy_canonical_credentials_file_still_written\""),
            "JSON must contain legacy_canonical_credentials_file_still_written; got: {json}"
        );
        assert!(
            json.contains("\"legacy_canonical_codex_credentials_file_still_written\""),
            "JSON must contain legacy_canonical_codex_credentials_file_still_written; got: {json}"
        );
        assert!(
            json.contains("\"decimal_marker_content_present\""),
            "JSON must contain decimal_marker_content_present; got: {json}"
        );
        assert!(
            json.contains("\"scheduled_for\""),
            "JSON must contain scheduled_for key; got: {json}"
        );
        assert!(
            json.contains("\"evidence\""),
            "JSON must contain evidence key; got: {json}"
        );

        // Assert: the empty-state path is also covered by an empty
        // fixture. Verify by running build_report on a fresh empty
        // tmpdir; the `legacy_compat_state` Vec must be empty.
        let empty_dir = tempfile::TempDir::new().unwrap();
        let empty_report = build_report(empty_dir.path());
        assert!(
            empty_report.legacy_compat_state.is_empty(),
            "empty base dir must produce empty legacy_compat_state; got: {:?}",
            empty_report.legacy_compat_state
        );
    }

    /// #578 regression: `detect_decimal_marker` MUST skip slots that are
    /// identity-store members. A decimal `.csq-account` marker on a slot
    /// present in `by_slot` (modern OAuth) or `by_slot_identity` (3P API
    /// key / codex / gemini) is cosmetic, not a pending-migration bridge.
    /// Only a slot with NO map entry is a genuine pre-migration footprint.
    ///
    /// This reproduces the maintainer-host false-positive: 4 of 5 flagged
    /// markers were `apikey:*` 3P slots (decimal by design) and one was an
    /// OAuth slot already in `by_slot`.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn decimal_marker_skips_identity_store_members() {
        use csq_core::accounts::profiles;

        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        // profiles.json: slot 3 is a modern OAuth account (by_slot UUID);
        // slot 4 is a 3P API-key account (by_slot_identity = "apikey:mm").
        // Slot 2 is absent from BOTH maps → genuine pre-migration.
        let profiles_path = profiles::profiles_path(base);
        std::fs::create_dir_all(profiles_path.parent().unwrap()).unwrap();
        std::fs::write(
            &profiles_path,
            r#"{"by_slot":{"3":"00000000-0000-0000-0000-000000000003"},"by_slot_identity":{"4":"apikey:mm"},"by_email":{},"profiles":{}}"#,
        )
        .unwrap();

        // Three config-N dirs, ALL carrying a decimal `.csq-account` marker.
        for n in [2u16, 3, 4] {
            let cfg = base.join(format!("config-{n}"));
            std::fs::create_dir_all(&cfg).unwrap();
            std::fs::write(cfg.join(".csq-account"), n.to_string()).unwrap();
        }

        // Act
        let entry = detect_decimal_marker(base);

        // Assert: only slot 2 (no map entry) is counted; slots 3 (by_slot)
        // and 4 (by_slot_identity) are skipped → exactly 1 marker.
        let entry = entry.expect("slot 2 has a decimal marker and no map entry → must fire");
        assert_eq!(entry.kind, "decimal_marker_content_present");
        assert!(
            entry.evidence.contains("1 marker") && !entry.evidence.contains("markers"),
            "only the 1 pre-migration slot (2) must count; 3+4 are identity-store members; \
             got evidence: {:?}",
            entry.evidence
        );

        // Assert: if EVERY decimal-marked slot is an identity-store member,
        // the detector is silent (no false positive).
        let dir2 = tempfile::TempDir::new().unwrap();
        let base2 = dir2.path();
        let pp2 = profiles::profiles_path(base2);
        std::fs::create_dir_all(pp2.parent().unwrap()).unwrap();
        std::fs::write(
            &pp2,
            r#"{"by_slot":{"6":"00000000-0000-0000-0000-000000000006"},"by_slot_identity":{"10":"apikey:deepseek","11":"apikey:zai"},"by_email":{},"profiles":{}}"#,
        )
        .unwrap();
        for n in [6u16, 10, 11] {
            let cfg = base2.join(format!("config-{n}"));
            std::fs::create_dir_all(&cfg).unwrap();
            std::fs::write(cfg.join(".csq-account"), n.to_string()).unwrap();
        }
        assert!(
            detect_decimal_marker(base2).is_none(),
            "all decimal-marked slots are identity-store members → detector MUST be silent (#578)"
        );
    }

    /// M4-11 acceptance criterion (a): text-mode renders the legacy
    /// compat state line per spec/13 §9.
    ///
    /// Two paths covered:
    /// - Empty array: `Legacy compat: ✓ none (Phase 4 final state)`.
    /// - Non-empty: `Legacy compat: ⚠ <count> bridge(s) active — <tag> (<sched>), ...`.
    ///
    /// The renderer is driven directly (no stdout capture) — the
    /// function writes to stdout via `println!`, so we exercise its
    /// behavior by constructing inputs and confirming the parts list
    /// is computed correctly. The structural test verifies the
    /// kind-to-tag dispatch via `kind_from_str` + `LegacyCompatKind::short_tag`.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn doctor_text_renders_legacy_compat_state_line() {
        // Path 1: empty Vec → final-state branch.
        let empty: Vec<LegacyCompatEntry> = Vec::new();
        render_legacy_compat_line(&empty); // stdout: "Legacy compat: ✓ none (Phase 4 final state)"

        // Path 2: non-empty Vec → bridge-active branch. Drive the
        // dispatch directly via kind_from_str so we can assert each
        // kind round-trips to its short tag and scheduled_for label
        // (the same data the renderer uses).
        let cases: &[(LegacyCompatKind, &str, &str)] = &[
            (
                LegacyCompatKind::V1AccountsFieldStillPresent,
                "v1_accounts_field",
                "M4-13 release N+1",
            ),
            (
                LegacyCompatKind::LegacyCanonicalCredentialsFileStillWritten,
                "legacy_credentials_file",
                "M4-12 release N+1",
            ),
            (
                LegacyCompatKind::LegacyCanonicalCodexCredentialsFileStillWritten,
                "legacy_codex_credentials_file",
                "M4-12 release N+1",
            ),
            (
                LegacyCompatKind::DecimalMarkerContentPresent,
                "decimal_marker",
                "future shard after phase4_gate_check refuses pure-legacy installs",
            ),
        ];

        // Assert: every variant's short_tag + scheduled_for are stable
        // strings that the renderer will surface. This is the
        // structural backstop against renderer drift.
        for (kind, expected_tag, expected_sched) in cases {
            assert_eq!(kind.short_tag(), *expected_tag, "short_tag drift");
            assert_eq!(kind.scheduled_for(), *expected_sched, "scheduled_for drift");
            // Round-trip: as_str → kind_from_str → original kind.
            let s = kind.as_str();
            assert_eq!(
                kind_from_str(s),
                Some(*kind),
                "kind_from_str round-trip drift for {s}"
            );
        }

        // Build one realistic input and exercise the renderer end-to-
        // end. We can't easily capture stdout from a `println!`-based
        // renderer in unit tests without taking a dependency we don't
        // want; the structural assertions above + the printing call
        // verify both branches run without panicking.
        let entries: Vec<LegacyCompatEntry> = cases
            .iter()
            .map(|(k, _, _)| LegacyCompatEntry {
                kind: k.as_str().to_string(),
                evidence: "test fixture".to_string(),
                scheduled_for: k.scheduled_for(),
            })
            .collect();
        render_legacy_compat_line(&entries);

        // Drift-surfacing: an unknown kind must NOT crash the
        // renderer — it should fall through to the
        // `(unknown_schedule)` path. We construct a synthetic entry
        // with a kind that `kind_from_str` rejects.
        let drift = vec![LegacyCompatEntry {
            kind: "future_kind_not_yet_in_spec_13".to_string(),
            evidence: "test fixture".to_string(),
            scheduled_for: "unknown",
        }];
        render_legacy_compat_line(&drift);
        // No assertion needed beyond "did not panic" — the renderer's
        // drift-surfacing path is structurally exercised.
    }

    /// `csq doctor --repair-identities` smoke test: invoking the
    /// command on an empty `base_dir` (no profiles.json) returns Ok
    /// and writes nothing — there are no UUID-mapped slots to repair.
    /// Pins the no-op idempotence contract.
    #[test]
    fn repair_identities_noop_on_empty_base_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        // No profiles.json on disk — heal pass returns empty report.
        assert!(super::run_repair_identities(dir.path(), true).is_ok());
        assert!(super::run_repair_identities(dir.path(), false).is_ok());
    }

    /// `csq doctor --repair-identities` exercises the underlying heal
    /// pass and returns Ok even when slots remain unhealed (no legacy
    /// source). The command is informational — it does NOT exit non-zero
    /// to preserve the v2.7.7 daemon-supervisor contract where the gate
    /// is the authoritative refusal site.
    ///
    /// We exercise both --json and text output paths.
    #[test]
    fn repair_identities_runs_heal_with_partial_recovery() {
        use csq_core::accounts::identity_store::IdentityId;
        use csq_core::daemon::identity_mint::STORE_VERSION_SCHEMA_CURRENT;

        let dir = tempfile::TempDir::new().unwrap();
        let sentinel = csq_core::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        // Seed sentinel directly — `write_sentinel` is csq-core-internal.
        let sentinel_json = format!(
            r#"{{"schema":{},"minted_at":"2026-05-15T00:00:00Z","source":"doctor-test"}}"#,
            STORE_VERSION_SCHEMA_CURRENT
        );
        std::fs::write(&sentinel, sentinel_json.as_bytes()).unwrap();

        let uuid = IdentityId::new_v4();
        let mut profiles = csq_core::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("2".to_string(), uuid);
        let profiles_path = csq_core::accounts::profiles::profiles_path(dir.path());
        csq_core::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // Legacy creds present → heal should seed identity creds.
        // Settings legacy absent → heal records MissingLegacySource.
        let legacy = dir.path().join("credentials");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("2.json"), br#"{"tokens":{}}"#).unwrap();

        // Both output paths return Ok.
        assert!(super::run_repair_identities(dir.path(), true).is_ok());
        assert!(super::run_repair_identities(dir.path(), false).is_ok());

        // Identity credentials.json MUST exist after the run.
        let identity_path = csq_core::accounts::identity_store::identities_dir(dir.path())
            .join(uuid.to_canonical_string())
            .join("credentials.json");
        assert!(
            identity_path.exists(),
            "repair-identities MUST seed credentials.json from legacy"
        );
    }

    // ── an internal journal entry (§FD #2 of 0041): phase4_incomplete alarm tests ──

    /// Healthy / pre-Phase-1 install — no UUID-mapped slots → alarm is
    /// `None` and JSON serialization omits the field entirely (the
    /// canonical "no alarm needed" state).
    #[test]
    fn phase4_incomplete_alarm_absent_when_no_uuid_mapped_slots() {
        // Hermeticity (test-hermeticity.md MUST 1b): build_report transitively reads
        // CSQ_AUDIT_EDITION; pin a clean community baseline under the shared env lock
        // so this test cannot race a concurrent enterprise-edition setter.
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let dir = TempDir::new().unwrap();
        let report = build_report(dir.path());
        assert!(
            report.phase4_incomplete.is_none(),
            "phase4_incomplete MUST be None when profiles.json is absent"
        );

        let json = serde_json::to_string(&report).unwrap();
        assert!(
            !json.contains("\"phase4_incomplete\""),
            "JSON output MUST omit phase4_incomplete when None; got: {json}"
        );
        // Schema version pins to the current contract regardless of alarm state.
        assert!(
            json.contains(&format!("\"schema_version\":{DOCTOR_SCHEMA_VERSION}")),
            "JSON must contain the edition-active schema_version; got: {json}"
        );
    }

    /// Phase-4-incomplete install — UUID-mapped slots with missing identity
    /// files. Alarm MUST surface in `build_report` AND in the JSON payload
    /// with the correct affected_slot_count + missing_file_count.
    #[test]
    fn phase4_incomplete_alarm_surfaces_with_correct_counts() {
        // Hermeticity (test-hermeticity.md MUST 1b): build_report transitively reads
        // CSQ_AUDIT_EDITION; pin a clean community baseline under the shared env lock
        // so this test cannot race a concurrent enterprise-edition setter.
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        use csq_core::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();

        // Two slots, both missing creds AND settings → 4 missing files,
        // 2 distinct affected slots.
        let uuid_1 = IdentityId::new_v4();
        let uuid_2 = IdentityId::new_v4();
        let mut profiles = csq_core::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("1".to_string(), uuid_1);
        profiles.by_slot.insert("2".to_string(), uuid_2);
        let profiles_path = csq_core::accounts::profiles::profiles_path(dir.path());
        csq_core::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // Anthropic-binding signals: 2026-05-22 phase4_gate_status was made
        // codex-only-aware (Check 3 skips slots without legacy Anthropic).
        // To assert the 4-missing-files count for Anthropic-bound slots,
        // seed the legacy `credentials/<N>.json` files.
        let legacy_creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&legacy_creds_dir).unwrap();
        std::fs::write(legacy_creds_dir.join("1.json"), b"{}").unwrap();
        std::fs::write(legacy_creds_dir.join("2.json"), b"{}").unwrap();

        let report = build_report(dir.path());
        let alarm = report.phase4_incomplete.as_ref().expect(
            "phase4_incomplete MUST be Some when UUID-mapped slots have missing identity files",
        );
        assert_eq!(alarm.affected_slot_count, 2);
        assert_eq!(alarm.missing_file_count, 4);

        let json = serde_json::to_string(&report).unwrap();
        assert!(
            json.contains("\"phase4_incomplete\""),
            "JSON output MUST contain phase4_incomplete when alarm fires; got: {json}"
        );
        assert!(
            json.contains("\"affected_slot_count\":2"),
            "JSON MUST carry affected_slot_count=2; got: {json}"
        );
        assert!(
            json.contains("\"missing_file_count\":4"),
            "JSON MUST carry missing_file_count=4; got: {json}"
        );
    }

    /// Schema version was bumped 15 → 16 by #694 item 2 (audit_roster_floor_anchor
    /// field). Pins the contract so a future change has to surface
    /// explicitly in the spec/12 §12.11.5 record.
    #[test]
    fn doctor_report_schema_version_is_current() {
        // Hermeticity (test-hermeticity.md MUST 1b): build_report transitively reads
        // CSQ_AUDIT_EDITION; pin a clean community baseline under the shared env lock
        // so this test cannot race a concurrent enterprise-edition setter.
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let dir = TempDir::new().unwrap();
        let report = build_report(dir.path());
        assert_eq!(report.schema_version, DOCTOR_SCHEMA_VERSION);
    }

    // ── #694 item 2: audit_roster_floor_anchor field ──────────────────────

    /// When no roster is installed `audit_roster_floor_anchor` is omitted from
    /// the JSON (None → skip_serializing_if). The assertion pins to the
    /// build-active `DOCTOR_SCHEMA_VERSION` const (edition-specific), never a
    /// literal — so it stays correct across schema bumps.
    #[test]
    fn doctor_audit_roster_floor_anchor_absent_when_no_roster() {
        // Hermeticity (test-hermeticity.md MUST 1b): build_report transitively reads
        // CSQ_AUDIT_EDITION; pin a clean community baseline under the shared env lock
        // so this test cannot race a concurrent enterprise-edition setter.
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        // Arrange
        let dir = TempDir::new().unwrap();

        // Act — build on an empty install (no chain, no roster).
        let report = build_report(dir.path());

        // Assert — field is None (omitted).
        assert!(
            report.audit_roster_floor_anchor.is_none(),
            "audit_roster_floor_anchor MUST be None when no roster is installed"
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            !json.contains("audit_roster_floor_anchor"),
            "JSON MUST omit audit_roster_floor_anchor when None; got: {json}"
        );
        assert_eq!(report.schema_version, DOCTOR_SCHEMA_VERSION);
    }

    /// an internal ticket review MED-2: an INITIALIZED install (chain.json present)
    /// that has never run `csq audit roster install` (floor None) must ALSO
    /// omit the field — `chain.json exists` alone is the wrong predicate.
    #[test]
    fn doctor_floor_anchor_omitted_when_initialized_but_no_roster() {
        // Hermeticity (test-hermeticity.md MUST 1b): build_report transitively reads
        // CSQ_AUDIT_EDITION; pin a clean community baseline under the shared env lock
        // so this test cannot race a concurrent enterprise-edition setter.
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let dir = TempDir::new().unwrap();
        // chain.json present, roster_version_floor None (audit init, no roster).
        csq_core::audit::ChainState::new("01ARZ3NDEKTSV4RRFFQ69G5D0C")
            .save(dir.path())
            .expect("save chain.json");

        let report = build_report(dir.path());

        assert!(
            report.audit_roster_floor_anchor.is_none(),
            "audit_roster_floor_anchor MUST be omitted on an initialized-but-rosterless \
             install; got {:?}",
            report.audit_roster_floor_anchor
        );
    }

    /// `make_report` fixture carries `audit_roster_floor_anchor: None` and
    /// the JSON does NOT contain the field (skip_serializing_if = Option::is_none).
    #[test]
    fn doctor_make_report_omits_floor_anchor_field() {
        // Arrange
        let report = make_report(TerminalInfo {
            modern_count: 0,
            legacy_count: 0,
            check_available: false,
        });

        // Assert — fixture has None and JSON omits it.
        assert!(
            report.audit_roster_floor_anchor.is_none(),
            "make_report fixture must have audit_roster_floor_anchor: None"
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            !json.contains("audit_roster_floor_anchor"),
            "JSON must omit the field when None; got: {json}"
        );
    }

    // ── H1 regression: doctor MUST read the CORRECT custody dirs ──

    /// `check_seam_custody_count` must find files in `csq-runs/.quarantine/`
    /// (leading dot) and in `csq-runs/.pending/provenance/`.
    /// Regression guard for the bug where the path was "quarantine" (no dot).
    #[test]
    fn doctor_seam_custody_counts_read_correct_dirs() {
        // Hermeticity (test-hermeticity.md MUST 1b): build_report transitively reads
        // CSQ_AUDIT_EDITION; pin a clean community baseline under the shared env lock
        // so this test cannot race a concurrent enterprise-edition setter.
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Seed one .json file in each real custody dir.
        let qdir = base.join("csq-runs").join(".quarantine");
        std::fs::create_dir_all(&qdir).unwrap();
        std::fs::write(qdir.join("event-001.json"), b"{}").unwrap();

        let pdir = base.join("csq-runs").join(".pending").join("provenance");
        std::fs::create_dir_all(&pdir).unwrap();
        std::fs::write(pdir.join("parked-001.json"), b"{}").unwrap();

        let report = build_report(base);
        assert_eq!(
            report.seam_quarantine_count,
            Some(1),
            "seam_quarantine_count must be Some(1) when .quarantine/ has 1 .json file"
        );
        assert_eq!(
            report.seam_pending_provenance_count,
            Some(1),
            "seam_pending_provenance_count must be Some(1) when .pending/provenance/ has 1 .json file"
        );
    }

    // ── M6 #914: MCP-gate attestation outbox backlog predicate ───────────────

    /// Absent outbox dir → None (healthy steady state; always the community case).
    #[test]
    fn mcp_gate_outbox_backlog_none_when_dir_absent() {
        let dir = TempDir::new().unwrap();
        assert!(
            check_mcp_gate_outbox_backlog(dir.path()).is_none(),
            "absent .pending-mcp-gate/ must yield None"
        );
    }

    /// Empty outbox dir (drained clean) → None.
    #[test]
    fn mcp_gate_outbox_backlog_none_when_dir_empty() {
        let dir = TempDir::new().unwrap();
        let outbox = dir.path().join("csq-runs").join(".pending-mcp-gate");
        std::fs::create_dir_all(&outbox).unwrap();
        assert!(
            check_mcp_gate_outbox_backlog(dir.path()).is_none(),
            "empty outbox dir must yield None (nothing to report)"
        );
    }

    /// A small, fresh backlog → Some with warn=false (drains on next start).
    /// `.tmp.` in-flight writes and subdirs are excluded, mirroring the drain.
    #[test]
    fn mcp_gate_outbox_backlog_counts_json_excludes_tmp_and_subdirs() {
        let dir = TempDir::new().unwrap();
        let outbox = dir.path().join("csq-runs").join(".pending-mcp-gate");
        std::fs::create_dir_all(&outbox).unwrap();
        std::fs::write(outbox.join("sess-a.0.json"), b"{}").unwrap();
        std::fs::write(outbox.join("sess-a.1.json"), b"{}").unwrap();
        // An in-flight tmp write and a non-json file must NOT be counted.
        std::fs::write(outbox.join("sess-a.2.tmp.1234.json"), b"{}").unwrap();
        std::fs::write(outbox.join("README"), b"x").unwrap();
        std::fs::create_dir_all(outbox.join("subdir.json")).unwrap();

        let backlog =
            check_mcp_gate_outbox_backlog(dir.path()).expect("non-empty outbox must yield Some");
        assert_eq!(
            backlog.pending_count, 2,
            "only the two real .json files count"
        );
        assert!(
            !backlog.warn,
            "a fresh 2-file backlog is a benign transient (warn=false)"
        );
        assert_eq!(
            backlog.state,
            McpGateBacklogState::PendingDaemonDown,
            "no drain stamp written in the test → daemon-down disposition (info, not stuck)"
        );
        assert!(
            backlog.oldest_age_secs.is_some(),
            "oldest_age_secs is populated when files carry readable mtimes"
        );
    }

    /// M6 #909 shard D wiring: `check_mcp_gate_outbox_backlog` reads the last-drain
    /// stamp (shard B) and classifies. A fresh stamp + a young backlog → `Draining`
    /// (daemon actively draining), with a small `last_drain_age_secs`. This proves
    /// the read is wired, complementing the pure-classifier unit test below.
    #[test]
    fn mcp_gate_outbox_backlog_draining_when_stamp_fresh() {
        let dir = TempDir::new().unwrap();
        let outbox = dir.path().join("csq-runs").join(".pending-mcp-gate");
        std::fs::create_dir_all(&outbox).unwrap();
        std::fs::write(outbox.join("sess-a.0.json"), b"{}").unwrap();
        // A fresh drain-cycle stamp ⟺ the daemon is actively draining.
        csq_core::audit::outbox_paths::stamp_outbox_drain(dir.path()).unwrap();

        let backlog = check_mcp_gate_outbox_backlog(dir.path()).expect("non-empty outbox → Some");
        assert_eq!(
            backlog.state,
            McpGateBacklogState::Draining,
            "fresh stamp + young backlog → Draining (daemon draining, benign)"
        );
        assert!(!backlog.warn, "Draining is not operator-actionable");
        assert!(
            backlog.last_drain_age_secs.is_some_and(|a| a <= 5),
            "last_drain_age_secs reflects the just-written stamp"
        );
    }

    /// M6 #909 shard D: the daemon-aware classifier across the count-cap,
    /// drain-freshness, and age axes — Stuck / Draining / PendingDaemonDown.
    #[test]
    fn classify_mcp_gate_backlog_daemon_aware() {
        use McpGateBacklogState::{Draining, PendingDaemonDown, Stuck};
        let now = 1_000_000u64;
        let fresh = now - 60; // stamp 60s ago → daemon actively draining
        let stale = now - (MCP_GATE_DRAIN_STAMP_FRESH_SECS + 60); // daemon down

        // Count cap → Stuck ALWAYS, regardless of stamp/age (even daemon-down: an
        // unbounded pending queue is never silently tolerated).
        assert_eq!(
            classify_mcp_gate_backlog(MCP_GATE_OUTBOX_STUCK_COUNT + 1, Some(0), None, now),
            Stuck
        );
        assert_eq!(
            classify_mcp_gate_backlog(MCP_GATE_OUTBOX_STUCK_COUNT + 1, Some(0), Some(stale), now),
            Stuck
        );

        // Daemon draining (fresh stamp) + young backlog → Draining (benign).
        assert_eq!(
            classify_mcp_gate_backlog(2, Some(60), Some(fresh), now),
            Draining
        );
        // Daemon draining + oldest past the stuck window → Stuck (chain not appendable).
        assert_eq!(
            classify_mcp_gate_backlog(
                2,
                Some(MCP_GATE_OUTBOX_STUCK_AGE_WHILE_DRAINING_SECS + 1),
                Some(fresh),
                now
            ),
            Stuck
        );
        // Exactly at the age window is NOT stuck (strict `>`).
        assert_eq!(
            classify_mcp_gate_backlog(
                2,
                Some(MCP_GATE_OUTBOX_STUCK_AGE_WHILE_DRAINING_SECS),
                Some(fresh),
                now
            ),
            Draining
        );

        // Stale stamp (daemon down) → PendingDaemonDown even for a very old backlog
        // (no false STUCK alarm during a maintenance window) — the count cap above
        // is the only escalation behind a down daemon.
        assert_eq!(
            classify_mcp_gate_backlog(2, Some(10 * 60 * 60), Some(stale), now),
            PendingDaemonDown
        );
        // No stamp at all (never drained on this base) → PendingDaemonDown.
        assert_eq!(
            classify_mcp_gate_backlog(2, Some(10 * 60 * 60), None, now),
            PendingDaemonDown
        );
        // Exactly at the freshness window still counts as draining (stale is strict `>`).
        assert_eq!(
            classify_mcp_gate_backlog(
                2,
                Some(60),
                Some(now - MCP_GATE_DRAIN_STAMP_FRESH_SECS),
                now
            ),
            Draining
        );
        // A future stamp (clock skew) reads as age 0 (fresh), never a giant age —
        // saturating_sub cannot manufacture a false disposition.
        assert_eq!(
            classify_mcp_gate_backlog(2, Some(60), Some(now + 500), now),
            Draining
        );
    }

    /// `fmt_age_secs` renders compact human units across the boundaries.
    #[test]
    fn fmt_age_secs_compact_units() {
        assert_eq!(fmt_age_secs(45), "45s");
        assert_eq!(fmt_age_secs(90), "1m");
        assert_eq!(fmt_age_secs(3 * 60 * 60), "3h");
        assert_eq!(fmt_age_secs(2 * 24 * 60 * 60), "2d");
    }

    // ── M19: seam_capture_conformance (Finding D enum) ───────────────────────

    /// Finding D: when `required-hooks.json` is absent, the conformance field
    /// is `NotConfigured` — operator-visible info line (never silent).
    #[test]
    fn m19_capture_conformance_not_configured_when_no_required_hooks_json() {
        // Hermeticity (test-hermeticity.md MUST 1b): build_report transitively reads
        // CSQ_AUDIT_EDITION; pin a clean community baseline under the shared env lock
        // so this test cannot race a concurrent enterprise-edition setter.
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let dir = TempDir::new().unwrap();
        let report = build_report(dir.path());
        assert_eq!(
            report.seam_capture_conformance,
            SeamConformanceState::NotConfigured,
            "seam_capture_conformance MUST be NotConfigured when required-hooks.json is absent"
        );
        // JSON shape: `{"state":"not_configured"}` — always present (no skip_serializing_if).
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            json.contains("\"state\":\"not_configured\""),
            "JSON MUST include state:not_configured when file absent; got: {json}"
        );
        assert!(
            json.contains(&format!("\"schema_version\":{DOCTOR_SCHEMA_VERSION}")),
            "JSON must contain the edition-active schema_version; got: {json}"
        );
    }

    /// Finding D: when `required-hooks.json` lists surfaces that are all Unwired,
    /// the conformance field is `Drift` with the unwired surface names.
    #[test]
    fn m19_capture_conformance_drift_when_required_surfaces_unwired() {
        // Hermeticity (test-hermeticity.md MUST 1b): build_report transitively reads
        // CSQ_AUDIT_EDITION; pin a clean community baseline under the shared env lock
        // so this test cannot race a concurrent enterprise-edition setter.
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        // Write a required-hooks.json requesting ["cc","codex"].
        let audit_dir = base.join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::write(audit_dir.join("required-hooks.json"), br#"["cc","codex"]"#).unwrap();

        let report = build_report(base);
        let drift = match &report.seam_capture_conformance {
            SeamConformanceState::Drift { drift } => drift,
            other => panic!(
                "seam_capture_conformance MUST be Drift when required surfaces are Unwired; got: {other:?}"
            ),
        };
        // Both cc and codex are Unwired in production — drift must list both.
        assert!(
            drift.contains(&"cc".to_string()),
            "drift must contain 'cc' (Unwired): {drift:?}"
        );
        assert!(
            drift.contains(&"codex".to_string()),
            "drift must contain 'codex' (Unwired): {drift:?}"
        );
        // JSON shape: `{"state":"drift","drift":["cc","codex"]}`.
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            json.contains("\"state\":\"drift\""),
            "JSON MUST include state:drift; got: {json}"
        );
    }

    /// Finding D: when `required-hooks.json` is present but is an empty `[]`,
    /// the conformance field is `NotConfigured` — `[]` means no requirement set.
    /// Documented in spec §12.20: empty array ≡ NotConfigured.
    #[test]
    fn m19_capture_conformance_not_configured_when_required_hooks_json_empty_array() {
        // Hermeticity (test-hermeticity.md MUST 1b): build_report transitively reads
        // CSQ_AUDIT_EDITION; pin a clean community baseline under the shared env lock
        // so this test cannot race a concurrent enterprise-edition setter.
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let audit_dir = base.join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::write(audit_dir.join("required-hooks.json"), b"[]").unwrap();

        let report = build_report(base);
        // Empty `[]` is treated as "no surfaces required" = NotConfigured (spec §12.20).
        assert_eq!(
            report.seam_capture_conformance,
            SeamConformanceState::NotConfigured,
            "empty required-hooks.json MUST yield NotConfigured"
        );
        let json = serde_json::to_string(&report).expect("report must serialize");
        assert!(
            json.contains("\"state\":\"not_configured\""),
            "JSON MUST include state:not_configured for empty array; got: {json}"
        );
    }

    /// Finding D: `PolicyUnreadable` when `required-hooks.json` contains
    /// invalid JSON (unreadable/unparseable policy → operator-visible ⚠).
    #[test]
    fn m19_capture_conformance_policy_unreadable_when_json_invalid() {
        // Hermeticity (test-hermeticity.md MUST 1b): build_report transitively reads
        // CSQ_AUDIT_EDITION; pin a clean community baseline under the shared env lock
        // so this test cannot race a concurrent enterprise-edition setter.
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let audit_dir = base.join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        // Write garbage — not a JSON array.
        std::fs::write(audit_dir.join("required-hooks.json"), b"not-json{{{").unwrap();

        let report = build_report(base);
        assert!(
            matches!(
                &report.seam_capture_conformance,
                SeamConformanceState::PolicyUnreadable { .. }
            ),
            "seam_capture_conformance MUST be PolicyUnreadable when JSON is invalid; \
             got: {:?}",
            report.seam_capture_conformance
        );
        // JSON shape: `{"state":"policy_unreadable","reason":"..."}`.
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            json.contains("\"state\":\"policy_unreadable\""),
            "JSON MUST include state:policy_unreadable; got: {json}"
        );
        assert!(
            json.contains("\"reason\":"),
            "JSON MUST include reason field; got: {json}"
        );
    }

    /// LOW-2: oversized required-hooks.json (> 64 KiB) → PolicyUnreadable with
    /// `reason: "required-hooks.json too large"`. Defends against same-UID DoS
    /// via a planted oversized file.
    #[test]
    fn m19_capture_conformance_policy_unreadable_when_required_hooks_too_large() {
        // Hermeticity (test-hermeticity.md MUST 1b): build_report transitively reads
        // CSQ_AUDIT_EDITION; pin a clean community baseline under the shared env lock
        // so this test cannot race a concurrent enterprise-edition setter.
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let audit_dir = base.join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        // Write a file exceeding the 64 KiB cap.
        let oversized = vec![b'x'; 65 * 1024 + 1];
        std::fs::write(audit_dir.join("required-hooks.json"), &oversized).unwrap();

        let report = build_report(base);
        match &report.seam_capture_conformance {
            SeamConformanceState::PolicyUnreadable { reason } => {
                assert!(
                    reason.contains("too large"),
                    "reason MUST mention 'too large'; got: {reason:?}"
                );
            }
            other => panic!(
                "seam_capture_conformance MUST be PolicyUnreadable for oversized file; got: {other:?}"
            ),
        }
    }

    /// AC-7 / schema-version pin: schema_version equals the edition-active
    /// `DOCTOR_SCHEMA_VERSION` const (the assertion pins to it, never a literal)
    /// regardless of conformance
    /// state.  `seam_capture_conformance` is always serialized (no
    /// skip_serializing_if), so the key is always present in `--json` output.
    #[test]
    fn m19_schema_version_14_with_and_without_conformance() {
        // Hermeticity (test-hermeticity.md MUST 1b): build_report transitively reads
        // CSQ_AUDIT_EDITION; pin a clean community baseline under the shared env lock
        // so this test cannot race a concurrent enterprise-edition setter.
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Without required-hooks.json → NotConfigured.
        let r1 = build_report(base);
        assert_eq!(
            r1.schema_version, DOCTOR_SCHEMA_VERSION,
            "schema_version must match edition-active const"
        );
        let j1 = serde_json::to_string(&r1).unwrap();
        assert!(
            j1.contains("seam_capture_conformance"),
            "seam_capture_conformance key MUST always be present in JSON (no skip); got: {j1}"
        );

        // With required-hooks.json present → Drift (all Unwired in production).
        let audit_dir = base.join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::write(audit_dir.join("required-hooks.json"), br#"["cc"]"#).unwrap();
        let r2 = build_report(base);
        assert_eq!(
            r2.schema_version, DOCTOR_SCHEMA_VERSION,
            "schema_version must match edition-active const"
        );
        let j2 = serde_json::to_string(&r2).unwrap();
        assert!(
            j2.contains("seam_capture_conformance"),
            "seam_capture_conformance key MUST always be present when file present; got: {j2}"
        );
    }

    /// Smoke test: the render path runs without panicking for both an
    /// alarm-present payload AND an empty one. Output capture is not
    /// available in unit tests without taking a stdout-grabber dep we
    /// don't want; the test confirms the renderer executes cleanly.
    #[test]
    fn render_phase4_incomplete_alarm_does_not_panic() {
        let alarm = Phase4IncompleteAlarm {
            affected_slot_count: 8,
            missing_file_count: 16,
        };
        super::render_phase4_incomplete_alarm(&alarm);
    }

    // ── RN1-D5 G1: unrecoverable rename label surfacing ──────────────────────

    /// RN1-D5 G1: `csq doctor` warns about unrecoverable rename labels —
    /// slots with `accounts[N].email` (a user rename label) but no
    /// `by_slot[N]` UUID — so they are NOT silently dropped when RN1-F
    /// removes the `accounts` field.
    ///
    /// Fixture: `accounts[3].email = "Work account"` (a user rename label)
    /// with NO `by_slot[3]` entry. Sentinel `label-channel-migrated` exists
    /// to signal that the relocation pass has already run.
    ///
    /// Asserts:
    /// - `report.unrecoverable_label_relocations` is non-empty
    /// - The single entry names slot 3
    /// - The `accounts_email` field carries the label text
    /// - The field is present in JSON output
    ///
    /// This test is the acceptance criterion for the WBS RN1-D5 "no silent
    /// drop" requirement per G1 of the verification pass.
    #[test]
    fn relocation_warns_unrecoverable_legacy_slots_no_silent_drop() {
        // Hermeticity (test-hermeticity.md MUST 1b): build_report transitively reads
        // CSQ_AUDIT_EDITION; pin a clean community baseline under the shared env lock
        // so this test cannot race a concurrent enterprise-edition setter.
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        use csq_core::accounts::profiles::{
            label_relocation_sentinel_path, profiles_path, save, AccountProfile, ProfilesFile,
        };

        // Arrange: a profiles.json where slot 3 has a user rename label
        // in accounts[3].email but NO by_slot[3] UUID entry (slot was
        // never Pass-0 minted — the unrecoverable class).
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        let mut pf = ProfilesFile::empty();
        pf.set_profile(
            3,
            AccountProfile {
                email: "Work account".to_string(),
                method: "oauth".to_string(),
                extra: Default::default(),
            },
        );
        // No pf.by_slot["3"] — deliberately absent to trigger the
        // unrecoverable path.
        save(&profiles_path(base), &pf).unwrap();

        // Write the label-channel-migrated sentinel. Without this
        // sentinel check_unrecoverable_label_relocations returns []
        // (pre-migration noise suppression).
        let sentinel = label_relocation_sentinel_path(base);
        std::fs::write(&sentinel, b"").unwrap();

        // Act
        let report = build_report(base);

        // Assert: warning field is non-empty and names slot 3.
        assert!(
            !report.unrecoverable_label_relocations.is_empty(),
            "unrecoverable_label_relocations MUST be non-empty when slot 3 \
             has an accounts email but no by_slot UUID"
        );
        let slot3 = report
            .unrecoverable_label_relocations
            .iter()
            .find(|s| s.slot == 3)
            .expect("slot 3 must appear in unrecoverable_label_relocations");
        assert_eq!(
            slot3.accounts_email, "Work account",
            "accounts_email must carry the user rename label"
        );

        // Assert: JSON output contains the field.
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            json.contains("\"unrecoverable_label_relocations\""),
            "JSON must contain unrecoverable_label_relocations field; got: {json}"
        );
        assert!(
            json.contains("\"Work account\""),
            "JSON must carry the label text; got: {json}"
        );
    }

    /// RN1-D5 G1 complement: pre-sentinel state returns no warning.
    /// Without the `label-channel-migrated` sentinel the field must be
    /// empty (the relocation pass has not run yet; warning would be
    /// noise for pre-migration users).
    #[test]
    fn relocation_no_warning_before_sentinel() {
        use csq_core::accounts::profiles::{profiles_path, save, AccountProfile, ProfilesFile};

        // Same fixture as relocation_warns_unrecoverable_legacy_slots —
        // slot 3 has an accounts email, no by_slot UUID — but no sentinel.
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        let mut pf = ProfilesFile::empty();
        pf.set_profile(
            3,
            AccountProfile {
                email: "Work account".to_string(),
                method: "oauth".to_string(),
                extra: Default::default(),
            },
        );
        save(&profiles_path(base), &pf).unwrap();
        // Deliberately NO sentinel file.

        // Act
        let slots = check_unrecoverable_label_relocations(base);

        // Assert: empty without sentinel.
        assert!(
            slots.is_empty(),
            "pre-sentinel state must return empty — no relocation pass has run yet"
        );
    }

    // ── RN1-D R1: Pass-0 skip warning surfacing ──────────────────────────────

    /// Helper: write a minimal-shape `credentials/<N>.json` whose payload
    /// has NO `oauthAccount` block — `read_oauth_email_from_cred_path`
    /// returns `None` for this file, which is the exact precondition that
    /// causes Pass-0 to skip the slot via the warn-log path at
    /// `csq-core/src/daemon/identity_mint.rs:188-195`.
    ///
    /// Lives next to the existing `write_credentials` helper conceptually;
    /// kept local to this test cluster because no other test needs the
    /// "no oauthAccount" shape.
    fn write_anthropic_cred_without_oauth_email(base: &std::path::Path, slot: u16) {
        let cred_dir = base.join("credentials");
        std::fs::create_dir_all(&cred_dir).unwrap();
        // Valid OAuth payload but no oauthAccount field — `credentials::load`
        // accepts this (oauthAccount lives in the typed struct's `extra`
        // HashMap, which defaults to empty); `read_oauth_email_from_cred_path`
        // returns None.
        let json = serde_json::json!({
            "claudeAiOauth": {
                "accessToken": format!("at-{slot}"),
                "refreshToken": format!("rt-{slot}"),
                "expiresAt": 9_999_999_999_999u64,
                "scopes": ["user:profile"],
                "subscriptionType": "max",
            }
        });
        std::fs::write(cred_dir.join(format!("{slot}.json")), json.to_string()).unwrap();
    }

    /// RN1-D R1: post-sentinel, a slot whose credentials file has no
    /// `oauthAccount.emailAddress` AND no `by_slot[N]` UUID MUST appear
    /// in `pass0_skipped_slots`. This is the exact set the daemon's
    /// Pass-0 (`identity_mint.rs:188-195`) would re-skip if the sentinel
    /// were deleted.
    #[test]
    fn doctor_surfaces_pass0_skipped_slot_post_sentinel() {
        // Hermeticity (test-hermeticity.md MUST 1b): build_report transitively reads
        // CSQ_AUDIT_EDITION; pin a clean community baseline under the shared env lock
        // so this test cannot race a concurrent enterprise-edition setter.
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        // Arrange: slot 5 has a credentials file with no oauthAccount,
        // no by_slot mapping, and the store-version sentinel exists.
        write_anthropic_cred_without_oauth_email(base, 5);
        let sentinel = csq_core::accounts::identity_store::store_version_path(base);
        std::fs::write(&sentinel, br#"{"schema":2}"#).unwrap();

        // Act
        let report = build_report(base);

        // Assert: pass0_skipped_slots non-empty and names slot 5.
        assert!(
            !report.pass0_skipped_slots.is_empty(),
            "pass0_skipped_slots MUST be non-empty when slot 5 has a \
             credential file with no oauthAccount.emailAddress and no \
             by_slot UUID"
        );
        let slot5 = report
            .pass0_skipped_slots
            .iter()
            .find(|s| s.slot == 5)
            .expect("slot 5 must appear in pass0_skipped_slots");
        assert_eq!(
            slot5.reason, "oauth_email_unresolved",
            "reason must match the daemon's error_kind tag"
        );

        // Assert: JSON output contains the field and the closed-enum reason.
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            json.contains("\"pass0_skipped_slots\""),
            "JSON must contain pass0_skipped_slots field; got: {json}"
        );
        assert!(
            json.contains("\"oauth_email_unresolved\""),
            "JSON must carry the reason tag verbatim; got: {json}"
        );

        // Assert: schema_version is the current contract.
        assert_eq!(
            report.schema_version, DOCTOR_SCHEMA_VERSION,
            "schema_version must equal the edition-active DOCTOR_SCHEMA_VERSION"
        );
    }

    /// RN1-D R1 complement: pre-sentinel state returns no warning.
    /// Without the `store-version` sentinel Pass-0 has not yet run on
    /// this host, so a "skip" framing would be premature noise.
    #[test]
    fn doctor_pass0_skip_field_empty_before_sentinel() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        // Same fixture as the post-sentinel test but no sentinel file.
        write_anthropic_cred_without_oauth_email(base, 5);
        // Deliberately NO store-version sentinel.

        // Act
        let slots = check_pass0_skipped_slots(base);

        // Assert: empty without sentinel.
        assert!(
            slots.is_empty(),
            "pre-sentinel state must return empty — Pass-0 has not run yet"
        );
    }

    /// RN1-D R1 noise-suppression: a slot whose `by_slot[N]` is present
    /// MUST be excluded from `pass0_skipped_slots` even if its
    /// `oauth_email` is currently absent. The presence of a UUID means
    /// the slot has already been remediated (most commonly by
    /// `mint_for_login` after the operator re-OAuth'd) — keeping it in
    /// the warning list would be a stale signal.
    #[test]
    fn doctor_pass0_skip_excludes_slot_already_minted() {
        use csq_core::accounts::profiles::{profiles_path, save, ProfilesFile};
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        // Arrange: cred file with no oauthAccount + sentinel present
        // (would trigger the warning) + by_slot[5] = uuid (suppresses).
        write_anthropic_cred_without_oauth_email(base, 5);
        let sentinel = csq_core::accounts::identity_store::store_version_path(base);
        std::fs::write(&sentinel, br#"{"schema":2}"#).unwrap();

        let uuid = csq_core::testing::identity_fixtures::fixture_uuid_for_slot(5);
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("5".to_string(), uuid);
        save(&profiles_path(base), &pf).unwrap();

        // Act
        let slots = check_pass0_skipped_slots(base);

        // Assert: empty — slot has been minted, no operator action needed.
        assert!(
            slots.is_empty(),
            "slot already minted (by_slot[5] present) MUST be excluded from \
             pass0_skipped_slots; got {slots:?}"
        );
    }

    // ── H3: doctor detects prior anchor activity when sink disabled ───────────

    /// H3 regression: when `audit.sink == "none"` but on-disk evidence of prior
    /// anchoring exists, `detect_prior_anchor_activity` MUST return `Some((sink, ts))`.
    /// When no evidence exists it MUST return `None`.
    ///
    /// This prevents witness-absence from going unnoticed: an operator who
    /// previously anchored to "rekor" and then set `sink = "none"` should see a
    /// doctor warning that the witness was disabled.
    #[test]
    fn doctor_detects_prior_anchor_activity_when_sink_disabled() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();

        // ── Part (a): sink "none" + anchor-state-rekor.json present → Some ──

        // Write an anchor-state file as if a prior "rekor" anchor succeeded.
        let state_path = base.join("anchor-state-rekor.json");
        let prior_ts = "2026-05-01T10:00:00Z";
        std::fs::write(
            &state_path,
            format!(
                r#"{{"last_anchor_ts":"{prior_ts}","replication_drift_count":0,"last_anchored_seq":3}}"#
            ),
        )
        .unwrap();

        // Act
        let result = detect_prior_anchor_activity(base);

        // Assert — must detect the rekor evidence.
        assert!(
            result.is_some(),
            "anchor-state-rekor.json present → must detect prior anchor activity"
        );
        let (sink_name, last_ts) = result.unwrap();
        assert_eq!(
            sink_name, "rekor",
            "detected sink name must be 'rekor', got '{sink_name}'"
        );
        assert_eq!(
            last_ts, prior_ts,
            "detected ts must match the state file's last_anchor_ts"
        );

        // ── Part (b): sink "none" + NO prior evidence → None ──

        let tmp2 = TempDir::new().unwrap();
        let base2 = tmp2.path();

        // Act — base2 has no anchor-state files at all.
        let result2 = detect_prior_anchor_activity(base2);

        // Assert — must return None when no evidence exists.
        assert!(
            result2.is_none(),
            "no anchor-state files present → must return None"
        );

        // ── Part (c): anchor-state-none.json (sentinel name) → still None ──
        // A file named "anchor-state-none.json" must be ignored (sink_name == "none"
        // is explicitly filtered out in detect_prior_anchor_activity).
        let sentinel_path = base2.join("anchor-state-none.json");
        std::fs::write(
            &sentinel_path,
            r#"{"last_anchor_ts":"2026-05-01T00:00:00Z","replication_drift_count":0}"#,
        )
        .unwrap();

        let result3 = detect_prior_anchor_activity(base2);
        assert!(
            result3.is_none(),
            "anchor-state-none.json must be ignored (sink 'none' is the disabled sentinel)"
        );
    }

    /// MED-1 regression: `detect_prior_anchor_activity` must surface the
    /// witness-disabled warning even when `anchor-state-<sink>.json` has been
    /// deleted by a same-UID attacker.
    ///
    /// The chain's own `ReplicationAck` / `ReplicationFailed` records are the
    /// authoritative, tamper-evident signal (they cannot be erased without
    /// breaking the hash chain that the daemon's pre-bind `verify_chain` rejects).
    ///
    /// Setup: no `anchor-state-*.json` files present, but the chain has a
    /// `ReplicationAck` record. The detection MUST fire via the chain scan.
    #[test]
    fn doctor_detects_prior_anchor_via_chain_when_sidecar_deleted() {
        use csq_core::audit::persist::write_record_v2;
        use csq_core::audit::types::{
            Ed25519Signature, EventKind, EventPayload, KeyId, RecordId, ReplicationAckPayload,
            Sha256Hex, SignedRecord, SinkId, SinkName,
        };

        let tmp = TempDir::new().unwrap();
        let base = tmp.path();

        // Write a minimal CsqRun record to initialise the chain.
        let seed = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new("01MED1000000000000000000S0").unwrap(),
            chain_id: RecordId::try_new("01MED1000000000000000000XY").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(csq_core::audit::types::CsqRunPayload {
                run_id: "seed".to_string(),
            }),
            ts: "2026-06-03T00:00:00Z".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        };
        write_record_v2(seed, Some(base)).unwrap();

        // Write a ReplicationAck record (simulates a prior anchor operation).
        let ack = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new("01MED1000000000000000000AK").unwrap(),
            chain_id: RecordId::try_new("01MED1000000000000000000XY").unwrap(),
            seq: 0, // writer assigns actual seq
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::ReplicationAck,
            payload: EventPayload::ReplicationAck(ReplicationAckPayload {
                sink: SinkName::try_new("rekor").unwrap(),
                sink_id: SinkId::try_new("sha256:abc123".to_string()).unwrap(),
            }),
            ts: "2026-06-03T01:00:00Z".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        };
        write_record_v2(ack, Some(base)).unwrap();

        // Confirm no anchor-state sidecar file exists.
        let has_sidecar = std::fs::read_dir(base)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().starts_with("anchor-state-"));
        assert!(
            !has_sidecar,
            "test precondition: no anchor-state sidecar files must be present"
        );

        // ACT: detect_prior_anchor_activity must surface the warning via the
        // chain scan even though the sidecar was "deleted" (never written here).
        let result = detect_prior_anchor_activity(base);

        assert!(
            result.is_some(),
            "MED-1 regression: detect_prior_anchor_activity returned None even though \
             chain contains a ReplicationAck record — sidecar deletion defeats detection"
        );
        let (sink_name, _ts) = result.unwrap();
        assert_eq!(
            sink_name, "rekor",
            "detected sink name must be 'rekor' (from ReplicationAck payload)"
        );
    }

    /// M3a AC-7 (doctor surface) — `csq doctor` MUST NOT surface the trust-plane
    /// grade bare: whenever `audit_trust_plane_grade` is `Some`, the companion
    /// `audit_verification_level_summary` MUST also be `Some` (honest-host
    /// boundary; redteam R1 HIGH, 2026-06-17). The sibling AC-7 test in
    /// verify.rs covers only the `csq audit verify --json` surface
    /// (`to_json_output`); this covers the doctor surface that shipped bare.
    #[cfg(feature = "enterprise")]
    #[test]
    fn doctor_grade_surface_includes_level_summary() {
        use csq_core::audit::persist::write_record_v2;
        use csq_core::audit::types::{
            Ed25519Signature, EventKind, EventPayload, KeyId, RecordId, Sha256Hex, SignedRecord,
        };

        // Hermeticity: build_report (called below) transitively reaches verify_chain
        // → resolve_registry → resolve_edition, which reads CSQ_AUDIT_EDITION. Hold
        // the shared env lock + pin a clean community baseline so this enterprise test
        // cannot race a concurrent enterprise-edition setter (testing.md Rule 6 /
        // test-hermeticity.md MUST 1b — reader side, transitive via build_report).
        let _env_guard = csq_core::platform::test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::remove_var("CSQ_AUDIT_ROSTER_ROOT_PUBKEY");

        let tmp = TempDir::new().unwrap();
        let base = tmp.path();

        // Write a CsqRun record via the production writer. In the enterprise
        // build the central stamp (write_record_v2_impl) fills
        // verification_level = AUTO_APPROVED, so the chain is leveled-to-head.
        let seed = SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new("01MED3000000000000000000S0").unwrap(),
            chain_id: RecordId::try_new("01MED3000000000000000000XY").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(csq_core::audit::types::CsqRunPayload {
                run_id: "ac7-doctor".to_string(),
            }),
            ts: "2100-01-01T00:00:00+00:00".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None, // central stamp fills AUTO_APPROVED (enterprise)
        };
        write_record_v2(seed, Some(base)).unwrap();

        let report = build_report(base);

        // The grade must be reachable (the leveled chain → CONFORMANT or better).
        assert!(
            report.audit_trust_plane_grade.is_some(),
            "leveled chain must surface a trust-plane grade"
        );
        // THE invariant this test defends: grade present ⇒ summary present.
        assert!(
            report.audit_verification_level_summary.is_some(),
            "doctor surfaced the grade ({:?}) WITHOUT the verification_level_summary \
             — a bare grade over-claims on the honest-host boundary",
            report.audit_trust_plane_grade
        );
        let summary = report.audit_verification_level_summary.unwrap();
        assert!(
            summary.get("AUTO_APPROVED").copied().unwrap_or(0) >= 1,
            "summary must count the AUTO_APPROVED record(s): {summary:?}"
        );
    }
}
