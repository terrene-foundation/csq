//! Operator-run live-wire `(provider × auth-mode)` contract verification.
//!
//! Authoritative spec: `specs/11-probe-driven-verification.md`. Probes
//! hit real provider endpoints with the slot's real credentials, parse
//! the response, and assert each load-bearing field matches the
//! contract pinned in spec 05.
//!
//! Probes are operator-only. They MUST NOT run in CI per
//! `.claude/rules/ci-real-oauth-prohibition.md`.

pub mod anthropic_api_key;
pub mod anthropic_oauth;
pub mod codex_oauth;
pub mod gemini_code_assist_oauth;
pub mod gemini_local;
pub mod ollama_keyless;
pub mod third_party_bearer;

use crate::types::AccountNum;
use serde::Serialize;
use std::path::Path;

/// Output schema version. Bump on breaking shape changes; consumers
/// (release-notes scripts, downstream tooling) MUST gate on this.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One probe execution record, per spec 11 §11.3 output schema.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeRecord {
    pub schema_version: &'static str,
    pub slot: u16,
    pub cell: &'static str,
    pub spec_anchor: &'static str,
    pub status: ProbeStatus,
    pub endpoint: String,
    pub elapsed_ms: u64,
    pub assertions_passed: u32,
    pub assertions_total: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<ProbeDiagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_response_excerpt: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProbeStatus {
    Ok,
    Fail,
    Skipped,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeDiagnostic {
    pub failed_assertion: String,
    pub observed_shape: String,
    pub hint: String,
}

/// Reason the probe could not be executed for this slot. Distinct from
/// a FAIL — a Skip means the slot's binding does not match any cell in
/// the matrix, or prerequisites are absent (e.g. missing credentials).
#[derive(Debug)]
pub enum SkipReason {
    /// No credential file at the canonical path for this slot.
    /// Payload deliberately omitted: the resolved path (OS username, home-dir
    /// layout, UUID-bearing identity-store fragment) MUST NOT appear in
    /// operator-facing output (`security.md` §2). Slot number is available
    /// on `ProbeRecord.slot` — callers do not need to embed it here.
    NoCredentials,
    /// #534: codex slot has neither identity-store creds (resolved via
    /// `profiles.json::by_slot` → `credentials_codex_path_for`) nor the
    /// legacy `credentials/codex-<N>.json` fallback. Distinct from
    /// `NoCredentials` (which covers Anthropic identity-store absence)
    /// because the operator remediation differs: codex requires
    /// `csq login <N> --provider codex`, NOT `csq login <N>`. Payload
    /// deliberately omitted — same path-freedom rationale as
    /// `NoCredentials` (`security.md` §2).
    NoCodexCredentials,
    /// Slot's surface/auth-mode is not yet implemented in the probe matrix.
    UnsupportedCell(String),
    /// Slot has a spawn-admissible binding marker whose JSON does not
    /// parse (corrupt / written by a newer csq / EACCES). The daemon WILL
    /// attempt a spawn for this slot (Gemini) or the probe would
    /// mis-route (Codex — pre-#534 the codex-oauth cell read a shared
    /// user-global file; post-#534 it reads per-identity creds via
    /// `credentials_codex_path_for`, but the corrupt-binding check
    /// remains load-bearing to surface the legacy file's parse failure
    /// to the operator). Payload uses a fixed-vocabulary `&'static str`
    /// tag from the underlying error type's
    /// `error_kind_tag()` — NEVER `format!("{e}")`, `Display`/`to_string()`,
    /// `Debug`/`{:?}`, or `Malformed.reason`/`Corrupt.reason` (all carry
    /// the absolute marker path; security.md §2; spec 11 §11.2).
    ///
    /// The `surface` discriminant drives the `as_diagnostic` arm's
    /// Gemini-vs-Codex literal prose. The arm MUST branch on `surface` via
    /// a fixed-vocabulary match — NEVER `Display::to_string()`,
    /// `format!("{}", surface)`, `surface.to_string()`, or `{:?}` (path-
    /// freedom of `Surface`'s `Display` impl is incidental, not enforced).
    CorruptBinding {
        surface: crate::providers::catalog::Surface,
        kind: &'static str,
    },
    /// #520: per-slot credential file parses but does not carry the
    /// expected surface variant (specifically: Anthropic-shape
    /// `claudeAiOauth` payload at a `codex-<N>.json` path). The
    /// `observed_kind` field is a fixed-vocabulary tag returned by
    /// `CredentialFile::observed_variant_tag()`. Today's only
    /// structurally-reachable value when this variant fires is
    /// `"anthropic"` (the parser is 2-variant untagged; a Codex-path
    /// `Ok(cf)` with `cf.codex().is_none()` always means `cf` is the
    /// Anthropic variant). The `&'static str` shape is
    /// forward-compatible if `CredentialFile` ever gains a third
    /// variant. Never the raw payload.
    WrongVariantBinding {
        surface: crate::providers::catalog::Surface,
        observed_kind: &'static str,
    },
}

impl SkipReason {
    fn as_diagnostic(&self) -> ProbeDiagnostic {
        match self {
            SkipReason::NoCredentials => ProbeDiagnostic {
                failed_assertion: "prerequisite: credential file present".into(),
                // Path-free per security.md §2: no absolute path, no OS username,
                // no home-dir layout, no UUID-bearing identity-store fragment.
                // Slot number is on ProbeRecord.slot — omit here.
                observed_shape: "missing".into(),
                hint: "run `csq login <N>` to provision the slot".into(),
            },
            SkipReason::NoCodexCredentials => ProbeDiagnostic {
                failed_assertion: "prerequisite: slot has codex credentials".into(),
                // Path-free per security.md §2 — slot number is on ProbeRecord.slot.
                observed_shape: "missing".into(),
                hint: "run `csq login <N> --provider codex` to provision credentials".into(),
            },
            SkipReason::UnsupportedCell(detail) => ProbeDiagnostic {
                failed_assertion: "matrix lookup: cell implemented".into(),
                observed_shape: detail.clone(),
                hint: "spec 11 §11.1 lists the implemented matrix; see §11.7 for outstanding cells"
                    .into(),
            },
            SkipReason::CorruptBinding { surface, kind } => match surface {
                crate::providers::catalog::Surface::Gemini => ProbeDiagnostic {
                    failed_assertion: "prerequisite: gemini binding parses".into(),
                    observed_shape: format!(
                        "binding marker present but does not parse (corrupt or written by a newer csq); kind: {kind}"
                    ),
                    hint: "fix with `csq logout <N>` then `csq login <N> --provider gemini`".into(),
                },
                crate::providers::catalog::Surface::Codex => ProbeDiagnostic {
                    failed_assertion: "prerequisite: codex credential file parses".into(),
                    observed_shape: format!(
                        "codex credential file present but does not parse (corrupt or written by a newer csq); kind: {kind}"
                    ),
                    hint: "fix with `csq logout <N>` then `csq login <N> --provider codex`".into(),
                },
                crate::providers::catalog::Surface::ClaudeCode => unreachable!(
                    "CorruptBinding is only constructed for Gemini and Codex surfaces"
                ),
            },
            // MIRROR the existing CorruptBinding arm above:
            // surface-specific literal strings, `unreachable!()` for non-wired
            // surfaces. #520 wires Codex only — the `surface` field on
            // WrongVariantBinding is forward-compatible per ADR-3, but the dispatch
            // arm is wired ONLY for `Surface::Codex` in this PR. A future Gemini
            // wrong-variant PR MUST add the `Surface::Gemini` arm with Gemini-specific
            // literals.
            SkipReason::WrongVariantBinding { surface, observed_kind } => match surface {
                crate::providers::catalog::Surface::Codex => ProbeDiagnostic {
                    failed_assertion: "prerequisite: codex credential file is the Codex variant".into(),
                    observed_shape: format!(
                        "codex credential file parses but carries a non-Codex variant; observed: {observed_kind}"
                    ),
                    hint: "fix with `csq logout <N>` then `csq login <N> --provider codex`".into(),
                },
                other => unreachable!(
                    "WrongVariantBinding is only constructed for Codex surface in #520; got {other:?}"
                ),
            },
        }
    }
}

/// Dispatch a probe for a single slot. Reads the credential file,
/// classifies the (surface, auth-mode) pair, and routes to the matching
/// cell implementation. Returns a `ProbeRecord` regardless of outcome —
/// errors become FAIL or Skipped records, never Rust `Err`.
///
/// `home_dir` is the user's home (e.g. `~`); used by cells that read OS-
/// level credential files (Cell 09 reads `~/.gemini/oauth_creds.json`).
/// CLI callers pass `dirs::home_dir().unwrap_or_default()`.
pub fn probe_slot(base_dir: &Path, home_dir: &Path, slot: AccountNum) -> ProbeRecord {
    use crate::credentials::file as cred_file;
    use crate::providers::gemini::provisioning::{is_gemini_bound_slot, read_binding, AuthMode};

    // ── Step 1: resolve the per-slot signals ────────────────────────────────
    //
    // `read_binding` is called EXACTLY ONCE. Bind `binding_res` and match
    // `&binding_res` for every Gemini branch. The `is_gemini_corrupt_bound`
    // helper re-reads the marker and discards the Ok value — it MUST NOT be
    // called here (spec 01-implementation-plan §M3 load-bearing constraint).
    //
    // M4-4: route through identity-keyed credentials when
    // `profiles.json::by_slot` has a UUID for this slot.
    // M4-12 / RN1-C: numeric fallback `credentials/<N>.json` retired.
    let bound = is_gemini_bound_slot(base_dir, slot);
    let binding_res = read_binding(base_dir, slot);

    // #515 M3: Codex per-slot signals (read-once invariant).
    // F-int-2 amendment: conditional bind avoids one ENOENT per unbound slot
    // per probe — only loads the credential file when the slot is actually
    // Codex-bound (mirrors the Gemini `binding_res` at line 149 above).
    let bound_codex = crate::providers::codex::provisioning::is_codex_bound_slot(base_dir, slot);
    let codex_load_res = bound_codex.then(|| {
        cred_file::load(&crate::providers::codex::provisioning::binding_path(
            base_dir, slot,
        ))
    });

    let anthropic_creds_path =
        crate::accounts::profiles::resolve_slot_to_uuid(base_dir, slot.get())
            .map(|uuid| crate::accounts::identity_store::credentials_path_for(base_dir, uuid));

    // `anthropic_present`: explicit `symlink_metadata` classification on the
    // resolved UUID credential path (spec 00-synthesis §Decided design step 1).
    // - Ok(_) → present (true)
    // - Err(PermissionDenied) → INDETERMINATE → fail-toward-C2 (true)
    //   lstat(2) requires search permission on every parent; when `identities/`
    //   is 0o000, `symlink_metadata` returns Err(PermissionDenied). A bare
    //   `.is_ok()` would yield false and let a corrupt-Gemini + unreadable-
    //   identities slot escape C2 (R3 deep-analyst HIGH — cascade-mask).
    // - Any other Err (NotFound, etc.) → false
    // NOT `.is_file()` and NOT a bare `.is_ok()`.
    let anthropic_present = anthropic_creds_path
        .as_deref()
        .map(|p| match std::fs::symlink_metadata(p) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => true,
            Err(_) => false,
        })
        .unwrap_or(false);

    // Keep the parsed credential for the later Anthropic dispatch branches.
    let anthropic_creds = anthropic_creds_path
        .as_deref()
        .and_then(|p| cred_file::load(p).ok());

    // ── Step 2: C2 ambiguity — presence-presence gate (order MANDATORY: before
    //    corrupt-binding and valid-Gemini branches) ────────────────────────
    //
    // Both conjuncts gate on artifact PRESENCE, not parse-success (synthesis
    // §Decided design step 2). Covers: FM-3 (corrupt Gemini + valid
    // Anthropic), FM-5 (corrupt Gemini + corrupt Anthropic), valid Gemini
    // + any credential file at the UUID path. Also covers: corrupt Codex +
    // valid Anthropic, and valid Codex + valid Anthropic (#515 F1 widening —
    // intentional behaviour change; valid Codex + valid Anthropic now FAILs
    // ambiguous-binding). Placed before the 3P/Codex `discover_all` walks
    // so corrupt slots short-circuit.
    if (bound || bound_codex) && anthropic_present {
        return ambiguous_binding(slot);
    }

    // ── Step 3: corrupt-binding ──────────────────────────────────────────────
    //
    // Spawn-admissible marker (`bound`) but `read_binding` failed. The daemon
    // WILL attempt a Gemini spawn and fail. Kind tag via `error_kind_tag()`
    // only — never Display/Debug/Malformed.reason (path leak, security.md §2).
    if bound && binding_res.is_err() {
        return skipped(
            slot,
            "gemini-corrupt-binding",
            "11§11.2",
            "n/a",
            SkipReason::CorruptBinding {
                surface: crate::providers::catalog::Surface::Gemini,
                kind: binding_res
                    .as_ref()
                    .err()
                    .map(|e| e.error_kind_tag())
                    .unwrap_or("unknown"),
            },
        );
    }

    // ── Step 4: valid Gemini — existing dispatch (unchanged) ─────────────
    //
    // Cells 07, 08, 09 — Gemini bindings live in a separate per-slot
    // file (`credentials/gemini-<N>.json`).
    //   - CodeAssistOAuth → Cell 09 (live wire)
    //   - ApiKey          → Cell 07 (local-state quota.json assertions)
    //   - VertexSa        → Cell 08 (local-state + SA file checks)
    //
    // Step 4 precedes Step 3.5: a valid Gemini binding on a slot that
    // ALSO has a corrupt Codex credential dispatches to Gemini (AC-12).
    // Gemini spawn-admissibility is marker-based (pure symlink_metadata);
    // when it resolves Ok, Gemini takes precedence over Codex corrupt-binding.
    if let Ok(binding) = &binding_res {
        match &binding.auth {
            AuthMode::CodeAssistOAuth => {
                return gemini_code_assist_oauth::probe(slot, home_dir);
            }
            AuthMode::ApiKey => {
                return gemini_local::probe_api_key(slot, base_dir);
            }
            AuthMode::VertexSa { path } => {
                return gemini_local::probe_vertex_sa(slot, base_dir, path);
            }
        }
    }

    // ── Step 3.5: corrupt OR wrong-variant Codex credential file ───────────
    //
    // Placed AFTER Step 4 (valid Gemini dispatch) and BEFORE Step 5
    // (codex-oauth cell dispatch). C2 already short-circuited the
    // `&& anthropic_present` case at Step 2, so this fires only when
    // anthropic_present == false (pure corrupt-Codex, no Anthropic
    // creds). Without this branch a corrupt slot's legacy file would
    // remain invisible — Step 5 dispatches via `discovery_codex_match`
    // which scans BOTH the legacy `credentials/codex-<N>.json` (Pass 1)
    // AND the identity-store `identities/<UUID>/credentials-codex.json`
    // (Pass 2). Step 5 routes to `codex_oauth::probe` which post-#534
    // reads per-identity creds; the corrupt legacy file would be
    // silently masked by the healthy identity-store creds, hiding the
    // misconfiguration from the operator. Step 3.5 surfaces the
    // legacy-file failure explicitly so the operator can repair it.
    //
    // Two structurally mutually-exclusive error cases on the same
    // `codex_load_res` (see synthesis §"Asymmetry with #515"):
    //   - Some(Err(_))                         → #515 corrupt-binding
    //   - Some(Ok(cf)) if cf.codex().is_none() → #520 wrong-variant-binding
    //
    // Both prerequisite-class → exit 64. C2 (Step 2) already short-circuited
    // the `&& anthropic_present` cases for either error class via presence-presence
    // (bound_codex is symlink_metadata, payload-agnostic).
    //
    // Kind tag via `error_kind_tag()` only — never Display/Debug/reason
    // (path leak, security.md §2).
    if bound_codex {
        match &codex_load_res {
            Some(Err(load_err)) => {
                return skipped(
                    slot,
                    "codex-corrupt-binding",
                    "11§11.2",
                    "n/a",
                    SkipReason::CorruptBinding {
                        surface: crate::providers::catalog::Surface::Codex,
                        kind: load_err.error_kind_tag(),
                    },
                );
            }
            Some(Ok(cf)) if cf.codex().is_none() => {
                return skipped(
                    slot,
                    "codex-wrong-variant-binding",
                    "11§11.2",
                    "n/a",
                    SkipReason::WrongVariantBinding {
                        surface: crate::providers::catalog::Surface::Codex,
                        observed_kind: cf.observed_variant_tag(),
                    },
                );
            }
            _ => {
                // Valid Codex (`Some(Ok(cf))` with `cf.codex().is_some()`) falls
                // through to Step 5 (3P / valid Codex / Anthropic). Defensive
                // `_ =>` also covers the impossible-None case (`codex_load_res`
                // is `None` only when `bound_codex == false`, contradicting the
                // outer `if bound_codex` guard — the conditional bind at
                // `probe/mod.rs:155-160` (`bound_codex.then(||)`) returns
                // `Some(_)` iff `bound_codex == true`). The `_ =>` arm exists
                // to keep the match exhaustive without `unreachable!()`/panic.
                // FM-7 impossibility argument: the `if bound_codex` wrapper IS
                // load-bearing — AC-13c structural pin catches any future
                // refactor that lifts this match outside the guard.
            }
        }
    }

    // ── Step 5: existing 3P / Codex / Anthropic fall-through (unchanged) ───

    // Cells 04-06 — 3P bearer providers (MiniMax, Z.AI, DeepSeek).
    // Cell 10 — Ollama (local, keyless). Identify via the discovery
    // layer's `AccountSource::ThirdParty`.
    if let Some(provider_id) = lookup_third_party_provider(base_dir, slot) {
        if provider_id == "ollama" {
            return ollama_keyless::probe(slot);
        }
        if let Some(rec) = third_party_bearer::probe(base_dir, slot, &provider_id) {
            return rec;
        }
        return skipped(
            slot,
            "third-party-bearer",
            "05§5",
            "n/a",
            SkipReason::UnsupportedCell(format!(
                "3P provider {provider_id} not yet implemented (cells 04-06 cover mm/zai/deepseek; cell 10 covers ollama)"
            )),
        );
    }

    // Cells 01, 02, 03 — credential-file-keyed slots.
    let creds = match anthropic_creds {
        Some(c) => c,
        None => {
            // No Anthropic-shape credential file found (either UUID
            // absent in profiles.json, or file missing at identity path).
            // M4-12: numeric path fallback removed; no UUID = no creds.
            // Try Codex OAuth before giving up — Codex slots are not
            // stored under the Anthropic identity path; the codex-oauth
            // cell resolves its own credential path via the identity
            // store (post-#534) or legacy `credentials/codex-<N>.json`
            // fallback (pre-A++). The dispatcher's gate is
            // `discovery_codex_match` ALONE — the prior
            // `codex_slot_present(home_dir)` conjunct read
            // `~/.codex/auth.json` which is not csq-managed and was
            // retired in #534 per `account-terminal-separation.md`
            // MUST Rule 4 (diagnostic-daemon parity).
            if discovery_codex_match(base_dir, slot) {
                return codex_oauth::probe(base_dir, slot);
            }
            // Do NOT propagate `path_display` into the SkipReason — the resolved
            // identity-store path leaks OS username + home-dir layout
            // (`security.md` §2). Slot number is on ProbeRecord.slot.
            return skipped(slot, "unknown", "n/a", "n/a", SkipReason::NoCredentials);
        }
    };

    // Cell 01 / 02 — Anthropic OAuth or API key, distinguished by
    // access-token prefix per spec 01 §1.2 (`sk-ant-oat01-` is OAuth,
    // `sk-ant-api03-` is API key).
    if let Some(anthro) = creds.anthropic() {
        let token = anthro.claude_ai_oauth.access_token.expose_secret();
        if token.starts_with("sk-ant-oat01-") {
            return anthropic_oauth::probe(slot, anthro);
        }
        return anthropic_api_key::probe(slot);
    }

    // Do NOT propagate `path_display` into UnsupportedCell — the resolved path
    // leaks OS username + home-dir layout (`security.md` §2).
    // The slot number is on ProbeRecord.slot; path is not needed for diagnosis.
    skipped(
        slot,
        "unknown-credential-shape",
        "n/a",
        "n/a",
        SkipReason::UnsupportedCell(
            "credential file parses as neither Anthropic nor Codex shape".into(),
        ),
    )
}

/// Returns the catalog provider id (`mm`, `zai`, `deepseek`, …) if
/// `slot` has a 3P binding under `<base_dir>/config-<N>/settings.json`.
/// Translates the discovery layer's display label (e.g. `"DeepSeek"`)
/// into the catalog id (e.g. `"deepseek"`) via
/// [`crate::providers::catalog::id_from_display_name`].
fn lookup_third_party_provider(base_dir: &Path, slot: AccountNum) -> Option<String> {
    use crate::accounts::{discovery, AccountSource};
    let label = discovery::discover_all(base_dir)
        .into_iter()
        .find(|info| info.id == slot.get())
        .and_then(|info| match info.source {
            AccountSource::ThirdParty { provider } => Some(provider),
            _ => None,
        })?;
    crate::providers::catalog::id_from_display_name(&label).map(|s| s.to_string())
}

/// Whether `slot` is registered as a Codex account in the discovery
/// layer. Avoids the false-positive of probing Codex when the slot
/// number happens not to be a Codex slot.
fn discovery_codex_match(base_dir: &Path, slot: AccountNum) -> bool {
    use crate::accounts::{discovery, AccountSource};
    discovery::discover_all(base_dir)
        .into_iter()
        .any(|info| info.id == slot.get() && matches!(info.source, AccountSource::Codex))
}

pub(super) fn skipped(
    slot: AccountNum,
    cell: &'static str,
    spec_anchor: &'static str,
    endpoint: &str,
    reason: SkipReason,
) -> ProbeRecord {
    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell,
        spec_anchor,
        status: ProbeStatus::Skipped,
        endpoint: endpoint.to_string(),
        elapsed_ms: 0,
        assertions_passed: 0,
        assertions_total: 0,
        diagnostic: Some(reason.as_diagnostic()),
        redacted_response_excerpt: None,
    }
}

/// Round-1 redteam C2 — ambiguous-binding case. A slot that has BOTH
/// a Gemini binding marker (spawn-admissible) AND an Anthropic credential
/// file at the resolved UUID path cannot be probed safely; either probe
/// would surface a misleading result.
///
/// **In-scope leak fix (#514):** the previous version accepted an
/// `anthropic_path: &Path` argument and interpolated it into
/// `observed_shape` — a `/Users/<user>/…` path leak (`security.md` §2).
/// The C2 predicate rewrite makes this branch fire more often; the path
/// is removed and replaced with a path-free fixed-vocabulary literal.
/// The slot number is already on the `ProbeRecord`.
fn ambiguous_binding(slot: AccountNum) -> ProbeRecord {
    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: "ambiguous-binding",
        spec_anchor: "11§11.2",
        status: ProbeStatus::Fail,
        endpoint: "n/a".to_string(),
        elapsed_ms: 0,
        assertions_passed: 0,
        assertions_total: 1,
        diagnostic: Some(ProbeDiagnostic {
            failed_assertion: "dispatcher: slot has exactly one cell binding".into(),
            observed_shape:
                "a provider binding marker AND an Anthropic credential both present for this slot"
                    .into(),
            hint: "data corruption — likely an orphan binding from an aborted unbind, \
                   or a slot that holds artifacts for two surfaces simultaneously. \
                   Reconcile manually: `csq logout <N>` then re-bind."
                .into(),
        }),
        redacted_response_excerpt: None,
    }
}

/// Map a `ProbeRecord.status` to the per-spec exit code. Used by the
/// CLI handler to compute the process exit code from `--all` runs.
/// Spec 11 §11.3:
/// - 0  if every probed slot is OK
/// - 1  if any slot FAILed an assertion
/// - 64 if a slot has no provider binding (misconfiguration — fix slot config)
/// - 65 if a slot is in transient operator state (stale OAuth token, empty
///   project, HTML interception) — fix one-shot, then retry
/// - 70 for transient infra failures (DNS, TCP refused)
///
/// Round-1 redteam H3-sec: Fail classification is by `failed_assertion`
/// prefix (a load-bearing string, not a hint), since hint text is
/// operator-facing English that drifts. Round-2 redteam C5: Skipped is
/// further split — `prerequisite:` failed_assertion → 64 (misconfiguration);
/// any other Skipped → 65 (operator state). Cell 09 routes 401 / empty
/// project / HTML interception to operator-state Skipped per spec 11
/// §11.4 so a stale gemini-cli token does not block release tagging.
pub fn exit_code_for(records: &[ProbeRecord]) -> i32 {
    let mut max = 0;
    for r in records {
        let code = match r.status {
            ProbeStatus::Ok => 0,
            ProbeStatus::Skipped => {
                let assertion = r
                    .diagnostic
                    .as_ref()
                    .map(|d| d.failed_assertion.as_str())
                    .unwrap_or("");
                if assertion.starts_with("prerequisite:") {
                    64
                } else {
                    65
                }
            }
            ProbeStatus::Fail => {
                let assertion = r
                    .diagnostic
                    .as_ref()
                    .map(|d| d.failed_assertion.as_str())
                    .unwrap_or("");
                if assertion.starts_with("transport:") {
                    70
                } else {
                    1
                }
            }
        };
        if code > max {
            max = code;
        }
    }
    max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_all_ok_is_zero() {
        let records = vec![ok_record()];
        assert_eq!(exit_code_for(&records), 0);
    }

    #[test]
    fn exit_code_any_fail_is_one() {
        let records = vec![ok_record(), fail_record_assertion("A5: parser drift")];
        assert_eq!(exit_code_for(&records), 1);
    }

    #[test]
    fn exit_code_routes_by_failed_assertion_not_hint() {
        // Round-1 redteam H3-sec: classification was previously by
        // hint substring (operator-facing English, drifts). Now by
        // failed_assertion prefix (load-bearing string).
        let r = ProbeRecord {
            schema_version: SCHEMA_VERSION,
            slot: 1,
            cell: "test",
            spec_anchor: "test",
            status: ProbeStatus::Fail,
            endpoint: "test".into(),
            elapsed_ms: 0,
            assertions_passed: 0,
            assertions_total: 1,
            diagnostic: Some(ProbeDiagnostic {
                failed_assertion: "transport: probe never reached endpoint".into(),
                observed_shape: "y".into(),
                hint: "anything goes here".into(),
            }),
            redacted_response_excerpt: None,
        };
        assert_eq!(exit_code_for(&[r]), 70);
    }

    #[test]
    fn ambiguous_binding_is_a_fail_record() {
        let r = ambiguous_binding(AccountNum::try_from(1).unwrap());
        assert_eq!(r.status, ProbeStatus::Fail);
        assert_eq!(r.cell, "ambiguous-binding");
        let d = r.diagnostic.unwrap();
        assert!(d
            .observed_shape
            .contains("provider binding marker AND an Anthropic credential"));
    }

    /// M4-4 AC: when `profiles.json::by_slot` is populated, `probe_slot`
    /// resolves the Anthropic credential path through the identity store,
    /// not through the legacy `credentials/<N>.json`. Validated by writing
    /// an Anthropic-shape credential at the identity-keyed path and leaving
    /// the legacy path absent; the probe must dispatch to a cell that
    /// requires reading those credentials (anthropic_oauth, indicated by
    /// the access-token prefix). Without the M4-4 read flip, the probe
    /// would skip with NoCredentials because the legacy path is empty.
    #[test]
    fn probe_account_reads_identity_credentials() {
        use tempfile::tempdir;
        let base = tempdir().unwrap();
        let home = tempdir().unwrap();
        let slot_num = AccountNum::try_from(2u16).unwrap();

        // Seed `profiles.json::by_slot[2] = UUID`.
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(2);
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("2".to_string(), uuid);
        crate::accounts::profiles::save(
            &crate::accounts::profiles::profiles_path(base.path()),
            &profiles,
        )
        .unwrap();

        // Write Anthropic OAuth creds at the identity-keyed path ONLY.
        // The legacy `credentials/2.json` is intentionally absent.
        let identity_path =
            crate::accounts::identity_store::credentials_path_for(base.path(), uuid);
        std::fs::create_dir_all(identity_path.parent().unwrap()).unwrap();
        std::fs::write(
            &identity_path,
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-IDENTITY-PROBE-TOKEN","refreshToken":"rt","expiresAt":99999999999999,"scopes":["user:inference"]}}"#,
        )
        .unwrap();

        // Sanity: the legacy path is NOT present.
        let legacy_path = crate::credentials::file::canonical_path(base.path(), slot_num);
        assert!(
            !legacy_path.exists(),
            "test setup: legacy credentials/2.json must be absent to prove the identity-keyed read"
        );

        let r = probe_slot(base.path(), home.path(), slot_num);

        // The probe must NOT have skipped with NoCredentials — the only
        // way for it to find creds is via the M4-4 identity-keyed read.
        // For an OAuth-shape token (`sk-ant-oat01-` prefix) the probe
        // routes to Cell 01 (anthropic-oauth). The HTTP layer won't
        // actually run in a unit-test (no network); the probe will
        // produce either Fail (transport error) or Ok depending on the
        // cell's implementation. The key M4-4 assertion is that the
        // probe did NOT short-circuit to Skipped/NoCredentials.
        assert_ne!(
            r.status,
            ProbeStatus::Skipped,
            "probe MUST not skip — identity-keyed credentials are present (status: {:?})",
            r.status
        );
        // And the cell is a credential-keyed cell, not an unsupported-cell skip.
        assert!(
            r.cell == "anthropic-oauth"
                || r.cell == "anthropic-api-key"
                || r.cell == "ambiguous-binding"
                || r.cell == "codex-oauth",
            "probe must have read the identity-keyed credentials and dispatched to a \
             credential-keyed cell, got cell={}",
            r.cell
        );
    }

    /// Integration test for the C2 ambiguous-binding dispatcher guard
    /// (round-1 redteam C2). A slot must resolve to exactly one cell.
    /// Staging both a Gemini binding AND an Anthropic credential file
    /// must short-circuit dispatch to the `ambiguous-binding` Fail
    /// record — never a per-cell probe. Round-2 redteam C2.
    #[test]
    fn dispatcher_returns_ambiguous_when_both_bindings_present() {
        use crate::providers::gemini::provisioning::provision_code_assist_oauth;
        use tempfile::tempdir;
        let base = tempdir().unwrap();
        let home = tempdir().unwrap();
        let slot = AccountNum::try_from(1).unwrap();

        // Stage Gemini Code Assist OAuth binding (lightweight: writes
        // the binding marker without secret payload, since gemini-cli
        // owns the OAuth tokens).
        provision_code_assist_oauth(base.path(), slot).unwrap();

        // M4-12: probe_slot now reads Anthropic credentials ONLY from
        // the UUID-keyed identity path (identities/<uuid>/credentials.json).
        // We must: (1) provision a UUID mapping in profiles.json::by_slot,
        // then (2) write the credential to the UUID-keyed path.
        // Writing to the old canonical_path (credentials/N.json) is no
        // longer read by probe_slot — the numeric path is retired as a
        // read path for the probe.
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);
        let profiles_path = crate::accounts::profiles::profiles_path(base.path());
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("1".to_string(), uuid);
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        let cred_path = crate::accounts::identity_store::credentials_path_for(base.path(), uuid);
        std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
        std::fs::write(
            &cred_path,
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-anything","refreshToken":"rt","expiresAt":99999999999999,"scopes":["user:inference"]}}"#,
        )
        .unwrap();

        let r = probe_slot(base.path(), home.path(), slot);
        assert_eq!(r.cell, "ambiguous-binding");
        assert_eq!(r.status, ProbeStatus::Fail);
        let d = r.diagnostic.unwrap();
        assert!(d
            .observed_shape
            .contains("provider binding marker AND an Anthropic credential"));
    }

    #[test]
    fn exit_code_skipped_prerequisite_is_64() {
        // Round-2 redteam C5: prerequisite-class Skipped (no credential
        // file, no provider binding) means misconfiguration. Operator
        // fixes slot config.
        let records = vec![skipped(
            AccountNum::try_from(1).unwrap(),
            "x",
            "y",
            "z",
            SkipReason::NoCredentials,
        )];
        assert_eq!(exit_code_for(&records), 64);
    }

    #[test]
    fn exit_code_skipped_operator_state_is_65() {
        // Round-2 redteam C5: operator-state Skipped (e.g. Cell 09
        // returns 401 because gemini-cli's OAuth token went stale)
        // means a one-shot fix, NOT misconfiguration. Distinct exit
        // code so operator hint isn't misread as "wrong slot config".
        let r = ProbeRecord {
            schema_version: SCHEMA_VERSION,
            slot: 1,
            cell: "gemini-code-assist-oauth",
            spec_anchor: "05§5.8.2",
            status: ProbeStatus::Skipped,
            endpoint: "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist".into(),
            elapsed_ms: 0,
            assertions_passed: 0,
            assertions_total: 6,
            diagnostic: Some(ProbeDiagnostic {
                failed_assertion: "loadCodeAssist returned 401".into(),
                observed_shape: "401 Unauthorized".into(),
                hint: "run `gemini` once interactively to refresh oauth_creds.json".into(),
            }),
            redacted_response_excerpt: None,
        };
        assert_eq!(exit_code_for(&[r]), 65);
    }

    #[test]
    fn exit_code_infra_fail_is_70() {
        let records = vec![fail_record_assertion("transport: request reached endpoint")];
        assert_eq!(exit_code_for(&records), 70);
    }

    /// M4-12 / RN1-C AC (Finding 1.2): when a slot has NO UUID mapping in
    /// `profiles.json::by_slot`, `probe_slot` MUST NOT fall back to the
    /// retired numeric `credentials/<N>.json` path. It must skip visibly
    /// with `ProbeStatus::Skipped` and a `failed_assertion` starting with
    /// `"prerequisite:"` (so `exit_code_for` maps it to 64, misconfiguration).
    ///
    /// Arrange: write a credential ONLY at the numeric path; leave `by_slot`
    /// absent from `profiles.json` (so `resolve_slot_to_uuid` returns None).
    /// Act: `probe_slot` for that account.
    /// Assert: (1) result is Skipped (not Ok/Fail), proving no read happened
    ///         via the UUID path or numeric path; (2) diagnostic
    ///         `failed_assertion` starts with "prerequisite:", confirming
    ///         this is misconfiguration-class and not an operator-state skip;
    ///         (3) `exit_code_for` returns 64 for the record.
    #[test]
    fn probe_slot_refuses_unresolvable_slot_no_numeric_fallback() {
        use tempfile::tempdir;
        let base = tempdir().unwrap();
        let home = tempdir().unwrap();
        let slot_num = AccountNum::try_from(3u16).unwrap();

        // Write a valid Anthropic-shape credential at the NUMERIC path ONLY.
        // This is the retired read path that M4-12 / RN1-C removes.
        let numeric_path = crate::credentials::file::canonical_path(base.path(), slot_num);
        std::fs::create_dir_all(numeric_path.parent().unwrap()).unwrap();
        std::fs::write(
            &numeric_path,
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-NUMERIC-FALLBACK-MUST-NOT-READ","refreshToken":"rt","expiresAt":99999999999999,"scopes":["user:inference"]}}"#,
        )
        .unwrap();

        // Intentionally do NOT write profiles.json (or write one with empty
        // by_slot). `resolve_slot_to_uuid` will return None for this slot —
        // so any credential dispatch MUST go through the UUID path (which
        // doesn't exist), not the numeric path (which has valid creds).
        // A profiles.json that exists but has an empty by_slot map is the
        // same scenario — we leave the file absent entirely.
        assert!(
            !crate::accounts::profiles::profiles_path(base.path()).exists(),
            "test setup: profiles.json must be absent to prove by_slot has no UUID"
        );

        // The numeric path DOES exist (credential present at retired path).
        assert!(
            numeric_path.exists(),
            "test setup: numeric credential must exist to prove numeric fallback was NOT used"
        );

        // Act.
        let r = probe_slot(base.path(), home.path(), slot_num);

        // Assert 1: the probe must have skipped — if it had read the numeric
        // credential it would have dispatched to anthropic-oauth (not Skipped).
        assert_eq!(
            r.status,
            ProbeStatus::Skipped,
            "probe MUST skip when slot has no UUID mapping (M4-12 numeric fallback retired), \
             got status={:?} cell={}",
            r.status,
            r.cell
        );

        // Assert 2: the skip must be prerequisite-class (failed_assertion
        // starts with "prerequisite:") — misconfiguration, not operator state.
        let diag = r
            .diagnostic
            .as_ref()
            .expect("Skipped record must have a diagnostic");
        assert!(
            diag.failed_assertion.starts_with("prerequisite:"),
            "skip must be prerequisite-class (misconfiguration); got failed_assertion={:?}",
            diag.failed_assertion
        );

        // Assert 3: exit_code_for maps prerequisite-class skips to 64.
        assert_eq!(
            exit_code_for(&[r]),
            64,
            "prerequisite-class skip must map to exit code 64 (misconfiguration)"
        );
    }

    /// M2/AC-5: the `CorruptBinding` and `WrongVariantBinding` diagnostics are
    /// path-free — the serialized output must contain neither `/Users/` nor an
    /// absolute credentials path prefix. The payload uses fixed-vocabulary tags
    /// only. Parameterised over `CorruptBinding × {Gemini, Codex}` and
    /// `WrongVariantBinding × {Codex}` per security L1 and AC-5.
    #[test]
    fn binding_diagnostics_are_path_free() {
        use crate::providers::catalog::Surface;

        // Build a skipped ProbeRecord for the given reason and serialize it.
        let build_skipped_record = |reason: SkipReason| -> ProbeRecord {
            let diag = reason.as_diagnostic();
            assert!(
                diag.failed_assertion.starts_with("prerequisite:"),
                "failed_assertion must start with 'prerequisite:'; got: {:?}",
                diag.failed_assertion
            );
            ProbeRecord {
                schema_version: SCHEMA_VERSION,
                slot: 1,
                cell: "binding-test",
                spec_anchor: "11§11.2",
                status: ProbeStatus::Skipped,
                endpoint: "n/a".to_string(),
                elapsed_ms: 0,
                assertions_passed: 0,
                assertions_total: 0,
                diagnostic: Some(diag),
                redacted_response_excerpt: None,
            }
        };

        let reasons: Vec<SkipReason> = vec![
            SkipReason::CorruptBinding {
                surface: Surface::Gemini,
                kind: "gemini_provision_malformed",
            },
            SkipReason::CorruptBinding {
                surface: Surface::Codex,
                kind: "credentials_malformed",
            },
            SkipReason::WrongVariantBinding {
                surface: Surface::Codex,
                observed_kind: "anthropic",
            },
        ];

        for reason in reasons {
            let record = build_skipped_record(reason);
            let serialized = serde_json::to_string(&record).unwrap();
            assert!(
                !serialized.contains("/Users/"),
                "diagnostic MUST NOT contain absolute /Users/ path; got: {serialized}"
            );
            assert!(
                !serialized.contains("credentials/codex-"),
                "diagnostic MUST NOT contain credentials/codex- prefix; got: {serialized}"
            );
            assert!(
                !serialized.contains("credentials/gemini-"),
                "diagnostic MUST NOT contain credentials/gemini- prefix; got: {serialized}"
            );
            assert!(
                !serialized.contains("identities/"),
                "diagnostic MUST NOT contain identities/ path; got: {serialized}"
            );
            assert_eq!(exit_code_for(&[record]), 64);
        }
    }

    /// M2/AC-5a: byte-for-byte template assertion for `WrongVariantBinding`.
    /// Verifies the serialized record's `diagnostic` field matches the expected
    /// template verbatim. Per 03-security-review.md §2.2 + AC-5a:
    /// template assertion catches future-flatten drift that banned
    /// substrings cannot.
    #[test]
    fn wrong_variant_diagnostic_matches_expected_template() {
        use crate::providers::catalog::Surface;

        let reason = SkipReason::WrongVariantBinding {
            surface: Surface::Codex,
            observed_kind: "anthropic",
        };
        let diagnostic = reason.as_diagnostic();
        let expected = serde_json::json!({
            "failed_assertion": "prerequisite: codex credential file is the Codex variant",
            "observed_shape": "codex credential file parses but carries a non-Codex variant; observed: anthropic",
            "hint": "fix with `csq logout <N>` then `csq login <N> --provider codex`"
        });
        let actual = serde_json::to_value(&diagnostic).unwrap();
        assert_eq!(actual, expected, "diagnostic template drift");

        // Belt-and-braces sanity tripwire: round-1 banned-substring scan
        // for known leak vectors.
        let serialized = serde_json::to_string(&diagnostic).unwrap();
        assert!(!serialized.contains("claudeAiOauth"));
        assert!(!serialized.contains("sk-ant-"));
        assert!(!serialized.contains("accessToken"));
        assert!(!serialized.contains("refreshToken"));
    }

    // ── M3 test helpers ──────────────────────────────────────────────────────

    /// Write a corrupt Gemini binding marker (present but unparseable).
    fn stage_corrupt_gemini_marker(base: &std::path::Path, slot_n: u16) {
        let creds = base.join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(
            creds.join(format!("gemini-{slot_n}.json")),
            b"{ not valid json",
        )
        .unwrap();
    }

    /// Write a Gemini binding marker for newer schema (version 999).
    fn stage_newer_schema_gemini_marker(base: &std::path::Path, slot_n: u16) {
        let creds = base.join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        let raw = serde_json::json!({
            "v": 999,
            "auth": { "mode": "api_key" },
            "model_name": "auto",
            "created_unix_secs": 0_u64,
        });
        std::fs::write(creds.join(format!("gemini-{slot_n}.json")), raw.to_string()).unwrap();
    }

    /// Seed profiles.json::by_slot[slot_n] = UUID and write Anthropic OAuth
    /// credentials at the UUID-keyed identity path. Returns the path written.
    fn stage_valid_anthropic_identity(base: &std::path::Path, slot_n: u16) -> std::path::PathBuf {
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(slot_n);
        let profiles_path = crate::accounts::profiles::profiles_path(base);
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert(slot_n.to_string(), uuid);
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();
        let cred_path = crate::accounts::identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
        std::fs::write(
            &cred_path,
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-VALID-TOKEN","refreshToken":"rt","expiresAt":99999999999999,"scopes":["user:inference"]}}"#,
        )
        .unwrap();
        cred_path
    }

    /// Write a corrupt Anthropic credential file at the UUID-keyed identity path.
    fn stage_corrupt_anthropic_identity(base: &std::path::Path, slot_n: u16) {
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(slot_n);
        let profiles_path = crate::accounts::profiles::profiles_path(base);
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert(slot_n.to_string(), uuid);
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();
        let cred_path = crate::accounts::identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
        // Write unparseable JSON — credential file present but corrupt.
        std::fs::write(&cred_path, b"{ not valid json for anthropic").unwrap();
    }

    /// Write a valid 3P settings.json at config-N/settings.json (MiniMax).
    fn stage_third_party_settings(base: &std::path::Path, slot_n: u16) {
        let config_dir = base.join(format!("config-{slot_n}"));
        std::fs::create_dir_all(&config_dir).unwrap();
        let json = r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.minimax.io/anthropic","ANTHROPIC_AUTH_TOKEN":"tok-mm"}}"#;
        std::fs::write(config_dir.join("settings.json"), json).unwrap();
    }

    /// Seed a valid Code Assist OAuth Gemini binding.
    fn stage_valid_gemini_binding(base: &std::path::Path, slot_n: u16) {
        use crate::providers::gemini::provisioning::provision_code_assist_oauth;
        let slot = AccountNum::try_from(slot_n).unwrap();
        provision_code_assist_oauth(base, slot).unwrap();
    }

    // ── #515 M3 Codex test helpers ────────────────────────────────────────────

    /// Write a corrupt (unparseable) Codex credential file at
    /// `credentials/codex-<N>.json`. Makes `is_codex_bound_slot` return true
    /// and `credentials::file::load(binding_path(...))` return Err.
    fn stage_corrupt_codex_credential(base: &std::path::Path, slot_n: u16) {
        let creds = base.join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(
            creds.join(format!("codex-{slot_n}.json")),
            b"{ not valid json",
        )
        .unwrap();
    }

    /// Write a valid Codex-shape credential file at `credentials/codex-<N>.json`.
    /// Makes `is_codex_bound_slot` return true and `credentials::file::load`
    /// return `Ok(CredentialFile::Codex(...))`.
    fn stage_valid_codex_credential(base: &std::path::Path, slot_n: u16) {
        use crate::credentials::{CodexCredentialFile, CodexTokensFile, CredentialFile};
        let creds = base.join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        let codex_cred = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some("test-acct".into()),
                access_token: "eyJhbGciOiJIUzI1NiJ9.valid.sig".into(),
                refresh_token: Some("rt_codex".into()),
                id_token: Some("eyJhbGciOiJIUzI1NiJ9.id.sig".into()),
                extra: Default::default(),
            },
            last_refresh: Some("2026-05-20T00:00:00Z".into()),
            extra: Default::default(),
        });
        let json = serde_json::to_string(&codex_cred).unwrap();
        std::fs::write(creds.join(format!("codex-{slot_n}.json")), json).unwrap();
    }

    /// Write a valid Codex credential then chmod 0o000 to make it unreadable.
    /// Returns the path for permission restoration.
    #[cfg(unix)]
    fn stage_eacces_codex_credential(base: &std::path::Path, slot_n: u16) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        stage_valid_codex_credential(base, slot_n);
        let path = base
            .join("credentials")
            .join(format!("codex-{slot_n}.json"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        path
    }

    // ── #520 M3 test helper ───────────────────────────────────────────────────

    /// Write a wrong-variant (Anthropic-shape `claudeAiOauth`) credential file
    /// at `credentials/codex-<N>.json`. Makes `is_codex_bound_slot` return true
    /// and `credentials::file::load(binding_path(...))` return `Ok(Anthropic(_))`
    /// (i.e. `cf.codex().is_none() == true`). Canonical fixture uses the
    /// project-canonical year-2100 ms literal (4102444800000) per
    /// `feedback_no_test_timebombs`. Token values are synthetic per
    /// `03-security-review.md` §3.4.
    fn stage_wrong_variant_codex_credential(base: &std::path::Path, slot_n: u16) {
        let creds = base.join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(
            creds.join(format!("codex-{slot_n}.json")),
            br#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","refreshToken":"rt","expiresAt":4102444800000,"scopes":[]}}"#,
        )
        .unwrap();
    }

    // ── #520 M3 tests — Codex wrong-variant-binding ───────────────────────────

    /// AC-1 (#520): canonical Anthropic-shape `credentials/codex-<N>.json` →
    /// `codex-wrong-variant-binding` skip, exit 64.
    ///
    /// Fixture: `{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","refreshToken":"rt",
    /// "expiresAt":4102444800000,"scopes":[]}}` — valid Anthropic shape at a
    /// Codex-prefixed path. Confirms cell is shape-driven (the `claudeAiOauth`
    /// key satisfies the Anthropic variant; no Codex `tokens` key present).
    #[test]
    fn wrong_variant_anthropic_shape_is_codex_wrong_variant_binding_skip() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(40u16).unwrap();

        stage_wrong_variant_codex_credential(base.path(), 40);
        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(r.status, ProbeStatus::Skipped, "status must be Skipped");
        assert_eq!(r.cell, "codex-wrong-variant-binding");
        let diag = r.diagnostic.as_ref().unwrap();
        assert!(
            diag.failed_assertion.starts_with("prerequisite:"),
            "failed_assertion must start with 'prerequisite:'; got: {:?}",
            diag.failed_assertion
        );
        assert_eq!(exit_code_for(&[r]), 64);
    }

    /// AC-2 (#520): variant Anthropic-shape `credentials/codex-<N>.json` →
    /// same `codex-wrong-variant-binding` classification as AC-1.
    ///
    /// Fixture differs from AC-1 in accessToken + scopes, confirming that
    /// wrong-variant detection is shape-driven (the `claudeAiOauth` key),
    /// not coupled to any specific payload literal.
    #[test]
    fn wrong_variant_anthropic_shape_variant_payload_is_codex_wrong_variant_binding_skip() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(41u16).unwrap();

        // AC-2 variant: different accessToken + scopes from AC-1.
        // Same shape (claudeAiOauth), same expiresAt canonical literal.
        let creds = base.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(
            creds.join("codex-41.json"),
            br#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-alt","refreshToken":"rt-alt","expiresAt":4102444800000,"scopes":["user:profile"]}}"#,
        )
        .unwrap();

        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(r.status, ProbeStatus::Skipped, "status must be Skipped");
        assert_eq!(
            r.cell, "codex-wrong-variant-binding",
            "variant Anthropic-shape must classify identically to AC-1 (shape-driven, not literal-driven); got: {}",
            r.cell
        );
        let diag = r.diagnostic.as_ref().unwrap();
        assert!(
            diag.failed_assertion.starts_with("prerequisite:"),
            "failed_assertion must start with 'prerequisite:'; got: {:?}",
            diag.failed_assertion
        );
        assert_eq!(exit_code_for(&[r]), 64);
    }

    /// AC-9 (#520): wrong-variant Codex + valid Anthropic identity →
    /// C2 `ambiguous-binding` Fail (Step 2 fires before Step 3.5).
    ///
    /// `bound_codex == true` (the wrong-variant file exists at the Codex path
    /// — `is_codex_bound_slot` is payload-agnostic) and `anthropic_present == true`
    /// → C2 short-circuits at Step 2 before Step 3.5 is reached.
    #[test]
    fn wrong_variant_codex_plus_valid_anthropic_is_ambiguous() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(42u16).unwrap();

        stage_wrong_variant_codex_credential(base.path(), 42);
        stage_valid_anthropic_identity(base.path(), 42);

        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(
            r.cell, "ambiguous-binding",
            "wrong-variant Codex + valid Anthropic must fire C2 ambiguous-binding (Step 2 before Step 3.5); got: {}",
            r.cell
        );
        assert_eq!(r.status, ProbeStatus::Fail);
        assert_eq!(exit_code_for(&[r]), 1);
    }

    /// AC-10 (#520): wrong-variant Codex + 3P provider settings.json →
    /// `codex-wrong-variant-binding` wins (Step 3.5 precedes Step 5).
    ///
    /// Step 3.5 fires on the wrong-variant arm before the Step 5
    /// `lookup_third_party_provider` walk, so the 3P settings are ignored.
    #[test]
    fn wrong_variant_codex_outranks_third_party_settings() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(43u16).unwrap();

        stage_wrong_variant_codex_credential(base.path(), 43);
        stage_third_party_settings(base.path(), 43);

        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(
            r.cell, "codex-wrong-variant-binding",
            "wrong-variant Codex must outrank 3P settings (Step 3.5 before Step 5); got: {}",
            r.cell
        );
        assert_eq!(r.status, ProbeStatus::Skipped);
        assert_eq!(exit_code_for(&[r]), 64);
    }

    /// AC-11 (#520): wrong-variant Codex + corrupt Gemini →
    /// `gemini-corrupt-binding` wins (Step 3 precedes Step 3.5).
    ///
    /// Step 3 (Gemini corrupt-binding) fires before Step 3.5, so the
    /// Gemini corrupt result takes precedence over the Codex wrong-variant.
    #[test]
    fn wrong_variant_codex_plus_corrupt_gemini_is_gemini_corrupt_binding() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(44u16).unwrap();

        stage_corrupt_gemini_marker(base.path(), 44);
        stage_wrong_variant_codex_credential(base.path(), 44);

        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(
            r.cell, "gemini-corrupt-binding",
            "corrupt Gemini must outrank wrong-variant Codex (Step 3 before Step 3.5); got: {}",
            r.cell
        );
        assert_eq!(r.status, ProbeStatus::Skipped);
        assert_eq!(exit_code_for(&[r]), 64);
    }

    /// AC-12 (#520): wrong-variant Codex + valid Gemini (no Anthropic) →
    /// valid Gemini dispatch wins (Step 4 precedes Step 3.5).
    ///
    /// Step 4 (valid Gemini binding dispatch) fires before Step 3.5, so the
    /// Gemini dispatch takes precedence over the Codex wrong-variant binding.
    #[test]
    fn wrong_variant_codex_plus_valid_gemini_dispatches_to_gemini() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(45u16).unwrap();

        // Valid Gemini binding (parses Ok → Step 4 fires).
        stage_valid_gemini_binding(base.path(), 45);
        // Wrong-variant Codex credential (Step 3.5 would fire, but Step 4 goes first).
        stage_wrong_variant_codex_credential(base.path(), 45);
        // No Anthropic creds — avoids C2 trigger.

        let r = probe_slot(base.path(), home.path(), slot);

        // Step 4 (valid Gemini dispatch) must win over Step 3.5 (wrong-variant Codex).
        assert_ne!(
            r.cell, "codex-wrong-variant-binding",
            "valid Gemini must outrank wrong-variant Codex at Step 4; got: {}",
            r.cell
        );
        assert_ne!(
            r.cell, "ambiguous-binding",
            "no Anthropic creds — must not be ambiguous"
        );
        assert_eq!(
            r.cell, "gemini-code-assist-oauth",
            "valid Gemini binding must dispatch to gemini-code-assist-oauth; got: {}",
            r.cell
        );
    }

    // ── #515 M3 tests — Codex corrupt-binding ────────────────────────────────

    /// AC-1 (Codex): malformed JSON `credentials/codex-<N>.json` →
    /// `codex-corrupt-binding` skip, exit 64.
    #[test]
    fn corrupt_malformed_json_is_codex_corrupt_binding_skip() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(20u16).unwrap();

        stage_corrupt_codex_credential(base.path(), 20);
        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(r.status, ProbeStatus::Skipped, "status must be Skipped");
        assert_eq!(r.cell, "codex-corrupt-binding");
        let diag = r.diagnostic.as_ref().unwrap();
        assert!(
            diag.failed_assertion.starts_with("prerequisite:"),
            "failed_assertion must start with 'prerequisite:'; got: {:?}",
            diag.failed_assertion
        );
        assert_eq!(exit_code_for(&[r]), 64);
    }

    /// AC-2 (Codex): EACCES `credentials/codex-<N>.json` (chmod 0o000) →
    /// `codex-corrupt-binding` skip, exit 64; kind tag = `credentials_io`.
    #[cfg(unix)]
    #[test]
    fn corrupt_unreadable_eacces_is_codex_corrupt_binding_skip() {
        use std::os::unix::fs::PermissionsExt;

        // Root guard — root bypasses 0o000 via DAC_OVERRIDE.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!(
                "SKIP: corrupt_unreadable_eacces_is_codex_corrupt_binding_skip — \
                 running as root, 0o000 is not enforced (DAC_OVERRIDE). \
                 This test requires a non-root process to exercise the EACCES path."
            );
            return;
        }

        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(21u16).unwrap();

        let cred_path = stage_eacces_codex_credential(base.path(), 21);

        let r = probe_slot(base.path(), home.path(), slot);

        // Restore permissions before asserting so TempDir cleanup doesn't fail.
        std::fs::set_permissions(&cred_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(r.status, ProbeStatus::Skipped);
        assert_eq!(r.cell, "codex-corrupt-binding");
        let diag = r.diagnostic.as_ref().unwrap();
        // Kind tag for an EACCES IO error is `credentials_io`.
        assert!(
            diag.observed_shape.contains("credentials_io"),
            "kind tag must be credentials_io; got: {:?}",
            diag.observed_shape
        );
        assert_eq!(exit_code_for(&[r]), 64);
    }

    /// AC-4 (Codex): hint for corrupt Codex binding has correct remediation
    /// (`csq logout`, `csq login`, `--provider codex`; NOT `--provider gemini`).
    #[test]
    fn codex_corrupt_binding_hint_has_correct_remediation() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(22u16).unwrap();

        stage_corrupt_codex_credential(base.path(), 22);
        let r = probe_slot(base.path(), home.path(), slot);

        let diag = r.diagnostic.as_ref().unwrap();
        assert!(
            diag.hint.contains("csq logout"),
            "hint must mention 'csq logout'; got: {:?}",
            diag.hint
        );
        assert!(
            diag.hint.contains("csq login"),
            "hint must mention 'csq login'; got: {:?}",
            diag.hint
        );
        assert!(
            diag.hint.contains("--provider codex"),
            "hint must mention '--provider codex'; got: {:?}",
            diag.hint
        );
        assert!(
            !diag.hint.contains("--provider gemini"),
            "hint MUST NOT mention '--provider gemini'; got: {:?}",
            diag.hint
        );
    }

    /// AC-8 (Codex): valid Codex credential slot still dispatches to
    /// `codex_oauth::probe` (Step 5 fall-through). Post-#534 the cell
    /// reads identity-store creds (or legacy `credentials/codex-<N>.json`
    /// via `binding_path` fallback), NOT `~/.codex/auth.json`. The
    /// `stage_valid_codex_credential` helper writes the legacy file at
    /// `credentials/codex-<N>.json`, which the cell's fallback path
    /// loads when `resolve_slot_to_uuid` returns None (no by_slot mapping
    /// staged here).
    ///
    /// **Also covers AC-F2** (#534 pre-A++ legacy fallback through the
    /// dispatcher). The fixture intentionally stages ONLY the legacy
    /// `credentials/codex-23.json` — no `profiles.json`, no identity-store
    /// `identities/<UUID>/credentials-codex.json`. This is exactly the
    /// pre-A++ install shape, and the dispatcher's Step 5
    /// `discovery_codex_match` gate must route it to the cell which then
    /// falls back to `binding_path`. If a future /redteam round surfaces
    /// "F2 dispatcher path uncovered," this is the test that covers it.
    #[test]
    fn valid_codex_modes_unchanged() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(23u16).unwrap();

        // Write a valid Codex-shape credential file at the legacy path.
        // The cell's `resolve_slot_to_uuid` → None branch picks this up
        // via `binding_path(base, 23)` = `credentials/codex-23.json`.
        stage_valid_codex_credential(base.path(), 23);

        let r = probe_slot(base.path(), home.path(), slot);

        // Must NOT be corrupt-binding or ambiguous-binding.
        assert_ne!(
            r.cell, "codex-corrupt-binding",
            "valid Codex must not be codex-corrupt-binding"
        );
        assert_ne!(
            r.cell, "ambiguous-binding",
            "valid Codex with no Anthropic cred must not be ambiguous"
        );
        // Must dispatch to codex-oauth.
        assert_eq!(
            r.cell, "codex-oauth",
            "valid Codex slot must route to codex-oauth cell; got: {}",
            r.cell
        );
    }

    /// AC-9 (Codex): corrupt Codex + valid Anthropic → C2 `ambiguous-binding`
    /// Fail (F1 fires for corrupt-Codex + Anthropic).
    #[test]
    fn corrupt_codex_plus_valid_anthropic_is_ambiguous() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(24u16).unwrap();

        stage_corrupt_codex_credential(base.path(), 24);
        stage_valid_anthropic_identity(base.path(), 24);

        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(r.cell, "ambiguous-binding");
        assert_eq!(r.status, ProbeStatus::Fail);
        // C2 fires as Fail (exit 1).
        assert_eq!(exit_code_for(&[r]), 1);
    }

    /// AC-9b (Codex F1 widening PIN): valid Codex + valid Anthropic →
    /// C2 `ambiguous-binding` Fail. This is an INTENTIONAL behaviour change
    /// introduced by #515 M3 (presence-presence guard).
    #[test]
    fn valid_codex_plus_valid_anthropic_is_ambiguous() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(25u16).unwrap();

        stage_valid_codex_credential(base.path(), 25);
        stage_valid_anthropic_identity(base.path(), 25);

        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(
            r.cell, "ambiguous-binding",
            "valid Codex + valid Anthropic must be ambiguous-binding (F1 widening); got: {}",
            r.cell
        );
        assert_eq!(r.status, ProbeStatus::Fail);
        assert_eq!(exit_code_for(&[r]), 1);
    }

    /// AC-10 (Codex): corrupt Codex + 3P settings.json → `codex-corrupt-binding`
    /// (Step 3.5 precedes Step 5's `lookup_third_party_provider`).
    #[test]
    fn corrupt_codex_outranks_third_party_settings() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(26u16).unwrap();

        stage_corrupt_codex_credential(base.path(), 26);
        stage_third_party_settings(base.path(), 26);

        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(
            r.cell, "codex-corrupt-binding",
            "corrupt Codex must outrank 3P settings; got: {}",
            r.cell
        );
        assert_eq!(r.status, ProbeStatus::Skipped);
        assert_eq!(exit_code_for(&[r]), 64);
    }

    /// AC-11 (Codex): corrupt Codex + corrupt Gemini → `gemini-corrupt-binding`
    /// (Step 3 precedes Step 3.5; #514 Gemini precedence preserved).
    #[test]
    fn corrupt_codex_plus_corrupt_gemini_is_gemini_corrupt_binding() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(27u16).unwrap();

        stage_corrupt_gemini_marker(base.path(), 27);
        stage_corrupt_codex_credential(base.path(), 27);

        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(
            r.cell, "gemini-corrupt-binding",
            "corrupt Gemini must outrank corrupt Codex (Step 3 before Step 3.5); got: {}",
            r.cell
        );
        assert_eq!(r.status, ProbeStatus::Skipped);
        assert_eq!(exit_code_for(&[r]), 64);
    }

    /// AC-12 (Codex): corrupt Codex + valid Gemini binding (no Anthropic) →
    /// valid Gemini dispatch wins (Step 4 fires before Step 3.5).
    #[test]
    fn corrupt_codex_plus_valid_gemini_dispatches_to_gemini() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(28u16).unwrap();

        // Valid Gemini binding (parses Ok → Step 4 fires).
        stage_valid_gemini_binding(base.path(), 28);
        // Corrupt Codex credential (Step 3.5 would fire, but Step 4 goes first).
        stage_corrupt_codex_credential(base.path(), 28);
        // No Anthropic creds — avoids C2 trigger.

        let r = probe_slot(base.path(), home.path(), slot);

        // Step 4 (valid Gemini dispatch) must win over Step 3.5 (corrupt Codex).
        assert_ne!(
            r.cell, "codex-corrupt-binding",
            "valid Gemini must outrank corrupt Codex at Step 4; got: {}",
            r.cell
        );
        assert_ne!(
            r.cell, "ambiguous-binding",
            "no Anthropic creds — must not be ambiguous"
        );
        assert_eq!(
            r.cell, "gemini-code-assist-oauth",
            "valid Gemini binding must dispatch to gemini-code-assist-oauth; got: {}",
            r.cell
        );
    }

    /// AC-9c / F2 PIN: `ambiguous_binding` hint is path-free and surface-agnostic.
    /// Asserts no orphan-file-name literal ("binding" + ".json"), no `/Users/`,
    /// no `credentials/` substring in the hint or observed_shape; also no
    /// Gemini-specific language. AC-9c grep gate: file must have zero matches
    /// for the orphan-file-name literal.
    #[test]
    fn ambiguous_binding_hint_is_path_free_and_surface_agnostic() {
        // The forbidden substring — build it from parts so this test's source
        // doesn't add a match to the AC-9c grep count.
        let forbidden_filename = ["binding", ".", "json"].concat();

        let r = ambiguous_binding(AccountNum::try_from(1).unwrap());
        let diag = r.diagnostic.as_ref().unwrap();

        assert!(
            !diag.hint.contains(&forbidden_filename),
            "hint MUST NOT contain orphan-file-name literal (AC-9c); got: {:?}",
            diag.hint
        );
        assert!(
            !diag.hint.contains("/Users/"),
            "hint MUST NOT contain absolute /Users/ path; got: {:?}",
            diag.hint
        );
        assert!(
            !diag.hint.contains("credentials/"),
            "hint MUST NOT contain 'credentials/' path; got: {:?}",
            diag.hint
        );
        assert!(
            !diag.observed_shape.contains(&forbidden_filename),
            "observed_shape MUST NOT contain orphan-file-name literal (AC-9c); got: {:?}",
            diag.observed_shape
        );
        assert!(
            !diag.observed_shape.contains("/Users/"),
            "observed_shape MUST NOT contain absolute /Users/ path; got: {:?}",
            diag.observed_shape
        );
        // Also verify the hint is surface-agnostic (no Gemini-specific language).
        assert!(
            !diag.hint.contains("gemini"),
            "hint MUST NOT contain 'gemini' (surface-agnostic); got: {:?}",
            diag.hint
        );
    }

    // ── #514 M3 tests — Gemini corrupt-binding ────────────────────────────────

    /// AC-1: a malformed Gemini marker (garbage JSON) → gemini-corrupt-binding
    /// skip, exit 64.
    #[test]
    fn corrupt_malformed_json_is_gemini_corrupt_binding_skip() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(1u16).unwrap();

        stage_corrupt_gemini_marker(base.path(), 1);
        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(r.status, ProbeStatus::Skipped, "status must be Skipped");
        assert_eq!(r.cell, "gemini-corrupt-binding");
        let diag = r.diagnostic.as_ref().unwrap();
        assert!(
            diag.failed_assertion.starts_with("prerequisite:"),
            "failed_assertion must start with 'prerequisite:'; got: {:?}",
            diag.failed_assertion
        );
        assert_eq!(exit_code_for(&[r]), 64);
    }

    /// AC-2: a newer-schema Gemini marker (v=999) → gemini-corrupt-binding
    /// skip, exit 64.
    #[test]
    fn corrupt_newer_schema_is_corrupt_binding_skip() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(2u16).unwrap();

        stage_newer_schema_gemini_marker(base.path(), 2);
        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(r.status, ProbeStatus::Skipped, "status must be Skipped");
        assert_eq!(r.cell, "gemini-corrupt-binding");
        let diag = r.diagnostic.as_ref().unwrap();
        assert!(diag.failed_assertion.starts_with("prerequisite:"));
        assert_eq!(exit_code_for(&[r]), 64);
    }

    /// AC-3: an EACCES Gemini binding (0o000 marker file) → gemini-corrupt-binding
    /// skip, exit 64; kind tag = gemini_provision_io.
    #[cfg(unix)]
    #[test]
    fn corrupt_unreadable_eacces_is_corrupt_binding_skip() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(3u16).unwrap();

        // Write a valid marker first, then chmod 0o000 to make it unreadable.
        stage_valid_gemini_binding(base.path(), 3);
        let marker = base.path().join("credentials").join("gemini-3.json");
        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o000)).unwrap();

        let r = probe_slot(base.path(), home.path(), slot);

        // Restore perms before asserting so TempDir cleanup doesn't fail.
        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(r.status, ProbeStatus::Skipped);
        assert_eq!(r.cell, "gemini-corrupt-binding");
        let diag = r.diagnostic.as_ref().unwrap();
        // Kind tag for an EACCES IO error.
        assert!(
            diag.observed_shape.contains("gemini_provision_io"),
            "kind tag must be gemini_provision_io; got: {:?}",
            diag.observed_shape
        );
        assert_eq!(exit_code_for(&[r]), 64);
    }

    /// AC-4: hint for corrupt binding has the correct remediation message.
    #[test]
    fn corrupt_binding_hint_has_correct_remediation() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(4u16).unwrap();

        stage_corrupt_gemini_marker(base.path(), 4);
        let r = probe_slot(base.path(), home.path(), slot);

        let diag = r.diagnostic.as_ref().unwrap();
        // Hint must reference `csq logout` + `csq login --provider gemini`.
        // The slot uses the `<N>` placeholder — consistent with the sibling
        // `SkipReason` hints (`NoCredentials` etc.); the concrete slot number
        // is the `ProbeRecord.slot` field, rendered on the `print_text` line.
        assert!(
            diag.hint.contains("csq logout"),
            "hint must mention 'csq logout'; got: {:?}",
            diag.hint
        );
        assert!(
            diag.hint.contains("csq login"),
            "hint must mention 'csq login'; got: {:?}",
            diag.hint
        );
        assert!(
            diag.hint.contains("--provider gemini"),
            "hint must mention '--provider gemini'; got: {:?}",
            diag.hint
        );
        // Must NOT use the bare generic "run `csq login`" wording.
        assert!(
            !diag.hint.contains("run `csq login`"),
            "hint MUST NOT use the bare 'run `csq login`' wording; got: {:?}",
            diag.hint
        );
    }

    /// #516 regression: `SkipReason::NoCredentials` `observed_shape` MUST NOT contain
    /// any absolute path, OS username, home-dir layout, or UUID-bearing identity-store
    /// fragment (`security.md` §2). The sibling fix for `ambiguous_binding` (#514) is
    /// the template — slot number is on `ProbeRecord.slot`; `observed_shape` is
    /// path-free. This test is the AC-1 requirement from issue #516.
    ///
    /// Contract: `observed_shape` == `"missing"` (byte-for-byte).
    #[test]
    fn no_credentials_diagnostic_is_path_free() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(5u16).unwrap();

        // Genuinely-unbound slot — no marker, no profiles.json, no Codex.
        // probe_slot returns Skipped(NoCredentials).
        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(r.status, ProbeStatus::Skipped);
        assert_eq!(r.cell, "unknown");

        let diag = r.diagnostic.as_ref().unwrap();

        // AC-1a: observed_shape must be the exact path-free literal "missing".
        assert_eq!(
            diag.observed_shape, "missing",
            "observed_shape MUST be exactly \"missing\"; got: {:?}",
            diag.observed_shape
        );

        // AC-1b: no absolute path components anywhere in the serialised record.
        let json = serde_json::to_string(&r).unwrap();
        // Check the JSON for common path-leak patterns.
        // /Users/ — macOS user home; /tmp/ and /private/ — tempdir prefixes.
        assert!(
            !json.contains("/Users/"),
            "NoCredentials record MUST NOT contain /Users/ path; got: {json}"
        );
        assert!(
            !json.contains("/private/"),
            "NoCredentials record MUST NOT contain /private/ path; got: {json}"
        );
        assert!(
            !json.contains("/tmp/"),
            "NoCredentials record MUST NOT contain /tmp/ path; got: {json}"
        );
        // UUID-bearing identity-store fragment: a UUID starts with 8 hex chars
        // followed by '-'. Scan the JSON for that pattern without regex (no new
        // deps per independence.md §3).
        fn has_uuid_fragment(s: &str) -> bool {
            let b = s.as_bytes();
            if b.len() < 9 {
                return false;
            }
            for i in 0..b.len().saturating_sub(8) {
                if b[i..i + 8].iter().all(|c| c.is_ascii_hexdigit()) && b[i + 8] == b'-' {
                    return true;
                }
            }
            false
        }
        assert!(
            !has_uuid_fragment(&json),
            "NoCredentials record MUST NOT contain UUID-bearing fragment; got: {json}"
        );

        // AC-1c: no home-dir layout leak — no path separators at all in observed_shape.
        assert!(
            !diag.observed_shape.contains('/'),
            "observed_shape MUST NOT contain path separator; got: {:?}",
            diag.observed_shape
        );
    }

    /// #516 regression (UUID-resolved branch): when `profiles.json::by_slot[N]` is
    /// populated (UUID resolved) but the identity-store credential file is absent,
    /// the OLD code interpolated the resolved `/Users/<u>/.claude/accounts/identities/
    /// <uuid>/credentials.json` path into `observed_shape` — the actual load-bearing
    /// leak site. The unit-variant rewrite makes `observed_shape` byte-equal `"missing"`
    /// on BOTH the UUID-resolved branch AND the no-UUID branch. This test pins the
    /// invariant against a future refactor that might reintroduce the path on either
    /// branch.
    #[test]
    fn no_credentials_diagnostic_is_path_free_uuid_resolved_branch() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot_n = 5u16;
        let slot = AccountNum::try_from(slot_n).unwrap();

        // Stage profiles.json::by_slot[5] = UUID, but DO NOT write the
        // credential file at the UUID-keyed identity path. anthropic_creds_path
        // resolves to Some(/.../identities/<uuid>/credentials.json) and cred-file
        // load returns None — driving the load-bearing leak code path.
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(slot_n);
        let profiles_path = crate::accounts::profiles::profiles_path(base.path());
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert(slot_n.to_string(), uuid);
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(r.status, ProbeStatus::Skipped);
        assert_eq!(r.cell, "unknown");

        let diag = r.diagnostic.as_ref().unwrap();
        assert_eq!(
            diag.observed_shape, "missing",
            "observed_shape MUST be exactly \"missing\" on UUID-resolved branch; got: {:?}",
            diag.observed_shape
        );

        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("/Users/"),
            "NoCredentials record MUST NOT contain /Users/ path; got: {json}"
        );
        assert!(
            !json.contains("/private/"),
            "NoCredentials record MUST NOT contain /private/ path; got: {json}"
        );
        assert!(
            !json.contains("/tmp/"),
            "NoCredentials record MUST NOT contain /tmp/ path; got: {json}"
        );
        // UUID fragment: 8 hex chars followed by '-' (same scan as the
        // no-UUID-branch sibling test).
        fn has_uuid_fragment(s: &str) -> bool {
            let b = s.as_bytes();
            if b.len() < 9 {
                return false;
            }
            for i in 0..b.len().saturating_sub(8) {
                if b[i..i + 8].iter().all(|c| c.is_ascii_hexdigit()) && b[i + 8] == b'-' {
                    return true;
                }
            }
            false
        }
        assert!(
            !has_uuid_fragment(&json),
            "NoCredentials record MUST NOT contain UUID-bearing fragment even on UUID-resolved branch; got: {json}"
        );
        assert!(
            !diag.observed_shape.contains('/'),
            "observed_shape MUST NOT contain path separator on UUID-resolved branch; got: {:?}",
            diag.observed_shape
        );
    }

    /// AC-7: genuinely-unbound slot (no marker, no UUID, no Codex) → prior
    /// cell=="unknown" NoCredentials exit 64. `probe_slot_refuses_unresolvable_slot_no_numeric_fallback`
    /// covers the byte-identical pass requirement; this is an explicit AC-7 assertion.
    #[test]
    fn genuinely_unbound_slot_unchanged() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(5u16).unwrap();

        // No marker, no profiles.json, nothing.
        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(r.status, ProbeStatus::Skipped);
        assert_eq!(r.cell, "unknown");
        let diag = r.diagnostic.as_ref().unwrap();
        assert!(diag.failed_assertion.starts_with("prerequisite:"));
        assert_eq!(exit_code_for(&[r]), 64);
    }

    /// AC-8: valid Gemini binding (CodeAssistOAuth) with readable identities/
    /// and NO UUID-path credential file → dispatches to gemini-code-assist-oauth cell.
    ///
    /// Note: the live-wire probe will fail (no network) but it must NOT skip
    /// as corrupt-binding or ambiguous-binding.
    #[test]
    fn valid_gemini_modes_unchanged() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(6u16).unwrap();

        // Write a valid CodeAssistOAuth binding. No Anthropic UUID mapping.
        stage_valid_gemini_binding(base.path(), 6);

        let r = probe_slot(base.path(), home.path(), slot);

        // Must NOT be corrupt-binding or ambiguous-binding.
        assert_ne!(
            r.cell, "gemini-corrupt-binding",
            "valid Gemini must not be corrupt-binding"
        );
        assert_ne!(
            r.cell, "ambiguous-binding",
            "valid Gemini with no Anthropic cred must not be ambiguous"
        );
        // Must dispatch to gemini-code-assist-oauth (may Fail due to no network, but correct cell).
        assert_eq!(
            r.cell, "gemini-code-assist-oauth",
            "valid CodeAssistOAuth must route to gemini-code-assist-oauth cell"
        );
    }

    /// AC-9: corrupt Gemini marker + valid Anthropic identity → ambiguous-binding Fail.
    #[test]
    fn corrupt_gemini_plus_valid_anthropic_is_ambiguous() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(7u16).unwrap();

        // Stage corrupt Gemini + valid Anthropic creds at UUID path.
        stage_corrupt_gemini_marker(base.path(), 7);
        stage_valid_anthropic_identity(base.path(), 7);

        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(r.cell, "ambiguous-binding");
        assert_eq!(r.status, ProbeStatus::Fail);
        // C2 fires for FM-3.
        assert_eq!(exit_code_for(&[r]), 1);
    }

    /// AC-11: corrupt Gemini marker + corrupt Anthropic identity credential →
    /// ambiguous-binding Fail (FM-5: C2 gates on presence, not parse-success).
    #[test]
    fn corrupt_gemini_plus_corrupt_anthropic_is_ambiguous() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(8u16).unwrap();

        stage_corrupt_gemini_marker(base.path(), 8);
        stage_corrupt_anthropic_identity(base.path(), 8);

        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(
            r.cell, "ambiguous-binding",
            "FM-5: corrupt Gemini + corrupt Anthropic must be ambiguous"
        );
        assert_eq!(r.status, ProbeStatus::Fail);
    }

    /// AC-12: ambiguous-binding record contains no absolute path in
    /// observed_shape or hint.
    #[test]
    fn ambiguous_binding_record_is_path_free() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(9u16).unwrap();

        stage_corrupt_gemini_marker(base.path(), 9);
        stage_valid_anthropic_identity(base.path(), 9);

        let r = probe_slot(base.path(), home.path(), slot);
        assert_eq!(r.cell, "ambiguous-binding");

        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("/Users/"),
            "ambiguous-binding record MUST NOT contain /Users/ path; got: {json}"
        );
        assert!(
            !json.contains("/tmp/"),
            "ambiguous-binding record MUST NOT contain /tmp/ path"
        );
        // Also check observed_shape directly.
        let diag = r.diagnostic.as_ref().unwrap();
        assert!(
            !diag.observed_shape.contains("credentials/"),
            "observed_shape must not contain credentials/ path; got: {:?}",
            diag.observed_shape
        );
    }

    /// AC-13: corrupt Gemini marker + 3P settings.json → gemini-corrupt-binding
    /// (corrupt-binding outranks 3P walk; step 3 precedes lookup_third_party).
    #[test]
    fn corrupt_gemini_outranks_third_party_settings() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(10u16).unwrap();

        stage_corrupt_gemini_marker(base.path(), 10);
        stage_third_party_settings(base.path(), 10);

        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(
            r.cell, "gemini-corrupt-binding",
            "corrupt Gemini must outrank 3P settings; got: {}",
            r.cell
        );
        assert_eq!(r.status, ProbeStatus::Skipped);
    }

    /// AC-14: valid Gemini binding + a credential file at the resolved UUID path →
    /// ambiguous-binding Fail (presence-gate C2's third newly-covered class).
    #[test]
    fn valid_gemini_plus_credential_at_uuid_path_is_ambiguous() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(11u16).unwrap();

        // Valid Gemini binding.
        stage_valid_gemini_binding(base.path(), 11);
        // A credential file at the UUID path (any credential type — presence gates C2).
        stage_valid_anthropic_identity(base.path(), 11);

        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(
            r.cell, "ambiguous-binding",
            "valid Gemini + UUID-path credential must be ambiguous; got: {}",
            r.cell
        );
        assert_eq!(r.status, ProbeStatus::Fail);
    }

    /// AC-15: corrupt Gemini marker + Codex discovery-matched → gemini-corrupt-binding
    /// (corrupt-binding outranks Codex walk; step 3 precedes discovery_codex_match).
    /// Post-#534: no longer stages `~/.codex/auth.json` — the retired
    /// `codex_slot_present(home_dir)` gate is gone; the codex discovery
    /// match alone is what could route to Step 5's codex dispatch (which
    /// Step 3 corrupt-Gemini correctly preempts).
    #[test]
    fn corrupt_gemini_outranks_codex_auth() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(12u16).unwrap();

        stage_corrupt_gemini_marker(base.path(), 12);

        // Stage a Codex discovery entry for slot 12.
        use crate::credentials::file::canonical_path_for;
        use crate::providers::catalog::Surface;
        let codex_path = canonical_path_for(
            base.path(),
            AccountNum::try_from(12u16).unwrap(),
            Surface::Codex,
        );
        std::fs::create_dir_all(codex_path.parent().unwrap()).unwrap();
        std::fs::write(&codex_path, r#"{"token":"codex-12"}"#).unwrap();

        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(
            r.cell, "gemini-corrupt-binding",
            "corrupt Gemini must outrank Codex auth; got: {}",
            r.cell
        );
        assert_eq!(r.status, ProbeStatus::Skipped);
    }

    /// AC-16: corrupt Gemini marker + 0o000 identities/ directory →
    /// ambiguous-binding Fail (PermissionDenied → present, fail-toward-C2).
    ///
    /// Setup: a UUID mapping exists in profiles.json so that `anthropic_creds_path`
    /// resolves to a path inside identities/, then chmod identities/ to 0o000.
    /// `symlink_metadata` on that path returns PermissionDenied → `anthropic_present=true`.
    ///
    /// Root guard: root bypasses 0o000 via DAC_OVERRIDE. When running as root,
    /// this test skips with a visible notice so a root CI run does not present
    /// false coverage of the PermissionDenied classification.
    #[cfg(unix)]
    #[test]
    fn corrupt_gemini_plus_eacces_identities_is_ambiguous() {
        use std::os::unix::fs::PermissionsExt;

        // Root guard — root bypasses 0o000, test cannot exercise PermissionDenied.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!(
                "SKIP: corrupt_gemini_plus_eacces_identities_is_ambiguous — running as root, \
                 0o000 directory is not enforced (DAC_OVERRIDE). \
                 This test requires a non-root process to exercise the PermissionDenied path."
            );
            return;
        }

        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(13u16).unwrap();

        stage_corrupt_gemini_marker(base.path(), 13);

        // Seed a UUID mapping so that `anthropic_creds_path` resolves to
        // a path INSIDE identities/. The credential file itself doesn't need
        // to exist — the PermissionDenied comes from the untraversable parent dir.
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(13);
        let profiles_path = crate::accounts::profiles::profiles_path(base.path());
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("13".to_string(), uuid);
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // Create the identities/ dir and chmod 0o000 to make it untraversable.
        // `symlink_metadata` on any path inside will return PermissionDenied →
        // `anthropic_present = true` (fail-toward-C2).
        let identities_dir = base.path().join("identities");
        std::fs::create_dir_all(&identities_dir).unwrap();
        std::fs::set_permissions(&identities_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let r = probe_slot(base.path(), home.path(), slot);

        // Restore permissions before asserting.
        std::fs::set_permissions(&identities_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(
            r.cell, "ambiguous-binding",
            "corrupt Gemini + 0o000 identities/ must be ambiguous (PermissionDenied → present); got: {}",
            r.cell
        );
        assert_eq!(r.status, ProbeStatus::Fail);
    }

    /// AC-17: valid Gemini binding + 0o000 identities/ directory →
    /// ambiguous-binding Fail (slot-agnostic fail-toward-warn: PermissionDenied
    /// makes `anthropic_present = true` for EVERY slot, including clean Gemini).
    ///
    /// Root guard: same as AC-16.
    #[cfg(unix)]
    #[test]
    fn valid_gemini_plus_eacces_identities_is_ambiguous() {
        use std::os::unix::fs::PermissionsExt;

        // Root guard.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!(
                "SKIP: valid_gemini_plus_eacces_identities_is_ambiguous — running as root, \
                 0o000 directory is not enforced (DAC_OVERRIDE). \
                 This test requires a non-root process to exercise the PermissionDenied path."
            );
            return;
        }

        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(14u16).unwrap();

        // Valid Gemini binding.
        stage_valid_gemini_binding(base.path(), 14);

        // Seed a UUID mapping so the identity path resolution resolves to
        // something inside identities/, then chmod the dir 0o000.
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(14);
        let profiles_path = crate::accounts::profiles::profiles_path(base.path());
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("14".to_string(), uuid);
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        let identities_dir = base.path().join("identities");
        std::fs::create_dir_all(&identities_dir).unwrap();
        std::fs::set_permissions(&identities_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let r = probe_slot(base.path(), home.path(), slot);

        // Restore permissions before asserting.
        std::fs::set_permissions(&identities_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(
            r.cell, "ambiguous-binding",
            "valid Gemini + 0o000 identities/ must be ambiguous (intended fail-toward-warn); got: {}",
            r.cell
        );
        assert_eq!(r.status, ProbeStatus::Fail);
    }

    // ── #534 staging helpers ──────────────────────────────────────────────────

    /// Stage a valid Codex slot with BOTH the legacy + identity-store
    /// credential files. Mirrors what `csq login N --provider codex`
    /// actually produces post-A++ / PR #500: the mint flow writes both
    /// `credentials/codex-<N>.json` (legacy marker) and
    /// `identities/<UUID>/credentials-codex.json` (identity-store) plus
    /// the `profiles.json::by_slot[N] = uuid` mapping. Without the legacy
    /// marker, `discover_anthropic`'s codex-only-slot guard (lines 356-364
    /// of discovery.rs) doesn't fire and the slot gets tagged as
    /// Anthropic in `discover_all` (first-source-wins dedup masks the
    /// later Codex discovery).
    fn stage_valid_codex_identity(base: &std::path::Path, slot_n: u16) {
        use crate::credentials::{CodexCredentialFile, CodexTokensFile, CredentialFile};

        // Legacy marker — also serves as the codex-only-slot guard signal
        // in `discover_anthropic` so slot N isn't shadowed by Anthropic.
        stage_valid_codex_credential(base, slot_n);

        // Profiles by_slot mapping (UUID).
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(slot_n);
        let profiles_path = crate::accounts::profiles::profiles_path(base);
        let mut profiles = match crate::accounts::profiles::load(&profiles_path) {
            Ok(p) => p,
            Err(_) => crate::accounts::profiles::ProfilesFile::empty(),
        };
        profiles.by_slot.insert(slot_n.to_string(), uuid);
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // identities/<uuid>/credentials-codex.json.
        let cred_path = crate::accounts::identity_store::credentials_codex_path_for(base, uuid);
        std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
        let codex_cred = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some(format!("fx{slot_n:08x}-fixture")),
                access_token: format!("stub-codex-at-{slot_n}"),
                refresh_token: Some(format!("stub-codex-rt-{slot_n}")),
                id_token: Some("stub-id-token-opaque".into()),
                extra: Default::default(),
            },
            last_refresh: Some("2026-05-20T00:00:00Z".into()),
            extra: Default::default(),
        });
        let json = serde_json::to_string(&codex_cred).unwrap();
        std::fs::write(&cred_path, json).unwrap();
    }

    // ── #534 M3 tests ─────────────────────────────────────────────────────────

    /// M3-2 (F1 + F6): `probe --all` across slots 12 / 16 / 17 (the user's
    /// empirical slot triple from journal 0001) routed through different
    /// cells PER SLOT, derived from per-slot credential state. Pre-#534 all
    /// three slots probed against the shared `~/.codex/auth.json` and
    /// returned IDENTICAL records (only `slot` differed). This test pins
    /// the multi-slot attribution invariant + the F6 mixed-cell pairing:
    ///   - slot 12 = valid identity-store Codex creds → `codex-oauth` cell.
    ///   - slot 16 = corrupt legacy `credentials/codex-16.json` → `codex-corrupt-binding`.
    ///   - slot 17 = wrong-variant legacy `credentials/codex-17.json` → `codex-wrong-variant-binding`.
    #[test]
    fn probe_all_distinguishes_multiple_codex_slots() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();

        // Slot 12 — valid identity-store Codex creds.
        stage_valid_codex_identity(base.path(), 12);
        // Slot 16 — corrupt legacy file (Step 3.5 corrupt-binding fires).
        stage_corrupt_codex_credential(base.path(), 16);
        // Slot 17 — Anthropic-shape JSON at codex path (Step 3.5 wrong-variant).
        stage_wrong_variant_codex_credential(base.path(), 17);

        let r12 = probe_slot(
            base.path(),
            home.path(),
            AccountNum::try_from(12u16).unwrap(),
        );
        let r16 = probe_slot(
            base.path(),
            home.path(),
            AccountNum::try_from(16u16).unwrap(),
        );
        let r17 = probe_slot(
            base.path(),
            home.path(),
            AccountNum::try_from(17u16).unwrap(),
        );

        // F1: per-slot attribution — three different cells across three slots.
        assert_eq!(
            r12.cell, "codex-oauth",
            "slot 12 (valid identity-store) must route to codex-oauth; got: {}",
            r12.cell
        );
        assert_eq!(
            r16.cell, "codex-corrupt-binding",
            "slot 16 (corrupt legacy) must route to codex-corrupt-binding; got: {}",
            r16.cell
        );
        assert_eq!(
            r17.cell, "codex-wrong-variant-binding",
            "slot 17 (Anthropic-shape legacy) must route to codex-wrong-variant-binding; got: {}",
            r17.cell
        );

        // F1 (negative): the three records would have been IDENTICAL pre-#534
        // (same `~/.codex/auth.json` for all). Now they differ in `cell`.
        // The structural invariant: no two slots share the same cell here.
        assert_ne!(r12.cell, r16.cell);
        assert_ne!(r12.cell, r17.cell);
        assert_ne!(r16.cell, r17.cell);
    }

    /// M3-3 (F2): a slot with NO `profiles.json::by_slot` UUID mapping but a
    /// present legacy `credentials/codex-<N>.json` MUST be probed via the
    /// cell's fallback path (`binding_path(base, slot)`). Pre-A++ installs
    /// rely on this branch. Uses a wrong-variant payload at the legacy path
    /// so the cell short-circuits to `WrongVariantBinding` BEFORE the HTTP
    /// fetch (deterministic, no network); the cell name being `codex-oauth`
    /// confirms the fallback executed (the wrong-variant Skip is the
    /// cell's own emission, not a Step 3.5 routing).
    #[test]
    fn pre_aplusplus_legacy_codex_credentials_probed_via_fallback() {
        let base = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(50u16).unwrap();

        // No profiles.json staged → resolve_slot_to_uuid returns None.
        // Legacy `credentials/codex-50.json` with wrong-variant payload.
        // NOTE: we call codex_oauth::probe DIRECTLY (bypassing the
        // dispatcher) because Step 3.5 would otherwise short-circuit
        // wrong-variant routing for `is_codex_bound_slot && load Ok(non-codex)`.
        // The direct call tests the cell's INTERNAL fallback chain
        // independently of the dispatcher's Step 3.5 gating.
        stage_wrong_variant_codex_credential(base.path(), 50);

        let r = codex_oauth::probe(base.path(), slot);

        assert_eq!(
            r.cell, "codex-oauth",
            "cell name MUST be codex-oauth (direct call to cell); got: {}",
            r.cell
        );
        assert_eq!(r.status, ProbeStatus::Skipped);
        let diag = r.diagnostic.as_ref().unwrap();
        assert!(
            diag.failed_assertion
                .contains("codex credential file is the Codex variant"),
            "fallback path loaded legacy file → wrong-variant arm fires; got: {:?}",
            diag.failed_assertion
        );
    }

    /// M3-4a (F4): corrupt-binding slot routes to `codex-corrupt-binding`
    /// cell post-#534, NOT to the new codex-oauth cell. Sibling-compatibility
    /// pin: the Step 3.5 dispatcher ordering invariant survives the M2-1
    /// refactor.
    #[test]
    fn corrupt_codex_binding_routes_to_corrupt_binding_cell_after_refactor() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(60u16).unwrap();

        stage_corrupt_codex_credential(base.path(), 60);

        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(
            r.cell, "codex-corrupt-binding",
            "corrupt legacy file MUST route to codex-corrupt-binding (Step 3.5); got: {}",
            r.cell
        );
        assert_ne!(
            r.cell, "codex-oauth",
            "Step 3.5 must fire BEFORE the new Step 5 codex-oauth dispatch"
        );
    }

    /// M3-4b (F4): wrong-variant slot routes to `codex-wrong-variant-binding`
    /// cell post-#534, NOT to the new codex-oauth cell.
    #[test]
    fn wrong_variant_codex_binding_routes_to_wrong_variant_cell_after_refactor() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(61u16).unwrap();

        stage_wrong_variant_codex_credential(base.path(), 61);

        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(
            r.cell, "codex-wrong-variant-binding",
            "Anthropic-shape legacy MUST route to wrong-variant cell (Step 3.5); got: {}",
            r.cell
        );
        assert_ne!(
            r.cell, "codex-oauth",
            "Step 3.5 must fire BEFORE the new Step 5 codex-oauth dispatch"
        );
    }

    /// M3-5 (DF1 mandatory regression): a slot with BOTH a corrupt legacy
    /// `credentials/codex-<N>.json` AND a healthy identity-store
    /// `identities/<UUID>/credentials-codex.json` MUST route to
    /// `codex-corrupt-binding` (Step 3.5), NOT to the codex-oauth cell
    /// reading the healthy identity creds. If Step 3.5 ever reorders below
    /// the new Step 5 gate, the corrupt legacy file would be silently
    /// masked — operator sees green probe for a slot with a real
    /// misconfiguration. This test is the structural pin against that
    /// regression.
    #[test]
    fn corrupt_legacy_codex_with_healthy_identity_routes_to_corrupt_binding() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(70u16).unwrap();

        // Healthy identity-store creds.
        stage_valid_codex_identity(base.path(), 70);
        // Corrupt legacy file. is_codex_bound_slot fires → Step 3.5 fires.
        stage_corrupt_codex_credential(base.path(), 70);

        let r = probe_slot(base.path(), home.path(), slot);

        assert_eq!(
            r.cell, "codex-corrupt-binding",
            "corrupt legacy + healthy identity MUST route to corrupt-binding; got: {}",
            r.cell
        );
        assert_ne!(
            r.cell, "codex-oauth",
            "Step 3.5 must fire BEFORE Step 5 codex-oauth dispatch — otherwise the corrupt legacy is masked"
        );
    }

    /// M3-6 (SF7): a malformed UUID in `profiles.json::by_slot[N]` MUST NOT
    /// produce a path-traversal read AND MUST result in
    /// `SkipReason::NoCodexCredentials` when no legacy fallback is staged.
    /// The chain under test: `resolve_slot_to_uuid` → None (profiles.json
    /// fails to load due to malformed UUID) → fallback `binding_path(base,
    /// slot)` → load Err → cell emits `NoCodexCredentials`.
    ///
    /// Direct call to `codex_oauth::probe` — the dispatcher's Step 5 gate
    /// requires `discovery_codex_match` which won't fire when neither
    /// channel parses. Per #534 the cell's resilience is the load-bearing
    /// invariant being pinned.
    ///
    /// **Mutation-resistance note:** this test does NOT stage a
    /// `~/.codex/auth.json` to defend against a reintroduced user-global
    /// read. That defense is STRUCTURAL — `codex_oauth::probe(base_dir,
    /// slot)` has no `home_dir` parameter, so any regression would require
    /// either a signature change OR a `dirs::home_dir()` call inside the
    /// cell. Both are mechanically caught by the `account-terminal-
    /// separation.md` MUST Rule 4 audit-grep (`grep -rEn
    /// 'home_dir\.join\("\.codex"\)' csq-core/src/probe/` → MUST return
    /// ZERO). The grep is the load-bearing defense; HOME-fixture staging
    /// would be redundant with it.
    #[test]
    fn malformed_uuid_in_profiles_json_routes_to_no_codex_credentials_skip() {
        let base = tempfile::tempdir().unwrap();
        let slot = AccountNum::try_from(80u16).unwrap();

        // Write a malformed profiles.json directly (bypassing serde, which
        // would reject the non-UUID string at load-time). The bytes simulate
        // the threat-model attack vector — a profiles.json tampered post-write.
        let profiles_path = crate::accounts::profiles::profiles_path(base.path());
        std::fs::create_dir_all(profiles_path.parent().unwrap()).unwrap();
        std::fs::write(
            &profiles_path,
            br#"{"by_slot":{"80":"..%2fetc%2fpasswd"},"by_email":{},"by_slot_identity":{}}"#,
        )
        .unwrap();
        // No legacy `credentials/codex-80.json` staged → fallback also absent.

        let r = codex_oauth::probe(base.path(), slot);

        assert_eq!(r.status, ProbeStatus::Skipped);
        assert_eq!(r.cell, "codex-oauth");
        let diag = r.diagnostic.as_ref().unwrap();
        assert_eq!(
            diag.failed_assertion, "prerequisite: slot has codex credentials",
            "malformed UUID + absent legacy MUST emit NoCodexCredentials, NOT path-traversal; got: {:?}",
            diag.failed_assertion
        );
        // The probe MUST NOT have opened `/etc/passwd` — the binding_path
        // template is fixed (`credentials/codex-<N>.json`) regardless of
        // profiles.json content. Verify the diagnostic contains no path
        // hint that would suggest a traversal read occurred.
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("etc/passwd"),
            "no path-traversal byte sequence may appear in the probe record; got: {json}"
        );
        assert!(
            !json.contains(".."),
            "no `..` path-traversal sequence may appear in the probe record; got: {json}"
        );
    }

    fn ok_record() -> ProbeRecord {
        ProbeRecord {
            schema_version: SCHEMA_VERSION,
            slot: 1,
            cell: "test",
            spec_anchor: "test",
            status: ProbeStatus::Ok,
            endpoint: "test".into(),
            elapsed_ms: 0,
            assertions_passed: 1,
            assertions_total: 1,
            diagnostic: None,
            redacted_response_excerpt: None,
        }
    }

    fn fail_record_assertion(failed_assertion: &str) -> ProbeRecord {
        ProbeRecord {
            schema_version: SCHEMA_VERSION,
            slot: 1,
            cell: "test",
            spec_anchor: "test",
            status: ProbeStatus::Fail,
            endpoint: "test".into(),
            elapsed_ms: 0,
            assertions_passed: 0,
            assertions_total: 1,
            diagnostic: Some(ProbeDiagnostic {
                failed_assertion: failed_assertion.into(),
                observed_shape: "y".into(),
                hint: "z".into(),
            }),
            redacted_response_excerpt: None,
        }
    }
}
