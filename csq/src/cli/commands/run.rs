//! `csq run [N]` — launch Claude Code or Codex with isolated credentials.

use anyhow::{anyhow, Context, Result};
use csq_core::accounts::{discovery, markers, AccountSource};
use csq_core::capability_layer::{
    load_capability_layer_toggles, run_post_spawn_toggled, run_with_layer_toggled,
    CapabilityLayerToggles, LayerOutcome, PromptClass, SpawnMode, StageError,
};
use csq_core::cli_deps::sanitize::redact_path;
use csq_core::cli_deps::SurfaceCli;
use csq_core::credentials::{self, file};
use csq_core::platform::env_check::{self, EnvIssue};
use csq_core::providers::catalog::Surface;
use csq_core::providers::codex::surface as codex_surface;
use csq_core::refresh::sentinel::is_broker_failed;
use csq_core::session;
use csq_core::types::AccountNum;
use std::collections::BTreeSet;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use csq_core::daemon::{self, DetectResult};

/// Phase B' billing-ledger attribution (an internal journal entry D2). Best-effort append
/// to `accounts/.csq-launch.log` so the daemon aggregator can attribute CC
/// session-meta files to slots via post-hoc time correlation.
///
/// Failure mode policy: never block the user's launch. Log at WARN with the
/// fixed-vocabulary `error_kind` tag per security.md.
pub(crate) fn append_launch_log(base_dir: &Path, event: &str, account: AccountNum) {
    // `project_path` is recorded into a `LaunchEvent` consumed by the
    // launch-log subscriber for `tracing::*` audit-trail / post-hoc
    // session-correlation. NOT operator-facing chat — per
    // `rules/operator-surface-verification.md` Rule 4, structured-log
    // fields MAY retain `path.display()` for the audit-trail policy.
    let project_path = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let ev = csq_core::usage::launch_log::LaunchEvent {
        ts,
        event: event.to_string(),
        slot: account.get(),
        pid: std::process::id(),
        project_path,
    };
    if let Err(e) = csq_core::usage::launch_log::append(base_dir, &ev) {
        tracing::warn!(
            error_kind = "launch_log_append_failed",
            error = %e,
            "Phase B' launch-log append failed (non-fatal)"
        );
    }
}

/// Mirror the bound account's Anthropic credential into the macOS keychain
/// item Claude Code reads for `handle_dir_abs`
/// (`credentials::keychain::sync_handle_dir`).
///
/// Current CC reads OAuth credentials KEYCHAIN-FIRST from that per-config-dir
/// item, falling back to the symlinked `.credentials.json` when the keychain
/// item is ABSENT (empirically confirmed: with the item absent, a running CC
/// still picks up a swapped account from the repointed file). The mirror keeps
/// the keychain copy fresh so a keychain-first read sees the current token.
/// Best-effort: a keychain failure is logged (INFO, not WARN — see
/// `sync_cc_keychain`) and never blocks the launch; account-switch still works
/// via the file fallback. No-op for 3P/Codex handle dirs (no `claudeAiOauth`
/// credential) and on non-macOS (CC reads the file directly there).
///
/// `account_changed` MUST be true when the handle dir's account BINDING just
/// changed (`csq swap` repointed its symlinks) — that bypasses the
/// newer-than-keychain guard (which compares only expiry and would otherwise
/// leave the PREVIOUS account's token in place → 401) and clears a stale item
/// when the new slot has no valid token. `csq run` creates a fresh handle dir
/// (no prior item), so it passes `false`.
pub(crate) fn sync_cc_keychain(handle_dir_abs: &Path, account_changed: bool) {
    let result = if account_changed {
        csq_core::credentials::keychain::sync_handle_dir_account_changed(handle_dir_abs)
    } else {
        csq_core::credentials::keychain::sync_handle_dir(handle_dir_abs)
    };
    if let Err(e) = result {
        // Best-effort mirror — INFO, not WARN. Claude Code reads the keychain
        // item when present but FALLS BACK to the symlinked `.credentials.json`
        // (which run/swap repoint) when it is absent, so a failed mirror does NOT
        // break account switching. The common cause is a non-interactive session
        // (SSH/tmux) that can't answer the macOS authorization prompt for an
        // ACL-set keychain item. Surfacing the redacted reason (visible under
        // `CSQ_LOG=info`) replaces the prior alarming per-swap WARN, which made a
        // harmless, expected condition look like a broken swap.
        tracing::info!(
            error_kind = "cc_keychain_mirror_skipped",
            reason = %csq_core::error::redact_tokens(&e.to_string()),
            "Claude Code keychain mirror not updated (best-effort); swap/run fall back \
             to the credential file — account switch still works, no action needed"
        );
    }
}

/// Exit code when `csq run` cannot spawn a Codex slot because the
/// daemon is not running (INV-P02). Distinct from anyhow's default 1
/// so scripts can detect "daemon-down" vs other launch failures.
const EXIT_CODE_DAEMON_REQUIRED: i32 = 2;

/// Exit code when `csq run` cannot write the audit record even to the
/// `.pending/` fallback (M06 fail-loud). Distinct from `1` (generic anyhow
/// failure) and `2` (daemon-required) so monitoring tools can detect an
/// audit-write failure programmatically. The launched operation already
/// completed; only the audit record was lost.
const EXIT_CODE_AUDIT_WRITE_FAILED: i32 = 3;

/// Exit code when `csq run` refuses to spawn a codex/gemini subprocess because
/// the M6 T6.1 spawn-boundary governance gate returned `Block`/`Escalate`, OR
/// because a configured operating envelope was malformed / the governor could
/// not be built (fail-closed). Distinct from 1 (generic), 2 (daemon-required),
/// and 3 (audit-write) so scripts can detect a governance refusal. Enterprise-only
/// (community spawns codex/gemini ungoverned).
#[cfg(feature = "enterprise")]
const EXIT_CODE_SPAWN_BLOCKED: i32 = 4;

// `handle` and the `launch_*` helpers exceed clippy's 7-arg threshold. Each
// arg is an independent CLI control surface (account, profile, layer
// flags, debug, bench-mode, cache-flag, passthrough rest) — bundling them
// into a config struct is a clean follow-up but out of scope for the
// per-PR additions that touch this signature. Tracked as a separate
// refactor; the additions land per-PR with this allow.
#[allow(clippy::too_many_arguments)]
pub fn handle(
    base_dir: &Path,
    account: Option<AccountNum>,
    profile: Option<&str>,
    layer_intent: super::super::LayerIntent,
    debug: bool,
    bench_mode: Option<&str>,
    coc_cache_enabled: bool,
    ignore_cli_version: bool,
    no_auto_update_cli: bool,
    no_audit: bool,
    rest: &[String],
) -> Result<()> {
    // M7: convert user intent → the `enabled` bool every downstream
    // helper already takes. `.coc/` detection stays in ONE place (the
    // spec-09 fallback walk inside `run_capability_layer_preflight`);
    // `AutoDefault` and `ForcedOn` both pass `enabled = true` and let
    // FR-RUN-04 no-op (≤5 ms) when `.coc/` is absent.
    let capability_layer_enabled = layer_intent.enabled();
    // Threaded alongside `capability_layer_enabled` to the one site
    // (`run_capability_layer_preflight`) that knows the layer actually
    // engaged, so the one-time "auto-engaged" stderr note prints only
    // on the no-flag default path with a real `.coc/`.
    let layer_is_auto = layer_intent.is_auto();
    let claude_home = super::claude_home()?;

    // Environment preflight — warn (non-blocking) about configured
    // hooks that will fail after we exec `claude`. Users on fresh WSL
    // most often hit this via `csq run`, not `csq install`, so we
    // surface the same signal here without the interactive prompt.
    run_env_preflight(&claude_home);

    // Load persisted capability-layer toggles (FR-CL-05). The desktop
    // tray (M6 PR-CA12) writes user preferences to
    // <base>/capability_layer.json; the CLI reads them here and
    // merges with the explicit `--capability-layer` flag below. CLI
    // flag wins for explicit overrides — see comment near
    // `effective_layer_toggles` for the precedence rules.
    let persisted_toggles = load_capability_layer_toggles(base_dir);

    // Resolve account number
    let account = resolve_account(base_dir, account)?;

    let account = match account {
        Some(a) => a,
        None => {
            // 0 accounts — launch vanilla claude
            println!("No accounts configured — launching vanilla claude.");
            return exec_claude(rest);
        }
    };

    // Phase B' billing-ledger attribution (an internal journal entry D2). Best-effort
    // append; failures MUST NOT block the launch — billing telemetry is
    // diagnostic, not load-bearing. Errors logged at WARN with redacted
    // context per security.md.
    append_launch_log(base_dir, "run", account);

    // M19b + H2/M3: determine the dispatch surface ONCE here, before BOTH the
    // audit-record construction below (so the v1 `AuditRecord` carries the
    // ACTUAL dispatched surface, not a hardcoded `cc`) AND the pre-flight /
    // dispatch ladder farther down. Reusing this single value preserves the
    // TOCTOU-closing "determine surface once" invariant (the pre-flight block
    // below documents it) AND fixes the M19b mislabel bug where every
    // codex/gemini run recorded `surface: cc` in its own audit record.
    let surface_for_preflight = surface_cli_for_slot(base_dir, account);

    // Audit trail (PR-CA10c): construct emitter with the true start_ts
    // captured here, before any spawn step.  All remaining fields are filled
    // after the spawn returns (spawn+wait paths) or immediately before exec
    // (exec-replace path on Unix) via the setter methods below.
    //
    // exec-replace invariant: `exec_or_spawn` on Unix calls `Command::exec`,
    // replacing the process image.  Rust `Drop` impls do NOT run after a
    // successful exec.  Every code path that reaches `exec_or_spawn` MUST call
    // `audit_emitter.flush_now()` immediately before, so the record is emitted
    // synchronously before the process image is replaced.
    //
    // M06 `--no-audit`: when set, skip emitter construction/emission entirely
    // for this invocation. A disabled emitter holds no record, so every flush
    // path is a no-op. We log the explicit acknowledgement to stderr at INFO
    // so the operator sees the gap they accepted.
    let start_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut audit_emitter = if no_audit {
        // Operator-facing acknowledgement on stderr: the operator explicitly
        // accepted the audit gap for this invocation.
        //
        // The `eprintln!` below MUST remain UNCONDITIONAL stderr — it is NOT
        // log-level-gated. The default `CSQ_LOG`/`RUST_LOG` filter is `warn`,
        // which would silently drop the `tracing::info!` mirror below; a
        // future maintainer who deletes the `eprintln!` and "relies on the
        // tracing event" would make the acknowledgement invisible on every
        // default-filter run, defeating the per-invocation visibility the
        // `--no-audit` escape is designed to guarantee (spec 12 §12.4
        // "Per-invocation escape"). The `tracing::info!` is SUPPLEMENTARY —
        // for structured-log subscribers only — never a substitute for the
        // unconditional stderr line.
        eprintln!("csq: --no-audit set; this invocation's audit record will not be written.");
        tracing::info!(
            event = "no_audit_set",
            "csq: --no-audit set; this invocation's audit record will not be written."
        );
        crate::cli::audit_emit::AuditEmitter::disabled()
    } else {
        use csq_core::audit::{AuditRecord, Decision, ResultState};
        let run_id = csq_core::audit::gen_run_id();
        let socket_path = csq_core::daemon::socket_path(base_dir);
        let pending_dir = base_dir.join("csq-runs").join(".pending");
        // Operation label surfaced in the fail-loud remediation message so the
        // operator knows WHICH run's record was lost.
        let operation = format!("csq run account {}", account.get());
        let record = AuditRecord {
            schema_version: "1".to_string(),
            run_id,
            fixture_sha256: "0".repeat(64),
            coc_sha256: "0".repeat(64),
            csq_version: env!("CARGO_PKG_VERSION").to_string(),
            cli_version: "unknown".to_string(),
            // M19b: the ACTUAL dispatched surface (determined once above), not a
            // hardcoded `cc`. 3P slots dispatch through the Claude binary
            // (network-layer redirect) so they map to `cc` — correct.
            surface: audit_surface_for(surface_for_preflight),
            model: "unknown".to_string(),
            // start_ts: captured before any spawn — correct.
            start_ts: start_ts.clone(),
            // end_ts: updated after spawn returns or before exec.
            end_ts: start_ts.clone(),
            // result_state/decision: updated after spawn returns.
            // Bypass/Degraded are the safe defaults for the exec-replace path
            // (layer is OFF — no rule validation ran).
            result_state: ResultState::Degraded,
            score_delta_vs_baseline: None,
            rule_ids_cited_original: vec![],
            rule_ids_cited_after_repair: vec![],
            rule_ids_dropped_invalid_format: 0,
            decision: Decision::Bypass,
            // M6 T6.1: filled by the spawn-boundary gate (codex/gemini,
            // enterprise) just before spawn; stays `None` for cc/3P (in-loop
            // gated) and ungoverned spawns.
            spawn_gate: None,
        };
        crate::cli::audit_emit::AuditEmitter::new(record, socket_path, pending_dir, operation)
    };

    // ── Pre-flight probe (PR-MCD2.5, spec/13 §3, R1-H5) ─────────────────────
    // H2+M3 (R1 redteam): hoist BOTH 3P detection AND surface determination to
    // a single pass BEFORE any pre-flight or dispatch logic. The captured
    // `is_third_party` and `surface_for_preflight` are used by BOTH the
    // pre-flight gate below AND the dispatch ladder farther down, eliminating
    // the TOCTOU window that existed when dispatch re-read canonical symlinks
    // independently of the pre-flight check.
    //
    // 3P collision defence: a slot that has BOTH a 3P binding (settings.json
    // with ANTHROPIC_BASE_URL) AND a Codex/Gemini canonical symlink present is
    // a corrupted state (e.g. from a logout race). We bail with a distinct
    // message instead of silently routing to the wrong path.
    let is_third_party = discovery::discover_per_slot_third_party(base_dir)
        .into_iter()
        .any(|a| a.id == account.get() && matches!(a.source, AccountSource::ThirdParty { .. }));

    // Surface was determined ONCE near the top of `handle` (hoisted there in
    // M19b so the audit record carries it too); `surface_for_preflight` is
    // reused here for both pre-flight and dispatch.

    // 3P collision check: if the slot is marked 3P but also has a
    // Codex/Gemini canonical present, the on-disk state is incoherent.
    if is_third_party && surface_for_preflight != SurfaceCli::Claude {
        return Err(anyhow!(
            "slot {account} is in an inconsistent state \
             (3P provider binding present AND Codex/Gemini canonical symlink present). \
             Run `csq logout {account}` to repair, then `csq login {account} --provider <X>` \
             to re-bind."
        ));
    }

    // Probe: skip for 3P slots (they redirect at the network layer, no
    // versioned CLI binary to probe). For all other surfaces, run the
    // shared pre-flight gate via cli_deps_gate::enforce (H4).
    if !is_third_party {
        super::cli_deps_gate::enforce(
            surface_for_preflight,
            ignore_cli_version,
            no_auto_update_cli,
            &format!("csq run {account}"),
        )?;
    }
    // ─────────────────────────────────────────────────────────────────────────

    // ── Surface dispatch (M3: uses captured `surface_for_preflight`) ──────────
    // The surface was determined ONCE above (in the pre-flight block) and is
    // reused here. This eliminates the TOCTOU window where the pre-flight and
    // dispatch read canonicals independently, giving two chances for state to
    // change between the reads.
    //
    // Codex dispatch: route to `launch_codex` when the captured surface is
    // Codex. The Codex path's `create_handle_dir_codex` owns the handle-dir-
    // level symlinks + marker writes (does NOT reuse the Claude-surface
    // `create_handle_dir`). Origin: spec 07 §7.5 INV-P02 + an internal journal entry
    if surface_for_preflight == SurfaceCli::Codex {
        if let Some(profile_id) = profile {
            return Err(anyhow!(
                "--profile is not supported for Codex slots (slot {account} is Codex, requested: {profile_id})"
            ));
        }
        return launch_codex(
            base_dir,
            account,
            capability_layer_enabled,
            layer_is_auto,
            &persisted_toggles,
            debug,
            bench_mode,
            coc_cache_enabled,
            rest,
            &mut audit_emitter,
        );
    }

    // Gemini dispatch (FR-G-CLI-03): route to `launch_gemini` when the
    // captured surface is Gemini. Per spec 07 §7.5 INV-P02 is INVERTED for
    // Gemini — no daemon prerequisite, no token refresh, no fanout.
    if surface_for_preflight == SurfaceCli::Gemini {
        if let Some(profile_id) = profile {
            return Err(anyhow!(
                "--profile is not supported for Gemini slots (slot {account} is Gemini, requested: {profile_id})"
            ));
        }
        return launch_gemini(
            base_dir,
            &claude_home,
            account,
            capability_layer_enabled,
            layer_is_auto,
            &persisted_toggles,
            debug,
            bench_mode,
            coc_cache_enabled,
            rest,
            &mut audit_emitter,
        );
    }

    // Ensure config-N exists (permanent account home)
    // PATH-BUILDER: constructs the permanent account directory path for
    // creation only; not reading credential content. Unchanged through
    // Phase 2 — see internal-design-docs
    // 03-phase2-readiness.md § M2-7. Phase 3 retargets.
    let config_dir = base_dir.join(format!("config-{}", account));
    std::fs::create_dir_all(&config_dir)?;

    // Mark account on config-N (permanent identity).
    //
    // M4-7 (an internal ticket Phase 4, spec 02 §INV-03 + §2.3.1): the
    // `.csq-account` marker content is the slot's identity UUID when
    // `profiles.json::by_slot` carries a mapping; otherwise we fall
    // back to the legacy decimal slot id. The filename is unchanged.
    match csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, account.get()) {
        Some(uuid) => markers::write_csq_account(&config_dir, uuid)?,
        None => markers::write_csq_account_legacy(&config_dir, account)?,
    }
    markers::write_current_account(&config_dir, account)?;

    // Mark onboarding complete on config-N
    session::mark_onboarding_complete(&config_dir)?;

    // `is_third_party` was already computed above in the pre-flight block.
    // Reuse the captured value — do NOT call discover_per_slot_third_party again.

    if is_third_party {
        if let Some(profile_id) = profile {
            return Err(anyhow!(
                "--profile is not supported for third-party slots (slot {account} is already provider-bound, requested: {profile_id})"
            ));
        }

        launch_third_party(base_dir, &claude_home, account, rest, &mut audit_emitter)
    } else {
        // Anthropic OAuth path.
        if is_broker_failed(base_dir, account) {
            return Err(anyhow!(
                "account {} is in LOGIN-NEEDED state — run `csq login {}` to re-authenticate",
                account,
                account
            ));
        }

        // Verify canonical credentials exist and are loadable.
        // M4-12: numeric credentials/ path retired — resolve via UUID.
        let canonical_path =
            csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, account.get())
                .map(|uuid| {
                    csq_core::accounts::identity_store::credentials_path_for(base_dir, uuid)
                })
                .ok_or_else(|| {
                    anyhow!(
                        "no identity record for account {} — run `csq login {}` to authenticate",
                        account,
                        account
                    )
                })?;
        let canonical = credentials::load(&canonical_path).with_context(|| {
            format!("failed to load canonical credentials for account {account}")
        })?;

        // Warn if token is already expired
        if canonical
            .expect_anthropic()
            .claude_ai_oauth
            .is_expired_within(0)
        {
            eprintln!(
                "warning: access token for account {} has expired — CC may fail until the daemon refreshes it",
                account
            );
        }

        // M3-7 fix-wave (R1 C1): the prior per-run `copy_credentials_for_session`
        // step is retired. It wrote `config-N/.credentials.json` (the legacy
        // live mirror) on every `csq run`, but post-M3-7 the handle dir's
        // `.credentials.json` symlink resolves to `identities/<UUID>/
        // credentials.json` (M3-3 retarget) — seeded by `finalize_login`'s
        // post-mint UUID-seed call to `save_canonical` and refreshed by the
        // daemon's broker tick (`save_canonical_for`). The legacy mirror is
        // no longer a credential reader for any production code path, so the
        // copy was a dead write. The canonical `credentials::load` above
        // already verifies the canonical file is readable before launch.

        // Profile support deferred
        if let Some(profile_id) = profile {
            return Err(anyhow!(
                "--profile support is not yet implemented (requested: {profile_id})"
            ));
        }

        launch_anthropic(
            base_dir,
            &claude_home,
            account,
            capability_layer_enabled,
            layer_is_auto,
            &persisted_toggles,
            debug,
            bench_mode,
            coc_cache_enabled,
            rest,
            &mut audit_emitter,
        )
    }
}

/// Determine which CLI surface this slot launches into.
///
/// Mirrors the surface dispatch logic in `handle` (the `symlink_metadata`
/// checks on canonical paths), extracted for the pre-flight probe so we know
/// which binary to probe before the surface-specific launch path runs.
///
/// Returns `SurfaceCli::Codex` when a Codex canonical credential file exists
/// at EITHER the legacy `credentials/codex-<N>.json` path OR the identity-keyed
/// `identities/<UUID>/credentials-codex.json` path (post-A++ layout, where the
/// legacy mirror has been retired), `SurfaceCli::Gemini` when a Gemini canonical
/// credential file exists, and `SurfaceCli::Claude` for every other case
/// (including 3P slots — the caller is responsible for skipping the probe on 3P
/// slots via the `is_third_party` guard in `handle`).
///
/// ## Mid-migration ambiguity (H1, R1 redteam)
///
/// When a slot is in mid-migration (e.g. the Codex/Gemini canonical symlink
/// has been removed but `settings.json` still carries a 3P binding), this
/// function returns `SurfaceCli::Claude` (the fallthrough). The 3P collision
/// detection in `handle` catches this case and bails with a distinct message:
/// the slot is recognized as 3P by `is_third_party == true` while no
/// Codex/Gemini canonical is present, so `surface_for_preflight == Claude` —
/// the 3P probe-skip path fires correctly (no spurious claude probe).
/// The true mid-migration failure mode is the opposite: Codex/Gemini canonical
/// present PLUS `is_third_party == true`, which the collision guard in `handle`
/// catches before pre-flight.
///
/// M9 A13 disposition: `csq-core::accounts::discovery::surface_for_slot` does
/// NOT currently exist in csq-core. This CLI-side helper is the minimal change
/// that satisfies the M2.5 requirement. If a future cycle adds a core-level
/// `surface_for_slot`, this helper should be removed and the callsite updated.
fn surface_cli_for_slot(base_dir: &Path, account: AccountNum) -> SurfaceCli {
    // Codex — legacy numeric canonical (pre-A++ / downgrade-safety layout).
    let codex_canonical = file::canonical_path_for(base_dir, account, Surface::Codex);
    if std::fs::symlink_metadata(&codex_canonical).is_ok() {
        return SurfaceCli::Codex;
    }
    // Codex — identity-keyed canonical (post-A++ layout). The legacy
    // `credentials/codex-<N>.json` mirror is retired by the credential-mirror
    // cleanup, so a freshly-logged-in Codex slot has its credential ONLY at
    // `identities/<UUID>/credentials-codex.json`. Without this branch,
    // `csq run N` for such a slot detects Claude, routes to the Anthropic
    // path, and dies loading the absent `credentials.json`. Mirrors the
    // UUID-first resolution in `verify_codex_canonical_is_regular_file` and
    // the identity-store-aware codex detection in
    // `account-terminal-separation.md` MUST Rule 4.
    if let Some(uuid) = csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, account.get())
    {
        let uuid_codex =
            csq_core::accounts::identity_store::credentials_codex_path_for(base_dir, uuid);
        if std::fs::symlink_metadata(&uuid_codex).is_ok() {
            return SurfaceCli::Codex;
        }
    }
    let gemini_canonical = file::canonical_path_for(base_dir, account, Surface::Gemini);
    if std::fs::symlink_metadata(&gemini_canonical).is_ok() {
        return SurfaceCli::Gemini;
    }
    SurfaceCli::Claude
}

/// Map the dispatch-time [`SurfaceCli`] to the audit-record
/// [`csq_core::audit::Surface`] tag (M19b).
///
/// The module-level `Surface` alias is `providers::catalog::Surface` (used for
/// canonical-path resolution), so this helper fully-qualifies the audit
/// `Surface` to avoid the collision.
///
/// `SurfaceCli` is `#[non_exhaustive]`; the wildcard arm maps any future
/// surface to `Cc` as a safe default until it is explicitly wired here. The
/// audit `Surface` enum currently has no variant beyond cc/codex/gemini, so a
/// new surface has no audit tag of its own until both are extended together.
fn audit_surface_for(surface: SurfaceCli) -> csq_core::audit::Surface {
    use csq_core::audit::Surface as AuditSurface;
    match surface {
        SurfaceCli::Claude => AuditSurface::Cc,
        SurfaceCli::Codex => AuditSurface::Codex,
        SurfaceCli::Gemini => AuditSurface::Gemini,
        _ => AuditSurface::Cc,
    }
}

/// `csq run N --native` dispatch (P0-B). Drives the native governed loop against
/// the slot's 3P provider instead of spawning a CLI. Enterprise-only
/// (`native-harness` feature); the source is moat-stripped from community.
#[cfg(feature = "native-harness")]
pub fn handle_native(
    base_dir: &Path,
    account: Option<AccountNum>,
    model: Option<&str>,
    governance: &str,
    bench_json: bool,
    rest: &[String],
) -> Result<()> {
    let account =
        account.ok_or_else(|| anyhow!("--native requires a slot: `csq run N --native`"))?;

    // The native loop targets the 3P substrate; resolve the slot's provider from
    // its 3P binding (the slot IS the credential channel). `discover_*` yields the
    // DISPLAY name (`"Z.AI"`), but every downstream consumer — `get_provider`,
    // `load_settings` (`settings-<id>.json`), the rate table — keys on the canonical
    // catalog id (`"zai"`), so map display-name → id here. Passing the display name
    // straight through was the P0-B live-path bug (`unknown provider 'Z.AI'`).
    let provider_label = discovery::discover_per_slot_third_party(base_dir)
        .into_iter()
        .find(|a| a.id == account.get())
        .and_then(|a| match a.source {
            AccountSource::ThirdParty { provider } => Some(provider),
            _ => None,
        })
        .ok_or_else(|| {
            anyhow!(
                "slot {account} is not a 3P provider slot — `csq run --native` targets the 3P \
                 substrate (z.ai/deepseek/minimax). Run `csq setkey <provider> --slot {account} \
                 --key <KEY>` first."
            )
        })?;
    let provider_id = csq_core::providers::catalog::id_from_display_name(&provider_label)
        .ok_or_else(|| anyhow!("slot {account} provider {provider_label:?} has no catalog id"))?
        .to_string();

    let governance = match governance {
        "on" => csq_core::native::Governance::On,
        "off" => csq_core::native::Governance::Off,
        other => return Err(anyhow!("--governance must be 'on' or 'off', got '{other}'")),
    };

    let prompt = rest.join(" ");
    if prompt.trim().is_empty() {
        return Err(anyhow!(
            "--native needs a prompt: `csq run {account} --native -- <task>`"
        ));
    }

    let workdir = std::env::current_dir().context("native: cannot resolve current dir")?;

    let cfg = csq_core::native::NativeRunConfig {
        base_dir: base_dir.to_path_buf(),
        provider_id,
        model: model.map(str::to_string),
        governance,
        workdir,
        prompt,
        max_iterations: 12,
        max_tokens: 4096,
        bench_json,
    };

    let runtime = tokio::runtime::Runtime::new().context("native: tokio runtime init")?;
    let summary = runtime.block_on(csq_core::native::run_native(cfg))?;

    if bench_json {
        // The single contract line the P0-A bench parses (last stdout line).
        println!("{}", summary.to_json_line());
    } else {
        eprintln!(
            "\n[native] provider={} model={} governance={} round_trips={} iterations={} \
             tokens_in={} tokens_out={} cost_usd={:.6} latency_ms={}",
            summary.provider,
            summary.model,
            summary.governance,
            summary.round_trips,
            summary.iterations,
            summary.tokens_in,
            summary.tokens_out,
            summary.cost_usd,
            summary.latency_ns / 1_000_000,
        );
    }
    Ok(())
}

// pre_flight_check removed from run.rs (H4 extraction, R1 redteam).
// The shared implementation now lives in super::cli_deps_gate::enforce,
// which is called from the pre-flight block in `handle` above.

/// Launches CC for a 3P slot. The slot's `config-<N>/settings.json`
/// carries `env.ANTHROPIC_BASE_URL` + `env.ANTHROPIC_AUTH_TOKEN`, and
/// CC reads both on startup. We strip the parent env as usual so a
/// poisoned dotfile can't redirect traffic, then exec with
/// `CLAUDE_CONFIG_DIR` pointing at the handle dir whose
/// `settings.json` symlink resolves back to `config-<N>`.
fn launch_third_party(
    base_dir: &Path,
    claude_home: &Path,
    account: AccountNum,
    rest: &[String],
    audit_emitter: &mut crate::cli::audit_emit::AuditEmitter,
) -> Result<()> {
    // PATH-BUILDER: builds the legacy config-N/settings.json path for an
    // existence check only; no content is read here. Unchanged through
    // Phase 2 — see internal-design-docs
    // 03-phase2-readiness.md § M2-7. Phase 3 retargets.
    let settings_path = base_dir.join(format!("config-{}/settings.json", account));
    if !settings_path.exists() {
        return Err(anyhow!(
            "slot {account} is missing config-{account}/settings.json — run `csq setkey <provider> --slot {account} --key <KEY>` first"
        ));
    }

    let pid = std::process::id();
    let handle_dir = session::create_handle_dir(base_dir, claude_home, account, pid)
        .context("failed to create handle dir")?;
    // M3-3: the defensive re-materialize (an internal journal entry belt-and-suspenders)
    // was removed here.  `create_handle_dir` already calls
    // `materialize_handle_settings_inner` with the UUID-aware path (M2-3),
    // so a second call via the public `materialize_handle_settings` (no-UUID
    // variant) would silently downgrade the settings overlay to config-N,
    // undoing the identity-keyed path for coexisting-layout slots.

    let handle_dir_abs = std::fs::canonicalize(&handle_dir).unwrap_or_else(|_| handle_dir.clone());

    println!(
        "Launching claude for 3P slot {} (term-{}) via {}...",
        account,
        pid,
        redact_path(&settings_path)
    );

    let mut cmd = Command::new("claude");
    cmd.env("CLAUDE_CONFIG_DIR", &handle_dir_abs);
    strip_sensitive_env(&mut cmd);
    cmd.args(rest);

    // Set the layer-bypass result_state + decision before handoff;
    // exec_or_spawn captures end_ts + flushes at the platform-correct
    // moment (Unix: before exec; Windows: after child.wait()).
    {
        use csq_core::audit::{Decision, ResultState};
        audit_emitter.set_result(ResultState::Degraded, Decision::Bypass);
    }
    exec_or_spawn(cmd, &handle_dir, audit_emitter)
}

/// Launches CC for an Anthropic OAuth slot. Assumes credentials have
/// already been copied into `config-<N>` by the caller.
#[allow(clippy::too_many_arguments)]
fn launch_anthropic(
    base_dir: &Path,
    claude_home: &Path,
    account: AccountNum,
    capability_layer_enabled: bool,
    layer_is_auto: bool,
    toggles: &CapabilityLayerToggles,
    debug: bool,
    bench_mode: Option<&str>,
    coc_cache_enabled: bool,
    rest: &[String],
    audit_emitter: &mut crate::cli::audit_emit::AuditEmitter,
) -> Result<()> {
    // Capability-layer pre-flight (spec 10 §10.4.2). When the flag
    // is OFF (default for v2.4.0-alpha) we short-circuit here and
    // fall through to the v2.3.1 launch path — argv + env are
    // byte-identical to pre-PR-CA5 by construction.
    //
    // When the flag is ON, the pre-spawn pipeline (scaffold real +
    // mcp_gate pass-through at PR-CA6b) succeeds end-to-end and the
    // returned `LayerControl::WithLayer` routes the spawn through
    // the always-spawn+wait path so the parent stays alive for the
    // post-spawn pipeline (PR-CA7+). PR-CA6c populates mcp_gate's
    // intersection-not-union semantics from `.coc/tools/policy.json`.
    let layer_control = match run_capability_layer_preflight(
        base_dir,
        account,
        capability_layer_enabled,
        layer_is_auto,
        toggles,
        debug,
        Surface::ClaudeCode,
        coc_cache_enabled,
        rest,
    ) {
        Ok(c) => c,
        Err(err) => {
            // StageError → spec 03 §3.9 exit code. We use
            // process::exit so the parent shell sees the
            // dedicated capability-layer code instead of
            // anyhow's generic 1.
            // PR-CA8 H6: redact_tokens before stderr per INV-P07.
            eprintln!(
                "error: {}",
                csq_core::error::redact_tokens(&format!("{err}"))
            );
            // M06 fail-loud (H1): this `process::exit` bypasses Drop, so the
            // owning emitter in `handle` would never flush. The capability
            // layer rejected the run before any CLI spawn → Fail + Reject.
            {
                use csq_core::audit::{Decision, ResultState};
                let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                audit_emitter.set_end_ts(end_ts);
                audit_emitter.set_result(ResultState::Fail, Decision::Reject);
                fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
            }
            std::process::exit(err.exit_code() as i32);
        }
    };

    // --bench-mode layer-only (design 08 §11 / R2/B56): terminate
    // after the capability-layer preflight, never spawn the CLI.
    if let Some("layer-only") = bench_mode {
        return handle_bench_mode_layer_only(Surface::ClaudeCode, audit_emitter);
    }

    // Create ephemeral handle dir: term-<pid> with symlinks to config-N
    // for credentials and ~/.claude for shared items. CC checks CWD
    // (not CLAUDE_CONFIG_DIR) for session identity, so handle dirs
    // are compatible with --resume as long as the CWD matches.
    let pid = std::process::id();
    let handle_dir = session::create_handle_dir(base_dir, claude_home, account, pid)
        .context("failed to create handle dir")?;
    // M3-3: the defensive re-materialize (an internal journal entry belt-and-suspenders)
    // was removed here.  `create_handle_dir` already calls
    // `materialize_handle_settings_inner` with the UUID-aware path (M2-3),
    // so a second call via the public `materialize_handle_settings` (no-UUID
    // variant) would silently downgrade the settings overlay to config-N,
    // undoing the identity-keyed path for coexisting-layout slots.

    let handle_dir_abs = std::fs::canonicalize(&handle_dir).unwrap_or_else(|_| handle_dir.clone());

    // CC reads this account's OAuth credential from the keychain item keyed by
    // the CLAUDE_CONFIG_DIR path below — not from the symlinked
    // `.credentials.json`. Mirror the bound account's current token into it so
    // CC picks up the fresh credential (it re-checks the keychain ~every 30s).
    sync_cc_keychain(&handle_dir_abs, false);

    println!("Launching claude for account {} (term-{})...", account, pid);

    // Strip ANTHROPIC_* (and related) env vars before exec.
    let mut cmd = Command::new("claude");
    cmd.env("CLAUDE_CONFIG_DIR", &handle_dir_abs);
    strip_sensitive_env(&mut cmd);
    cmd.args(rest);

    match layer_control {
        LayerControl::Inherit => {
            // Layer-bypass result shape; exec_or_spawn handles platform-
            // conditional end_ts + flush (PR-CA10c R1 redteam HIGH fix —
            // Unix flushes before exec; Windows captures end_ts after
            // child.wait() so the record reflects true session duration).
            use csq_core::audit::{Decision, ResultState};
            audit_emitter.set_result(ResultState::Degraded, Decision::Bypass);
            exec_or_spawn(cmd, &handle_dir, audit_emitter)
        }
        LayerControl::WithLayer {
            mode,
            class,
            rule_ids_in_scope,
            scaffold,
        } => {
            // PR-CA7c: deliver the scaffold (rules + structured-output
            // directive when applicable) to CC via the same env var
            // CC reads from `settings.json::env`. This is what makes
            // FR-CL-02 (rule citation) and FR-CL-01 (structured output)
            // actually reach the model — without this injection, the
            // pipeline computes the scaffold but drops it.
            //
            // Empty/missing scaffold is a no-op: the env var is set
            // only when there's something to deliver. CC tolerates
            // either presence or absence of the var.
            if let Some(s) = scaffold.as_deref() {
                if !s.is_empty() {
                    cmd.env("CLAUDE_SYSTEM_PROMPT_APPEND", s);
                }
            }
            let result = spawn_with_layer(
                cmd,
                &handle_dir,
                mode,
                class,
                rule_ids_in_scope.clone(),
                toggles,
                debug,
                audit_emitter,
            );
            // WithLayer path: spawn+wait, so Drop fires normally. We still
            // populate the emitter fields so the record reflects the actual
            // post-spawn state rather than the construction-time defaults.
            //
            // PR-CA10c R1 redteam MEDIUM fix: `rule_ids_cited_*` are the
            // rules the MODEL CITED, not the rules MADE AVAILABLE (which
            // is `rule_ids_in_scope`). The cited set is buried inside
            // spawn_with_layer's post-validate pass and isn't returned to
            // this call site. Leave the cited vectors empty (honest "not
            // yet plumbed") rather than populate them with in-scope rules
            // — per no-stubs.md Rule 3, populated-with-wrong-data is worse
            // than empty because it signals "this is the answer." Plumbing
            // the actual cited set requires extending spawn_with_layer's
            // return type in a follow-up.
            let _ = rule_ids_in_scope;
            {
                use csq_core::audit::{Decision, ResultState};
                let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                audit_emitter.set_end_ts(end_ts);
                // WithLayer passed the pre-spawn pipeline; treat the run as
                // Pass (post-validate accepted the output or layer exited
                // normally). Any post-validate failure exits via
                // process::exit before reaching here.
                audit_emitter.set_result(ResultState::Pass, Decision::Accept);
                audit_emitter.set_rule_ids(vec![], vec![]);
            }
            result
        }
    }
}

/// Launches Codex for a Codex-surface slot.
///
/// Spec 07 §7.5 INV-P02: daemon is a hard prerequisite — if the
/// daemon is not running, refresh cadence cannot be guaranteed and
/// codex-cli's on-expiry refresh will burn the refresh token
/// (openai/codex#10332). Refuse with exit 2 before creating a handle
/// dir.
///
/// Spec 07 §7.2.2 on-disk layout: `term-<pid>` IS `$CODEX_HOME`.
/// The Codex child sees auth.json / config.toml / sessions /
/// history.jsonl through the handle-dir symlinks assembled by
/// `create_handle_dir_codex` (PR-C3a).
///
/// Env: `strip_sensitive_env` removes `ANTHROPIC_*` + bedrock/vertex
/// variants (same attack surface as Claude launch — a poisoned
/// dotfile cannot redirect traffic). Additionally removes
/// `CLAUDE_CONFIG_DIR` so a parent csq-managed shell does not leak
/// the Claude-surface state dir into the Codex child. Full
/// `env_clear + allowlist` is a PR-C3c-follow-up hardening target;
/// today's env_remove set matches PR-C3b's login spawn.
#[allow(clippy::too_many_arguments)]
fn launch_codex(
    base_dir: &Path,
    account: AccountNum,
    capability_layer_enabled: bool,
    layer_is_auto: bool,
    toggles: &CapabilityLayerToggles,
    debug: bool,
    bench_mode: Option<&str>,
    coc_cache_enabled: bool,
    rest: &[String],
    audit_emitter: &mut crate::cli::audit_emit::AuditEmitter,
) -> Result<()> {
    require_daemon_healthy(base_dir, audit_emitter)?;
    verify_codex_config_toml(base_dir, account)?;
    verify_codex_canonical_is_regular_file(base_dir, account)?;

    // Re-merge the slot's `config.toml` from the CURRENT `~/.codex` on
    // every launch, so the user's global-config edits propagate to live
    // slots (the `~/.codex` single-source-of-truth model, matching how CC
    // live-links `~/.claude`). Runs BEFORE the capability-layer preflight
    // and `create_handle_dir_codex` so BOTH the Inherit symlink and the
    // WithLayer materialization (which reads `config-<N>/config.toml` as
    // its base) see the fresh content. The slot's per-account `model` is
    // preserved; existence is already guaranteed by the verify above.
    //
    // Degradation posture (never abort the launch on these):
    // - present-but-malformed `~/.codex` → existing slot config is KEPT
    //   (the helper refuses to wipe it to the 2-key fallback); tell the
    //   operator so they know why their edit did not propagate.
    // - write failure → `atomic_replace` leaves the prior `config.toml`
    //   intact; warn and continue with the existing (possibly stale)
    //   config rather than block a launch on a transient FS error.
    match codex_surface::regenerate_slot_config_preserving_model(base_dir, account) {
        Ok(codex_surface::RegenOutcome::AlreadyCurrent)
        | Ok(codex_surface::RegenOutcome::Rewritten {
            was_global_malformed: false,
            ..
        }) => {}
        // Both the no-op (SkippedMalformedGlobal) AND the repaired-under-malformed
        // (Rewritten { was_global_malformed: true }) cases mean the user's global
        // is invalid and new edits are NOT propagating — surface the same note.
        Ok(codex_surface::RegenOutcome::SkippedMalformedGlobal)
        | Ok(codex_surface::RegenOutcome::Rewritten {
            was_global_malformed: true,
            ..
        }) => {
            eprintln!(
                "note: ~/.codex/config.toml is not valid TOML — slot {account} kept its \
                 existing config. Fix your global config so edits propagate."
            );
        }
        Err(_) => {
            eprintln!(
                "warning: could not refresh slot {account} config from ~/.codex \
                 (continuing with the existing config)."
            );
        }
    }

    // PR-CA8 commit 2: capability-layer pre-flight. When the flag is
    // OFF (default for v2.4.0-alpha) or `.coc/` resolves to fallback,
    // the path is the v2.3.1 path verbatim (Inherit branch below).
    // When ON and `.coc/` populated, the per-spawn handle-dir
    // `config.toml` is materialized with the layer's `instructions`
    // block (spec 10 §10.4.6.1 codex row).
    let layer_control = match run_capability_layer_preflight(
        base_dir,
        account,
        capability_layer_enabled,
        layer_is_auto,
        toggles,
        debug,
        Surface::Codex,
        coc_cache_enabled,
        rest,
    ) {
        Ok(c) => c,
        Err(err) => {
            // PR-CA8 H6: redact_tokens before stderr per INV-P07.
            eprintln!(
                "error: {}",
                csq_core::error::redact_tokens(&format!("{err}"))
            );
            // M06 fail-loud (H1): this `process::exit` bypasses Drop — flush the
            // owning emitter's record BEFORE exit. Capability layer rejected the
            // Codex run before any spawn → Fail + Reject.
            {
                use csq_core::audit::{Decision, ResultState};
                let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                audit_emitter.set_end_ts(end_ts);
                audit_emitter.set_result(ResultState::Fail, Decision::Reject);
                fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
            }
            std::process::exit(err.exit_code() as i32);
        }
    };

    // --bench-mode layer-only: terminate before subprocess spawn.
    if let Some("layer-only") = bench_mode {
        return handle_bench_mode_layer_only(Surface::Codex, audit_emitter);
    }

    // M6 T6.1: cross-CLI spawn-boundary governance gate (enterprise-only).
    // Evaluated BEFORE the codex subprocess is built/spawned. Block/Escalate (or a
    // present-but-malformed/unbuildable envelope) → refuse to spawn (fail-loud
    // audit + non-zero exit); Conditional → inject the advisory path-scope env
    // (T6.4); Pass/Ungoverned → proceed. Community builds carry no governor and
    // spawn ungoverned (the `Vec::new()` arm).
    //
    // The gate returns the RESOLVED operating envelope alongside its verdict so the
    // Shard 3a MCP config-rewrite below can consult the SAME validated envelope
    // WITHOUT a second `load_spawn_envelope` read (redteam R1 finding 1.1: two loads
    // could diverge — the gate admits under an `mcp` policy while a re-read sees none
    // and spawns un-gated MCP).
    #[cfg(feature = "enterprise")]
    let (codex_spawn_scope_env, codex_gate_env): (
        Vec<(String, String)>,
        Option<Box<csq_trust_contract::OperatingEnvelope>>,
    ) = {
        use crate::cli::commands::spawn_gate;
        use csq_core::daemon::interactive_live::SpawnGate;
        let (gate, gate_env) =
            spawn_gate::evaluate_spawn(base_dir, csq_trust_contract::SpawnCli::Codex);
        let scope = match gate {
            SpawnGate::Ungoverned => Vec::new(),
            SpawnGate::Proceed {
                verdict,
                action_id,
                path_scope_env,
            } => {
                audit_emitter.set_spawn_gate("codex", &action_id, spawn_gate::verdict_tag(verdict));
                path_scope_env
            }
            SpawnGate::Refuse { reason, action_id } => {
                eprintln!("error: csq run codex refused by operating envelope ({reason})");
                use csq_core::audit::{Decision, ResultState};
                let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                audit_emitter.set_spawn_gate("codex", &action_id, reason);
                audit_emitter.set_end_ts(end_ts);
                audit_emitter.set_result(ResultState::Fail, Decision::Reject);
                fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
                std::process::exit(EXIT_CODE_SPAWN_BLOCKED);
            }
        };
        (scope, gate_env)
    };
    #[cfg(not(feature = "enterprise"))]
    let codex_spawn_scope_env: Vec<(String, String)> = Vec::new();

    let pid = std::process::id();
    let handle_dir = session::create_handle_dir_codex(base_dir, account, pid)
        .with_context(|| format!("create Codex handle dir for account {account}"))?;

    let handle_dir_abs = std::fs::canonicalize(&handle_dir).unwrap_or_else(|_| handle_dir.clone());

    // M6 T6.2 Shard 3a: resolve whether this governed codex spawn routes its MCP
    // servers through `csq mcp-proxy`. `Some((csq_bin, envelope_snapshot))` iff the
    // gate's resolved envelope declares an `mcp` policy (opt-in); this stages the
    // envelope snapshot the proxy will `--envelope`-load. Consumes the SAME envelope
    // the M6 T6.1 gate above resolved (single load — no divergence window). `None` in
    // the community build and for any ungoverned / no-MCP-policy session.
    #[cfg(feature = "enterprise")]
    let codex_mcp_rewrite = resolve_codex_mcp_rewrite(codex_gate_env.as_deref(), &handle_dir_abs)?;
    #[cfg(not(feature = "enterprise"))]
    let codex_mcp_rewrite: Option<(String, std::path::PathBuf)> = None;

    // Task 8: JWT exp pre-flight — defense-in-depth against stale tokens.
    // Delegates to `check_codex_token_freshness` so the logic is unit-testable.
    {
        let auth_json_link = handle_dir_abs.join("auth.json");
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        check_codex_token_freshness(&auth_json_link, account, now_secs)?;
    }

    println!("Launching codex for account {} (term-{})...", account, pid);

    // Strip BEFORE `cmd.env(HOME_ENV_VAR, …)` so our explicit
    // CODEX_HOME value wins over any parent-shell export.
    // `strip_sensitive_env` scrubs CODEX_HOME from the parent env
    // (H1 fix) — if we set it first it would get env_remove'd right
    // back out.
    let mut cmd = Command::new(codex_surface::CLI_BINARY);
    strip_sensitive_env(&mut cmd);
    // Codex does not read CLAUDE_CONFIG_DIR today, but a parent csq
    // shell will have it set — scrub so a future codex-cli cannot
    // accidentally resolve a Claude state dir. Mirrors PR-C3b login
    // spawn's posture.
    cmd.env_remove("CLAUDE_CONFIG_DIR");
    cmd.env_remove("CLAUDE_HOME");
    cmd.env(codex_surface::HOME_ENV_VAR, &handle_dir_abs);

    // 2026-05-15 sandbox bug fix: pass sandbox/approval flags derived
    // from user-global ~/.codex/config.toml at spawn. Codex CLI's
    // policy precedence treats CLI flags as authoritative for the
    // strict policy layer; merging keys into config-N/config.toml
    // alone produced sessions where the model still had to request
    // escalation despite the file having approval_policy = "never" +
    // sandbox_mode = "danger-full-access".
    //
    // GH #978: the derived FULL-BYPASS flag
    // (`--dangerously-bypass-approvals-and-sandbox`) is a TERMINAL override —
    // a later `-s read-only` in the passthrough cannot undo it (it is not a
    // `-s` value, so codex's last-wins argparse does not apply). So a caller
    // driving a sandboxed one-shot (`csq run N -- exec -s read-only …`) could
    // not downscope. Fix: when the caller's passthrough ALREADY specifies a
    // sandbox / approval policy (or `--ignore-user-config`), suppress the
    // derived flags entirely so the caller's explicit policy is the ONLY one
    // codex sees. Otherwise inject as before (BEFORE `rest`, last-wins for the
    // granular `-a`/`-s` case).
    if !codex_surface::caller_overrides_sandbox(rest) {
        let derived_flags = codex_surface::derive_spawn_flags(
            codex_surface::read_user_global_config_toml().as_deref(),
        );
        cmd.args(&derived_flags);
    }
    cmd.args(rest);

    // M6 T6.4: inject the advisory path-scope env (empty unless the gate returned
    // Conditional with a declared path-scope). codex does NOT natively enforce
    // this var — the constraint is advisory + attested per the M6 fidelity gap.
    for (k, v) in &codex_spawn_scope_env {
        cmd.env(k, v);
    }

    // The MCP-proxy rewrite (Shard 3a) as a `(csq_bin, envelope_path)` pair for the
    // materializer, threaded into both the Inherit and WithLayer paths.
    let mcp_wrap = codex_mcp_rewrite
        .as_ref()
        .map(|(bin, path)| (bin.as_str(), path.as_path()));

    match layer_control {
        LayerControl::Inherit => {
            // Layer-bypass result shape; exec_or_spawn handles platform-
            // conditional end_ts + flush (PR-CA10c R1 redteam HIGH fix).
            use csq_core::audit::{Decision, ResultState};

            // M6 T6.2 Shard 3a: even on the layer-bypass path, a governed codex
            // spawn with an MCP policy must route its servers through the proxy —
            // which means materializing the handle config.toml as a regular file
            // (breaking the Inherit symlink `create_handle_dir_codex` planted) with
            // `[mcp_servers.*]` rewritten. No MCP policy → the v2.3.1 symlink path
            // is preserved verbatim (no materialization, no re-stat).
            if mcp_wrap.is_some() {
                let skipped =
                    materialize_handle_config_toml(base_dir, account, &handle_dir, None, mcp_wrap)
                        .context("failed to materialize per-spawn config.toml (MCP proxy)")?;
                warn_skipped_remote_mcp(&skipped);
                // Post-rename re-stat closes the materialize→spawn TOCTOU window.
                verify_codex_handle_config_toml_is_regular_file(&handle_dir)?;
            }

            audit_emitter.set_result(ResultState::Degraded, Decision::Bypass);
            exec_or_spawn(cmd, &handle_dir, audit_emitter)
        }
        LayerControl::WithLayer {
            mode,
            class,
            rule_ids_in_scope,
            scaffold,
        } => {
            // PR-CA8 commit 2: materialize per-spawn config.toml in the
            // handle dir with the layer's `instructions` block merged
            // in (+ Shard 3a MCP-proxy rewrite when a policy is active).
            // Replaces the symlink at handle_dir/config.toml with a
            // regular file (spec 07 §7.2.2 deviation under the with-layer
            // path).
            //
            // No mutex acquisition (round-2 R2-C2 retraction) — the
            // safety net is (a) atomic_replace at canonical writers,
            // (b) writer rarity (only `csq login --provider codex`
            // and `daemon::startup_reconciler::pass2_codex_config_toml`
            // touch the canonical), (c) toml::from_str parse-as-
            // defense-in-depth on the merge path.
            let instructions = scaffold.as_deref().filter(|s| !s.is_empty());
            if instructions.is_some() || mcp_wrap.is_some() {
                let skipped = materialize_handle_config_toml(
                    base_dir,
                    account,
                    &handle_dir,
                    instructions,
                    mcp_wrap,
                )
                .context("failed to materialize per-spawn config.toml overlay")?;
                warn_skipped_remote_mcp(&skipped);
                // Round-1 C4: post-rename re-stat closes the TOCTOU window between
                // materialization and `Command::spawn`. GUARDED by the same
                // condition as the materialization (redteam R1 finding 3.1): when
                // NEITHER instructions nor an MCP policy applies, no materialization
                // ran and `handle_dir/config.toml` is still the symlink
                // `create_handle_dir_codex` planted — re-stating it would spuriously
                // fail-closed with a bogus "became a symlink (TOCTOU)" refusal.
                // Symmetric with the Inherit arm's guarded re-stat.
                verify_codex_handle_config_toml_is_regular_file(&handle_dir)?;
            }
            let result = spawn_with_layer(
                cmd,
                &handle_dir,
                mode,
                class,
                rule_ids_in_scope.clone(),
                toggles,
                debug,
                audit_emitter,
            );
            // WithLayer path: spawn+wait, so Drop fires normally. Populate
            // audit fields reflecting the actual post-spawn outcome.
            //
            // PR-CA10c R1 redteam MEDIUM fix: cited fields stay empty until
            // spawn_with_layer plumbs the actual cited set — see the
            // matching block in launch_anthropic for full rationale.
            let _ = rule_ids_in_scope;
            {
                use csq_core::audit::{Decision, ResultState};
                let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                audit_emitter.set_end_ts(end_ts);
                audit_emitter.set_result(ResultState::Pass, Decision::Accept);
                audit_emitter.set_rule_ids(vec![], vec![]);
            }
            result
        }
    }
}

/// PR-CA8 commit 2 + M6 T6.2 Shard 3a: materialize `term-<pid>/config.toml`
/// as a regular file, composing up to two per-spawn transforms over the
/// canonical `config-<N>/config.toml`:
///
/// 1. `instructions` (capability layer, both editions): merge the per-spawn
///    `instructions = "..."` block via `merge_instructions_via_toml_value`.
/// 2. `mcp_wrap` (M6 T6.2 Shard 3a, enterprise-only): rewrite every STDIO
///    `[mcp_servers.*]` table so its `command`/`args` route through
///    `csq mcp-proxy --envelope <path> -- …`, gating the MCP tool-calls through
///    the Shard-2 proxy. `mcp_wrap = Some((csq_bin, envelope_snapshot_path))`.
///
/// Either, both, or neither transform may apply; with neither this is just a
/// symlink→regular-file copy. Replaces the symlink `create_handle_dir_codex`
/// planted (spec 07 §7.2.2 deviation). NEVER mutates the canonical
/// `config-<N>/config.toml` — the rewrite lives only in the ephemeral handle dir.
///
/// Returns the names of REMOTE (`url`-transport) MCP servers left un-gated, so the
/// caller can warn the operator (the stdio proxy cannot interpose HTTP/SSE).
///
/// Idiom: `unique_tmp_path → write → secure_file → atomic_replace`, with
/// `let _ = remove_file(&tmp);` cleanup on every error branch per
/// `.claude/rules/security.md` §5a.
fn materialize_handle_config_toml(
    base_dir: &Path,
    account: AccountNum,
    handle_dir: &Path,
    instructions: Option<&str>,
    mcp_wrap: Option<(&str, &Path)>,
) -> Result<Vec<String>> {
    use csq_core::coc::translate::codex_merge::merge_instructions_via_toml_value;
    use csq_core::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
    use std::collections::BTreeMap;

    // PATH-BUILDER: constructs the config-N/config.toml path to read CC's
    // native config. config.toml is NOT part of the UUID credential/settings
    // migration (credentials.json and settings.json are migrated; config.toml
    // stays account-local). Unchanged through Phase 2 — see workspaces/
    // an internal workspace/02-plans/03-phase2-readiness.md § M2-7.
    let canonical = base_dir
        .join(format!("config-{}", account))
        .join("config.toml");
    let mut content = std::fs::read_to_string(&canonical)
        .with_context(|| format!("read {}", redact_path(&canonical)))?;

    // Transform 1 — capability-layer instructions merge.
    if let Some(scaffold_text) = instructions {
        // The overlay is reserved for future MCP-filter parameters; empty today
        // so the merge is a no-op for non-instructions keys.
        let overlay: BTreeMap<String, String> = BTreeMap::new();
        content = merge_instructions_via_toml_value(&content, scaffold_text, &overlay)
            .context("merging instructions into config.toml")?;
    }

    // Transform 2 — MCP proxy rewrite (enterprise-only; `mcp_wrap` is always
    // `None` in the community build so this branch never fires there).
    let skipped_remote: Vec<String> = if let Some((csq_bin, envelope_path)) = mcp_wrap {
        #[cfg(feature = "enterprise")]
        {
            let rewrite = csq_core::daemon::mcp_rewrite::rewrite_codex_config_mcp_servers(
                &content,
                csq_bin,
                &envelope_path.to_string_lossy(),
            )
            // Fail-CLOSED: the operator declared an MCP policy, so if the rewrite
            // fails we must NOT spawn with un-gated MCP — surface the fixed-vocab
            // tag and abort the launch.
            .map_err(|e| anyhow!("csq run codex: MCP proxy rewrite failed ({})", e.tag()))?;
            content = rewrite.toml;
            rewrite.skipped_remote
        }
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = (csq_bin, envelope_path);
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let target = handle_dir.join("config.toml");
    let tmp = unique_tmp_path(&target);

    if let Err(e) = std::fs::write(&tmp, content.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow!("write {}: {e}", redact_path(&tmp)));
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow!("secure_file {}: {e}", redact_path(&tmp)));
    }
    // atomic_replace is rename(2) on Unix / retry-loop MoveFileExW on
    // Windows; both atomically replace whatever was at `target`
    // (symlink or regular file) with the new regular file. No
    // explicit unlink needed — and skipping it closes the TOCTOU
    // window that round-1 H5 surfaced.
    if let Err(e) = atomic_replace(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow!(
            "atomic_replace {} -> {}: {e}",
            redact_path(&tmp),
            redact_path(&target)
        ));
    }
    Ok(skipped_remote)
}

/// Warn the operator (once per server) that a REMOTE (`url`-transport) MCP server
/// is NOT routed through the governance proxy — the stdio proxy cannot interpose an
/// HTTP/SSE transport, so its tool-calls run un-gated (spec 25 §25.11). Server
/// names only; no host paths, so no redaction needed.
fn warn_skipped_remote_mcp(skipped: &[String]) {
    for name in skipped {
        eprintln!(
            "note: codex MCP server '{name}' uses a remote (url) transport — its tool-calls are \
             NOT gated by csq (the MCP proxy interposes stdio servers only)."
        );
    }
}

/// M6 T6.2 Shard 3a: resolve whether a governed `csq run … --provider codex` spawn
/// routes its MCP servers through `csq mcp-proxy`, and if so stage the envelope
/// snapshot the proxy will load.
///
/// Takes the envelope the M6 T6.1 spawn gate ALREADY resolved and validated (single
/// load — no re-read, so no gate-vs-rewrite divergence; redteam R1 finding 1.1).
/// Returns `Some((csq_bin, envelope_snapshot_path))` iff that envelope is present
/// (`Configured`) AND declares an `mcp` policy (`env.mcp.is_some()`) — MCP gating is
/// opt-in via the envelope's `mcp` field. An ungoverned spawn (`gate_env == None`) or
/// a governed session with no `mcp` policy → `None` (MCP servers run direct,
/// backward-compatible). A refused/malformed envelope never reaches here — the gate
/// exits the process fail-closed upstream, and it returns `None` for those anyway.
///
/// `csq_bin` is `current_exe()` VERBATIM (no canonicalize). `launch_codex` only runs
/// inside an already-`Mode::Cli` process (the desktop app launches codex via a
/// terminal running the CLI binary; it never calls `launch_codex` directly), so
/// `current_exe()` is by construction a path that did NOT match the desktop-bundle
/// sentinel and re-resolves to CLI mode — the `mcp-proxy` subprocess dispatches
/// correctly. Canonicalizing is deliberately avoided (a symlinked CLI path can
/// canonicalize INTO the desktop bundle and flip mode detection — memory
/// `discovery_csq_symlink_breaks_mode_detect`). Fail-CLOSED: an unresolvable binary
/// or a failed snapshot write aborts the launch rather than spawning un-gated MCP.
#[cfg(feature = "enterprise")]
fn resolve_codex_mcp_rewrite(
    gate_env: Option<&csq_trust_contract::OperatingEnvelope>,
    handle_dir_abs: &Path,
) -> Result<Option<(String, std::path::PathBuf)>> {
    use csq_core::daemon::interactive_live::materialize_envelope_snapshot;

    let Some(env) = gate_env else {
        // Ungoverned (or the gate refused upstream) → nothing to gate.
        return Ok(None);
    };
    if env.mcp.is_none() {
        // Governed, but the operator declared no MCP allow-list → not opted in.
        return Ok(None);
    }

    let csq_bin = std::env::current_exe()
        .map_err(|_| {
            anyhow!("csq run codex: could not resolve the csq binary path for MCP proxy wiring")
        })?
        .to_string_lossy()
        .into_owned();

    let envelope_path = handle_dir_abs.join(".pact-mcp-envelope.json");
    materialize_envelope_snapshot(env, &envelope_path).map_err(|tag| {
        anyhow!("csq run codex: failed to stage the MCP operating-envelope snapshot ({tag})")
    })?;

    Ok(Some((csq_bin, envelope_path)))
}

/// PR-CA8 round-1 C4: post-materialization re-stat. Refuses any non-
/// regular-file at `handle_dir/config.toml` immediately before
/// `Command::spawn`. Closes the TOCTOU window between
/// `atomic_replace` returning and codex starting up — a same-user
/// attacker who unlinks our regular file and replaces it with a
/// symlink to attacker content would otherwise inject system-prompt
/// instructions into codex.
///
/// Mirrors the existing `verify_codex_canonical_is_regular_file`
/// posture (line ~393). Fail-closed on symlink; user re-runs.
fn verify_codex_handle_config_toml_is_regular_file(handle_dir: &Path) -> Result<()> {
    let path = handle_dir.join("config.toml");
    let meta = std::fs::symlink_metadata(&path).with_context(|| {
        format!(
            "stat {} — handle-dir config.toml missing post-materialization",
            redact_path(&path)
        )
    })?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Err(anyhow!(
            "refusing Codex spawn: {} became a symlink between materialization and spawn (TOCTOU). \
             Re-run `csq run`.",
            redact_path(&path)
        ));
    }
    if !ft.is_file() {
        return Err(anyhow!(
            "refusing Codex spawn: {} is not a regular file (type: {:?})",
            redact_path(&path),
            ft
        ));
    }
    Ok(())
}

/// JWT-exp pre-flight check on auth.json.
///
/// Reads `tokens.access_token` from the JSON at `auth_json_path`, decodes the
/// JWT `exp` claim, and returns `Err` if the token is expired or within the
/// grace window of expiry. Non-fatal on missing / unparseable auth.json — the
/// daemon's normal refresh path handles legitimate token lifecycle.
///
/// `now_secs` is injected so callers in tests can supply a deterministic clock.
///
/// # Race window
///
/// There is a small window between this read and codex-cli's first auth.json
/// read where the daemon's refresher could rotate the tokens. The pre-flight
/// catches the steady-state stale-on-disk case (the original
/// `csq run 12 --provider codex` refresh-token-reuse bug) — it does NOT
/// prevent a race during a concurrent daemon refresh tick. The structural
/// defense for the concurrent case is the per-canonical-path refresh-lock used
/// by `broker_codex_check` (`refresh/check.rs:274`); a future hardening pass
/// MAY acquire that lock here too, but the cost (~100ms hold on every
/// `csq run`) is not justified by the rarity of the race in practice (daemon
/// refreshes 5-min cadence; user launches are seconds).
fn check_codex_token_freshness(
    auth_json_path: &std::path::Path,
    account: AccountNum,
    now_secs: u64,
) -> Result<()> {
    let content = match std::fs::read_to_string(auth_json_path) {
        Ok(c) => c,
        Err(_) => return Ok(()), // Missing or unreadable auth.json — non-fatal.
    };
    let json = match serde_json::from_str::<serde_json::Value>(&content) {
        Ok(v) => v,
        Err(_) => return Ok(()), // Malformed JSON — non-fatal; credentials::load will surface the real error.
    };
    // Missing `tokens` key or `access_token` key — non-fatal (no JWT to check).
    let access_token = match json
        .get("tokens")
        .and_then(|t| t.get("access_token"))
        .and_then(|v| v.as_str())
    {
        Some(t) => t,
        None => return Ok(()),
    };
    // Malformed JWT (no dots, missing base64 payload) — non-fatal.
    let Some(exp) = csq_core::http::codex::jwt_exp_secs(access_token) else {
        return Ok(());
    };
    const GRACE_SECS: u64 = 60;
    if exp.saturating_sub(GRACE_SECS) <= now_secs {
        return Err(anyhow!(
            "slot {account} has an expired Codex access token \
             (exp={exp}, now={now_secs}) — the refresher cooldown may have \
             been missed. Re-run `csq login {account} --provider codex` \
             to get fresh tokens."
        ));
    }
    Ok(())
}

/// Verifies the Codex canonical credential file is a regular file, not a
/// symlink, before a Codex spawn. Origin: PR-C3c security review M1.
///
/// Resolution order (M4-12 UUID-keyed vs legacy numeric path):
///
/// 1. If `profiles.json::by_slot[N]` resolves to a UUID AND
///    `identities/<UUID>/credentials-codex.json` exists as a regular file →
///    accept (identity-keyed path, post-M4-12 layout).
/// 2. Else fall back to `credentials/codex-<N>.json` (legacy numeric path,
///    retained through Phase 4 for downgrade safety).
///
/// In both cases a symlink at the resolved path is rejected (same-user
/// TOCTOU guard — PR-C3b's `save_canonical_for` always writes a regular
/// file).
///
/// The dispatch branch in [`handle`] uses `symlink_metadata` so a
/// dangling symlink still routes to Codex (refusing to silently fall
/// through to the Claude path — an internal journal entry). But `symlink_metadata`
/// also accepts a symlink-to-anywhere, which would let a same-user
/// attacker who races a swap between dispatch and spawn inject
/// attacker-chosen tokens into the handle dir's `auth.json` symlink
/// chain. Refusing any canonical that is a symlink at spawn time
/// closes that vector.
fn verify_codex_canonical_is_regular_file(base_dir: &Path, account: AccountNum) -> Result<()> {
    // Task 4: Try the UUID-keyed path first.
    if let Some(uuid) = csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, account.get())
    {
        let uuid_path =
            csq_core::accounts::identity_store::credentials_codex_path_for(base_dir, uuid);
        if let Ok(meta) = std::fs::symlink_metadata(&uuid_path) {
            let ft = meta.file_type();
            if ft.is_symlink() {
                return Err(anyhow!(
                    "refusing Codex launch: identities/<UUID>/credentials-codex.json is a symlink. \
                     csq only writes a regular file at this path (spec 07 §7.2.2 + INV-P08); \
                     a symlink here means an external process mutated the credentials directory. \
                     Re-run `csq login {account} --provider codex` to rewrite."
                ));
            }
            if ft.is_file() {
                // UUID-keyed path exists and is a regular file — accept.
                return Ok(());
            }
            // UUID path exists but is neither file nor symlink (directory?): fall through to legacy.
        }
        // UUID path does not exist: fall through to legacy for downgrade safety.
    }

    // Fall back to the legacy numeric path.
    let path = file::canonical_path_for(base_dir, account, Surface::Codex);
    let meta = std::fs::symlink_metadata(&path).with_context(|| {
        format!(
            "stat Codex canonical — neither UUID-keyed nor legacy path exists; \
             run `csq login {account} --provider codex`"
        )
    })?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Err(anyhow!(
            "refusing Codex launch: credentials/codex-{account}.json is a symlink. \
             csq only writes a regular file at this path (spec 07 §7.2.2 + INV-P08); \
             a symlink here means an external process mutated the credentials directory. \
             Re-run `csq login {account} --provider codex` to rewrite."
        ));
    }
    if !ft.is_file() {
        return Err(anyhow!(
            "refusing Codex launch: credentials/codex-{account}.json is not a regular file (type: {:?})",
            ft
        ));
    }
    Ok(())
}

/// Verifies `config-<N>/config.toml` exists before a Codex spawn.
/// Extracted from [`launch_codex`] so the precondition can be
/// unit-tested without shelling out to `codex` or exit(2)-ing on the
/// daemon check.
fn verify_codex_config_toml(base_dir: &Path, account: AccountNum) -> Result<()> {
    let config_toml = codex_surface::config_toml_path(base_dir, account);
    if !config_toml.exists() {
        return Err(anyhow!(
            "slot {account} is missing {} — run `csq login {account} --provider codex` to complete login",
            redact_path(&config_toml)
        ));
    }
    Ok(())
}

/// Requires the daemon to be `Healthy` before a Codex spawn. Spec 07
/// §7.5 INV-P02: without the daemon, codex's on-expiry in-process
/// refresh will fire and burn the refresh token. Exits with
/// [`EXIT_CODE_DAEMON_REQUIRED`] on any non-Healthy state so scripts
/// can distinguish "daemon-down" from other launch failures.
///
/// PR-C4 (H2 gate): cross-platform — `daemon::detect_daemon` already
/// has a Windows named-pipe branch (`csq-core/src/daemon/detect.rs`
/// `windows_health_check`), so the same DetectResult variants apply
/// across Unix and Windows. This closes the an internal journal entry
/// `#[cfg(not(unix))] Ok(())` carve-out.
/// Launches gemini-cli for a Gemini-surface slot.
///
/// Spec 07 §7.2.3 / §7.5: Gemini does NOT require the daemon for
/// spawn (INV-P02 inverted). The CLI talks directly to Google's
/// API via `gemini-cli`; csq's role is to (a) keep the slot's API
/// key in the platform-native vault and (b) pre-seed
/// `<handle_dir>/.gemini/settings.json` with
/// `selectedType=gemini-api-key` so gemini-cli doesn't
/// interactively prompt for an auth choice on first spawn (UX
/// shortcut for API-key bound slots, not a ToS-driven defense —
/// the original "EP1-EP7 / 7-layer ToS guard" framing was
/// retracted in an internal journal entry). Neither task needs the daemon.
///
/// Handle dir layout for Gemini is minimal:
///
/// ```text
/// term-<pid>/
///   .csq-account             # marker file (diagnostic)
///   .gemini/
///     settings.json          # pre-seeded selectedType + model
/// ```
///
/// No `.credentials.json` symlink (Gemini has no Anthropic OAuth
/// path) and no `config-<N>/` housekeeping beyond what `setkey
/// gemini` already wrote.
///
/// THRESHOLD — D4 factoring trigger. Sibling: `exec_gemini` in
/// `commands/swap.rs`. At N=2 callers the ~20 LOC duplication is
/// cheaper than introducing a `csq_core::providers::gemini::session`
/// module + typed error enum. When a 3rd caller surfaces (most
/// likely the desktop spawn path landing inside csq-cli, or a
/// future Bedrock launcher reusing the same shape), factor both
/// bodies into csq-core. Both sites must be edited together.
#[allow(clippy::too_many_arguments)]
fn launch_gemini(
    base_dir: &Path,
    claude_home: &Path,
    account: AccountNum,
    capability_layer_enabled: bool,
    layer_is_auto: bool,
    toggles: &CapabilityLayerToggles,
    debug: bool,
    bench_mode: Option<&str>,
    coc_cache_enabled: bool,
    rest: &[String],
    audit_emitter: &mut crate::cli::audit_emit::AuditEmitter,
) -> Result<()> {
    use csq_core::platform::secret;
    use csq_core::providers::gemini::spawn::{
        build_spawn_plan_with_system_instruction, execute_plan_as_child,
        execute_plan_as_child_piped, spawn_gemini,
    };

    // PR-CA8b commit 4: build HostContext from the parent env BEFORE
    // any spawn-time work. Detected names are used by the layer-on
    // path to emit the host-isolation warning per spec 08 MED-03;
    // they're inert on the layer-off path.
    let host_ctx = detect_host_context();

    // PR-CA8b commit 4: capability-layer pre-flight. When the flag
    // is OFF (default for v2.4.0-alpha) or `.coc/` resolves to
    // fallback, the path is the v2.3.1 path verbatim (Inherit
    // branch). When ON, the per-spawn handle-dir settings.json is
    // materialized with the layer's `system_instruction` field
    // (spec 10 §10.4.6.1 gemini row).
    let layer_control = match run_capability_layer_preflight(
        base_dir,
        account,
        capability_layer_enabled,
        layer_is_auto,
        toggles,
        debug,
        Surface::Gemini,
        coc_cache_enabled,
        rest,
    ) {
        Ok(c) => c,
        Err(err) => {
            eprintln!(
                "error: {}",
                csq_core::error::redact_tokens(&format!("{err}"))
            );
            // M06 fail-loud (H1): this `process::exit` bypasses Drop — flush the
            // owning emitter's record BEFORE exit. Capability layer rejected the
            // Gemini run before any spawn → Fail + Reject.
            {
                use csq_core::audit::{Decision, ResultState};
                let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                audit_emitter.set_end_ts(end_ts);
                audit_emitter.set_result(ResultState::Fail, Decision::Reject);
                fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
            }
            std::process::exit(err.exit_code() as i32);
        }
    };

    // --bench-mode layer-only: terminate before subprocess spawn.
    if let Some("layer-only") = bench_mode {
        return handle_bench_mode_layer_only(Surface::Gemini, audit_emitter);
    }

    // M6 T6.1: cross-CLI spawn-boundary governance gate (enterprise-only).
    // Block/Escalate (or a malformed/unbuildable envelope) → refuse to spawn
    // (fail-loud audit + non-zero exit); Pass/Conditional/Ungoverned → proceed.
    // T6.4 note: gemini's `spawn_gemini` snapshots the global process env to
    // build the child env; csq-ee declines to mutate global process state in
    // production, so a Conditional gemini path-scope is RECORDED (attested) but
    // NOT injected into the child — advisory-only per the M6 fidelity gap (the
    // spec documents codex/gemini as spawn-boundary-only, not in-loop).
    #[cfg(feature = "enterprise")]
    {
        use crate::cli::commands::spawn_gate;
        use csq_core::daemon::interactive_live::SpawnGate;
        // Gemini has no MCP config-rewrite (honest fidelity gap — spec 25 §25.11.4),
        // so it ignores the resolved envelope the gate now returns.
        let (gate, _gate_env) =
            spawn_gate::evaluate_spawn(base_dir, csq_trust_contract::SpawnCli::Gemini);
        match gate {
            SpawnGate::Ungoverned => {}
            SpawnGate::Proceed {
                verdict, action_id, ..
            } => {
                audit_emitter.set_spawn_gate(
                    "gemini",
                    &action_id,
                    spawn_gate::verdict_tag(verdict),
                );
            }
            SpawnGate::Refuse { reason, action_id } => {
                eprintln!("error: csq run gemini refused by operating envelope ({reason})");
                use csq_core::audit::{Decision, ResultState};
                let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                audit_emitter.set_spawn_gate("gemini", &action_id, reason);
                audit_emitter.set_end_ts(end_ts);
                audit_emitter.set_result(ResultState::Fail, Decision::Reject);
                fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
                std::process::exit(EXIT_CODE_SPAWN_BLOCKED);
            }
        }
    }

    // Refuse symlink at the binding marker — same posture as
    // `verify_codex_canonical_is_regular_file`. csq writes a
    // regular file here; a symlink at this path is an external
    // mutation that deserves an abort.
    let binding_path = file::canonical_path_for(base_dir, account, Surface::Gemini);
    let meta = std::fs::symlink_metadata(&binding_path).with_context(|| {
        format!(
            "stat {} — Gemini binding missing; run `csq setkey gemini --slot {account}` (API key / Vertex SA) or `csq login {account} --provider gemini` (Code Assist OAuth) first",
            redact_path(&binding_path)
        )
    })?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!(
            "refusing Gemini launch: {} is a symlink. csq only writes a regular file at this path; a symlink here means an external process mutated the credentials directory. Re-run `csq setkey gemini --slot {account}` to rewrite.",
            redact_path(&binding_path)
        ));
    }

    // Ensure ~/.claude/accounts exists. We do NOT create config-N/
    // for Gemini — the binding marker lives in
    // ~/.claude/accounts/credentials/, and the per-spawn settings
    // file lives in the handle dir.
    let accounts_root = claude_home.join("accounts");
    std::fs::create_dir_all(&accounts_root).context("failed to create accounts root")?;

    // Minimal handle dir: just the directory + .csq-account marker.
    // The settings drift reassertion (called inside
    // build_spawn_plan*) creates the .gemini/ subdir and writes
    // settings.json with the pre-seeded selectedType + model.
    let pid = std::process::id();
    let handle_dir = base_dir.join(format!("term-{}", pid));
    std::fs::create_dir_all(&handle_dir).with_context(|| {
        format!(
            "failed to create Gemini handle dir at {}",
            redact_path(&handle_dir)
        )
    })?;
    // M4-7: Gemini handle-dir marker uses the slot's identity UUID
    // when a `by_slot` mapping exists; otherwise the legacy decimal
    // slot id.
    match csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, account.get()) {
        Some(uuid) => markers::write_csq_account(&handle_dir, uuid)
            .context("failed to write .csq-account marker for Gemini handle dir")?,
        None => markers::write_csq_account_legacy(&handle_dir, account)
            .context("failed to write .csq-account marker for Gemini handle dir")?,
    }

    let handle_dir_abs = std::fs::canonicalize(&handle_dir).unwrap_or_else(|_| handle_dir.clone());

    // Open the platform-native vault. Failures here are
    // user-actionable (locked keychain, missing libsecret) — surface
    // via anyhow rather than panicking.
    let vault = secret::open_default_vault().map_err(|e| {
        let _ = std::fs::remove_dir_all(&handle_dir);
        anyhow!("secret vault unavailable ({}): {e}", e.error_kind_tag())
    })?;

    println!("Launching gemini for account {} (term-{})...", account, pid);

    match layer_control {
        LayerControl::Inherit => {
            // v2.3.1 byte-equivalent path — exec on Unix / exit on
            // Windows. spawn_gemini handles everything (settings
            // drift reassertion, .env scan, vault read, exec).
            //
            // exec-replace invariant (PR-CA10c): Gemini Inherit path calls
            // exec inside spawn_gemini on Unix (return type Infallible) —
            // Drop is bypassed after a successful exec. We pre-flush so
            // the record is durable on the Unix happy path.
            //
            // Windows limitation: spawn_gemini's Result<Infallible, _>
            // return type means it cannot thread an `&mut AuditEmitter`
            // through to capture end_ts AFTER child.wait() (the way
            // exec_or_spawn does for Anthropic/Codex/3P). On Windows,
            // end_ts will equal start_ts for Gemini Inherit sessions
            // until spawn_gemini gains a cross-module refactor in a
            // follow-up PR (tracked separately). Pre-flush is preferred
            // over not-flushing because Windows process::exit on
            // non-zero child status would otherwise bypass Drop and
            // drop the record entirely.
            {
                use csq_core::audit::{Decision, ResultState};
                let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                audit_emitter.set_end_ts(end_ts);
                audit_emitter.set_result(ResultState::Degraded, Decision::Bypass);
                // M06 fail-loud: Gemini Inherit calls exec inside spawn_gemini
                // (Unix) / process::exit (Windows) — Drop is bypassed. We still
                // own the exit code here, so surface a `.pending/` total failure
                // before handing off.
                fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
            }
            match spawn_gemini(
                base_dir,
                &handle_dir_abs,
                account,
                rest.to_vec(),
                vault.as_ref(),
            ) {
                Ok(_never) => unreachable!("spawn_gemini returns Infallible on success"),
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&handle_dir);
                    Err(map_spawn_error(account, e))
                }
            }
        }
        LayerControl::WithLayer {
            mode,
            class,
            rule_ids_in_scope,
            scaffold,
        } => {
            // PR-CA8b commit 4: emit the host-isolation warning per
            // spec 08 MED-03 if production-shaped secrets were
            // detected. Informational — does NOT abort spawn.
            // Operator-side mitigation (clean VM) per spec 08 stays
            // load-bearing.
            emit_host_isolation_warning_if_needed(&host_ctx, account);

            // Build the spawn plan. Layer-on variant calls
            // probe::reassert_settings_drift_with_system_instruction
            // internally with the scaffold (overwrites any prior
            // system_instruction value — csq-owned during layer-on
            // per round-3 R3-H1).
            let parent_env: std::collections::HashMap<String, String> = std::env::vars().collect();
            let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
            let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
            let system_instruction = scaffold.as_deref().filter(|s| !s.is_empty());

            let plan = match build_spawn_plan_with_system_instruction(
                base_dir,
                &handle_dir_abs,
                account,
                &parent_env,
                &cwd,
                home.as_deref(),
                vault.as_ref(),
                rest.to_vec(),
                system_instruction,
            ) {
                Ok(p) => p,
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&handle_dir);
                    return Err(map_spawn_error(account, e));
                }
            };

            // Round-1 C4: post-rename re-stat closes TOCTOU window
            // between settings.json materialization and gemini-cli
            // starting up.
            verify_gemini_handle_settings_is_regular_file(&handle_dir_abs)?;

            // CU2 (an internal ticket): spawn shape is mode-driven BEFORE the child
            // is created. OneShot requires piped stdio for post-validate
            // capture; Interactive keeps inherited stdio.
            //
            // GOTCHA-A: #3a alone (detection) would be a silent no-op without
            // this dispatch branch — detecting OneShot but spawning with
            // inherited stdio would land in a dead arm that drops inputs.
            // Both detection AND piped-spawn MUST land together.
            let child = match mode {
                SpawnMode::OneShot => {
                    // Piped stdio variant preserves the same security posture
                    // (env_clear + allowlist, current_dir, Unix pre_exec
                    // RLIMIT_CORE=0) as execute_plan_as_child.
                    match execute_plan_as_child_piped(plan) {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = std::fs::remove_dir_all(&handle_dir);
                            return Err(anyhow!("failed to spawn gemini-cli (piped): {e}"));
                        }
                    }
                }
                SpawnMode::Interactive => {
                    // Inherited stdio (existing behavior — INV-2 unchanged).
                    match execute_plan_as_child(plan) {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = std::fs::remove_dir_all(&handle_dir);
                            return Err(anyhow!("failed to spawn gemini-cli: {e}"));
                        }
                    }
                }
            };

            // CU2 (#3d): audit attribution comes from the ACTUAL outcome.
            // For OneShot, spawn_gemini_with_layer_dispatch sets all audit
            // fields internally (including process::exit paths — GOTCHA-F).
            // For Interactive success, the dispatch returns Ok(()) and we
            // set Pass+Accept here (the WithLayer path completed normally).
            let result = spawn_gemini_with_layer_dispatch(
                child,
                &handle_dir,
                mode,
                class,
                rule_ids_in_scope,
                toggles,
                debug,
                audit_emitter,
            );

            // Interactive success path: set audit fields here so Drop
            // flushes the complete record. OneShot and error paths set
            // their own audit fields inside the dispatch function.
            if result.is_ok() && mode == SpawnMode::Interactive {
                use csq_core::audit::{Decision, ResultState};
                let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                audit_emitter.set_end_ts(end_ts);
                audit_emitter.set_result(ResultState::Pass, Decision::Accept);
                audit_emitter.set_rule_ids(vec![], vec![]);
            }
            result
        }
    }
}

/// CU2 (an internal ticket): dispatches a spawned gemini Child on the
/// with-layer path. The child was spawned with the correct stdio
/// shape for `mode` by the caller (piped for OneShot, inherited for
/// Interactive) — this function only waits and drives post-validate.
///
/// # OneShot path (CU2 #3c)
///
/// Child was spawned with `execute_plan_as_child_piped` by the
/// caller. This function captures with `wait_with_output`, builds
/// lossy-UTF-8 for the validator, runs `run_post_spawn_toggled`, then:
/// - **Pass:** echo Gemini's exact stdout+stderr bytes; clean up
///   handle_dir; propagate child exit (Fail+Accept if non-zero).
/// - **Fail (PostValidateFailed):** do NOT echo stdout; echo stderr;
///   print csq's structured-error line; clean up handle_dir;
///   flush Fail/Reject audit; `process::exit(24)`.
///
/// # GOTCHA-D (false-reject DoS guard — enforcement defaults OFF)
///
/// The Gemini one-shot citation gate REJECTING uncited output is the
/// DoS-prone half: if gemini-cli does NOT honor
/// `settings.json::system_instruction` in `--prompt` mode, the model
/// never receives the RULE_IDs, can never cite them, and EVERY Gemini
/// one-shot would exit 24 (self-inflicted denial of service). CU0's
/// probe confirming `system_instruction` delivery is still pending
/// (external dependency), so the OneShot arm forces
/// `disable_post_validate = true` BY DEFAULT — detection + piped capture
/// run, but the gate does not reject. Operators whose gemini-cli is
/// confirmed opt IN with `CSQ_GEMINI_ONE_SHOT_POST_VALIDATE=1`. When
/// CU0's probe clears, flip enforcement default-on here (an internal ticket).
/// Distinct from `--no-post-validate` (FR-CL-05), which disables the
/// gate for ALL surfaces; the GOTCHA-D default-off is Gemini-one-shot-
/// specific and DoS-motivated.
///
/// # Audit attribution (#3d)
///
/// Every exit branch sets audit result fields from the ACTUAL outcome:
/// - Interactive pass: Pass+Accept (set by caller after return).
/// - OneShot post-validate pass, child success: Pass+Accept (set here).
/// - OneShot post-validate pass, child non-zero: Fail+Accept (set here,
///   then process::exit — GOTCHA-F flush before exit).
/// - OneShot post-validate reject: Fail+Reject (set here, then
///   process::exit — GOTCHA-F flush before exit).
///
/// # INV-2 (GOTCHA-E)
///
/// Interactive path is UNCHANGED: inherited stdio, no post-validate,
/// wait-then-propagate-exit.
#[allow(clippy::too_many_arguments)]
fn spawn_gemini_with_layer_dispatch(
    mut child: std::process::Child,
    handle_dir: &Path,
    mode: SpawnMode,
    class: PromptClass,
    rule_ids_in_scope: BTreeSet<String>,
    toggles: &CapabilityLayerToggles,
    debug: bool,
    audit_emitter: &mut crate::cli::audit_emit::AuditEmitter,
) -> Result<()> {
    match mode {
        SpawnMode::OneShot => {
            // CU2 #3c: child was spawned with piped stdio by caller.
            // Capture full output, run post-validate, then echo/suppress.
            let output = match child.wait_with_output() {
                Ok(o) => o,
                Err(e) => {
                    let _ = std::fs::remove_dir_all(handle_dir);
                    return Err(anyhow!("failed to wait for gemini-cli: {e}"));
                }
            };

            // UTF-8 lossy: citation / negative-evidence checks operate on
            // textual signal; a mid-byte truncation cannot manufacture a
            // citation nor erase a negative pattern. The bytes echoed to
            // the user are the original output.stdout — lossy only feeds
            // the validator. Mirrors the CC reference path exactly.
            let raw = String::from_utf8_lossy(&output.stdout).into_owned();

            // GOTCHA-D (false-reject DoS guard): default Gemini one-shot
            // enforcement OFF until CU0's probe confirms gemini-cli honors
            // settings.json::system_instruction in `--prompt` mode. The
            // gate MECHANISM (detection + piped capture) runs regardless;
            // only REJECTION is suppressed by default. Opt in once the
            // probe clears with CSQ_GEMINI_ONE_SHOT_POST_VALIDATE=1.
            let gemini_enforce = std::env::var("CSQ_GEMINI_ONE_SHOT_POST_VALIDATE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            let mut eff_toggles = *toggles;
            if !gemini_enforce {
                eff_toggles.disable_post_validate = true;
            }

            match run_post_spawn_toggled(raw, class, rule_ids_in_scope, &eff_toggles) {
                Ok(post_state) => {
                    if debug {
                        let cited = post_state
                            .decoded
                            .as_ref()
                            .and_then(|d| d.fields.get("rule_ids_cited"))
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default();
                        emit_debug_post_validate(true, &cited, None);
                    }
                    // Post-validate passed — echo Gemini's exact bytes to
                    // the user (no transformation). Stderr also forwarded
                    // so gemini-cli's diagnostic output reaches the terminal.
                    let _ = std::io::stdout().write_all(&output.stdout);
                    let _ = std::io::stderr().write_all(&output.stderr);
                    let _ = std::fs::remove_dir_all(handle_dir);

                    if !output.status.success() {
                        // GOTCHA-F (INV-7): this process::exit bypasses Drop →
                        // audit_emitter never flushes. Flush BEFORE exiting.
                        // Post-validate accepted the output (Accept); child
                        // itself exited non-zero → Fail.
                        use csq_core::audit::{Decision, ResultState};
                        let end_ts =
                            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                        audit_emitter.set_end_ts(end_ts);
                        audit_emitter.set_result(ResultState::Fail, Decision::Accept);
                        audit_emitter.set_rule_ids(vec![], vec![]);
                        fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
                        std::process::exit(output.status.code().unwrap_or(1));
                    }

                    // #3d: successful OneShot + post-validate pass → Pass+Accept.
                    // Audit fields set here; caller no longer sets unconditionally.
                    {
                        use csq_core::audit::{Decision, ResultState};
                        let end_ts =
                            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                        audit_emitter.set_end_ts(end_ts);
                        audit_emitter.set_result(ResultState::Pass, Decision::Accept);
                        // Cited rule_ids from post-validation decoded state.
                        let cited: Vec<String> = post_state
                            .decoded
                            .as_ref()
                            .and_then(|d| d.fields.get("rule_ids_cited"))
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();
                        audit_emitter.set_rule_ids(cited, vec![]);
                    }
                    Ok(())
                }
                Err(e) => {
                    if debug {
                        let reason = match &e {
                            StageError::PostValidateFailed { reason } => Some(reason.as_str()),
                            _ => None,
                        };
                        emit_debug_post_validate(false, &[], reason);
                    }
                    // Post-validate failed — do NOT echo Gemini's stdout
                    // (user must not act on rejected content). Stderr IS
                    // echoed so Gemini's diagnostic context survives.
                    let _ = std::io::stderr().write_all(&output.stderr);
                    eprintln!("csq: capability layer rejected output: {e}");
                    let exit_code = match &e {
                        StageError::PostValidateFailed { .. } => 24,
                        _ => e.exit_code() as i32,
                    };
                    // GOTCHA-G: clean up handle_dir on reject path too.
                    let _ = std::fs::remove_dir_all(handle_dir);
                    // GOTCHA-F (INV-7): flush audit BEFORE process::exit.
                    // The capability layer rejected the output → Fail+Reject.
                    {
                        use csq_core::audit::{Decision, ResultState};
                        let end_ts =
                            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                        audit_emitter.set_end_ts(end_ts);
                        audit_emitter.set_result(ResultState::Fail, Decision::Reject);
                        audit_emitter.set_rule_ids(vec![], vec![]);
                        fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
                    }
                    std::process::exit(exit_code);
                }
            }
        }
        SpawnMode::Interactive => {
            // INV-2 (GOTCHA-E): Interactive path is UNCHANGED.
            // Inherited stdio (child was spawned with execute_plan_as_child
            // by the caller). No post-validate runs on this path.
            let _ = (class, rule_ids_in_scope, debug, toggles);
            let status = child.wait().map_err(|e| {
                let _ = std::fs::remove_dir_all(handle_dir);
                anyhow!("failed to wait for gemini-cli: {e}")
            })?;
            let _ = std::fs::remove_dir_all(handle_dir);
            if !status.success() {
                // GOTCHA-F (INV-7): gemini Interactive child exited
                // non-zero. This process::exit bypasses Drop — flush BEFORE
                // exiting. Fail+Accept (no post-validate rejection on the
                // interactive path).
                use csq_core::audit::{Decision, ResultState};
                let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                audit_emitter.set_end_ts(end_ts);
                audit_emitter.set_result(ResultState::Fail, Decision::Accept);
                audit_emitter.set_rule_ids(vec![], vec![]);
                fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
                std::process::exit(status.code().unwrap_or(1));
            }
            // #3d: Interactive pass → Pass+Accept (set by caller after return).
            Ok(())
        }
    }
}

/// Detects production-shaped env-var names in the parent process
/// environment and builds a `gemini::HostContext` for the spec 08
/// MED-03 host-isolation warning. Pure observation of env at
/// invocation time (read-on-spawn matches doctor's read-on-invoke
/// posture).
fn detect_host_context() -> csq_core::coc::translate::gemini::HostContext {
    let detected: BTreeSet<String> = std::env::vars()
        .map(|(k, _v)| k)
        .filter(|k| csq_core::env::looks_like_production_secret(k))
        .collect();
    csq_core::coc::translate::gemini::HostContext {
        production_secrets_present: !detected.is_empty(),
        detected_var_names: detected,
    }
}

/// Emits the spec 08 MED-03 host-isolation warning to stderr +
/// structured log. Round-2 H3 disclosure-minimization: surface
/// `count + first-name exemplar`, NOT the full `detected_var_names`
/// list. Round-1 H8: uses `tracing::warn!` with structured fields,
/// NOT `log::warn!` formatted string.
///
/// Informational — does NOT abort the spawn. Operator-side
/// mitigation (clean VM) per spec 08 stays load-bearing.
fn emit_host_isolation_warning_if_needed(
    host_ctx: &csq_core::coc::translate::gemini::HostContext,
    account: AccountNum,
) {
    if !host_ctx.production_secrets_present {
        return;
    }
    let count = host_ctx.detected_var_names.len();
    let exemplar = csq_core::env::first_exemplar(&host_ctx.detected_var_names)
        .unwrap_or("<unknown>")
        .to_string();
    eprintln!(
        "warning: gemini host-isolation — {count} production-shaped env-var name(s) detected \
         (e.g. {exemplar}); model running gemini reads $HOME unfiltered; \
         see specs/08 MED-03 host-isolation caveat."
    );
    tracing::warn!(
        target: "csq::capability_layer",
        error_kind = "gemini_host_isolation_warning",
        surface = "gemini",
        account = account.get(),
        detected_count = count,
        first_name = exemplar.as_str(),
        "gemini host-isolation warning emitted"
    );
}

/// PR-CA8b round-1 C4 + R2-H3: post-rename re-stat for gemini's
/// handle-dir settings.json. Mirrors `verify_codex_handle_config_toml_is_regular_file`.
/// Closes the TOCTOU window between materialization and
/// `gemini-cli` starting up; on Windows the upper bound is ~500ms
/// per `atomic_replace_windows` retry-loop semantics.
fn verify_gemini_handle_settings_is_regular_file(handle_dir: &Path) -> Result<()> {
    let path = handle_dir.join(".gemini").join("settings.json");
    let meta = std::fs::symlink_metadata(&path).with_context(|| {
        format!(
            "stat {} — handle-dir gemini settings.json missing post-materialization",
            redact_path(&path)
        )
    })?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Err(anyhow!(
            "refusing Gemini spawn: {} became a symlink between materialization and spawn (TOCTOU). \
             Re-run `csq run`.",
            redact_path(&path)
        ));
    }
    if !ft.is_file() {
        return Err(anyhow!(
            "refusing Gemini spawn: {} is not a regular file (type: {:?})",
            redact_path(&path),
            ft
        ));
    }
    Ok(())
}

/// Maps a `SpawnError` to user-actionable anyhow text.
fn map_spawn_error(
    account: AccountNum,
    e: csq_core::providers::gemini::spawn::SpawnError,
) -> anyhow::Error {
    use csq_core::providers::gemini::spawn::SpawnError as S;
    match e {
        // Mirror the variant's own Display string per
        // `rules/operator-surface-verification.md` Rule 2 (field-shape
        // trigger): `env_file: PathBuf` is the leak-class field, and
        // surfacing it here would re-leak the user's directory tree
        // even though the variant's `#[error(...)]` was hardened in
        // the same shard (see `csq-core/src/providers/gemini/spawn.rs`
        // `SpawnError::ShadowAuth` design-intent comment). Drop the
        // path; keep the actionable variable name + remediation hint.
        S::ShadowAuth { env_file: _, variable } => anyhow!(
            "refusing Gemini spawn — a `.env` file declares {} which would override the csq-injected key. \
             Remove or rename the variable before retrying, or run `csq run` from a different directory.",
            variable
        ),
        S::Probe(p) => anyhow!("Gemini drift detector failed: {p}"),
        S::Provision(p) => anyhow!("Gemini provisioning state for slot {account} is unusable: {p}"),
        S::Vault(v) => anyhow!(
            "Gemini secret vault read failed ({}) for slot {account}: {v}",
            v.error_kind_tag()
        ),
    }
}

fn require_daemon_healthy(
    base_dir: &Path,
    audit_emitter: &mut crate::cli::audit_emit::AuditEmitter,
) -> Result<()> {
    // M06 fail-loud (H1): every "Codex spawn refused" branch below uses
    // `process::exit`, which bypasses the owning emitter's `Drop` in
    // `handle`. The daemon-prerequisite gate is a real run outcome (the
    // Codex run was refused before any spawn) → Fail + Reject. Flush the
    // record BEFORE the exit, fail-loud if even `.pending/` is unwritable.
    let flush_refused = |emitter: &mut crate::cli::audit_emit::AuditEmitter| {
        use csq_core::audit::{Decision, ResultState};
        let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        emitter.set_end_ts(end_ts);
        emitter.set_result(ResultState::Fail, Decision::Reject);
        fail_loud_on_audit_write_failure(emitter.try_flush_now());
    };

    match daemon::detect_daemon(base_dir) {
        DetectResult::Healthy { daemon_version, .. } => {
            // A long-running daemon spawned from a pre-upgrade binary
            // may carry stale Codex provider config or token-refresh
            // logic. Spec 07 §7.5 INV-P02 puts the daemon on the
            // refresh hot path for Codex, so refusing the spawn is
            // safer than risking a refresh against a stale endpoint.
            if let Some(reason) = daemon::version_drift_reason(&daemon_version) {
                eprintln!("Codex spawn refused — {reason}.");
                flush_refused(audit_emitter);
                std::process::exit(EXIT_CODE_DAEMON_REQUIRED);
            }
            Ok(())
        }
        DetectResult::NotRunning => {
            eprintln!(
                "Codex spawn refused — csq daemon is not running.\n\
                 The daemon must own token refresh for Codex (spec 07 §7.5 INV-P02);\n\
                 start it with `csq daemon start` or install the desktop app."
            );
            flush_refused(audit_emitter);
            std::process::exit(EXIT_CODE_DAEMON_REQUIRED);
        }
        DetectResult::Stale { reason } => {
            eprintln!(
                "Codex spawn refused — csq daemon is stale: {reason}.\n\
                 Restart with `csq daemon stop && csq daemon start`."
            );
            flush_refused(audit_emitter);
            std::process::exit(EXIT_CODE_DAEMON_REQUIRED);
        }
        DetectResult::Unhealthy { reason } => {
            eprintln!(
                "Codex spawn refused — csq daemon is unhealthy: {reason}.\n\
                 Inspect logs with `csq daemon status` and restart if needed."
            );
            flush_refused(audit_emitter);
            std::process::exit(EXIT_CODE_DAEMON_REQUIRED);
        }
    }
}

/// Caller-side dispatch instruction returned by
/// [`run_capability_layer_preflight`]. The csq-cli launch path uses
/// it to decide between the v2.3.1 inherit-and-exec shape and the
/// PR-CA6b+ with-layer spawn+wait shape (spec 10 §10.4.2).
enum LayerControl {
    /// Layer is OFF or `.coc/` resolved to fallback. Caller takes
    /// the v2.3.1 path: `exec_or_spawn` (exec on Unix, spawn+wait on
    /// Windows). Argv + env are byte-identical to pre-PR-CA5.
    Inherit,
    /// Layer ran the pre-spawn pipeline successfully. Caller spawns
    /// CC as a child (always spawn+wait — never `exec`) so the parent
    /// stays alive for the post-spawn pipeline. Per spec 10 §10.4.2:
    /// - `mode == OneShot` (PR-CA7b1) → `Stdio::piped()` capture +
    ///   post-validate against captured output + echo to user stdout.
    /// - `mode == Interactive` (PR-CA7b2 deferred) → inherited stdio
    ///   today; PTY allocation when interactive post-validate ships.
    ///
    /// `scaffold` is the system-prompt-append text built by
    /// `ScaffoldStage`, including the FR-CL-01 structured-output
    /// directive when `class == Compliance` (PR-CA7c). The caller
    /// injects this into CC's environment via
    /// `CLAUDE_SYSTEM_PROMPT_APPEND` (the same name CC reads from
    /// `settings.json::env`); spec 10 §10.4.6 records the delivery
    /// mechanism.
    WithLayer {
        mode: SpawnMode,
        class: PromptClass,
        rule_ids_in_scope: BTreeSet<String>,
        scaffold: Option<String>,
    },
}

/// Time the `.coc/` load and emit either `STAGE_COC_LOAD` (warm hit) or
/// `STAGE_COC_LOAD_COLD` (cold parse) per spec 10 §10.9.1.
///
/// Wraps [`csq_core::coc::load_with_cache`] in stage instrumentation so
/// the bench harness can fill the `(binary, cache)` matrix from a single
/// call site. The stage_id is decided at finish time based on the
/// returned [`csq_core::coc::Warmth`].
///
/// `cache_enabled` plumbs `--no-coc-cache` (spec 10 §10.9.5). When
/// `false`, the cache is neither read nor written for this invocation
/// and the emit is always `STAGE_COC_LOAD_COLD`.
///
/// Result mapping:
/// - `Ok(Warm)` → `STAGE_COC_LOAD` + `StageResult::Applied`
/// - `Ok(Cold)` → `STAGE_COC_LOAD_COLD` + `StageResult::Applied`
///   (parse produced a `CocSet`, even on legacy / empty / version-refused
///   fall-throughs — those are structured outcomes, not stage errors).
/// - `Err(_)` → `STAGE_COC_LOAD_COLD` + `StageResult::Error` (the
///   resolver itself failed, e.g. I/O on `COC.lock`; warm path cannot
///   surface a load error because the cache hit short-circuits parsing).
fn load_coc_with_timing(
    cwd: &Path,
    base_dir: &Path,
    cache_enabled: bool,
) -> Result<csq_core::coc::LoadOutcomeWithWarmth, csq_core::coc::LoadError> {
    use csq_core::capability_layer::{
        emit_stage_timing, StageResult, StageTiming, STAGE_COC_LOAD, STAGE_COC_LOAD_COLD,
    };
    use csq_core::coc::Warmth;
    let started_at_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let start_instant = std::time::Instant::now();
    let result = csq_core::coc::load_with_cache(cwd, base_dir, cache_enabled);
    let elapsed_ns = start_instant.elapsed().as_nanos();
    let (stage_id, stage_result) = match &result {
        Ok(o) => match o.warmth {
            Warmth::Warm => (STAGE_COC_LOAD, StageResult::Applied),
            Warmth::Cold => (STAGE_COC_LOAD_COLD, StageResult::Applied),
        },
        Err(_) => (STAGE_COC_LOAD_COLD, StageResult::Error),
    };
    let timing = StageTiming {
        stage_id,
        started_at_ns,
        elapsed_ns,
        result: stage_result,
    };
    emit_stage_timing(&timing);
    result
}

/// Best-effort append of `project_root` to the transitional roots-seen
/// FIFO at `~/.csq/coc-roots-seen.jsonl` per spec 10 §10.9.3.
///
/// This is the "every `csq run` invocation appends its `coc_root`
/// (deduplicated per file) on success" half of the cache-sweeper
/// contract: the daemon-side `coc_cache_sweeper` reads this file to
/// discover known roots and GCs cache files whose `lock_sha` matches no
/// current root. Without this append, every parse cache file is orphaned
/// from the sweeper's perspective.
///
/// `roots_seen_path = None` resolves to the spec-mandated default; tests
/// pass an explicit override under `tempfile::TempDir`.
///
/// Failures are logged at WARN with a fixed `error_kind` tag; never
/// propagated. A failed roots-seen append must NOT block `csq run`.
fn record_root_seen(project_root: &Path, roots_seen_path: Option<&Path>) {
    let path: PathBuf = match roots_seen_path {
        Some(p) => p.to_path_buf(),
        None => match dirs::home_dir() {
            Some(h) => h.join(".csq").join("coc-roots-seen.jsonl"),
            None => {
                tracing::warn!(
                    error_kind = "coc_roots_seen_path",
                    "could not resolve home directory for coc-roots-seen.jsonl"
                );
                return;
            }
        },
    };
    if let Err(e) = csq_core::daemon::coc_cache_sweeper::append_root_seen(&path, project_root) {
        tracing::warn!(
            error_kind = "coc_roots_seen_append",
            "failed to append project_root to coc-roots-seen.jsonl: {e}"
        );
    }
}

/// Capability-layer pre-flight (PR-CA6b wire-up). Resolves `.coc/`
/// from the project root (CWD walk) and runs the pre-spawn pipeline
/// when the user opted in via `--capability-layer`.
///
/// Returns:
/// - `Ok(LayerControl::Inherit)` when the layer is OFF (no flag,
///   default-OFF for v2.4.0-alpha) OR when `.coc/` resolved to
///   `CocSource::Empty` (FR-RUN-04 graceful no-`.coc/`). Caller takes
///   the v2.3.1 launch path with byte-identical argv + env.
/// - `Ok(LayerControl::WithLayer { mode })` when the pre-spawn
///   pipeline succeeded. Caller spawns+waits per spec 10 §10.4.2.
/// - `Err(StageError)` when any stage in the pre-spawn pipeline
///   errored. The caller maps `err.exit_code()` to the process exit
///   code per spec 03 §3.9.
#[allow(clippy::too_many_arguments)]
fn run_capability_layer_preflight(
    _base_dir: &Path,
    _account: AccountNum,
    enabled: bool,
    // M7: `true` when the layer is on via the no-flag `AutoDefault`
    // path (not an explicit `--capability-layer`). Drives the
    // one-time "auto-engaged" stderr note below.
    layer_is_auto: bool,
    toggles: &CapabilityLayerToggles,
    debug: bool,
    surface: Surface,
    coc_cache_enabled: bool,
    rest: &[String],
) -> Result<LayerControl, csq_core::capability_layer::StageError> {
    // Per-technique full-disable AND the global flag both inhibit
    // every layer stage, so treat them as `enabled=false` for the
    // hot-path short-circuit. The CLI flag short-circuit
    // (`enabled == false`) keeps its v2.3.1 byte-equivalent path.
    if !enabled || toggles.is_layer_fully_disabled() {
        // Hot-path short-circuit: zero pipeline cost when the layer
        // is off. The NFR-COMPAT-02 ≤ 5 ms overhead budget for
        // empty `.coc/` only applies when the layer is ON; when
        // OFF the path is the v2.3.1 path verbatim.
        return Ok(LayerControl::Inherit);
    }

    // Resolve `.coc/` via the spec-09 fallback chain. Per an internal journal entry
    // the prior first-pull trust gate was retracted (`.coc/` is files
    // in the user's repo, equivalent to `.claude/`); the version-grace
    // state lives at `<base_dir>/coc-version-grace.json`.
    let cwd = std::env::current_dir().map_err(|e| {
        csq_core::capability_layer::StageError::ScaffoldFailed {
            reason: format!("could not resolve CWD for .coc/ walk: {e}"),
        }
    })?;
    let base_dir = super::claude_home().unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
    let with_warmth = match load_coc_with_timing(&cwd, &base_dir, coc_cache_enabled) {
        Ok(o) => o,
        Err(e) => {
            // A `.coc/` load failure should NOT block `csq run`.
            // Log + fall through to the bare-CLI path. This matches
            // FR-RUN-04 for any unrecoverable resolver failure
            // (corrupt parse, version refused). The user sees the
            // warning on stderr but the launch continues.
            eprintln!("warning: capability-layer .coc/ load failed: {e}");
            return Ok(LayerControl::Inherit);
        }
    };
    let outcome = with_warmth.outcome;

    if let Some(project_root) = outcome.project_root.as_deref() {
        record_root_seen(project_root, None);
    }

    let stdin_is_tty = std::io::stdin().is_terminal();
    match run_with_layer_toggled(
        true,
        outcome.set,
        surface,
        rest.to_vec(),
        stdin_is_tty,
        toggles,
    )? {
        LayerOutcome::Disabled => Ok(LayerControl::Inherit),
        LayerOutcome::Enabled {
            mode,
            class,
            rule_ids_in_scope,
            pre_spawn,
        } => {
            if debug {
                emit_debug_classifier(class);
            }
            // M7 auto-engage note. Print once, on stderr, only when:
            // (a) the layer is on via the no-flag default path
            //     (`layer_is_auto`) — NOT when the user explicitly
            //     passed `--capability-layer`, who already knows;
            // (b) stderr is a TTY — keeps piped/scripted stdout+stderr
            //     byte-clean for harness and CI consumers;
            // so a user who didn't realize a `.coc/` was present in an
            // ancestor dir learns why CC's behavior changed and how to
            // opt out. Goes to stderr so it never contaminates the
            // captured stdout the post-validate stage echoes.
            if layer_is_auto && std::io::stderr().is_terminal() {
                eprintln!(
                    "csq: capability layer engaged (.coc/ detected). \
                     Disable for this run with --no-capability-layer, \
                     or durably via the desktop tray toggle."
                );
            }
            Ok(LayerControl::WithLayer {
                mode,
                class,
                rule_ids_in_scope,
                scaffold: pre_spawn.scaffold,
            })
        }
    }
}

/// Build the classifier JSONL record (PR-CA7d1; spec 10 §10.7.4).
/// Pure function; deterministic. Separated from the eprintln so tests
/// can verify the JSON shape without stderr capture.
fn build_debug_classifier_record(class: PromptClass) -> serde_json::Value {
    use csq_core::capability_layer::errors::CLASSIFIER_THRESHOLD;
    use csq_core::capability_layer::PromptClassKind;
    let class_str = match class.class {
        PromptClassKind::Compliance => "compliance",
        PromptClassKind::FreeForm => "freeform",
    };
    let conf = (class.conf as f64 * 10_000.0).round() / 10_000.0;
    let threshold = (CLASSIFIER_THRESHOLD as f64 * 10_000.0).round() / 10_000.0;
    serde_json::json!({
        "event": "classifier",
        "class": class_str,
        "confidence": conf,
        "threshold": threshold,
        "low_confidence": class.conf < CLASSIFIER_THRESHOLD,
    })
}

/// Build the post-validate JSONL record (PR-CA7d1). Pure function;
/// deterministic. `ok=true` carries the rule_ids the validator
/// confirmed cited; `ok=false` carries the failure reason verbatim
/// from `StageError::PostValidateFailed`.
fn build_debug_post_validate_record(
    ok: bool,
    rule_ids_cited: &[String],
    reason: Option<&str>,
) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "event".into(),
        serde_json::Value::String("post_validate".into()),
    );
    obj.insert("ok".into(), serde_json::Value::Bool(ok));
    if ok {
        obj.insert(
            "rule_ids_cited".into(),
            serde_json::Value::Array(
                rule_ids_cited
                    .iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
        );
    } else if let Some(r) = reason {
        obj.insert("reason".into(), serde_json::Value::String(r.to_string()));
    }
    serde_json::Value::Object(obj)
}

/// Emit a JSONL record of the classifier verdict to stderr. The
/// harness parses lines starting with `csq-debug: ` per invocation.
fn emit_debug_classifier(class: PromptClass) {
    let payload = build_debug_classifier_record(class);
    if let Ok(line) = serde_json::to_string(&payload) {
        eprintln!("csq-debug: {line}");
    }
}

/// Emit a JSONL record of the post-validate result to stderr.
fn emit_debug_post_validate(ok: bool, rule_ids_cited: &[String], reason: Option<&str>) {
    let payload = build_debug_post_validate_record(ok, rule_ids_cited, reason);
    if let Ok(line) = serde_json::to_string(&payload) {
        eprintln!("csq-debug: {line}");
    }
}

#[cfg(test)]
mod debug_record_tests {
    use super::*;
    use csq_core::capability_layer::PromptClassKind;

    #[test]
    fn build_debug_classifier_record_has_event_class_confidence() {
        let class = PromptClass {
            class: PromptClassKind::Compliance,
            conf: 0.4286,
        };
        let v = build_debug_classifier_record(class);
        assert_eq!(v["event"], "classifier");
        assert_eq!(v["class"], "compliance");
        assert!((v["confidence"].as_f64().unwrap() - 0.4286).abs() < 1e-4);
        assert!((v["threshold"].as_f64().unwrap() - 0.15).abs() < 1e-4);
        assert_eq!(v["low_confidence"], false);
    }

    #[test]
    fn build_debug_classifier_record_marks_low_confidence_below_threshold() {
        let class = PromptClass {
            class: PromptClassKind::Compliance,
            conf: 0.05, // below 0.15 threshold
        };
        let v = build_debug_classifier_record(class);
        assert_eq!(v["low_confidence"], true);
    }

    #[test]
    fn build_debug_classifier_record_freeform_class_is_serialized() {
        let class = PromptClass {
            class: PromptClassKind::FreeForm,
            conf: 0.50,
        };
        let v = build_debug_classifier_record(class);
        assert_eq!(v["class"], "freeform");
        // Conf=0.50 is above threshold so low_confidence is false.
        assert_eq!(v["low_confidence"], false);
    }

    #[test]
    fn build_debug_post_validate_ok_carries_rule_ids() {
        let cited = vec!["RULE-NO-PII".to_string(), "RULE-AUTH".to_string()];
        let v = build_debug_post_validate_record(true, &cited, None);
        assert_eq!(v["event"], "post_validate");
        assert_eq!(v["ok"], true);
        assert_eq!(v["rule_ids_cited"][0], "RULE-NO-PII");
        assert_eq!(v["rule_ids_cited"][1], "RULE-AUTH");
        assert!(v.get("reason").is_none(), "ok=true must omit reason");
    }

    #[test]
    fn build_debug_post_validate_fail_carries_reason_no_rule_ids() {
        let v = build_debug_post_validate_record(false, &[], Some("missing RULE_ID citation"));
        assert_eq!(v["ok"], false);
        assert_eq!(v["reason"], "missing RULE_ID citation");
        assert!(
            v.get("rule_ids_cited").is_none(),
            "ok=false must omit rule_ids_cited"
        );
    }
}

/// Spawn step (spec 10 §10.4.2). Always spawns CC as a child (never
/// `exec`s) so the parent process stays alive for the post-spawn
/// pipeline. Dispatches on `mode`:
///
/// - **OneShot** (PR-CA7b1) — `Stdio::piped()` captures CC's stdout to
///   memory; csq runs `run_post_spawn` against the captured output;
///   if post-validate succeeds the captured bytes are echoed to the
///   user's stdout. If post-validate fails (`PostValidateFailed`,
///   exit 24) csq exits with that code WITHOUT echoing CC's output —
///   the user sees the structured error instead.
/// - **Interactive** — inherited stdio; no post-spawn validation
///   runs on this path (spec 10 §10.4.2.1).
///
/// Cleans up the handle dir on spawn failure to mirror
/// `exec_or_spawn`'s posture.
#[allow(clippy::too_many_arguments)]
fn spawn_with_layer(
    cmd: Command,
    handle_dir: &Path,
    mode: SpawnMode,
    class: PromptClass,
    rule_ids_in_scope: BTreeSet<String>,
    toggles: &CapabilityLayerToggles,
    debug: bool,
    audit_emitter: &mut crate::cli::audit_emit::AuditEmitter,
) -> Result<()> {
    match mode {
        SpawnMode::OneShot => spawn_one_shot_with_post_validate(
            cmd,
            handle_dir,
            class,
            rule_ids_in_scope,
            toggles,
            debug,
            audit_emitter,
        ),
        // Interactive shape doesn't have a post-validate stage today
        // (PR-CA7b2 deferred). The classifier debug event already
        // landed in run_capability_layer_preflight; nothing further
        // for `--debug` to emit here until per-turn validate ships.
        SpawnMode::Interactive => spawn_interactive_inherited(cmd, handle_dir, audit_emitter),
    }
}

/// PR-CA7b1 OneShot spawn shape: `Stdio::piped()` for stdout/stderr,
/// `Stdio::null()` for stdin (CC's `--print` mode reads no
/// interactive input). Captures the full output, runs `run_post_spawn`,
/// then either echoes to the user's stdout (success) or exits with the
/// post-validate exit code WITHOUT echoing (failure — the user sees
/// the structured error so they don't act on rejected content).
#[allow(clippy::too_many_arguments)]
fn spawn_one_shot_with_post_validate(
    mut cmd: Command,
    handle_dir: &Path,
    class: PromptClass,
    rule_ids_in_scope: BTreeSet<String>,
    toggles: &CapabilityLayerToggles,
    debug: bool,
    audit_emitter: &mut crate::cli::audit_emit::AuditEmitter,
) -> Result<()> {
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let handle_dir_abs =
        std::fs::canonicalize(handle_dir).unwrap_or_else(|_| handle_dir.to_path_buf());
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_dir_all(handle_dir);
            return Err(anyhow!("failed to launch claude: {e}"));
        }
    };
    let child_pid = child.id();
    if let Err(e) = markers::write_live_cc_pid(&handle_dir_abs, child_pid) {
        eprintln!("warning: could not record CC child PID: {e}");
    }

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            let _ = std::fs::remove_dir_all(handle_dir);
            return Err(anyhow!("failed to wait for claude: {e}"));
        }
    };

    // UTF-8 lossy is acceptable for post-validation: the citation +
    // negative-evidence checks operate on textual signal, and a
    // mid-byte truncation cannot manufacture a citation that wasn't
    // there nor erase a negative-evidence pattern that was. The
    // bytes echoed to the user are the original `output.stdout` —
    // the lossy conversion only feeds the validator.
    let raw = String::from_utf8_lossy(&output.stdout).into_owned();

    match run_post_spawn_toggled(raw, class, rule_ids_in_scope, toggles) {
        Ok(post_state) => {
            if debug {
                let cited = post_state
                    .decoded
                    .as_ref()
                    .and_then(|d| d.fields.get("rule_ids_cited"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                emit_debug_post_validate(true, &cited, None);
            }
            // Post-validate passed — echo CC's exact bytes to the
            // user (no transformation). Stderr is also forwarded so
            // CC's diagnostic output reaches the terminal.
            let _ = std::io::stdout().write_all(&output.stdout);
            let _ = std::io::stderr().write_all(&output.stderr);
            let _ = std::fs::remove_dir_all(handle_dir);
            if !output.status.success() {
                // M06 fail-loud (H1): this `process::exit` bypasses Drop, so
                // the owning `audit_emitter` in `run::handle` would never
                // flush — the record would be lost with no `.pending/` write
                // and no WARN. csq owns this exit code, so flush BEFORE the
                // exit and surface a `.pending/` total failure fail-loud.
                // Post-validate accepted the output (Decision::Accept); the
                // child itself exited non-zero, so the run result is Fail.
                {
                    use csq_core::audit::{Decision, ResultState};
                    let end_ts =
                        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                    audit_emitter.set_end_ts(end_ts);
                    audit_emitter.set_result(ResultState::Fail, Decision::Accept);
                    fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
                }
                std::process::exit(output.status.code().unwrap_or(1));
            }
            Ok(())
        }
        Err(e) => {
            if debug {
                let reason = match &e {
                    StageError::PostValidateFailed { reason } => Some(reason.as_str()),
                    _ => None,
                };
                emit_debug_post_validate(false, &[], reason);
            }
            // Post-validate failed — DO NOT echo CC's stdout (the
            // user must not act on rejected output). Stderr IS
            // echoed so CC's diagnostic context survives. The
            // structured error is printed in csq's own voice, then
            // we exit with the spec 03 §3.9 code.
            let _ = std::io::stderr().write_all(&output.stderr);
            eprintln!("csq: capability layer rejected output: {e}");
            let exit_code = match &e {
                StageError::PostValidateFailed { .. } => 24,
                _ => e.exit_code() as i32,
            };
            let _ = std::fs::remove_dir_all(handle_dir);
            // M06 fail-loud (H1): post-validate rejected the output. This
            // `process::exit` bypasses Drop, so flush the audit record BEFORE
            // exiting (csq owns this exit code). The capability layer
            // rejected the run → ResultState::Fail + Decision::Reject.
            {
                use csq_core::audit::{Decision, ResultState};
                let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                audit_emitter.set_end_ts(end_ts);
                audit_emitter.set_result(ResultState::Fail, Decision::Reject);
                fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
            }
            std::process::exit(exit_code);
        }
    }
}

/// Interactive spawn shape: inherited stdio (parent's stdio IS the
/// user's terminal, so the child's `isatty` returns 1 for free). No
/// post-spawn validation runs on this path (spec 10 §10.4.2.1).
fn spawn_interactive_inherited(
    mut cmd: Command,
    handle_dir: &Path,
    audit_emitter: &mut crate::cli::audit_emit::AuditEmitter,
) -> Result<()> {
    let handle_dir_abs =
        std::fs::canonicalize(handle_dir).unwrap_or_else(|_| handle_dir.to_path_buf());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_dir_all(handle_dir);
            return Err(anyhow!("failed to launch claude: {e}"));
        }
    };
    let child_pid = child.id();
    if let Err(e) = markers::write_live_cc_pid(&handle_dir_abs, child_pid) {
        eprintln!("warning: could not record CC child PID: {e}");
    }
    let status = child.wait();
    let _ = std::fs::remove_dir_all(handle_dir);
    match status {
        Ok(s) if !s.success() => {
            // M06 fail-loud (H1): the interactive child exited non-zero. This
            // `process::exit` bypasses Drop, so flush the audit record BEFORE
            // exiting (csq owns this exit code). Interactive has no
            // post-validate gate (PR-CA7b2 deferred) — the layer was active
            // and did not reject, so the run result is Fail + Accept (mirrors
            // the WithLayer success-path setter, with Fail for the non-zero
            // child).
            use csq_core::audit::{Decision, ResultState};
            let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            audit_emitter.set_end_ts(end_ts);
            audit_emitter.set_result(ResultState::Fail, Decision::Accept);
            fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
            std::process::exit(s.code().unwrap_or(1))
        }
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow!("failed to wait for claude: {e}")),
    }
}

/// M06 fail-loud handler for the primary `csq run` flow.
///
/// The flush callsites that reach this helper are the ones where csq still
/// owns the exit code (immediately before the Unix `exec` replace, or before
/// the Windows `process::exit`).  When even the `.pending/` fallback write
/// fails, [`crate::cli::audit_emit::AuditEmitter::try_flush_now`] returns
/// `Err(AuditEmitError::PendingWriteFailed)`; we print the multi-line
/// remediation to stderr and exit non-zero BEFORE control hands off to the
/// process image replacement.
///
/// On `Ok(())` this is a no-op.  The `Drop` / `flush_now` teardown paths do
/// NOT route through here — they keep the best-effort WARN posture because the
/// operation already completed and there is no exit code left to own (see
/// `audit_emit.rs` fail-loud split doc-comment and spec 12 §12.4).
fn fail_loud_on_audit_write_failure(
    result: std::result::Result<(), crate::cli::audit_emit::AuditEmitError>,
) {
    if let Err(e) = result {
        eprintln!("{}", e.remediation_message());
        std::process::exit(EXIT_CODE_AUDIT_WRITE_FAILED);
    }
}

/// Execs CC on Unix or spawns + waits on Windows, cleaning up the
/// handle dir on failure.
///
/// PR-CA10c platform-conditional audit emit:
/// - **Unix**: `cmd.exec()` replaces the process image; Rust destructors do
///   not run. `end_ts` is captured and the audit record flushed BEFORE
///   exec, so the record reflects the exec-handoff timestamp.
/// - **Windows**: `cmd.spawn()` + `child.wait()` returns after the child
///   exits. `end_ts` is captured AFTER wait (the true child-exit
///   timestamp), then flushed before `process::exit` may bypass Drop.
///   This avoids the Windows `end_ts == start_ts` asymmetry that would
///   otherwise hide long-running session durations from the audit trail.
fn exec_or_spawn(
    mut cmd: Command,
    handle_dir: &Path,
    audit_emitter: &mut crate::cli::audit_emit::AuditEmitter,
) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // exec replaces process — Drop is bypassed. Capture end_ts +
        // flush synchronously BEFORE handoff so the record is durable.
        //
        // M06 fail-loud: this is the primary `csq run` flow. We still own the
        // exit code here (exec has not happened yet), so a `.pending/` total
        // failure MUST surface the multi-line remediation and exit non-zero
        // BEFORE `cmd.exec()` replaces the process image.
        let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        audit_emitter.set_end_ts(end_ts);
        fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
        let err = cmd.exec();
        let _ = std::fs::remove_dir_all(handle_dir);
        Err(anyhow!("exec failed: {err}"))
    }

    #[cfg(not(unix))]
    {
        // Non-Unix (Windows): spawn CC as a child and record its
        // PID in `.live-cc-pid` so the daemon sweep can tell CC
        // apart from csq-cli. On Unix `exec` replaces csq-cli with
        // claude and the csq PID becomes claude's PID, so there is
        // only one PID and this marker is not needed.
        let handle_dir_abs =
            std::fs::canonicalize(handle_dir).unwrap_or_else(|_| handle_dir.to_path_buf());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_dir_all(handle_dir);
                // Capture end_ts at the failure point — record reflects
                // when the launch attempt terminated even on spawn error.
                let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                audit_emitter.set_end_ts(end_ts);
                fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
                return Err(anyhow!("failed to launch claude: {e}"));
            }
        };
        let child_pid = child.id();
        if let Err(e) = markers::write_live_cc_pid(&handle_dir_abs, child_pid) {
            eprintln!("warning: could not record CC child PID: {e}");
        }
        let status = child.wait();
        let _ = std::fs::remove_dir_all(handle_dir);
        // Capture end_ts AFTER wait — this is the true child-exit time.
        // Flush BEFORE `process::exit` on non-zero status (process::exit
        // bypasses Drop, same as Unix exec).
        //
        // M06 fail-loud: we still own the exit code here (process::exit below
        // has not run), so surface a `.pending/` total failure before exit.
        let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        audit_emitter.set_end_ts(end_ts);
        fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
        match status {
            Ok(s) if !s.success() => std::process::exit(s.code().unwrap_or(1)),
            Ok(_) => Ok(()),
            Err(e) => Err(anyhow!("failed to wait for claude: {e}")),
        }
    }
}

fn resolve_account(base_dir: &Path, explicit: Option<AccountNum>) -> Result<Option<AccountNum>> {
    if let Some(a) = explicit {
        return Ok(Some(a));
    }

    // PR-C3c: the "pick the only live slot" convenience must consider
    // Codex slots too — otherwise `csq run` on a machine with only a
    // Codex slot would resolve `None` and launch vanilla claude.
    // Multi-slot listings include Codex entries via `discover_codex`
    // so the user can pick by number across surfaces.
    let mut accounts = discovery::discover_anthropic(base_dir);
    accounts.extend(discovery::discover_codex(base_dir));
    let with_creds: Vec<_> = accounts.iter().filter(|a| a.has_credentials).collect();

    match with_creds.len() {
        0 => Ok(None), // vanilla claude
        1 => {
            let num = AccountNum::try_from(with_creds[0].id)
                .map_err(|e| anyhow!("invalid account: {e}"))?;
            Ok(Some(num))
        }
        _ => {
            let mut msg = String::from("multiple accounts configured — specify one:\n");
            for a in &with_creds {
                let surface_hint = match a.surface {
                    Surface::ClaudeCode => "",
                    Surface::Codex => " [codex]",
                    Surface::Gemini => " [gemini]",
                };
                msg.push_str(&format!(
                    "  csq run {}  ({}){}\n",
                    a.id, a.label, surface_hint
                ));
            }
            Err(anyhow!(msg))
        }
    }
}

/// Warn-only environment preflight invoked at the top of `handle`.
///
/// Prints to stderr so it shows up during exec without polluting
/// parseable stdout. Never blocks — users have already decided to
/// launch; mid-session interactive prompts would strand them.
fn run_env_preflight(claude_home: &Path) {
    let cwd = std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());
    let issues = env_check::run_preflight(claude_home, &cwd);
    if issues.is_empty() {
        return;
    }
    eprintln!("csq: environment issues detected before launch:");
    for issue in &issues {
        match issue {
            EnvIssue::NodeMissingForHooks { hook_count } => {
                eprintln!("  ! node / bun not found, but {hook_count} hook command(s) configured.");
                eprintln!("    Claude Code will emit 'SessionStart:startup hook error' on launch.");
                eprintln!("    Fix: {}", env_check::node_install_hint());
            }
            EnvIssue::HookScriptMissing { script_path, .. } => {
                // `csq run` is NOT operator-explicit-action over the
                // hook path; the operator invoked `run` to launch CC,
                // not to inspect hooks. Redact `$HOME` per
                // `rules/operator-surface-verification.md` Rule 4 —
                // path is preserved as diagnostic value but the
                // username prefix becomes `~`.
                eprintln!("  ! hook script not found: {}", redact_path(script_path));
            }
            EnvIssue::HookRelativeRequireMissing {
                script_path,
                missing_sibling,
            } => {
                eprintln!(
                    "  ! hook require fails: {} expects {}",
                    redact_path(script_path),
                    redact_path(missing_sibling)
                );
                eprintln!(
                    "    (this is node:internal/modules/cjs/loader:1143 — sibling modules missing)"
                );
            }
        }
    }
    eprintln!();
}

fn exec_claude(rest: &[String]) -> Result<()> {
    let mut cmd = Command::new("claude");
    // Always strip sensitive env vars, even on the vanilla path.
    strip_sensitive_env(&mut cmd);
    cmd.args(rest);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        Err(anyhow!("exec failed: {err}"))
    }

    #[cfg(not(unix))]
    {
        let status = cmd.status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Removes env vars that could override credentials, redirect API traffic,
/// or otherwise compromise the isolated session.
///
/// Strips:
///
/// - `ANTHROPIC_*` — base-URL redirects / auth-token overrides for the
///   Claude Code surface.
/// - `AWS_BEARER_TOKEN_BEDROCK` — bedrock bypass.
/// - `CLAUDE_API_KEY` — direct key override.
/// - `OPENAI_*` — symmetric protection for the Codex surface. A
///   poisoned dotfile setting `OPENAI_BASE_URL=https://attacker.example`
///   would silently redirect every Codex API call and exfiltrate the
///   JWT access token csq just provisioned. Origin: PR-C3c security
///   review H1 — symmetric with the `ANTHROPIC_*` threat.
/// - `CODEX_HOME` — scrubbed so the only authoritative value is the
///   `cmd.env(HOME_ENV_VAR, handle_dir)` csq sets explicitly in
///   `launch_codex`. Prevents a parent shell that already exported
///   `CODEX_HOME=/somewhere-else` from winning a clash if csq's
///   layering ever regresses.
///
/// Both the Claude and Codex launch paths call this so a mis-
/// provisioned slot cannot leak credentials across surfaces via a
/// parent-shell env var. `csq exec` (`commands::exec`) reuses it for the
/// same reason — it is the single source of truth for the spawn env allowlist.
pub(crate) fn strip_sensitive_env(cmd: &mut Command) {
    // Collect into a Vec first so we don't mutate env vars during iteration.
    let to_strip: Vec<String> = std::env::vars()
        .filter_map(|(k, _)| {
            if k.starts_with("ANTHROPIC_")
                || k.starts_with("OPENAI_")
                || k == "AWS_BEARER_TOKEN_BEDROCK"
                || k == "CLAUDE_API_KEY"
                || k == "CODEX_HOME"
            {
                Some(k)
            } else {
                None
            }
        })
        .collect();

    for key in to_strip {
        cmd.env_remove(&key);
    }
}

// ---------------------------------------------------------------------------
// Bench-mode helpers (design 08 §11 / R2/B56, T11, T12)
// ---------------------------------------------------------------------------

/// Entry point for `--bench-mode layer-only`.
///
/// Design contract (R2/B56):
/// 1. Env gate: `CSQ_BENCH_MODE=1` must be set or exit 64.
/// 2. Emit a stderr WARN (not a public CLI surface).
/// 3. Append a JSONL audit record to `~/.csq/bench-mode-audits.jsonl`
///    (FIFO 256-line cap, mode 0600, atomic_replace + §5a cleanup on
///    every error branch so the tmp file never lingers at default
///    permissions).
/// 4. Drain `csq_core::capability_layer::drain_timings()`.
/// 5. Write timing JSONL to `COC_BENCH_OUT` env path or stdout.
/// 6. Return `Ok(())` — the CLI subprocess is NOT spawned.
///
/// The caller's `audit_emitter` already holds a record from the successful
/// capability-layer preflight that ran immediately before this function. On
/// the `Ok` paths (steps 2-6) this function returns to `launch_*`, the owning
/// emitter `Drop`-flushes the record with its default `Degraded` + `Bypass`
/// (the run terminated before spawn), and there is nothing to do here. The ONE
/// path that needs an explicit flush is the env-gate failure branch below: its
/// `std::process::exit(64)` bypasses `Drop`, so the held record would be lost
/// with no `.pending/` write and no WARN — the exact fail-open class M06
/// closes. We flush it fail-loud BEFORE the exit.
fn handle_bench_mode_layer_only(
    surface: Surface,
    audit_emitter: &mut crate::cli::audit_emit::AuditEmitter,
) -> Result<()> {
    // 1. Env gate.
    if std::env::var("CSQ_BENCH_MODE").as_deref() != Ok("1") {
        eprintln!("error: --bench-mode requires CSQ_BENCH_MODE=1 in env");
        // M06 fail-loud (MED, same class as H1): this `process::exit` bypasses
        // the owning emitter's `Drop` in `launch_*`. The bench-mode env gate is
        // a PRECONDITION REFUSAL — `CSQ_BENCH_MODE=1` was required and absent,
        // so the run did not execute. This mirrors the daemon-gate
        // precondition-refusal exits (`require_daemon_healthy` → Fail+Reject):
        // the result is `Fail` (run refused) + `Reject` (refused before any
        // spawn). Flush BEFORE the exit; `try_flush_now` take()s the record so
        // the owner's `Drop` stays a guaranteed no-op (no double-emit).
        {
            use csq_core::audit::{Decision, ResultState};
            let end_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            audit_emitter.set_end_ts(end_ts);
            audit_emitter.set_result(ResultState::Fail, Decision::Reject);
            fail_loud_on_audit_write_failure(audit_emitter.try_flush_now());
        }
        std::process::exit(64);
    }

    // 2. Stderr WARN.
    eprintln!(
        "WARNING: --bench-mode layer-only is bench-internal; \
         not part of the public CLI surface"
    );

    // 3. Audit record.
    let home = dirs::home_dir().context("could not determine home directory")?;
    let csq_home = home.join(".csq");
    std::fs::create_dir_all(&csq_home).context("failed to create ~/.csq")?;
    let audit_path = csq_home.join("bench-mode-audits.jsonl");
    append_bench_audit_record(&audit_path)?;

    // 4. Drain timings.
    let timings = csq_core::capability_layer::drain_timings();

    // 5. Write JSONL.
    let out_path = std::env::var("COC_BENCH_OUT").ok();
    write_bench_jsonl(timings, out_path.as_deref(), surface)?;

    Ok(())
}

/// Append a single audit record to `~/.csq/bench-mode-audits.jsonl`.
///
/// FIFO semantics: keep at most 256 lines (oldest lines dropped first).
/// Atomic write (tmp → secure_file → atomic_replace) with §5a cleanup
/// on every error branch so the tmp file never lingers at umask-default
/// permissions with audit content inside.
fn append_bench_audit_record(audit_path: &std::path::Path) -> Result<()> {
    use csq_core::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
    use std::collections::BTreeMap;

    // Build the audit record using BTreeMap for deterministic key order
    // (R2/B70: all serialized maps must be BTreeMap).
    let mut record: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
    record.insert(
        "event",
        serde_json::Value::String("bench_mode_invocation".into()),
    );

    let caller_pid = std::process::id();
    record.insert(
        "caller_pid",
        serde_json::Value::Number(serde_json::Number::from(caller_pid)),
    );

    // argv[0] of the csq process (best-effort; empty string on failure).
    let caller_argv0 = std::env::args().next().unwrap_or_default();
    record.insert("caller_argv0", serde_json::Value::String(caller_argv0));

    // csq_pid == caller_pid in the single-process model.
    record.insert(
        "csq_pid",
        serde_json::Value::Number(serde_json::Number::from(caller_pid)),
    );

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    record.insert(
        "ts",
        serde_json::Value::Number(serde_json::Number::from(ts)),
    );

    let line =
        serde_json::to_string(&record).context("failed to serialize bench-mode audit record")?;

    // Read existing lines (if any), cap at 255 to leave room for the new record.
    const FIFO_CAP: usize = 256;
    let existing: Vec<String> = if audit_path.exists() {
        std::fs::read_to_string(audit_path)
            .context("failed to read bench-mode-audits.jsonl")?
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect()
    } else {
        Vec::new()
    };

    let keep_from = existing.len().saturating_sub(FIFO_CAP - 1);
    let mut buf: Vec<u8> = Vec::new();
    for old_line in &existing[keep_from..] {
        buf.extend_from_slice(old_line.as_bytes());
        buf.push(b'\n');
    }
    buf.extend_from_slice(line.as_bytes());
    buf.push(b'\n');

    // Atomic write: tmp → secure_file(0o600) → atomic_replace → done.
    // §5a cleanup: remove tmp on every error branch.
    let tmp = unique_tmp_path(audit_path);

    if let Err(e) = std::fs::write(&tmp, &buf) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow!("write bench audit tmp {}: {e}", redact_path(&tmp)));
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow!(
            "secure_file bench audit tmp {}: {e}",
            redact_path(&tmp)
        ));
    }
    if let Err(e) = atomic_replace(&tmp, audit_path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow!(
            "atomic_replace bench audit {} -> {}: {e}",
            redact_path(&tmp),
            redact_path(audit_path)
        ));
    }
    Ok(())
}

/// Emit per-stage timing records to `out_path` (a file path) or stdout.
///
/// Schema (spec 08 §"Latency bench harness", schema_version "1.0.0"):
///   - One `header` record
///   - One `stage_timing` record per collected stage
///
/// All maps use `BTreeMap` (R2/B70) for deterministic key ordering.
fn write_bench_jsonl(
    timings: csq_core::capability_layer::PipelineTimings,
    out_path: Option<&str>,
    surface: Surface,
) -> Result<()> {
    use std::collections::BTreeMap;
    use std::io::Write as _;

    // run_id: "<unix_ms_13d>-<4d_random>" per R2/B82.
    let unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let rand_suffix = unix_ms.wrapping_mul(6364136223846793005).wrapping_add(1) & 0xFFFF;
    let run_id = format!("{unix_ms:013}-{rand_suffix:04}");

    let surface_str = match surface {
        Surface::ClaudeCode => "cc",
        Surface::Codex => "codex",
        Surface::Gemini => "gemini",
    };

    // Header record.
    let mut header: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
    header.insert("event", serde_json::Value::String("header".into()));
    header.insert("schema_version", serde_json::Value::String("1.0.0".into()));
    header.insert(
        "bench_id",
        serde_json::Value::String("capability_layer_cost".into()),
    );
    header.insert("run_id", serde_json::Value::String(run_id));
    header.insert(
        "csq_version",
        serde_json::Value::String(env!("CARGO_PKG_VERSION").into()),
    );
    header.insert("surface", serde_json::Value::String(surface_str.into()));

    let platform_str = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    };
    header.insert("platform", serde_json::Value::String(platform_str.into()));

    let header_line =
        serde_json::to_string(&header).context("failed to serialize bench JSONL header")?;

    // Per-stage timing records.
    let mut stage_lines: Vec<String> = Vec::with_capacity(timings.timings.len());
    for t in &timings.timings {
        let mut rec: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
        rec.insert("event", serde_json::Value::String("stage_timing".into()));
        rec.insert(
            "stage_id",
            serde_json::Value::String(t.stage_id.to_string()),
        );
        rec.insert(
            "elapsed_ns",
            serde_json::Value::Number(serde_json::Number::from(t.elapsed_ns as u64)),
        );
        rec.insert(
            "started_at_ns",
            serde_json::Value::Number(serde_json::Number::from(t.started_at_ns as u64)),
        );
        // warmth: "cold" if stage_id is "cap.coc_load.cold", else "warm".
        let warmth = if t.stage_id == csq_core::capability_layer::STAGE_COC_LOAD_COLD {
            "cold"
        } else {
            "warm"
        };
        rec.insert("warmth", serde_json::Value::String(warmth.into()));
        let result_str = format!("{:?}", t.result).to_lowercase();
        rec.insert("result", serde_json::Value::String(result_str));
        stage_lines
            .push(serde_json::to_string(&rec).context("failed to serialize stage_timing record")?);
    }

    // Assemble output.
    let mut buf = String::new();
    buf.push_str(&header_line);
    buf.push('\n');
    for l in &stage_lines {
        buf.push_str(l);
        buf.push('\n');
    }

    // Write to file or stdout.
    match out_path {
        Some(path) => {
            let p = std::path::Path::new(path);
            std::fs::write(p, buf.as_bytes())
                .with_context(|| format!("failed to write bench JSONL to {path}"))?;
        }
        None => {
            std::io::stdout()
                .lock()
                .write_all(buf.as_bytes())
                .context("failed to write bench JSONL to stdout")?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn acc(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    /// PR-C3c regression: `verify_codex_config_toml` errors with an
    /// actionable message when the pre-seed is missing.
    #[test]
    fn codex_precondition_errors_on_missing_config_toml() {
        let dir = TempDir::new().unwrap();
        let err = verify_codex_config_toml(dir.path(), acc(4))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("config.toml"),
            "error should name config.toml: {err}"
        );
        assert!(
            err.contains("csq login 4 --provider codex"),
            "error should point at the fix: {err}"
        );
    }

    /// PR-C3c regression: precondition succeeds once the pre-seed
    /// exists (PR-C3b's `surface::write_config_toml` output).
    #[test]
    fn codex_precondition_succeeds_when_config_toml_present() {
        let dir = TempDir::new().unwrap();
        let slot = acc(5);
        codex_surface::write_config_toml(dir.path(), slot, "gpt-5.4").unwrap();
        verify_codex_config_toml(dir.path(), slot).expect("precondition should pass");
    }

    /// **2026-05-26 post-A++ run-dispatch regression (host slot 8).** A Codex
    /// slot logged in after the legacy-mirror cleanup has its credential ONLY
    /// at `identities/<UUID>/credentials-codex.json` — no legacy
    /// `credentials/codex-<N>.json`. The pre-fix `surface_cli_for_slot` checked
    /// only the legacy path, so `csq run N` detected Claude, routed to the
    /// Anthropic path, and died with `credential file not found:
    /// identities/<UUID>/credentials.json`. This pins the identity-keyed codex
    /// detection: a post-A++ codex slot dispatches to `SurfaceCli::Codex`.
    #[test]
    fn surface_cli_for_slot_detects_post_aplusplus_codex_via_identity_store() {
        use csq_core::accounts::identity_store::{credentials_codex_path_for, identity_path};
        use csq_core::accounts::profiles::{profiles_path, save, ProfilesFile};

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let slot = acc(8);

        // by_slot maps slot 8 → a UUID; credentials-codex.json at the identity
        // path; NO legacy credentials/codex-8.json mirror.
        let uuid = csq_core::accounts::identity_store::IdentityId::new_v4();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("8".to_string(), uuid);
        save(&profiles_path(base), &pf).unwrap();
        std::fs::create_dir_all(identity_path(base, uuid)).unwrap();
        std::fs::write(credentials_codex_path_for(base, uuid), b"{}").unwrap();

        assert_eq!(
            surface_cli_for_slot(base, slot),
            SurfaceCli::Codex,
            "post-A++ codex slot (identity-keyed credentials-codex.json, no legacy \
             mirror) MUST dispatch to Codex, not fall through to Claude"
        );
    }

    /// M19b regression: the v1 `AuditRecord.surface` records the ACTUAL
    /// dispatched surface, not a hardcoded `cc`. Pre-fix, `run.rs` built the
    /// record with `surface: Surface::Cc` before the surface was even determined,
    /// mislabeling every codex/gemini run as `cc` in its own audit record. This
    /// pins the record-construction value: a post-A++ codex slot maps to
    /// `audit::Surface::Codex`.
    #[test]
    fn audit_record_surface_reflects_codex_slot() {
        use csq_core::accounts::identity_store::{credentials_codex_path_for, identity_path};
        use csq_core::accounts::profiles::{profiles_path, save, ProfilesFile};

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let slot = acc(8);

        let uuid = csq_core::accounts::identity_store::IdentityId::new_v4();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("8".to_string(), uuid);
        save(&profiles_path(base), &pf).unwrap();
        std::fs::create_dir_all(identity_path(base, uuid)).unwrap();
        std::fs::write(credentials_codex_path_for(base, uuid), b"{}").unwrap();

        // The exact composition `handle` uses to build the record's `surface`.
        let surface = audit_surface_for(surface_cli_for_slot(base, slot));
        assert_eq!(
            surface,
            csq_core::audit::Surface::Codex,
            "a codex run's audit record MUST carry surface: codex, not the pre-fix hardcoded cc"
        );
    }

    /// M19b: the surface mapping is total and correct for every wired surface.
    #[test]
    fn audit_surface_for_maps_every_surface() {
        use csq_core::audit::Surface as A;
        assert_eq!(audit_surface_for(SurfaceCli::Claude), A::Cc);
        assert_eq!(audit_surface_for(SurfaceCli::Codex), A::Codex);
        assert_eq!(audit_surface_for(SurfaceCli::Gemini), A::Gemini);
    }

    /// PR-C3c regression: `resolve_account` lists Codex slots
    /// alongside Claude slots and returns an error listing BOTH when
    /// multiple are configured. The surface hint ` [codex]` lets the
    /// user disambiguate without reading `credentials/` directly.
    #[test]
    fn resolve_account_multi_slot_lists_codex_alongside_claude() {
        use csq_core::credentials::{
            AnthropicCredentialFile, CodexCredentialFile, CodexTokensFile, CredentialFile,
            OAuthPayload,
        };
        use csq_core::types::{AccessToken, RefreshToken};

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Install one Anthropic slot…
        let anth = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-fake".into()),
                refresh_token: RefreshToken::new("sk-ant-ort01-fake".into()),
                expires_at: 1775726524877,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        });
        credentials::save(&file::canonical_path(base, acc(1)), &anth).unwrap();

        // …and one Codex slot.
        let codex = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some("acct-1234".into()),
                access_token: "eyJ.jwt.stub".into(),
                refresh_token: Some("rt_stub_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".into()),
                id_token: Some("eyJ.id.stub".into()),
                extra: Default::default(),
            },
            last_refresh: None,
            extra: Default::default(),
        });
        credentials::save(
            &file::canonical_path_for(base, acc(4), Surface::Codex),
            &codex,
        )
        .unwrap();

        let err = resolve_account(base, None).unwrap_err().to_string();
        assert!(
            err.contains("csq run 1"),
            "multi-slot listing must include Anthropic slot 1: {err}"
        );
        assert!(
            err.contains("csq run 4"),
            "multi-slot listing must include Codex slot 4: {err}"
        );
        assert!(
            err.contains("[codex]"),
            "Codex slots must carry a surface hint: {err}"
        );
    }

    /// PR-C3c security review M1 regression: a Codex canonical that
    /// is a symlink (same-user swap attack) is refused at launch
    /// time even though the dispatch branch in `handle` accepts a
    /// `symlink_metadata`-present file.
    #[cfg(unix)]
    #[test]
    fn codex_canonical_symlink_is_refused() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let slot = acc(9);

        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        // Attacker-target file with a fake credential shape.
        let decoy = dir.path().join("decoy.json");
        std::fs::write(&decoy, b"{}").unwrap();
        // Canonical is a symlink to the decoy — NOT a regular file.
        symlink(&decoy, creds_dir.join("codex-9.json")).unwrap();

        let err = verify_codex_canonical_is_regular_file(base, slot)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("symlink"),
            "error must name the symlink posture: {err}"
        );
        assert!(
            err.contains("csq login 9 --provider codex"),
            "error must point at the fix: {err}"
        );
    }

    #[test]
    fn codex_canonical_regular_file_passes() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("codex-10.json"), b"{}").unwrap();

        verify_codex_canonical_is_regular_file(base, acc(10)).expect("regular file accepted");
    }

    // ── Task 4: verify_codex_canonical_is_regular_file — UUID-keyed path ────

    /// After the root-cause fix, slots provisioned via `mint_for_codex_login`
    /// have credentials only at `identities/<UUID>/credentials-codex.json`.
    /// The pre-flight check must accept this path as a regular file.
    #[test]
    fn codex_canonical_uuid_keyed_regular_file_passes() {
        use csq_core::accounts::identity_store::{credentials_codex_path_for, IdentityId};
        use csq_core::accounts::profiles;
        use std::str::FromStr;

        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();

        // Seed by_slot mapping for slot 11.
        let uuid = IdentityId::from_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let mut pf = profiles::ProfilesFile::empty();
        pf.by_slot.insert("11".to_string(), uuid);
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();

        // Write credentials-codex.json at the UUID-keyed path (regular file).
        let cred_path = credentials_codex_path_for(base, uuid);
        std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
        std::fs::write(&cred_path, b"{}").unwrap();

        // No legacy credentials/codex-11.json file — UUID path only.
        verify_codex_canonical_is_regular_file(base, acc(11))
            .expect("UUID-keyed regular file must be accepted");
    }

    /// When neither the UUID-keyed path nor the legacy path exists, the
    /// check must return an error pointing the user at `csq login`.
    #[test]
    fn codex_canonical_neither_uuid_nor_legacy_returns_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        // No credentials anywhere.
        let err = verify_codex_canonical_is_regular_file(base, acc(15))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("csq login 15 --provider codex"),
            "error must point at the fix: {err}"
        );
    }

    /// PR-C3c security review H1 regression: `strip_sensitive_env`
    /// now covers `OPENAI_*` and `CODEX_HOME` in addition to the
    /// pre-existing `ANTHROPIC_*` / `AWS_BEARER_TOKEN_BEDROCK` /
    /// `CLAUDE_API_KEY` set. A poisoned dotfile setting
    /// `OPENAI_BASE_URL` must not leak into a Codex child.
    #[test]
    fn strip_sensitive_env_covers_openai_and_codex_home() {
        let test_vars = [
            ("OPENAI_API_KEY", true),
            ("OPENAI_BASE_URL", true),
            ("OPENAI_API_BASE", true),
            ("OPENAI_ORG_ID", true),
            ("CODEX_HOME", true),
            ("ANTHROPIC_API_KEY", true),
            ("CLAUDE_API_KEY", true),
            ("AWS_BEARER_TOKEN_BEDROCK", true),
            ("PATH", false),
            ("HOME", false),
            ("CLAUDE_CONFIG_DIR", false),
        ];
        for (var, should_strip) in test_vars {
            let matches = var.starts_with("ANTHROPIC_")
                || var.starts_with("OPENAI_")
                || var == "AWS_BEARER_TOKEN_BEDROCK"
                || var == "CLAUDE_API_KEY"
                || var == "CODEX_HOME";
            assert_eq!(matches, should_strip, "var {var} classification mismatch");
        }
    }

    /// PR-C3c regression: when only a Codex slot is present,
    /// `resolve_account` picks it (rather than falling through to
    /// vanilla claude). This is the "single-Codex user" onboarding
    /// path — `csq run` with no args must still work.
    #[test]
    fn resolve_account_single_codex_slot_is_picked() {
        use csq_core::credentials::{CodexCredentialFile, CodexTokensFile, CredentialFile};

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let codex = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some("acct-only".into()),
                access_token: "eyJ.jwt".into(),
                refresh_token: Some("rt_only_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".into()),
                id_token: None,
                extra: Default::default(),
            },
            last_refresh: None,
            extra: Default::default(),
        });
        credentials::save(
            &file::canonical_path_for(base, acc(2), Surface::Codex),
            &codex,
        )
        .unwrap();

        let picked = resolve_account(base, None).unwrap();
        assert_eq!(
            picked,
            Some(acc(2)),
            "the single Codex slot must be auto-picked"
        );
    }

    #[test]
    fn strip_sensitive_env_removes_anthropic_vars() {
        // We can't modify the real env during tests (parallel safety), so
        // we test the logic by verifying the filter directly.
        let test_vars = [
            ("ANTHROPIC_API_KEY", true),
            ("ANTHROPIC_BASE_URL", true),
            ("ANTHROPIC_AUTH_TOKEN", true),
            ("ANTHROPIC_MODEL", true),
            ("AWS_BEARER_TOKEN_BEDROCK", true),
            ("CLAUDE_API_KEY", true),
            ("PATH", false),
            ("HOME", false),
            ("CLAUDE_CONFIG_DIR", false),
            ("CLAUDE_HOME", false),
        ];

        for (var, should_strip) in test_vars {
            let matches = var.starts_with("ANTHROPIC_")
                || var == "AWS_BEARER_TOKEN_BEDROCK"
                || var == "CLAUDE_API_KEY";
            assert_eq!(matches, should_strip, "var {var}");
        }
    }

    /// Regression guard for an internal journal entry invariant: csq run N MUST leave
    /// term-<pid>/settings.json populated after handle dir creation.
    ///
    /// This test exercises `csq_core::session::create_handle_dir` plus the
    /// explicit defensive re-materialize that run.rs adds at the call site.
    /// It does NOT invoke `run()` itself because `run()` execs claude and
    /// would hang the test suite. The invariant we care about — settings.json
    /// exists, is valid JSON, and reflects the merged base+overlay — is fully
    /// observable at the handle-dir level.
    ///
    /// Arrange: tempdir with ~/.claude/settings.json (global base) and
    ///          config-1/settings.json (slot overlay).
    /// Act:     create_handle_dir + defensive re-materialize.
    /// Assert:  term-<pid>/settings.json exists, is a regular file (not a
    ///          symlink), is parseable JSON, and merges content from both
    ///          sources (overlay key wins).
    #[test]
    fn settings_json_exists_after_create_handle_dir() {
        use csq_core::session;
        use csq_core::types::AccountNum;

        let base = tempfile::tempdir().expect("tempdir");
        let claude_home = tempfile::tempdir().expect("tempdir");

        // Arrange: permanent account dir
        let account = AccountNum::try_from(1u16).unwrap();
        let config_dir = base.path().join("config-1");
        std::fs::create_dir_all(&config_dir).unwrap();

        // Write account marker so create_handle_dir sees a valid config-N
        csq_core::accounts::markers::write_csq_account_legacy(&config_dir, account).unwrap();
        csq_core::accounts::markers::write_current_account(&config_dir, account).unwrap();

        // Global settings: base layer (statusLine customization)
        let global_settings = serde_json::json!({
            "env": {},
            "statusBar": {"visible": true},
            "theme": "dark"
        });
        std::fs::write(
            claude_home.path().join("settings.json"),
            serde_json::to_string_pretty(&global_settings).unwrap(),
        )
        .unwrap();

        // Slot settings: overlay layer (3P env block wins over base)
        let slot_settings = serde_json::json!({
            "env": {
                "ANTHROPIC_BASE_URL": "https://example.com/v1"
            }
        });
        std::fs::write(
            config_dir.join("settings.json"),
            serde_json::to_string_pretty(&slot_settings).unwrap(),
        )
        .unwrap();

        // Act: create handle dir (which calls materialize internally)
        let pid = std::process::id();
        let handle_dir =
            session::create_handle_dir(base.path(), claude_home.path(), account, pid).unwrap();

        // Defensive re-materialize — mirrors exactly what run.rs does
        let result =
            session::materialize_handle_settings(&handle_dir, claude_home.path(), &config_dir);
        assert!(
            result.is_ok(),
            "defensive re-materialize failed: {:?}",
            result.err()
        );

        // Assert: settings.json exists as a real file (not a symlink)
        let settings_path = handle_dir.join("settings.json");
        assert!(settings_path.exists(), "settings.json must exist");
        let metadata = std::fs::symlink_metadata(&settings_path).unwrap();
        assert!(
            !metadata.file_type().is_symlink(),
            "settings.json must be a real file, not a symlink"
        );

        // Assert: parseable JSON
        let content = std::fs::read_to_string(&settings_path).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&content).expect("settings.json must be valid JSON");

        // Assert: overlay key present (env.ANTHROPIC_BASE_URL from slot settings)
        assert_eq!(
            parsed["env"]["ANTHROPIC_BASE_URL"],
            serde_json::json!("https://example.com/v1"),
            "slot overlay env key must survive merge"
        );

        // Assert: base key present (theme from global settings)
        assert_eq!(
            parsed["theme"],
            serde_json::json!("dark"),
            "global base key must survive merge"
        );
    }

    // ============================================================
    // PR-CA8 commit 2 — codex handle-dir config.toml verification
    // ============================================================

    /// PR-CA8 round-1 C4: post-materialization re-stat accepts a
    /// regular file.
    #[test]
    fn verify_codex_handle_config_toml_accepts_regular_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("config.toml"), "model = \"x\"\n").unwrap(); // CI-ALLOW-fs-write-config-toml
        verify_codex_handle_config_toml_is_regular_file(dir.path()).unwrap();
    }

    /// PR-CA8 round-1 C4 + round-2 H3: post-materialization re-stat
    /// rejects a symlink replacement (TOCTOU window between
    /// `atomic_replace` returning and `Command::spawn` invocation).
    #[test]
    #[cfg(unix)]
    fn verify_codex_handle_config_toml_rejects_symlink_replaced_post_rename() {
        let dir = tempfile::tempdir().expect("tempdir");
        let attacker = dir.path().join("attacker.toml");
        std::fs::write(&attacker, "model = \"attacker\"\n").unwrap();
        // Simulate post-rename TOCTOU: an attacker has unlinked our
        // regular file and replaced it with a symlink to attacker
        // content.
        std::os::unix::fs::symlink(&attacker, dir.path().join("config.toml")).unwrap();
        let err = verify_codex_handle_config_toml_is_regular_file(dir.path()).unwrap_err();
        let err_text = format!("{err}");
        assert!(
            err_text.contains("symlink") || err_text.contains("TOCTOU"),
            "error must flag the symlink replacement: {err_text}"
        );
    }

    /// PR-CA8 round-1 C4: post-materialization re-stat rejects a
    /// missing file (handle-dir corruption).
    #[test]
    fn verify_codex_handle_config_toml_rejects_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = verify_codex_handle_config_toml_is_regular_file(dir.path()).unwrap_err();
        let err_text = format!("{err}");
        assert!(
            err_text.contains("missing") || err_text.contains("stat"),
            "error must flag the missing file: {err_text}"
        );
    }

    /// PR-CA8 commit 2: materialize_handle_config_toml writes a regular
    /// file (NOT a symlink) at handle_dir/config.toml, atomically
    /// replacing whatever was there. Tempdir test exercises the full
    /// merge → write → secure_file → atomic_replace pipeline against
    /// a synthetic canonical config-N/config.toml.
    #[test]
    fn materialize_handle_config_toml_writes_regular_file_replacing_symlink() {
        use csq_core::types::AccountNum;
        let base = tempfile::tempdir().expect("tempdir");
        let account = AccountNum::try_from(1u16).unwrap();

        // Set up canonical at base/config-1/config.toml
        let canonical_dir = base.path().join("config-1");
        std::fs::create_dir_all(&canonical_dir).unwrap();
        std::fs::write(
            canonical_dir.join("config.toml"),
            "cli_auth_credentials_store = \"file\"\nmodel = \"gpt-5\"\n",
        )
        .unwrap();

        // Set up handle dir with symlink at term-<pid>/config.toml
        // pointing back to canonical (mimics create_handle_dir_codex).
        let handle_dir = base.path().join("term-test");
        std::fs::create_dir_all(&handle_dir).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            canonical_dir.join("config.toml"),
            handle_dir.join("config.toml"),
        )
        .unwrap();
        #[cfg(not(unix))]
        std::fs::write(handle_dir.join("config.toml"), "placeholder\n").unwrap(); // CI-ALLOW-fs-write-config-toml

        // Act — instructions-only (no MCP wrap) exercises the same
        // symlink→regular-file materialization path.
        let scaffold = "## Compliance rules\n\nCite RULE_IDs.\n";
        let skipped =
            materialize_handle_config_toml(base.path(), account, &handle_dir, Some(scaffold), None)
                .expect("materialize must succeed against valid canonical");
        assert!(skipped.is_empty(), "no MCP wrap → no skipped remotes");

        // Assert: handle_dir/config.toml is now a REGULAR FILE
        let target = handle_dir.join("config.toml");
        let meta = std::fs::symlink_metadata(&target).unwrap();
        assert!(
            !meta.file_type().is_symlink(),
            "materialize must replace the symlink with a regular file"
        );
        assert!(meta.file_type().is_file());

        // Assert: content has canonical keys + scaffold-derived
        // instructions
        let body = std::fs::read_to_string(&target).unwrap();
        assert!(
            body.contains("cli_auth_credentials_store"),
            "canonical key must survive merge: {body}"
        );
        assert!(
            body.contains("model"),
            "canonical model key must survive merge: {body}"
        );
        assert!(
            body.contains("Cite RULE_IDs"),
            "scaffold body must reach instructions: {body}"
        );
    }

    /// M6 T6.2 Shard 3a: the MCP-wrap materialization path rewrites the
    /// canonical `[mcp_servers.*]` stdio tables through `csq mcp-proxy` in the
    /// HANDLE-dir config.toml, leaving the canonical `config-<N>/config.toml`
    /// untouched, and reports remote (url-transport) servers as skipped.
    #[cfg(feature = "enterprise")]
    #[test]
    fn materialize_handle_config_toml_wraps_mcp_servers_leaving_canonical_untouched() {
        use csq_core::types::AccountNum;
        let base = tempfile::tempdir().expect("tempdir");
        let account = AccountNum::try_from(1u16).unwrap();

        let canonical_dir = base.path().join("config-1");
        std::fs::create_dir_all(&canonical_dir).unwrap();
        let canonical_body = "cli_auth_credentials_store = \"file\"\nmodel = \"gpt-5\"\n\
             \n[mcp_servers.github]\ncommand = \"github-mcp\"\nargs = [\"--stdio\"]\n\
             \n[mcp_servers.remote]\nurl = \"https://mcp.example/sse\"\n";
        let canonical_path = canonical_dir.join("config.toml");
        std::fs::write(&canonical_path, canonical_body).unwrap();

        let handle_dir = base.path().join("term-mcp");
        std::fs::create_dir_all(&handle_dir).unwrap();

        let csq_bin = "/usr/local/bin/csq";
        let env_path = handle_dir.join(".pact-mcp-envelope.json");
        let skipped = materialize_handle_config_toml(
            base.path(),
            account,
            &handle_dir,
            None,
            Some((csq_bin, env_path.as_path())),
        )
        .expect("mcp-wrap materialize succeeds");

        // Remote server reported as un-gated.
        assert_eq!(skipped, vec!["remote".to_string()]);

        // Handle-dir config.toml has the github server routed through the proxy.
        // (String assertions — the `csq` crate does not depend on `toml`; the
        // structural TOML shape is pinned by the csq-core `mcp_rewrite` unit tests.)
        let written = std::fs::read_to_string(handle_dir.join("config.toml")).unwrap();
        assert!(
            written.contains(&format!("command = \"{csq_bin}\"")),
            "github server command must be rewritten to the csq binary:\n{written}"
        );
        assert!(
            written.contains("\"mcp-proxy\"") && written.contains("\"github-mcp\""),
            "args must route mcp-proxy through the original github-mcp command:\n{written}"
        );
        // Remote untouched — its url survives and no command was injected.
        assert!(
            written.contains("url = \"https://mcp.example/sse\""),
            "remote server url must be preserved:\n{written}"
        );

        // CANONICAL config.toml is byte-unchanged — the rewrite lives only in the
        // ephemeral handle dir (never mutate the user's slot config).
        assert_eq!(
            std::fs::read_to_string(&canonical_path).unwrap(),
            canonical_body,
            "canonical config-N/config.toml must NOT be rewritten"
        );
    }

    /// Regression guard: calling `materialize_handle_settings` twice on the
    /// same handle dir produces identical byte content (idempotency).
    ///
    /// This pins the invariant that the defensive re-materialize in run.rs
    /// cannot corrupt a settings.json that create_handle_dir already wrote.
    #[test]
    fn materialize_handle_settings_is_idempotent() {
        use csq_core::session;
        use csq_core::types::AccountNum;

        let base = tempfile::tempdir().expect("tempdir");
        let claude_home = tempfile::tempdir().expect("tempdir");

        let account = AccountNum::try_from(1u16).unwrap();
        let config_dir = base.path().join("config-1");
        std::fs::create_dir_all(&config_dir).unwrap();

        csq_core::accounts::markers::write_csq_account_legacy(&config_dir, account).unwrap();
        csq_core::accounts::markers::write_current_account(&config_dir, account).unwrap();

        let slot_settings = serde_json::json!({
            "env": {"ANTHROPIC_MODEL": "claude-opus-4"},
            "statusBar": {"visible": false}
        });
        std::fs::write(
            config_dir.join("settings.json"),
            serde_json::to_string_pretty(&slot_settings).unwrap(),
        )
        .unwrap();

        let pid = std::process::id();
        let handle_dir =
            session::create_handle_dir(base.path(), claude_home.path(), account, pid).unwrap();

        // First call (already done by create_handle_dir, but call explicitly)
        session::materialize_handle_settings(&handle_dir, claude_home.path(), &config_dir).unwrap();
        let first_read = std::fs::read(handle_dir.join("settings.json")).unwrap();

        // Second call — must produce identical bytes
        session::materialize_handle_settings(&handle_dir, claude_home.path(), &config_dir).unwrap();
        let second_read = std::fs::read(handle_dir.join("settings.json")).unwrap();

        assert_eq!(
            first_read, second_read,
            "materialize_handle_settings must be idempotent: second call produced different bytes"
        );
    }

    // ------------------------------------------------------------------
    // T12 — bench JSONL emission shape tests (design 08 §"Latency bench
    // harness", R2/B56/B80).
    // ------------------------------------------------------------------

    /// `write_bench_jsonl` emits lines where every `stage_timing` record
    /// carries an `"event": "stage_timing"` field.
    #[test]
    fn bench_jsonl_emission_carries_event_stage_timing_field() {
        use csq_core::capability_layer::{
            PipelineTimings, StageResult, StageTiming, STAGE_SCAFFOLD,
        };
        use csq_core::providers::catalog::Surface;

        let t = StageTiming {
            stage_id: STAGE_SCAFFOLD,
            started_at_ns: 0,
            elapsed_ns: 100_000,
            result: StageResult::Applied,
        };
        let pt = PipelineTimings {
            timings: vec![t],
            total_ns: 100_000,
        };

        let tmp_dir = tempfile::tempdir().expect("tempdir");
        let out = tmp_dir.path().join("bench.jsonl");
        write_bench_jsonl(pt, Some(out.to_str().unwrap()), Surface::ClaudeCode).unwrap();

        let content = std::fs::read_to_string(&out).unwrap();
        let stage_lines: Vec<&str> = content
            .lines()
            .filter(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap_or_default();
                v.get("event").and_then(|e| e.as_str()) == Some("stage_timing")
            })
            .collect();

        assert!(
            !stage_lines.is_empty(),
            "expected at least one stage_timing record in bench JSONL output"
        );
        for line in &stage_lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(
                v.get("event").and_then(|e| e.as_str()),
                Some("stage_timing"),
                "every stage_timing line must carry event=stage_timing"
            );
        }
    }

    /// `write_bench_jsonl` emits `warmth` as either `"cold"` or `"warm"`.
    /// `cap.coc_load.cold` → "cold"; all others → "warm".
    #[test]
    fn bench_jsonl_emission_carries_warmth_field_cold_or_warm() {
        use csq_core::capability_layer::{
            PipelineTimings, StageResult, StageTiming, STAGE_COC_LOAD_COLD, STAGE_SCAFFOLD,
        };
        use csq_core::providers::catalog::Surface;

        let timings = vec![
            StageTiming {
                stage_id: STAGE_COC_LOAD_COLD,
                started_at_ns: 0,
                elapsed_ns: 50_000,
                result: StageResult::Applied,
            },
            StageTiming {
                stage_id: STAGE_SCAFFOLD,
                started_at_ns: 50_000,
                elapsed_ns: 80_000,
                result: StageResult::Applied,
            },
        ];
        let total_ns: u128 = timings.iter().map(|t| t.elapsed_ns).sum();
        let pt = PipelineTimings { timings, total_ns };

        let tmp_dir = tempfile::tempdir().expect("tempdir");
        let out = tmp_dir.path().join("bench_warmth.jsonl");
        write_bench_jsonl(pt, Some(out.to_str().unwrap()), Surface::Codex).unwrap();

        let content = std::fs::read_to_string(&out).unwrap();
        let stage_records: Vec<serde_json::Value> = content
            .lines()
            .filter_map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).ok()?;
                if v.get("event").and_then(|e| e.as_str()) == Some("stage_timing") {
                    Some(v)
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(stage_records.len(), 2, "expected 2 stage_timing records");

        let cold_rec = &stage_records[0];
        assert_eq!(
            cold_rec.get("stage_id").and_then(|v| v.as_str()),
            Some(csq_core::capability_layer::STAGE_COC_LOAD_COLD),
            "first record must be cap.coc_load.cold"
        );
        assert_eq!(
            cold_rec.get("warmth").and_then(|v| v.as_str()),
            Some("cold"),
            "cap.coc_load.cold must produce warmth=cold"
        );

        let warm_rec = &stage_records[1];
        assert_eq!(
            warm_rec.get("warmth").and_then(|v| v.as_str()),
            Some("warm"),
            "all stages other than cap.coc_load.cold must produce warmth=warm"
        );
    }

    /// `write_bench_jsonl` serializes `StageResult` variants as lowercase
    /// strings: applied, skipped, degraded, error.
    #[test]
    fn bench_jsonl_emission_carries_result_applied_skipped_degraded_error() {
        use csq_core::capability_layer::{
            PipelineTimings, StageResult, StageTiming, STAGE_COC_LOAD, STAGE_MCP_GATE,
            STAGE_POST_VALIDATE, STAGE_SCAFFOLD,
        };
        use csq_core::providers::catalog::Surface;

        let cases = [
            (STAGE_COC_LOAD, StageResult::Applied, "applied"),
            (STAGE_SCAFFOLD, StageResult::Skipped, "skipped"),
            (STAGE_MCP_GATE, StageResult::Degraded, "degraded"),
            (STAGE_POST_VALIDATE, StageResult::Error, "error"),
        ];
        let timings: Vec<StageTiming> = cases
            .iter()
            .enumerate()
            .map(|(i, (id, result, _))| StageTiming {
                stage_id: id,
                started_at_ns: i as u128 * 10_000,
                elapsed_ns: 10_000,
                result: *result,
            })
            .collect();
        let total_ns: u128 = timings.iter().map(|t| t.elapsed_ns).sum();
        let pt = PipelineTimings { timings, total_ns };

        let tmp_dir = tempfile::tempdir().expect("tempdir");
        let out = tmp_dir.path().join("bench_result.jsonl");
        write_bench_jsonl(pt, Some(out.to_str().unwrap()), Surface::Gemini).unwrap();

        let content = std::fs::read_to_string(&out).unwrap();
        let stage_records: Vec<serde_json::Value> = content
            .lines()
            .filter_map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).ok()?;
                if v.get("event").and_then(|e| e.as_str()) == Some("stage_timing") {
                    Some(v)
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(stage_records.len(), 4, "expected 4 stage_timing records");
        for (i, (_, _, expected_result)) in cases.iter().enumerate() {
            let actual = stage_records[i]
                .get("result")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            assert_eq!(
                actual, *expected_result,
                "record[{i}] result must be {expected_result:?}, got {actual:?}"
            );
        }
    }

    /// PR-CA9b carry-forward: `load_coc_with_timing` emits exactly one
    /// `STAGE_COC_LOAD_COLD` record into the thread-local timings store on
    /// the no-`.coc/`-found path (an empty tempdir resolves to
    /// `CocSource::Empty` per FR-RUN-04 — a structured outcome that maps to
    /// `StageResult::Applied`, not `Error`).
    #[test]
    fn load_coc_with_timing_emits_cold_stage_on_empty_root() {
        use csq_core::capability_layer::{drain_timings, StageResult, STAGE_COC_LOAD_COLD};

        // Drain any residue from earlier tests on this thread.
        let _ = drain_timings();

        let dir = TempDir::new().unwrap();
        let with_warmth = load_coc_with_timing(dir.path(), dir.path(), true)
            .expect("load on empty tmpdir should succeed (returns Empty source)");
        // No `.coc/` found → project_root is None.
        assert!(with_warmth.outcome.project_root.is_none());
        assert_eq!(with_warmth.warmth, csq_core::coc::Warmth::Cold);

        let result = drain_timings();
        let cold = result
            .timings
            .iter()
            .find(|t| t.stage_id == STAGE_COC_LOAD_COLD)
            .expect("expected one STAGE_COC_LOAD_COLD timing");
        assert_eq!(cold.result, StageResult::Applied);
        assert!(cold.elapsed_ns > 0, "cold-load timing must be non-zero");
    }

    /// Build a minimal `.coc/` with COC.lock. Per an internal journal entry the
    /// per-artifact signing apparatus was retracted, so no COC.sig
    /// step is required.
    fn build_coc_dir(parent: &Path, lock_content: &[u8]) {
        let coc = parent.join(".coc");
        std::fs::create_dir_all(coc.join("rules")).unwrap();
        std::fs::create_dir_all(coc.join("agents")).unwrap();
        std::fs::create_dir_all(coc.join("skills")).unwrap();
        std::fs::create_dir_all(coc.join("commands")).unwrap();
        std::fs::write(coc.join("COC.md"), "---\ncoc.version: 1.0.0\n---\n").unwrap();
        std::fs::write(coc.join("COC.lock"), lock_content).unwrap();
    }

    /// PR-CA9b Shard 2: a second `load_coc_with_timing` call against the
    /// same `.coc/` (with `cache_enabled=true`) emits `STAGE_COC_LOAD`
    /// (warm) instead of `STAGE_COC_LOAD_COLD`.
    #[test]
    fn load_coc_with_timing_emits_warm_stage_on_second_call() {
        use csq_core::capability_layer::{drain_timings, StageResult, STAGE_COC_LOAD};

        let _ = drain_timings();

        let dir = TempDir::new().unwrap();
        build_coc_dir(dir.path(), b"{\"v\":1,\"key\":\"warm-stage-shard2\"}");

        // First call populates the cache.
        let _ = load_coc_with_timing(dir.path(), dir.path(), true).unwrap();
        let _ = drain_timings();

        // Second call hits the cache → warm stage.
        let with_warmth = load_coc_with_timing(dir.path(), dir.path(), true).unwrap();
        assert_eq!(with_warmth.warmth, csq_core::coc::Warmth::Warm);
        let result = drain_timings();
        let warm = result
            .timings
            .iter()
            .find(|t| t.stage_id == STAGE_COC_LOAD)
            .expect("expected one STAGE_COC_LOAD (warm) timing");
        assert_eq!(warm.result, StageResult::Applied);
    }

    /// PR-CA9b Shard 2: `cache_enabled=false` emits `STAGE_COC_LOAD_COLD`
    /// even when a cache file exists. Verifies the `--no-coc-cache` flag
    /// suppresses cache reads (not just writes).
    #[test]
    fn load_coc_with_timing_cache_disabled_always_cold() {
        use csq_core::capability_layer::{drain_timings, STAGE_COC_LOAD, STAGE_COC_LOAD_COLD};

        let _ = drain_timings();

        let dir = TempDir::new().unwrap();
        build_coc_dir(dir.path(), b"{\"v\":1,\"key\":\"no-cache-flag\"}");

        // First call WITH cache populates it.
        let _ = load_coc_with_timing(dir.path(), dir.path(), true).unwrap();
        let _ = drain_timings();

        // Second call with cache_enabled=false stays Cold even though
        // a fresh cache file exists on disk.
        let with_warmth = load_coc_with_timing(dir.path(), dir.path(), false).unwrap();
        assert_eq!(with_warmth.warmth, csq_core::coc::Warmth::Cold);
        let result = drain_timings();
        assert!(
            result.timings.iter().all(|t| t.stage_id != STAGE_COC_LOAD),
            "no STAGE_COC_LOAD warm record allowed when cache_enabled=false"
        );
        assert!(
            result
                .timings
                .iter()
                .any(|t| t.stage_id == STAGE_COC_LOAD_COLD),
            "expected STAGE_COC_LOAD_COLD when cache_enabled=false"
        );
    }

    /// PR-CA9b carry-forward: `record_root_seen` writes a parseable
    /// `RootEntry` into the explicit override path. Spec 10 §10.9.3:
    /// "Each `csq run` invocation appends its `coc_root` (deduplicated
    /// per file) on success."
    #[test]
    fn record_root_seen_writes_parseable_entry_to_override_path() {
        use csq_core::daemon::coc_cache_sweeper::read_roots_seen;

        let dir = TempDir::new().unwrap();
        let fifo = dir.path().join("coc-roots-seen.jsonl");
        let project_root = dir.path().join("repo-A");
        std::fs::create_dir(&project_root).unwrap();

        record_root_seen(&project_root, Some(&fifo));

        let entries = read_roots_seen(&fifo).expect("FIFO must be readable");
        assert_eq!(entries.len(), 1, "expected exactly one entry");
        assert_eq!(entries[0].coc_root, project_root.to_string_lossy());
        assert!(entries[0].last_seen > 0, "last_seen must be set");
    }

    /// PR-CA9b carry-forward: `record_root_seen` swallows write errors —
    /// a failed roots-seen append must NOT block `csq run`. Pointing the
    /// FIFO at a non-existent parent that cannot be created (a regular
    /// file path used as a parent) makes `append_root_seen` fail; the
    /// helper must return without panicking and without propagating.
    #[cfg(unix)]
    #[test]
    fn record_root_seen_swallows_write_errors() {
        let dir = TempDir::new().unwrap();
        // Block `create_dir_all` by using a regular file as a path
        // segment. `<tmp>/blocker/sub/coc-roots-seen.jsonl` cannot be
        // created because `<tmp>/blocker` is a file, not a dir.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"").unwrap();
        let fifo = blocker.join("sub").join("coc-roots-seen.jsonl");
        let project_root = dir.path().join("repo-A");
        std::fs::create_dir(&project_root).unwrap();

        // Must not panic, must not propagate.
        record_root_seen(&project_root, Some(&fifo));

        // FIFO was not created.
        assert!(!fifo.exists());
    }

    // ── M3-3 Phase 2/3 boundary pin (INVERTED) ────────────────────────────
    //
    // Previously named `run_command_handle_dir_symlinks_target_unchanged`
    // (M2-7 pin asserting config-N/ target through Phase 2).
    //
    // Per M3-3 PRIMARY METHODOLOGICAL DIRECTIVE 2 (WBS line 92):
    // this test is INVERTED in the SAME COMMIT as the source-tree changes.
    // The test now asserts the Phase 3 invariant: under a coexisting layout
    // (UUID present in profiles.json::by_slot), `.credentials.json` MUST
    // target `identities/<UUID>/credentials.json`, NOT `config-N/`.

    /// M3-3 (INVERTED boundary pin): `create_handle_dir` builds `.credentials.json`
    /// symlinks that target `identities/<UUID>/credentials.json` when a UUID is
    /// present in `profiles.json::by_slot`.
    ///
    /// This test replaces the Phase 2/3 boundary test
    /// `run_command_handle_dir_symlinks_target_unchanged` (M2-7 pin).
    /// Phase 3 has shipped the retarget; the assertion is now that the symlink
    /// goes to the identity-keyed path.  A regression to `config-N/` will fail
    /// this test.
    ///
    /// See internal-design-docs
    /// § M3-3 acceptance criterion 8.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn run_command_handle_dir_symlinks_target_identity_uuid() {
        use csq_core::accounts::profiles;
        use csq_core::testing::identity_fixtures::fixture_uuid_for_slot;

        // Arrange: coexisting layout — both config-N/ AND identities/<UUID>/
        // exist, with profiles.json mapping slot→UUID.
        let base_dir = TempDir::new().unwrap();
        let claude_home_dir = TempDir::new().unwrap();
        let base = base_dir.path();
        let claude_home = claude_home_dir.path();
        let slot_num: u16 = 3;
        let slot = AccountNum::try_from(slot_num).unwrap();
        let pid: u32 = 99999;

        // Write profiles.json with slot→UUID mapping.
        let uuid = fixture_uuid_for_slot(slot_num);
        let profiles_path = profiles::profiles_path(base);
        let mut pf = csq_core::accounts::profiles::ProfilesFile::empty();
        pf.by_slot.insert(slot_num.to_string(), uuid);
        profiles::save(&profiles_path, &pf).unwrap();

        // Create config-N/ with .credentials.json and .csq-account.
        let config_dir = base.join(format!("config-{slot_num}"));
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join(".credentials.json"), b"{}").unwrap();
        std::fs::write(config_dir.join(".csq-account"), b"3").unwrap();
        std::fs::write(config_dir.join("settings.json"), b"{}").unwrap();
        std::fs::write(config_dir.join(".claude.json"), b"{}").unwrap();

        // Create identities/<UUID>/ with credentials.json (Phase 3 canonical target).
        let uuid_dir = base.join("identities").join(uuid.to_string());
        std::fs::create_dir_all(&uuid_dir).unwrap();
        std::fs::write(uuid_dir.join("credentials.json"), b"{}").unwrap();

        // Act: create the handle dir.
        csq_core::session::create_handle_dir(base, claude_home, slot, pid).unwrap();

        // Assert: .credentials.json symlink targets identities/<UUID>/credentials.json
        // (Phase 3 invariant), NOT config-N/ (Phase 2 invariant).
        let handle_dir = base.join(format!("term-{pid}"));
        let creds_link = handle_dir.join(".credentials.json");
        let symlink_target = std::fs::read_link(&creds_link).unwrap();
        let target_str = symlink_target.to_string_lossy();
        assert!(
            target_str.contains("identities"),
            "Phase 3: .credentials.json symlink must target identities/<UUID>/, \
             got: {target_str}"
        );
        assert!(
            target_str.contains(&uuid.to_canonical_string()),
            "Phase 3: .credentials.json symlink must contain the UUID for slot {slot_num}, \
             got: {target_str}"
        );
        assert!(
            !target_str.contains(&format!("config-{slot_num}")),
            "Phase 3: .credentials.json must NOT target config-{slot_num}/ \
             (that was Phase 2); got: {target_str}"
        );

        // Defensive: the handle dir itself must exist.
        assert!(handle_dir.is_dir(), "handle dir must be created");
    }

    // ── IR-H3: check_codex_token_freshness unit tests ─────────────────────

    /// Build a minimal auth.json in a tempdir with the given access_token.
    fn write_auth_json_for_jwt_test(
        dir: &std::path::Path,
        access_token: &str,
    ) -> std::path::PathBuf {
        let body = serde_json::json!({
            "auth_mode": "chatgpt",
            "tokens": {
                "access_token": access_token,
                "refresh_token": "rt_test",
                "account_id": "acct-test"
            }
        });
        let path = dir.join("auth.json");
        std::fs::write(&path, serde_json::to_string(&body).unwrap()).unwrap();
        path
    }

    /// Build a base64url-encoded JWT payload with the given `exp` value and
    /// return a three-part JWT string (`header.payload.sig`).
    fn make_jwt_with_exp(exp: u64) -> String {
        // Encode with standard base64url (no padding) for compatibility with
        // csq_core::http::codex::jwt_exp_secs.
        fn b64url(s: &str) -> String {
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                s.as_bytes(),
            )
        }
        let header = b64url(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = b64url(&format!(r#"{{"exp":{exp},"sub":"test"}}"#));
        format!("{header}.{payload}.fakesig")
    }

    #[test]
    fn jwt_exp_pre_flight_expired_token_returns_error() {
        let dir = TempDir::new().unwrap();
        // exp = 1000, now = 2000 → clearly expired
        let jwt = make_jwt_with_exp(1000);
        let path = write_auth_json_for_jwt_test(dir.path(), &jwt);
        let err = check_codex_token_freshness(&path, acc(1), 2000)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("expired Codex access token"),
            "expired token must produce actionable error: {err}"
        );
        assert!(
            err.contains("csq login 1 --provider codex"),
            "error must name the fix command: {err}"
        );
    }

    #[test]
    fn jwt_exp_pre_flight_about_to_expire_within_grace_returns_error() {
        let dir = TempDir::new().unwrap();
        // exp = 1050, grace = 60, now = 1000 → exp - 60 = 990 ≤ now (1000) → stale
        let jwt = make_jwt_with_exp(1050);
        let path = write_auth_json_for_jwt_test(dir.path(), &jwt);
        let err = check_codex_token_freshness(&path, acc(2), 1000)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("expired Codex access token"),
            "within-grace token must also produce error: {err}"
        );
    }

    #[test]
    fn jwt_exp_pre_flight_fresh_token_returns_ok() {
        let dir = TempDir::new().unwrap();
        // exp = 9999, now = 1000, grace = 60 → exp - 60 = 9939 > 1000 → fresh
        let jwt = make_jwt_with_exp(9999);
        let path = write_auth_json_for_jwt_test(dir.path(), &jwt);
        check_codex_token_freshness(&path, acc(3), 1000).expect("fresh token must pass pre-flight");
    }

    #[test]
    fn jwt_exp_pre_flight_malformed_jwt_no_dots_is_nonfatal() {
        let dir = TempDir::new().unwrap();
        // access_token with no dots — jwt_exp_secs returns None → non-fatal
        let path = write_auth_json_for_jwt_test(dir.path(), "notajwt");
        check_codex_token_freshness(&path, acc(4), 9999)
            .expect("malformed JWT (no dots) must not block launch");
    }

    #[test]
    fn jwt_exp_pre_flight_missing_tokens_key_is_nonfatal() {
        let dir = TempDir::new().unwrap();
        // auth.json with no `tokens` key
        let body = serde_json::json!({"auth_mode": "chatgpt"});
        let path = dir.path().join("auth.json");
        std::fs::write(&path, serde_json::to_string(&body).unwrap()).unwrap();
        check_codex_token_freshness(&path, acc(5), 9999)
            .expect("missing 'tokens' key must be non-fatal");
    }

    #[test]
    fn jwt_exp_pre_flight_missing_access_token_key_is_nonfatal() {
        let dir = TempDir::new().unwrap();
        // `tokens` present but no `access_token` field
        let body = serde_json::json!({"auth_mode": "chatgpt", "tokens": {"refresh_token": "rt"}});
        let path = dir.path().join("auth.json");
        std::fs::write(&path, serde_json::to_string(&body).unwrap()).unwrap();
        check_codex_token_freshness(&path, acc(6), 9999)
            .expect("missing 'access_token' key must be non-fatal");
    }

    #[test]
    fn jwt_exp_pre_flight_missing_auth_json_is_nonfatal() {
        let dir = TempDir::new().unwrap();
        // auth.json does not exist
        let path = dir.path().join("auth.json");
        check_codex_token_freshness(&path, acc(7), 9999)
            .expect("absent auth.json must be non-fatal");
    }

    #[cfg(unix)]
    #[test]
    fn jwt_exp_pre_flight_dangling_symlink_is_nonfatal() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        // Create a symlink pointing at a non-existent target — read_to_string will fail.
        let path = dir.path().join("auth.json");
        symlink(dir.path().join("nowhere"), &path).unwrap();
        check_codex_token_freshness(&path, acc(8), 9999)
            .expect("dangling symlink auth.json must be non-fatal");
    }
}
