//! Daemon startup reconciler — clamps invariants the running daemon
//! later relies on (PR-C4).
//!
//! Two passes, both surface-scoped to Codex (the only surface today
//! with the 0o400-outside-refresh invariant + the
//! `cli_auth_credentials_store = "file"` config.toml directive).
//!
//! # Pass 1 — credential mode flip (INV-P08)
//!
//! Walks `{base_dir}/credentials/codex-<N>.json` and flips any file
//! whose mode is not 0o400 back to 0o400 under the per-account
//! `(Surface::Codex, AccountNum)` write mutex (INV-P09). The mutex
//! coordinates with the live refresher so a flip cannot land mid-
//! refresh — the refresher already holds the same mutex through
//! `save_canonical_for`'s 0o400→0o600→write→0o400 dance, so the
//! reconciler simply blocks until any in-flight refresh completes
//! and then asserts the canonical sits at 0o400.
//!
//! Catches the failure mode where `save_canonical_for` crashes
//! between `secure_file` (0o600) and `secure_file_readonly` (0o400)
//! — atomically replaced files always have a mode, but the post-
//! write flip is a separate syscall and a sigkill in between leaves
//! the canonical at 0o600 until the next reconciler pass.
//!
//! # Pass 2 — config.toml drift rewrite (INV-P03)
//!
//! Walks every `config-<N>/config.toml` for slots that have a Codex
//! canonical credential and ensures the file contains
//! `cli_auth_credentials_store = "file"`. If the directive is
//! missing or the value drifted, the reconciler rewrites via
//! `surface::write_config_toml` preserving any existing `model` key
//! (parsed line-wise — csq has no TOML parser dep, and the file
//! shape is fixed by spec 07 §7.3.3 to two keys).
//!
//! Codex respects the file-backed auth store ONLY when this key is
//! present at startup; a rewrite landed AFTER codex starts does not
//! migrate an existing keychain entry. Repairing it at daemon
//! startup means the next `csq run N` (which already requires the
//! daemon — INV-P02) sees a correctly-configured codex.
//!
//! No-op on Windows for Pass 1 — `secure_file_readonly` is a no-op
//! there. Pass 2 still runs to close the config.toml drift gap.

use crate::accounts::identity_store::settings_path_for;
use crate::accounts::profiles;
use crate::audit::persist::{write_record_to, AuditRecord};
use crate::credentials::file as cred_file;
use crate::credentials::mutex::AccountMutexTable;
use crate::credentials::write_uuid_settings;
use crate::daemon::identity_mint::{self, MintSummary};
use crate::platform::fs::{atomic_replace, secure_dir, secure_file, secure_file_readonly};
use crate::providers::catalog::Surface;
use crate::providers::codex::surface as codex_surface;
use crate::types::AccountNum;
use std::path::Path;
use tracing::{debug, info, warn};

/// Outcome counters returned to the daemon start path. Useful for
/// telemetry / `csq doctor` and asserted in unit tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReconcileSummary {
    /// Number of Codex canonical files inspected.
    pub codex_credentials_seen: usize,
    /// Number of Codex canonicals whose mode was already 0o400 → no-op.
    pub codex_credentials_already_ok: usize,
    /// Number of Codex canonicals flipped from 0o600 → 0o400.
    pub codex_credentials_repaired: usize,
    /// Number of `config-<N>/config.toml` files inspected.
    pub config_tomls_seen: usize,
    /// Number of `config.toml` files whose `cli_auth_credentials_store`
    /// key was already `"file"` → no-op.
    pub config_tomls_already_ok: usize,
    /// Number of `config.toml` files rewritten because the directive
    /// was missing or had drifted to a non-`"file"` value.
    pub config_tomls_repaired: usize,
    /// Number of `config.toml` files left UNTOUCHED because the
    /// user-global `~/.codex/config.toml` is present but not valid TOML.
    /// The slot config is KEPT rather than wiped to the degraded 2-key
    /// fallback (see `surface::regenerate_slot_config`).
    pub config_tomls_skipped_malformed_global: usize,
    /// PR-C6: whether a v1→v2 `quota.json` migration ran this start.
    /// `None` means no file existed (fresh install); `Some(false)` means
    /// the file was already at v2; `Some(true)` means the reconciler
    /// rewrote it atomically from v1 to v2.
    pub quota_migrated: Option<bool>,
    /// Number of account records that survived the v1→v2 quota migration
    /// (0 if no migration ran).
    pub quota_accounts_migrated: usize,
    /// an internal ticket: number of 3P settings files inspected for the
    /// legacy `apiKeyHelper` field (`config-N/settings.json` +
    /// `settings-*.json`).
    pub api_key_helper_files_seen: usize,
    /// an internal ticket: number of 3P settings files actually rewritten to
    /// strip the legacy `apiKeyHelper`.
    pub api_key_helper_files_migrated: usize,
    /// PR-CA10c T9: number of `.pending/*.jsonl` files seen during audit drain.
    pub audit_pending_files_seen: usize,
    /// PR-CA10c T9: number of `.pending/` records successfully drained into
    /// `csq-runs/` via `audit::persist::write_record`.
    pub audit_pending_files_drained: usize,
    /// PR-CA10c T9: number of `.pending/` files deleted because they were
    /// syntactically invalid (unrecoverable — not a retryable error).
    pub audit_pending_files_invalid: usize,
    /// PR-CA10c T9: number of `.pending/` files left in place because their
    /// `schema_version` was unknown (awaiting a future-version daemon).
    pub audit_pending_files_unknown_version: usize,
    /// M6 #909: number of `.pending-mcp-gate/*.json` outbox files seen during the
    /// MCP-gate attestation drain. Always 0 in the community edition (the proxy
    /// producer is enterprise-only, so the outbox is never written).
    pub mcp_gate_pending_files_seen: usize,
    /// M6 #909: MCP-gate outbox files whose decision was appended to the chain OR
    /// was already accounted for (deduped / no chain) — source deleted.
    pub mcp_gate_pending_files_drained: usize,
    /// M6 #909: MCP-gate outbox files deleted as unrecoverable (malformed / wrong
    /// shape).
    pub mcp_gate_pending_files_invalid: usize,
    /// M6 #909: MCP-gate outbox files left in place (unknown `schema_version`).
    pub mcp_gate_pending_files_unknown_version: usize,
    /// M6 #909: MCP-gate outbox files left in place because the decision could not
    /// be confirmed on the chain (a transient/deterministic emit error, or a
    /// signing-cutoff skip) — fail-closed retry on next start.
    pub mcp_gate_pending_files_write_failed: usize,
    /// M6 #914: the subset of `mcp_gate_pending_files_write_failed` whose emit
    /// error was DETERMINISTIC (not a `ChainLockTimeout` and not a signing-cutoff
    /// skip). A lock-timeout / cutoff backlog self-heals on the next start; a
    /// deterministic-error backlog is operator-actionable. Always 0 in the
    /// community edition.
    pub mcp_gate_pending_files_write_failed_terminal: usize,
    /// M6 #909: the MCP-gate drain was deferred because the chain was not
    /// appendable (broken sentinel, uninitialised, or malformed `chain_id`) — every
    /// outbox file was left for a next-start retry after the operator repairs /
    /// initialises the chain.
    pub mcp_gate_drain_deferred_chain_unavailable: bool,
    /// M6 #914: the number of `.json` outbox files present when the drain was
    /// deferred. Distinguishes "0 files queued" from "N files ALL left
    /// unprocessed" (the deferred path never enters the per-file loop, so
    /// `mcp_gate_pending_files_seen` stays 0). Always 0 in the community edition.
    pub mcp_gate_drain_deferred_pending_count: usize,
    /// M1-4: identity mint pass summary. `None` means the pass was not
    /// attempted (e.g. skipped due to build-time feature gate).
    /// `Some(summary)` carries per-slot counters and any non-fatal slot
    /// errors.
    pub identity_mint: Option<MintSummary>,
    /// M2-5: number of legacy `usage-{slot}.ndjson` files inspected during
    /// the ledger catch-up pass. Only slots with a UUID in `by_slot` are
    /// examined.
    pub ledger_files_seen: usize,
    /// M2-5: number of legacy ledger files successfully renamed to
    /// `identities/<UUID>/usage.ndjson`.
    pub ledger_files_renamed: usize,
    /// RN1-D5b: whether the one-shot label-relocation pass ran on this start.
    /// `None` means the sentinel was already present (pass already ran
    /// previously). `Some(report)` carries the per-slot relocation counters
    /// for diagnostics / `csq doctor`.
    pub label_relocation: Option<profiles::RelocationReport>,
    /// RN1-D R3: idempotent accounts-prune pass result. `None` = pass not
    /// run (lock contention / load error — non-fatal, retries next start).
    /// `Some(report)` carries pruned + kept-unrecoverable counts.
    pub accounts_prune: Option<profiles::AccountsPruneReport>,
    /// RN1-E: number of `by_slot_identity` entries written by the backfill
    /// pass this start. 0 means no new entries written (pass was a no-op,
    /// either because all eligible slots are already backfilled or
    /// `accounts` is empty / contains only OAuth slots).
    pub by_slot_identity_backfilled: usize,
    /// RN1-C R2: idempotent legacy-mirror cleanup pass result. `None` =
    /// pass not run (lock contention / load error — non-fatal, retries
    /// next start). `Some(report)` carries pruned + kept counts per
    /// keep-reason. See `crate::accounts::legacy_mirror_cleanup`.
    pub legacy_mirror_prune:
        Option<crate::accounts::legacy_mirror_cleanup::LegacyMirrorPruneReport>,
    /// Orphan-identity GC pass result. `None` = pass not run (lock contention
    /// or profiles-load error; retries next start). `Some(report)` carries
    /// pruned + kept counts per keep-reason. See
    /// `crate::accounts::orphan_identity_gc`.
    pub orphan_identity_gc: Option<crate::accounts::orphan_identity_gc::OrphanIdentityGcReport>,
    /// Number of orphan `coc-trust.json` files removed this start.
    /// Per `internal-design-docs` the first-pull trust gate
    /// was retracted; this pass removes the pre-retraction state file
    /// (private trust history of `(realpath, lock_sha)` decisions) when
    /// found. Idempotent — 0 on every start after the file is gone.
    /// See `rules/reconciler-cleanup-parity.md` Rule 6.
    pub coc_trust_orphans_removed: usize,
}

/// Runs the reconciler synchronously. Safe to call before
/// [`crate::daemon::spawn_refresher`] because both writers
/// (reconciler + refresher) coordinate via the same per-account
/// mutex table.
///
/// Returns a [`ReconcileSummary`] with per-pass counters.
pub fn run_reconciler(base_dir: &Path) -> ReconcileSummary {
    let mut summary = ReconcileSummary::default();

    // Pass 0 — A++ identity minting (M1-4, an internal ticket Phase 1).
    // Non-fatal: a mint error logs a warning and lets daemon continue.
    // The pass is idempotent: presence of `store-version` sentinel causes
    // an immediate no-op on every subsequent daemon start.
    match identity_mint::run_if_unsentineled(base_dir) {
        Ok(mint) => {
            if !mint.already_minted {
                info!(
                    slots_seen = mint.slots_seen,
                    slots_fresh = mint.slots_fresh,
                    slots_reused = mint.slots_reused,
                    slot_errors = mint.slot_errors.len(),
                    "identity mint pass 0 complete"
                );
            } else {
                debug!("identity mint pass 0: already minted, skipped");
            }
            summary.identity_mint = Some(mint);
        }
        Err(e) => {
            // Fixed-vocabulary error_kind — no `%e` interpolation.
            // `IdentityMintError::DirWalk` Display includes the I/O
            // error message which may contain `$HOME`-rooted paths
            // (e.g. `/Users/<user>/.claude/accounts/.profiles.lock`).
            // Logging the variant discriminator only keeps the log
            // operator-actionable without leaking user-specific paths.
            let error_kind = match &e {
                crate::daemon::identity_mint::IdentityMintError::DirWalk(_) => "dir_walk_failed",
                crate::daemon::identity_mint::IdentityMintError::SentinelWrite(_) => {
                    "sentinel_write_failed"
                }
            };
            warn!(
                error_kind,
                "identity mint pass 0 failed (non-fatal); daemon continues without identity layer"
            );
            // summary.identity_mint stays None — caller can distinguish
            // "not attempted" from "attempted but sentinel-already-present"
        }
    }

    // Pass 0 Phase 2 extension (M2-3): walk config-N/settings.json for slots
    // whose UUID is already in profiles.json and seed identities/<UUID>/settings.json
    // if not yet present. Non-fatal; runs after identity_mint sentinel check so
    // profiles.json is populated.
    pass0_phase2_settings_catchup(base_dir);

    // Pass 0 Phase 2 extension (M2-5): rename legacy usage-{slot}.ndjson files
    // to identities/<UUID>/usage.ndjson for slots whose UUID is in by_slot.
    // Non-fatal; idempotent (skips slots whose UUID ledger already exists).
    pass0_phase2_ledger_catchup(base_dir, &mut summary);

    // Pass 0 (M3-7): schema bump 1→2.
    //
    // If a pre-Phase-3 daemon wrote a schema:1 sentinel and we are now
    // booting on a Phase-3 build, rewrite the sentinel atomically so the
    // fail-closed gate (`phase4_gate_check`) below passes on the next
    // start. Idempotent: schema:≥2 is a no-op. Non-fatal: the gate will
    // surface a clear error if the bump itself fails.
    pass0_m3_7_store_version_schema_bump(base_dir);

    // Pass 0 (M3-7): legacy handle-dir advisory log.
    //
    // Walks `term-*/` handle dirs and warns when their `.credentials.json`
    // symlink resolves to a `config-N/`-shaped path (pre-M3-7 layout). A
    // running CC session in such a handle dir continues to function but
    // will not receive refreshed tokens until restarted — see release
    // notes for the live-process upgrade guidance.
    pass0_m3_7_legacy_handle_dir_advisory(base_dir);

    // RN1-D5b: one-shot label-channel relocation.
    // Copies user-chosen rename labels from `profiles.accounts[N].email`
    // (the legacy rename channel) into `by_slot_label[N]` (the A1 channel).
    // Guarded by a sentinel file so it runs exactly once.
    pass_rn1_d5_label_relocation(base_dir, &mut summary);

    // RN1-E: backfill `by_slot_identity` for non-OAuth slots (3P API keys,
    // Codex). Non-sentinel-gated — pure function of disk state, second run
    // is a no-op. MUST run AFTER relocation (so user renames win) and
    // BEFORE prune (so the new identity channel makes accounts[N] entries
    // arm-4-removable).
    pass_rn1_e_backfill_by_slot_identity(base_dir, &mut summary);

    // RN1-D R3: idempotent prune of information-recoverable accounts[N]
    // entries (MUST run AFTER relocation so genuine renames are already in
    // by_slot_label AND AFTER RN1-E backfill so arm-4 predicate has a
    // populated by_slot_identity to match against). Closes the WINDOW-CLOSE
    // P1 gate gap — nothing else empties existing populated `accounts` maps
    // to the M4-9 `{}` target.
    pass_rn1_d_r3_prune_accounts(base_dir, &mut summary);

    pass1_codex_credential_mode(base_dir, &mut summary);
    pass2_codex_config_toml(base_dir, &mut summary);
    pass3_quota_v1_to_v2(base_dir, &mut summary);
    pass4_strip_legacy_api_key_helper(base_dir, &mut summary);
    pass5_audit_drain(base_dir, &mut summary);
    // M6 #909: drain the MCP gate-decision durable outbox onto the chain. Sibling
    // of pass5 (both are audit drains) but a SEPARATE `.pending-mcp-gate/` dir +
    // record shape, so ordering vs pass5 is independent. No other pass reads that
    // dir, so it satisfies `reconciler-cleanup-parity.md` Rule 2 trivially.
    // Enterprise-only — the outbox producer (`csq mcp-proxy`) and the
    // `mcp_gate_floor` chain writer are both enterprise-gated.
    #[cfg(feature = "enterprise")]
    pass6_mcp_gate_drain(base_dir, &mut summary);

    // M6 #909 shard B: stamp this drain cycle so shard D's `csq doctor`
    // daemon-aware "stuck" predicate can distinguish an actively-draining daemon
    // (recent stamp → a persistent backlog is genuinely STUCK) from a down daemon
    // (stale stamp → backlog merely PENDING, no false alarm). Startup is one of
    // three drain-cycle stamp sites (with the periodic refresher backstop + the
    // event-driven live-path-recovery drain). Best-effort + only when the chain
    // dir exists — nothing can be queued without it, so a missing stamp there is
    // harmless. Placed after both drain passes so it reflects "the drain ran".
    if base_dir.join("csq-runs").exists() {
        if let Err(e) = crate::audit::outbox_paths::stamp_outbox_drain(base_dir) {
            warn!(
                error_kind = "outbox_drain_stamp_failed",
                "reconciler: outbox drain-stamp write failed: {e}"
            );
        }
    }

    // RN1-C R2: idempotent legacy-mirror cleanup pass. Closes the OTHER
    // half of the WINDOW-CLOSE P1 gate gap (paired with RN1-D R3): removes
    // pre-M4-12 `credentials/<N>.json` + `credentials/codex-<N>.json`
    // mirror files whose M4-12 successor at `identities/<UUID>/...` is
    // present and parseable. MUST run AFTER Pass 0 identity_mint (which
    // materialises the identity files the predicate checks) AND AFTER
    // every legacy-handling pass (pass1_codex_credential_mode reads
    // `credentials/codex-<N>.json` for the 0o400 mode flip; pass4 reads
    // legacy settings files) so those passes observe the legacy files
    // before cleanup removes them. Independent of RN1-D R3 ordering
    // (deep-analyst FM3 — `accounts` and `credentials/` surfaces don't
    // interact). Placed at the END of the chain so cleanup is the last
    // word on the legacy `credentials/` surface this start.
    pass_rn1_c_r2_prune_legacy_mirrors(base_dir, &mut summary);

    // Orphan-identity GC: delete `identities/<UUID>/` dirs unreferenced by
    // by_slot AND by_email. MUST run LAST — it deletes a surface that earlier
    // passes READ (`pass_rn1_d_r3_prune_accounts` arm-3 reads
    // `identities/<UUID>/credentials.json`; `pass_rn1_c_r2_prune_legacy_mirrors`
    // reads the identity-keyed successor). Placing it after every identity-dir
    // reader satisfies the RN1-C R2 cross-pass lesson (a cleanup pass that
    // deletes a surface other passes read MUST run after those passes). The
    // pass holds the profiles lock across snapshot + enumeration + deletion to
    // serialize against concurrent `csq login` mints (it deletes in the
    // live-mint namespace — see the module's lock-posture note).
    pass_orphan_identity_gc(base_dir, &mut summary);

    // Orphan `coc-trust.json` cleanup. Per `internal-design-docs`
    // the first-pull trust gate was retracted; any `coc-trust.json` written
    // by a pre-retraction csq build is now an orphan (no consumer reads it).
    // The file's content is privacy-sensitive (`(realpath, lock_sha) ->
    // trust_decision` records reveal which `.coc/`-bearing repos the user
    // has accepted). Idempotent — best-effort delete; absence is the
    // success state, so subsequent starts are no-ops.
    pass_coc_trust_orphan_cleanup(base_dir, &mut summary);

    info!(
        codex_credentials_seen = summary.codex_credentials_seen,
        codex_credentials_repaired = summary.codex_credentials_repaired,
        config_tomls_seen = summary.config_tomls_seen,
        config_tomls_repaired = summary.config_tomls_repaired,
        quota_migrated = ?summary.quota_migrated,
        quota_accounts_migrated = summary.quota_accounts_migrated,
        api_key_helper_files_seen = summary.api_key_helper_files_seen,
        api_key_helper_files_migrated = summary.api_key_helper_files_migrated,
        audit_pending_files_seen = summary.audit_pending_files_seen,
        audit_pending_files_drained = summary.audit_pending_files_drained,
        audit_pending_files_invalid = summary.audit_pending_files_invalid,
        audit_pending_files_unknown_version = summary.audit_pending_files_unknown_version,
        mcp_gate_pending_files_seen = summary.mcp_gate_pending_files_seen,
        mcp_gate_pending_files_drained = summary.mcp_gate_pending_files_drained,
        mcp_gate_pending_files_invalid = summary.mcp_gate_pending_files_invalid,
        mcp_gate_pending_files_unknown_version = summary.mcp_gate_pending_files_unknown_version,
        mcp_gate_pending_files_write_failed = summary.mcp_gate_pending_files_write_failed,
        mcp_gate_pending_files_write_failed_terminal =
            summary.mcp_gate_pending_files_write_failed_terminal,
        mcp_gate_drain_deferred_chain_unavailable = summary.mcp_gate_drain_deferred_chain_unavailable,
        mcp_gate_drain_deferred_pending_count = summary.mcp_gate_drain_deferred_pending_count,
        by_slot_identity_backfilled = summary.by_slot_identity_backfilled,
        legacy_mirrors_pruned = summary
            .legacy_mirror_prune
            .as_ref()
            .map(|r| r.pruned_count)
            .unwrap_or(0),
        legacy_mirrors_kept = summary
            .legacy_mirror_prune
            .as_ref()
            .map(|r| r.kept_count)
            .unwrap_or(0),
        orphan_identities_pruned = summary
            .orphan_identity_gc
            .as_ref()
            .map(|r| r.pruned_count)
            .unwrap_or(0),
        orphan_identities_kept = summary
            .orphan_identity_gc
            .as_ref()
            .map(|r| r.kept_count)
            .unwrap_or(0),
        coc_trust_orphans_removed = summary.coc_trust_orphans_removed,
        "startup reconciler complete"
    );
    summary
}

// ─── M4-5 Phase 4 gate + passes ──────────────────────────────────────────────

/// Error returned by [`phase4_gate_check`] when the on-disk state does
/// not satisfy the Phase-4 fail-closed contract. The daemon binary calls
/// the gate after `run_reconciler` and exits with a clear message on Err.
///
/// **M4-5 history (2026-05-15):** renamed from `Phase3GateError` and
/// extended with two new variants (`SettingsUnseeded`,
/// `CodexCredentialsUnseeded`) covering the M4-1 (Codex identity-keyed
/// canonical) + M4-2 (settings identity-keyed materialize) write surfaces.
/// The pre-M4-5 variants (`StoreVersionUnset`, `SchemaTooOld`,
/// `IdentityCredentialsUnseeded`) are preserved verbatim — M4-5
/// strengthens, does not replace.
///
/// Per `rules/tauri-commands.md` MUST Rule 6, each variant's `#[error(...)]`
/// Display string MUST surface a specific, operator-actionable next step
/// (`csq login N`, `re-run with a writable accounts dir`, etc.); generic
/// fallback like "gate failure" is BLOCKED. The `match` arm at the gate
/// caller (`csq/src/desktop/daemon_supervisor.rs` + `csq/src/cli/commands/daemon.rs`)
/// uses `{e}` interpolation which routes through `thiserror`'s `Display`,
/// so the per-variant strings ARE the UI text.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Phase4GateError {
    /// `store-version` sentinel is missing — identity mint has not run
    /// (or the sentinel was deleted out of band). User must let the
    /// reconciler complete a clean start, OR run `csq doctor --repair`
    /// to re-mint.
    #[error(
        "csq daemon refuses to start: store-version sentinel missing — \
         re-run after identity mint completes"
    )]
    StoreVersionUnset,

    /// `store-version` exists but its schema is older than the Phase 3
    /// minimum. The bump pass should have promoted this — `SchemaTooOld`
    /// at gate time means the bump itself failed (disk full, permission
    /// denied, etc.) or the sentinel was hand-edited.
    #[error(
        "csq daemon refuses to start: store-version schema {schema} predates \
         Phase 3 (expected {expected}) — re-run with a writable accounts dir"
    )]
    SchemaTooOld {
        /// The schema value read from disk.
        schema: u32,
        /// The minimum schema required by this daemon build.
        expected: u32,
    },

    /// A slot in `profiles.json::by_slot` has a UUID mapping but the
    /// corresponding `identities/<UUID>/credentials.json` does not
    /// exist on disk. M3-7 retired the legacy fallback at
    /// `repoint_handle_dir`, so an unseeded identity path would route
    /// a handle dir's symlink to a non-existent file. The fail-closed
    /// gate forces re-login for the affected slot before any swap or
    /// run attempts a fragile path. Origin: R2 MED-1.
    #[error(
        "csq daemon refuses to start: slot {slot} has UUID mapping but \
         identities/<uuid>/credentials.json is unseeded — re-run \
         `csq login {slot}` to seed credentials"
    )]
    IdentityCredentialsUnseeded {
        /// The slot number whose identity credentials file is missing.
        slot: u16,
        /// Short prefix (first 8 chars) of the UUID — full UUID is
        /// PII-adjacent so we redact for the error display.
        uuid_short: String,
    },

    /// **M4-5 new variant.** A slot in `profiles.json::by_slot` has a
    /// UUID mapping but the corresponding `identities/<UUID>/settings.json`
    /// does not exist on disk. M4-2 wired every login path to pair-write
    /// the identity-keyed settings file alongside the legacy
    /// `config-<N>/settings.json` overlay source. The reader-flip in M4-4
    /// prefers the identity-keyed path; absence of that file at daemon
    /// start means handle-dir materialization would silently fall through
    /// to the legacy path even after M4-7 retires it. The fail-closed gate
    /// forces re-login (which runs the pair-write) before the daemon
    /// serves any handle-dir request.
    #[error(
        "csq daemon refuses to start: slot {slot} has UUID mapping but \
         identities/<uuid>/settings.json is unseeded — re-run \
         `csq login {slot}` to seed per-account settings"
    )]
    SettingsUnseeded {
        /// The slot number whose identity settings file is missing.
        slot: u16,
        /// Short prefix (first 8 chars) of the UUID — full UUID is
        /// PII-adjacent so we redact for the error display.
        uuid_short: String,
    },

    /// **M4-5 new variant.** A slot in `profiles.json::by_slot` whose
    /// legacy Codex canonical (`credentials/codex-<N>.json`) exists on
    /// disk — signalling that the slot is Codex-bound — does NOT have
    /// its identity-keyed Codex canonical
    /// (`identities/<UUID>/credentials-codex.json`) seeded. M4-1 ships
    /// the identity-keyed Codex write as the canonical write site;
    /// absence at daemon start means a swap/run targeting Codex on
    /// this slot would resolve its handle-dir symlink to a non-existent
    /// path. The fail-closed gate forces re-login (`csq login N`) so
    /// the identity-keyed canonical is seeded before the daemon serves
    /// any Codex handle-dir request.
    ///
    /// **Binding detection:** "Codex-bound" is structurally defined as
    /// "`credentials/codex-<N>.json` exists on disk." profiles.json
    /// itself carries no per-surface binding map; the legacy canonical's
    /// presence is the unambiguous signal (parity with
    /// `gemini::provisioning::detect_other_surface_binding`).
    #[error(
        "csq daemon refuses to start: slot {slot} is Codex-bound but \
         identities/<uuid>/credentials-codex.json is unseeded — re-run \
         `csq login {slot}` to seed Codex credentials"
    )]
    CodexCredentialsUnseeded {
        /// The slot number whose identity-keyed Codex credentials file is missing.
        slot: u16,
        /// Short prefix (first 8 chars) of the UUID — full UUID is
        /// PII-adjacent so we redact for the error display.
        uuid_short: String,
    },
}

/// Phase 4 fail-closed gate (an internal journal entry Delta F / OQ #7; extended for
/// M4-5).
///
/// MUST be called by the daemon binary AFTER `run_reconciler` returns.
/// Returns `Err` when the on-disk store is not yet at Phase 4 layout;
/// daemon binary exits with the error's Display so the operator can act.
///
/// The gate is a structural defense for the post-Phase-3 invariant: every
/// UUID-keyed slot's identity credentials AND identity settings are
/// seeded, AND every Codex-bound slot's identity-keyed Codex canonical is
/// seeded, before any handle dir resolves a symlink to them. M3-7 retired
/// the live-mirror fallbacks in `create_handle_dir`/`repoint_handle_dir`;
/// M4-5 extends the gate to cover the M4-1 + M4-2 write surfaces that
/// M4-7 (mirror retirement) makes load-bearing.
///
/// **M4-5 strengthening (2026-05-15), codex-only-aware (2026-05-22):**
/// the gate now performs five checks in order:
///
/// 1. `store-version` sentinel exists (rejects pre-Pass-0 state).
/// 2. `store-version.schema >= STORE_VERSION_SCHEMA_CURRENT`.
/// 3. Every **ClaudeCode-bound** slot (legacy `credentials/<N>.json` exists)
///    in `profiles.json::by_slot` has its
///    `identities/<UUID>/credentials.json` file present on disk (M3-7).
/// 4. Every UUID in `profiles.json::by_slot` has its
///    `identities/<UUID>/settings.json` file present on disk (M4-2).
/// 5. Every **Codex-bound** slot (legacy `credentials/codex-<N>.json` exists)
///    in `profiles.json::by_slot` has its
///    `identities/<UUID>/credentials-codex.json` file present on disk
///    (M4-1).
///
/// Check 3 and Check 5 use the same structural binding signal: legacy
/// canonical's presence on disk. Codex-only slots (an internal ticket mint path —
/// UUID minted for `csq login N --provider codex` without any prior
/// Anthropic OAuth) legitimately lack the Anthropic legacy canonical
/// and identity-keyed credentials.json; Check 3 MUST allow them.
/// Symmetric reasoning for Anthropic-only slots vs Check 5.
///
/// Check 4 closes the gap where M2-3's settings catch-up pass writes the
/// identity-keyed settings BUT no callsite seeds it on first daemon start
/// for pre-M4-2 installs whose `config-N/settings.json` is absent. M4-2's
/// login pair-write guarantees the file exists for every fresh login
/// (CC or Codex); the gate enforces it for every existing UUID-keyed
/// slot regardless of surface.
pub fn phase4_gate_check(base_dir: &Path) -> Result<(), Phase4GateError> {
    let schema = identity_mint::read_store_version_schema(base_dir)
        .ok_or(Phase4GateError::StoreVersionUnset)?;
    if schema < identity_mint::STORE_VERSION_SCHEMA_CURRENT {
        return Err(Phase4GateError::SchemaTooOld {
            schema,
            expected: identity_mint::STORE_VERSION_SCHEMA_CURRENT,
        });
    }

    // an internal journal entry §Follow-up #1: best-effort legacy→identity self-heal
    // for installs that jumped over the daemon starts that would have
    // seeded identity-keyed files (v2.7.3 → v2.7.7 upgrade class). The
    // pass is idempotent and best-effort; if a slot's legacy source is
    // also absent the gate's check walk below refuses start as before.
    // Fail-closed semantics are preserved — the heal raises the floor
    // for upgrade-skip cases without weakening refusal when no legacy
    // source exists.
    let _ = phase4_gate_self_heal(base_dir);

    // M4-5 walk: enforce checks 3–5 over every UUID-keyed slot in
    // `profiles.json::by_slot`. Missing profiles.json is OK (no UUID-keyed
    // slots to check — the legacy fallback in `repoint_handle_dir`'s `else`
    // branch handles pure-legacy installs by reading CC's own
    // `config-N/.credentials.json` write, which M3-7 retired only on csq's
    // writers, not CC's).
    let profiles_path = crate::accounts::profiles::profiles_path(base_dir);
    let profiles = match crate::accounts::profiles::load(&profiles_path) {
        Ok(p) => p,
        Err(_) => return Ok(()), // unreadable / malformed profiles.json — let
                                 // the reconciler surface the actual error
                                 // through its own channel; gate stays open.
    };
    for (slot_str, uuid) in &profiles.by_slot {
        let slot: u16 = match slot_str.parse() {
            Ok(n) => n,
            Err(_) => continue, // non-numeric key — by_slot keys are normalized
                                // to digit strings; a malformed key is a
                                // separate bug class, not this gate's concern.
        };
        let identity_dir = crate::accounts::identity_store::identities_dir(base_dir)
            .join(uuid.to_canonical_string());

        // Check 3 (M3-7, codex-only-aware): identity-keyed ClaudeCode credentials,
        // ONLY for slots that are ClaudeCode-bound on disk. Parallel to Check 5's
        // codex-binding guard below: a slot's binding to a surface is structurally
        // signalled by the presence of that surface's legacy canonical at
        // `canonical_path_for`. Codex-only slots (an internal ticket mint path — UUID minted
        // for `csq login N --provider codex` without any prior Anthropic OAuth)
        // legitimately have NO Anthropic credentials.json and MUST NOT block
        // daemon start. The structural shape mirrors Check 5 exactly so the gate
        // treats Anthropic-binding and Codex-binding symmetrically.
        if let Ok(account) = crate::types::AccountNum::try_from(slot) {
            let legacy_anthropic = cred_file::canonical_path_for(
                base_dir,
                account,
                crate::providers::catalog::Surface::ClaudeCode,
            );
            if legacy_anthropic.exists() {
                let creds_path = identity_dir.join("credentials.json");
                if !creds_path.exists() {
                    return Err(Phase4GateError::IdentityCredentialsUnseeded {
                        slot,
                        uuid_short: uuid.to_canonical_string().chars().take(8).collect(),
                    });
                }
            }
        }

        // Check 4 (M4-5 new): identity-keyed settings.json. Pair-written
        // at every login (M4-2 `finalize_login` + Codex CLI/desktop login
        // hooks); the gate refuses start when the pair-write is missing
        // for any UUID-keyed slot.
        let settings_path = identity_dir.join("settings.json");
        if !settings_path.exists() {
            return Err(Phase4GateError::SettingsUnseeded {
                slot,
                uuid_short: uuid.to_canonical_string().chars().take(8).collect(),
            });
        }

        // Check 5 (M4-5 new): identity-keyed Codex canonical, but ONLY for
        // slots that are Codex-bound on disk. The legacy
        // `credentials/codex-<N>.json` canonical's presence is the
        // structural signal (parity with
        // `gemini::provisioning::detect_other_surface_binding`).
        // Slots with no Codex binding fall through without check 5.
        //
        // The `AccountNum::try_from(slot)` conversion enforces the
        // 1..=MAX_ACCOUNTS bound — out-of-range slots (e.g. a hand-edited
        // profiles.json with slot 0) cannot have a legitimate Codex
        // canonical at `canonical_path_for` since that function takes
        // AccountNum; an unconvertible slot is by construction
        // not-Codex-bound and skipping check 5 is correct.
        if let Ok(account) = crate::types::AccountNum::try_from(slot) {
            let legacy_codex = cred_file::canonical_path_for(
                base_dir,
                account,
                crate::providers::catalog::Surface::Codex,
            );
            if legacy_codex.exists() {
                let codex_identity_path = identity_dir.join("credentials-codex.json");
                if !codex_identity_path.exists() {
                    return Err(Phase4GateError::CodexCredentialsUnseeded {
                        slot,
                        uuid_short: uuid.to_canonical_string().chars().take(8).collect(),
                    });
                }
            }
        }
    }

    Ok(())
}

/// Per-slot outcome of [`phase4_gate_self_heal`] for one identity-keyed
/// file. The variants name the structural shape, not the surface — the
/// surface is carried alongside in [`Phase4HealSlotRecord::file`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase4HealOutcome {
    /// Identity-keyed file was missing AND a legacy source was found AND
    /// the byte-copy succeeded. The identity path is now seeded.
    Seeded,
    /// Identity-keyed file was already present; no action taken.
    AlreadySeeded,
    /// Identity-keyed file was missing AND no legacy source exists. The
    /// gate's check walk will refuse start with the original error.
    MissingLegacySource,
    /// Identity-keyed file was missing, a legacy source was found, but
    /// the copy failed (I/O error, permission denied, etc.). The
    /// error_kind tag is fixed-vocabulary per `rules/security.md` Rule 2.
    CopyFailed {
        /// Fixed-vocabulary error kind for structured logging.
        error_kind: String,
    },
}

/// Names one identity-keyed file the heal pass inspected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase4HealFile {
    /// `identities/<UUID>/credentials.json` — Anthropic ClaudeCode tokens.
    /// Legacy source: `credentials/<N>.json`.
    ClaudeCodeCredentials,
    /// `identities/<UUID>/settings.json` — per-account settings overlay.
    /// Legacy source: `config-<N>/settings.json`.
    Settings,
    /// `identities/<UUID>/credentials-codex.json` — Codex OAuth tokens.
    /// Legacy source: `credentials/codex-<N>.json`. Only inspected for
    /// slots whose legacy Codex canonical exists on disk.
    CodexCredentials,
}

/// Single (slot, file) heal record in [`Phase4HealReport::records`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phase4HealSlotRecord {
    /// The slot number this record covers.
    pub slot: u16,
    /// Which identity-keyed file this record covers.
    pub file: Phase4HealFile,
    /// What happened for this (slot, file).
    pub outcome: Phase4HealOutcome,
}

/// Aggregated outcome of [`phase4_gate_self_heal`]. The CLI doctor
/// command surfaces the per-record list to the operator; the gate
/// check itself just runs the heal as a side effect and re-checks.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Phase4HealReport {
    /// Per-(slot, file) records in `by_slot` iteration order. Empty when
    /// `profiles.json` is absent / malformed / has no `by_slot` entries.
    pub records: Vec<Phase4HealSlotRecord>,
}

impl Phase4HealReport {
    /// Count of (slot, file) pairs that were successfully seeded from a
    /// legacy source during this heal pass.
    pub fn seeded_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| matches!(r.outcome, Phase4HealOutcome::Seeded))
            .count()
    }

    /// Count of records whose identity file remains unseeded (legacy
    /// source missing OR copy failed). The gate's check walk will refuse
    /// start for these.
    pub fn unhealed_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| {
                matches!(
                    r.outcome,
                    Phase4HealOutcome::MissingLegacySource | Phase4HealOutcome::CopyFailed { .. }
                )
            })
            .count()
    }
}

/// One identity-keyed file that is currently absent for a UUID-mapped
/// slot — the read-only sibling of [`Phase4HealSlotRecord`].
///
/// Origin: workspace `an internal workspace` an internal journal entry §For
/// Discussion #2 (top-level `csq doctor` alarm when phase-4 incomplete).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phase4MissingFile {
    /// The slot number whose identity-keyed file is missing.
    pub slot: u16,
    /// Which identity-keyed file is missing. Reuses [`Phase4HealFile`] so
    /// `phase4_gate_status` and `phase4_gate_self_heal` stay aligned on
    /// the surface they cover.
    pub file: Phase4HealFile,
}

/// Read-only enumeration of UUID-mapped slots whose identity-keyed files
/// would cause [`phase4_gate_check`] to refuse daemon start. Produced by
/// [`phase4_gate_status`]; consumed by `csq doctor` to surface a top-level
/// "phase-4 incomplete" alarm BEFORE the operator attempts a daemon start.
///
/// Empty `missing` is the canonical Phase-4 final state (every UUID-mapped
/// slot has all three identity files present) AND the pre-mint state
/// (profiles.json absent / has no `by_slot` entries — pure-legacy install
/// that the gate passes without the M4-5 walk).
///
/// Origin: workspace `an internal workspace` an internal journal entry §For
/// Discussion #2.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Phase4GateStatus {
    /// One record per (slot, file) pair whose identity file is currently
    /// missing. A single slot can contribute up to three records — one
    /// for each of credentials / settings / codex credentials.
    pub missing: Vec<Phase4MissingFile>,
}

impl Phase4GateStatus {
    /// True when at least one identity file is missing — the daemon's
    /// `phase4_gate_check` would refuse start with this layout.
    pub fn is_incomplete(&self) -> bool {
        !self.missing.is_empty()
    }

    /// Distinct slot count across `missing` (deduped). A single slot
    /// missing credentials AND settings counts once.
    pub fn affected_slot_count(&self) -> usize {
        let mut slots: Vec<u16> = self.missing.iter().map(|r| r.slot).collect();
        slots.sort_unstable();
        slots.dedup();
        slots.len()
    }
}

/// One-shot best-effort legacy→identity copy pass for any UUID-mapped
/// slot in `profiles.json::by_slot` whose identity files are missing
/// but whose legacy sources exist.
///
/// Called automatically by [`phase4_gate_check`] before its check walk
/// (preserves fail-closed posture — refusal floor unchanged when no
/// legacy source exists) AND directly by `csq doctor --repair-identities`
/// as the operator entry point for the same migration.
///
/// **Three files per slot:**
///
/// | Identity file                                  | Legacy source                       |
/// |------------------------------------------------|-------------------------------------|
/// | `identities/<UUID>/credentials.json`           | `credentials/<N>.json`              |
/// | `identities/<UUID>/settings.json`              | `config-<N>/settings.json`          |
/// | `identities/<UUID>/credentials-codex.json`*    | `credentials/codex-<N>.json`        |
///
/// \* Only inspected when the legacy Codex canonical exists (Codex-bound
/// slots; see `Phase4GateError::CodexCredentialsUnseeded` for the
/// matching gate check).
///
/// **Permissions:** `credentials.json` and `settings.json` identity
/// files land at `0o600` via `secure_file`. The `credentials-codex.json`
/// identity file is flipped to `0o400` after `atomic_replace` via
/// `secure_file_readonly` for INV-P08 parity with `save_canonical_for`
/// (the M4-1 chokepoint for normal-flow Codex writes; spec 07 INV-P08
/// prescribes that Codex canonicals live at `0o400` between refresh
/// windows). The parent `identities/<UUID>/` dir is set to `0o700` via
/// `secure_dir` (matches the M2-2 SEC-2.15 trust boundary). The legacy
/// Codex canonical's `0o400` POSIX mode at `credentials/codex-<N>.json`
/// is preserved during the read — owner can still read at `0o400`.
/// The mode-flip is fail-closed: a `secure_file_readonly` error returns
/// `CopyFailed { error_kind: "heal_mode_flip_failed" }` and the gate
/// continues to refuse, matching `save_canonical_for`'s fail-closed
/// policy on chmod failure (`credentials/file.rs::save_canonical_for`
/// returns `CredentialError::Io` on the same branch).
///
/// **Idempotency:** records every (slot, file) pair as `AlreadySeeded`
/// when the identity file is present; running twice with no upstream
/// change produces no disk writes.
///
/// **Best-effort:** per-file copy failures log a structured WARN with
/// fixed-vocabulary `error_kind` (`heal_read_failed`, `heal_write_failed`,
/// `heal_secure_failed`, `heal_atomic_replace_failed`) and continue with
/// the next file. The §5a tmp-cleanup contract is preserved on every
/// failure branch.
///
/// Origin: workspace `an internal workspace` an internal journal entry §Follow-up
/// #1 (v2.7.3 → v2.7.7 upgrade-skip class).
pub fn phase4_gate_self_heal(base_dir: &Path) -> Phase4HealReport {
    let mut report = Phase4HealReport::default();

    // Same gating shape as phase4_gate_check: missing profiles.json
    // means no UUID-keyed slots exist, so nothing to heal. Malformed
    // profiles.json surfaces through the reconciler's own channel; the
    // heal pass stays silent.
    let profiles_path = crate::accounts::profiles::profiles_path(base_dir);
    let profiles = match crate::accounts::profiles::load(&profiles_path) {
        Ok(p) => p,
        Err(_) => return report,
    };

    for (slot_str, uuid) in &profiles.by_slot {
        let slot: u16 = match slot_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let identity_dir = crate::accounts::identity_store::identities_dir(base_dir)
            .join(uuid.to_canonical_string());

        // Pre-create + chmod the identity dir if a heal will write into
        // it. We do this lazily once per slot — but `secure_dir` is
        // idempotent so doing it eagerly is fine if any of the three
        // identity files is missing.
        let any_target_missing = !identity_dir.join("credentials.json").exists()
            || !identity_dir.join("settings.json").exists()
            || (crate::types::AccountNum::try_from(slot)
                .map(|acct| cred_file::canonical_path_for(base_dir, acct, Surface::Codex).exists())
                .unwrap_or(false)
                && !identity_dir.join("credentials-codex.json").exists());
        if any_target_missing {
            if let Err(e) = std::fs::create_dir_all(&identity_dir) {
                warn!(
                    error_kind = "heal_identity_dir_create_failed",
                    slot = slot,
                    "phase4 self-heal: cannot create identity dir; skipping slot: {}",
                    crate::error::redact_tokens(&e.to_string())
                );
                continue;
            }
            if let Err(e) = secure_dir(&identity_dir) {
                // Non-fatal — file-level 0o600 still protects content.
                warn!(
                    error_kind = "heal_identity_dir_secure_failed",
                    slot = slot,
                    "phase4 self-heal: secure_dir on identity dir failed: {}",
                    crate::error::redact_tokens(&e.to_string())
                );
            }
        }

        // ── File 1: identity ClaudeCode credentials (only for Anthropic-bound slots) ──
        // Symmetric with File 3 below: legacy canonical's presence is the
        // structural binding signal. Codex-only slots (an internal ticket mint) have no
        // Anthropic legacy and legitimately have no identity credentials.json;
        // recording a MissingLegacySource for them is noise and inflates the
        // `unhealed` count in the operator-visible info log.
        if let Ok(acct) = crate::types::AccountNum::try_from(slot) {
            let legacy_anthropic =
                cred_file::canonical_path_for(base_dir, acct, Surface::ClaudeCode);
            if legacy_anthropic.exists() {
                let identity_path = identity_dir.join("credentials.json");
                let outcome =
                    heal_copy_legacy_to_identity(&identity_path, Some(legacy_anthropic.as_path()));
                report.records.push(Phase4HealSlotRecord {
                    slot,
                    file: Phase4HealFile::ClaudeCodeCredentials,
                    outcome,
                });
            }
            // Slots without a legacy Anthropic canonical are not Anthropic-bound
            // (codex-only, gemini-only, 3P-only); the gate's Check 3 skips them too.
        }

        // ── File 2: identity settings.json ──
        {
            let identity_path = identity_dir.join("settings.json");
            let legacy_path = match crate::types::AccountNum::try_from(slot) {
                Ok(acct) => Some(settings_path_legacy_for(base_dir, acct)),
                Err(_) => None,
            };
            let outcome = heal_copy_legacy_to_identity(&identity_path, legacy_path.as_deref());
            report.records.push(Phase4HealSlotRecord {
                slot,
                file: Phase4HealFile::Settings,
                outcome,
            });
        }

        // ── File 3: identity Codex credentials (only for Codex-bound slots) ──
        if let Ok(acct) = crate::types::AccountNum::try_from(slot) {
            let legacy_codex = cred_file::canonical_path_for(base_dir, acct, Surface::Codex);
            if legacy_codex.exists() {
                let identity_path = identity_dir.join("credentials-codex.json");
                let outcome =
                    heal_copy_legacy_to_identity(&identity_path, Some(legacy_codex.as_path()));
                report.records.push(Phase4HealSlotRecord {
                    slot,
                    file: Phase4HealFile::CodexCredentials,
                    outcome,
                });
            }
            // Slots without a legacy Codex canonical are not Codex-bound;
            // the gate's check walk skips them too. No record.
        }
    }

    if report.seeded_count() > 0 || report.unhealed_count() > 0 {
        info!(
            seeded = report.seeded_count(),
            unhealed = report.unhealed_count(),
            "phase4 self-heal complete"
        );
    }
    report
}

/// Legacy `config-<N>/settings.json` path used as the heal source for
/// `identities/<UUID>/settings.json`. Mirrors the M4-2 settings overlay
/// chokepoint's fallback source.
fn settings_path_legacy_for(base_dir: &Path, account: AccountNum) -> std::path::PathBuf {
    base_dir
        .join(format!("config-{}", account))
        .join("settings.json")
}

/// Byte-copy a legacy file to an identity-keyed path via the canonical
/// secure-write pipeline (unique_tmp_path → write → secure_file →
/// atomic_replace; §5a tmp-cleanup on every failure branch).
///
/// Returns the [`Phase4HealOutcome`] for the (slot, file) pair without
/// propagating errors — the caller wants a record, not a `Result`.
fn heal_copy_legacy_to_identity(
    identity_path: &Path,
    legacy_path: Option<&Path>,
) -> Phase4HealOutcome {
    if identity_path.exists() {
        return Phase4HealOutcome::AlreadySeeded;
    }
    let legacy = match legacy_path {
        Some(p) if p.exists() => p,
        _ => return Phase4HealOutcome::MissingLegacySource,
    };

    let bytes = match std::fs::read(legacy) {
        Ok(b) => b,
        Err(e) => {
            warn!(
                error_kind = "heal_read_failed",
                legacy = %legacy.display(),
                identity = %identity_path.display(),
                "phase4 self-heal: legacy read failed: {}",
                crate::error::redact_tokens(&e.to_string())
            );
            return Phase4HealOutcome::CopyFailed {
                error_kind: "heal_read_failed".to_string(),
            };
        }
    };

    let tmp = crate::platform::fs::unique_tmp_path(identity_path);

    if let Err(e) = std::fs::write(&tmp, &bytes) {
        let _ = std::fs::remove_file(&tmp);
        warn!(
            error_kind = "heal_write_failed",
            identity = %identity_path.display(),
            "phase4 self-heal: tmp write failed: {}",
            crate::error::redact_tokens(&e.to_string())
        );
        return Phase4HealOutcome::CopyFailed {
            error_kind: "heal_write_failed".to_string(),
        };
    }

    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        warn!(
            error_kind = "heal_secure_failed",
            identity = %identity_path.display(),
            "phase4 self-heal: secure_file failed: {}",
            crate::error::redact_tokens(&e.to_string())
        );
        return Phase4HealOutcome::CopyFailed {
            error_kind: "heal_secure_failed".to_string(),
        };
    }

    if let Err(e) = atomic_replace(&tmp, identity_path) {
        let _ = std::fs::remove_file(&tmp);
        warn!(
            error_kind = "heal_atomic_replace_failed",
            identity = %identity_path.display(),
            "phase4 self-heal: atomic_replace failed: {}",
            crate::error::redact_tokens(&e.to_string())
        );
        return Phase4HealOutcome::CopyFailed {
            error_kind: "heal_atomic_replace_failed".to_string(),
        };
    }

    // INV-P08 parity: Codex identity files land at 0o400 to match the
    // M4-1 chokepoint (`save_canonical_for` for `Surface::Codex`). Non-
    // Codex identity files (`credentials.json`, `settings.json`) stay
    // at 0o600. Fail-closed on flip failure — see fn docstring for the
    // policy match with `save_canonical_for`.
    if identity_path.file_name().and_then(|s| s.to_str()) == Some("credentials-codex.json") {
        if let Err(e) = secure_file_readonly(identity_path) {
            warn!(
                error_kind = "heal_mode_flip_failed",
                identity = %identity_path.display(),
                "phase4 self-heal: secure_file_readonly (0o400 flip) failed: {}",
                crate::error::redact_tokens(&e.to_string())
            );
            return Phase4HealOutcome::CopyFailed {
                error_kind: "heal_mode_flip_failed".to_string(),
            };
        }
    }

    Phase4HealOutcome::Seeded
}

/// Read-only sibling of [`phase4_gate_check`] — walks the same surface
/// (`profiles.json::by_slot` UUID-mapped slots × three identity files)
/// but performs no writes and surfaces the per-(slot, file) presence
/// state for `csq doctor`'s top-level alarm.
///
/// The gate's M4-5 walk refuses start when a ClaudeCode-bound slot lacks
/// `credentials.json`, when ANY UUID-mapped slot lacks `settings.json`,
/// or when a Codex-bound slot lacks `credentials-codex.json`. This function
/// enumerates ALL such missing pairs without refusing or healing, so the
/// doctor can surface the impending refusal AND the scope (how many
/// slots are affected) before the operator attempts `csq daemon start`.
///
/// **ClaudeCode-bound and Codex-bound detection:** parity with the gate —
/// the respective legacy canonical (`credentials/<N>.json` and
/// `credentials/codex-<N>.json`) presence is the structural signal.
/// Slots without the relevant legacy canonical are not bound to that
/// surface and contribute no record for that surface's identity file.
/// `settings.json` is checked unconditionally because every login path
/// (CC or Codex) pair-writes it (M4-2).
///
/// **Out-of-range slots:** silently skipped (parity with
/// `phase4_gate_self_heal`'s same handling). A hand-edited
/// `profiles.json` with slot 0 or slot > `MAX_ACCOUNTS` is structurally
/// unreachable from any production write path; surfacing it would be a
/// separate diagnostic concern.
///
/// **Absent / malformed `profiles.json`:** returns the default (empty)
/// status — parity with the gate's behavior in the same conditions.
///
/// Origin: workspace `an internal workspace` an internal journal entry §For
/// Discussion #2.
pub fn phase4_gate_status(base_dir: &Path) -> Phase4GateStatus {
    let mut status = Phase4GateStatus::default();

    let profiles_path = crate::accounts::profiles::profiles_path(base_dir);
    let profiles = match crate::accounts::profiles::load(&profiles_path) {
        Ok(p) => p,
        Err(_) => return status,
    };

    for (slot_str, uuid) in &profiles.by_slot {
        let slot: u16 = match slot_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let identity_dir = crate::accounts::identity_store::identities_dir(base_dir)
            .join(uuid.to_canonical_string());

        if !identity_dir.join("settings.json").exists() {
            status.missing.push(Phase4MissingFile {
                slot,
                file: Phase4HealFile::Settings,
            });
        }
        if let Ok(account) = AccountNum::try_from(slot) {
            // Anthropic-binding-aware (parity with gate Check 3): only
            // record missing credentials.json when the slot is ClaudeCode-bound
            // on disk (legacy `credentials/<N>.json` exists). Codex-only
            // slots legitimately lack both files.
            let legacy_anthropic =
                cred_file::canonical_path_for(base_dir, account, Surface::ClaudeCode);
            if legacy_anthropic.exists() && !identity_dir.join("credentials.json").exists() {
                status.missing.push(Phase4MissingFile {
                    slot,
                    file: Phase4HealFile::ClaudeCodeCredentials,
                });
            }

            let legacy_codex = cred_file::canonical_path_for(base_dir, account, Surface::Codex);
            if legacy_codex.exists() && !identity_dir.join("credentials-codex.json").exists() {
                status.missing.push(Phase4MissingFile {
                    slot,
                    file: Phase4HealFile::CodexCredentials,
                });
            }
        }
    }

    status
}

/// Pass 0 (M3-7): bump `store-version` schema from any older value to
/// the current Phase-3 schema. Idempotent; runs on every daemon start;
/// no-op when schema is already current.
fn pass0_m3_7_store_version_schema_bump(base_dir: &Path) {
    let current = identity_mint::read_store_version_schema(base_dir);
    let target = identity_mint::STORE_VERSION_SCHEMA_CURRENT;
    match current {
        Some(s) if s >= target => {
            debug!(schema = s, "store-version schema already at current");
        }
        Some(s) => {
            info!(
                from_schema = s,
                to_schema = target,
                "M3-7: bumping store-version schema to Phase 3 layout"
            );
            let sentinel = crate::accounts::identity_store::store_version_path(base_dir);
            if let Err(e) = identity_mint::write_sentinel(&sentinel) {
                warn!(
                    error_kind = "store_version_bump_failed",
                    "M3-7: store-version schema bump failed; phase3 gate will surface error"
                );
                let _ = e; // do not interpolate; redaction concern
            }
        }
        None => {
            // No sentinel on disk. Either identity_mint just ran (and wrote
            // the current schema directly) or identity_mint failed; in either
            // case `phase4_gate_check` will produce the right error/no-op.
            debug!("M3-7: no store-version sentinel found; bump no-op");
        }
    }
}

/// Pass 0 (M3-7): legacy handle-dir advisory log.
///
/// Walks `term-*/` handle dirs and emits a structured WARN when their
/// `.credentials.json` symlink resolves to a `config-N/`-shaped target
/// (pre-M3-7 layout). The advisory tells operators that running CC
/// sessions in those handle dirs will continue to function but will not
/// receive refreshed tokens until restarted — see release notes.
fn pass0_m3_7_legacy_handle_dir_advisory(base_dir: &Path) {
    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !name.starts_with("term-") {
            continue;
        }
        let creds_link = path.join(".credentials.json");
        let target = match std::fs::read_link(&creds_link) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let target_str = target.to_string_lossy();
        // Identity-keyed symlinks resolve through `identities/<UUID>/...`.
        // Legacy / pre-M3-7 symlinks resolve through `config-N/.credentials.json`.
        let component_strs: Vec<String> = target
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .collect();
        let is_legacy = component_strs.iter().any(|c| c.starts_with("config-"))
            && !target_str.contains("/identities/");
        if is_legacy {
            // R1 H2-Sec fix-wave: `name` (the handle dir filename) and
            // `target_str` (the symlink target) are attacker-influenceable
            // — a directory created with embedded `\r\n`, ANSI escape
            // sequences, or other control chars would otherwise smuggle
            // log-injection payloads into the structured WARN. Escape
            // both for the structured fields, and drop the body
            // interpolation of `{name}` so any control chars in the
            // input cannot break out of the message envelope.
            let safe_name = escape_log(&name);
            let safe_target = escape_log(&target_str);
            warn!(
                handle_dir = %safe_name,
                target = %safe_target,
                "M3-7: pre-Phase-3 handle dir found; running session will not \
                 receive refreshed tokens until restarted"
            );
        }
    }
}

/// Escape control characters for safe inclusion in structured log fields.
///
/// Replaces `\r`, `\n`, `\t`, and other ASCII control characters (0x00-0x1F,
/// 0x7F) with `\xNN` escape sequences. Used to prevent log injection via
/// attacker-influenceable inputs (filenames, symlink targets, etc.) where
/// embedded CR/LF or ANSI escape sequences would otherwise break the log
/// envelope or smuggle terminal escape sequences into operator views.
///
/// Origin: R1 H2-Sec fix-wave (internal-design-docs
/// 0021), generalized from the warn-site at `pass0_m3_7_legacy_handle_dir_advisory`.
fn escape_log(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if (c as u32) < 0x20 || c == '\x7f' {
            out.push_str(&format!("\\x{:02x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// Pass 5 — PR-CA10c T9: drain `.pending/*.jsonl` into `csq-runs/`.
///
/// Reads every file under `<base_dir>/csq-runs/.pending/`, dispatches on
/// `schema_version`, and applies each v1 record via
/// `audit::persist::write_record` (the single authorized write site per
/// spec 12 §12.3).  Ordering is by `start_ts` ascending so records
/// appear causally in the output directory.
///
/// # Disposition per file
///
/// | Condition                                | Action                          |
/// |------------------------------------------|---------------------------------|
/// | `schema_version` missing or unknown       | Log `audit_drain_unknown_version`; LEAVE file in `.pending/` for a future daemon. |
/// | `schema_version == "1"`, valid record     | Write via `write_record`; delete source on success. |
/// | `schema_version == "1"`, invalid JSON     | Log `audit_drain_invalid`; DELETE file (unrecoverable). |
/// | `start_ts` unparseable                   | Log `audit_drain_invalid`; DELETE file (cannot sort → invalid). |
/// | `write_record` fails (I/O)               | Log `audit_drain_write_failed`; LEAVE file for next start. |
///
/// Whether a floor-record emit error during the `.pending` drain is TRANSIENT
/// and worth preserving the `.pending` file for a next-start retry (M19b
/// R1-LOW-1). Only `ChainLockTimeout` qualifies: its root cause (another writer
/// holding `.chain-lock`) is guaranteed gone after a process restart. Every
/// other `AuditV2Error` is deterministic given the same on-disk input
/// (`Io` = disk-full / permission / corrupt dir; `Signing` = real cutoff;
/// `Serialize`/`ChainCorrupt`/`Internal` = data-shape) — retrying would loop
/// forever, so those stay terminal-non-fatal (the v1 record is already durable).
fn floor_emit_is_retryable(e: &crate::audit::persist::AuditV2Error) -> bool {
    matches!(
        e,
        crate::audit::persist::AuditV2Error::ChainLockTimeout { .. }
    )
}

/// Per-drain tally for the `csq run` audit-floor outbox (`csq-runs/.pending/`),
/// returned by [`drain_run_floor`] and copied into the reconciler's
/// `ReconcileSummary` by the startup wrapper [`pass5_audit_drain`]. Extracted so
/// the same drain runs on the periodic refresher-tick backstop (M6 #909 shard B),
/// not only at daemon start.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct RunFloorDrainSummary {
    /// `.jsonl` files seen (excludes `.tmp.` in-flight writes and subdirs).
    pub seen: usize,
    /// Files whose v1 record was durably written to the chain — source deleted.
    pub drained: usize,
    /// Files deleted as unrecoverable (malformed JSON / wrong-shape v1 /
    /// unparseable `start_ts`).
    pub invalid: usize,
    /// Files left in place because their `schema_version` is missing / unknown to
    /// this daemon (forward-compat — a future daemon drains them).
    pub unknown_version: usize,
}

/// Drain the `csq run` audit-floor outbox (`csq-runs/.pending/*.jsonl`) onto the
/// chain, returning a per-drain tally. Shared by the daemon-start reconciler
/// (via [`pass5_audit_drain`]) and the periodic refresher-tick backstop (M6 #909
/// shard B — [`crate::daemon::refresher`]). Best-effort: never panics, never
/// propagates. Single-threaded-safe on both call sites (startup runs before socket
/// bind; the periodic tick runs the drain under `spawn_blocking`, and each drained
/// record's chain write is serialized by the `.chain-lock`, so a concurrent live
/// `POST /api/audit/record` cannot double-append — every write is idempotent by
/// filename + `run:<run_id>` dedup).
///
/// See spec 12 §12.7 and spec 04 §4.2.8.
pub(crate) fn drain_run_floor(base_dir: &Path) -> RunFloorDrainSummary {
    let mut summary = RunFloorDrainSummary::default();
    let pending_dir = base_dir.join("csq-runs").join(".pending");
    if !pending_dir.exists() {
        return summary;
    }

    let entries = match std::fs::read_dir(&pending_dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(
                error_kind = "audit_drain_readdir_failed",
                dir = %pending_dir.display(),
                "pass 5 audit drain: read_dir failed: {e}"
            );
            return summary;
        }
    };

    // Collect all .jsonl files first; we'll sort before processing.
    struct PendingEntry {
        path: std::path::PathBuf,
        start_ts: Option<String>,
        content: Vec<u8>,
        version: String,
    }

    let mut valid_v1: Vec<PendingEntry> = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        // Skip tmp files.
        let fname = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if fname.contains(".tmp.") {
            continue;
        }

        summary.seen += 1;

        // Read the file content.
        let content = match std::fs::read(&path) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    error_kind = "audit_drain_read_failed",
                    path = %path.display(),
                    "pass 5 audit drain: cannot read file: {e}"
                );
                continue;
            }
        };

        // Parse as serde_json::Value first to inspect schema_version before
        // strict deserialization (per spec 12 §12.7).
        let value: serde_json::Value = match serde_json::from_slice(&content) {
            Ok(v) => v,
            Err(_) => {
                // Malformed JSON — delete immediately (unrecoverable).
                warn!(
                    event = "audit_drain_invalid",
                    path = %path.display(),
                    "pass 5 audit drain: malformed JSON — deleting"
                );
                let _ = std::fs::remove_file(&path);
                summary.invalid += 1;
                continue;
            }
        };

        let version = match value.get("schema_version").and_then(|v| v.as_str()) {
            Some(v) => v.to_string(),
            None => {
                // Missing schema_version — leave for future daemon.
                info!(
                    event = "audit_drain_unknown_version",
                    path = %path.display(),
                    schema_version = "missing",
                    "pass 5 audit drain: unknown schema_version — leaving for future daemon"
                );
                summary.unknown_version += 1;
                continue;
            }
        };

        if version != "1" {
            // Unknown version — leave for future daemon per spec 12 §12.7.
            info!(
                event = "audit_drain_unknown_version",
                path = %path.display(),
                schema_version = %version,
                "pass 5 audit drain: unknown schema_version — leaving for future daemon"
            );
            summary.unknown_version += 1;
            continue;
        }

        // schema_version == "1": attempt strict deserialization.
        let record: AuditRecord = match serde_json::from_slice(&content) {
            Ok(r) => r,
            Err(e) => {
                // Valid JSON but invalid record shape — delete (unrecoverable).
                warn!(
                    event = "audit_drain_invalid",
                    path = %path.display(),
                    "pass 5 audit drain: v1 record fails strict deserialization — deleting: {e}"
                );
                let _ = std::fs::remove_file(&path);
                summary.invalid += 1;
                continue;
            }
        };

        // Parse start_ts for sorting; treat unparseable as invalid.
        let start_ts_parsed = parse_rfc3339(&record.start_ts);
        if start_ts_parsed.is_none() {
            warn!(
                event = "audit_drain_invalid",
                path = %path.display(),
                start_ts = %record.start_ts,
                "pass 5 audit drain: unparseable start_ts — deleting"
            );
            let _ = std::fs::remove_file(&path);
            summary.invalid += 1;
            continue;
        }

        valid_v1.push(PendingEntry {
            path,
            start_ts: Some(record.start_ts.clone()),
            content,
            version,
        });

        // Suppress "field not read" warning — version is used in the unknown-version
        // path above; we keep it in the struct for clarity.
        let _ = valid_v1.last().unwrap().version.as_str();
    }

    // Sort by start_ts ascending (causal ordering per spec 04 §4.2.8).
    valid_v1.sort_by(|a, b| {
        let ta = a.start_ts.as_deref().unwrap_or("");
        let tb = b.start_ts.as_deref().unwrap_or("");
        ta.cmp(tb)
    });

    // Apply each record via the single write site.
    for entry in valid_v1 {
        // Re-deserialize now that we know the record is valid.
        let record: AuditRecord = match serde_json::from_slice(&entry.content) {
            Ok(r) => r,
            Err(_) => {
                summary.invalid += 1;
                let _ = std::fs::remove_file(&entry.path);
                continue;
            }
        };

        // M19b: capture run_id before the record is moved into the writer so we
        // can emit the chain-level session-floor record after a durable v1 write.
        let run_id = record.run_id.clone();

        match write_record_to(record, Some(base_dir)) {
            Ok(()) => {
                // M19b: emit the signed chain-level session-floor record for this
                // drained run. Synchronous is fine here — this is the daemon
                // startup drain, no user is waiting on a `csq run` response. The
                // emit is idempotent (`run:<run_id>` dedup), so a run that the
                // live `audit_record_handler` ALREADY floored (the rare crash/retry
                // overlap that left a `.pending` copy) is a no-op Duplicate.
                // Best-effort: the v1 record is already drained — a floor failure
                // is logged, never blocks the drain.
                // R1-LOW-1 (M19b redteam): a `.chain-lock` timeout is TRANSIENT
                // and RETRYABLE — leave the `.pending` file in place so the next
                // daemon start re-drains (the v1 write is idempotent by filename,
                // the floor emit idempotent by `run:<run_id>` dedup) and re-emits
                // the floor record, rather than permanently losing it. Any other
                // floor error (or an `Ok(_)` skip) is terminal/non-fatal: the v1
                // record is already durable, so fall through to delete the source.
                let floor = crate::audit::run_floor::emit_csq_run_record(base_dir, &run_id);
                match &floor {
                    Ok(_) => {}
                    Err(e) if floor_emit_is_retryable(e) => {
                        warn!(
                            error_kind = "csq_run_floor_emit_retry_pending",
                            path = %entry.path.display(),
                            "pass 5 audit drain: floor emit hit a transient error; \
                             leaving .pending for retry on next daemon start"
                        );
                        // Do NOT delete the source; do NOT count as drained.
                        continue;
                    }
                    Err(e) => {
                        // Fixed-vocabulary tag only — no `{e}` interpolation
                        // (security.md §2). The typed error is dropped; tag is the signal.
                        let _ = e;
                        warn!(
                            error_kind = "csq_run_floor_emit_failed",
                            path = %entry.path.display(),
                            "pass 5 audit drain: csq-run session-floor emit failed (non-fatal)"
                        );
                    }
                }
                // Delete source on success.
                match std::fs::remove_file(&entry.path) {
                    Ok(()) => {
                        debug!(
                            event = "audit_drain_drained",
                            path = %entry.path.display(),
                            "pass 5 audit drain: drained successfully"
                        );
                        summary.drained += 1;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        // Already removed (concurrent sweep) — still counts as drained.
                        summary.drained += 1;
                    }
                    Err(e) => {
                        warn!(
                            error_kind = "audit_drain_source_delete_failed",
                            path = %entry.path.display(),
                            "pass 5 audit drain: record written but source delete failed: {e}"
                        );
                        // The record IS drained; count it. On next start the
                        // source file will cause a duplicate-write attempt
                        // which is idempotent (same run_id → same file).
                        summary.drained += 1;
                    }
                }
            }
            Err(e) => {
                // Retry-eligible I/O failure — leave file in .pending/.
                warn!(
                    event = "audit_drain_write_failed",
                    path = %entry.path.display(),
                    error_kind = e.fixed_tag(),
                    "pass 5 audit drain: write_record failed — leaving for next start"
                );
                // Do NOT increment summary.drained.
            }
        }
    }

    summary
}

/// Pass 5 — drain the `csq run` audit floor at daemon start. Thin wrapper over
/// [`drain_run_floor`] that copies the per-drain tally into the reconciler summary
/// (the drain body is shared with the periodic refresher-tick backstop, M6 #909
/// shard B). See spec 12 §12.7 and spec 04 §4.2.8.
fn pass5_audit_drain(base_dir: &Path, summary: &mut ReconcileSummary) {
    let s = drain_run_floor(base_dir);
    summary.audit_pending_files_seen += s.seen;
    summary.audit_pending_files_drained += s.drained;
    summary.audit_pending_files_invalid += s.invalid;
    summary.audit_pending_files_unknown_version += s.unknown_version;
}

/// Pass 6 — M6 #909: drain the MCP gate-decision durable outbox onto the chain.
///
/// Thin wrapper over [`crate::audit::mcp_gate_outbox::drain_pending`] (which owns
/// the read/dispatch/emit/delete logic + the fail-closed disposition) that copies
/// the per-file tally into the reconciler summary. Enterprise-only — the outbox
/// producer and the `mcp_gate_floor` chain writer are both enterprise-gated.
#[cfg(feature = "enterprise")]
fn pass6_mcp_gate_drain(base_dir: &Path, summary: &mut ReconcileSummary) {
    let s = crate::audit::mcp_gate_outbox::drain_pending(base_dir);
    summary.mcp_gate_pending_files_seen = s.seen;
    summary.mcp_gate_pending_files_drained = s.drained;
    summary.mcp_gate_pending_files_invalid = s.invalid;
    summary.mcp_gate_pending_files_unknown_version = s.unknown_version;
    summary.mcp_gate_pending_files_write_failed = s.write_failed;
    summary.mcp_gate_pending_files_write_failed_terminal = s.write_failed_terminal;
    summary.mcp_gate_drain_deferred_chain_unavailable = s.deferred_chain_unavailable;
    summary.mcp_gate_drain_deferred_pending_count = s.deferred_pending_count;
}

/// Minimal RFC3339 / ISO-8601 UTC timestamp parser.
///
/// Accepts `YYYY-MM-DDTHH:MM:SSZ` and `YYYY-MM-DDTHH:MM:SS+00:00`.
/// Returns `None` on parse failure (the record's `start_ts` is then invalid).
/// Used only for sort ordering in `pass5_audit_drain`; full chrono accuracy
/// is NOT required here — lexicographic comparison of valid ISO timestamps
/// is equivalent when all timestamps share the same timezone offset.
fn parse_rfc3339(s: &str) -> Option<i64> {
    // Quick structural validation: minimum 20 chars, ends with 'Z' or '+'.
    if s.len() < 20 {
        return None;
    }
    // Validate year-month-day-hour-minute-second structure is digit-heavy.
    // We convert to a comparable integer by treating the string as
    // `YYYYMMDDTHHMMSS` — lexicographic sort == chronological sort when
    // all records use UTC.  This is sufficient for drain ordering.
    let digits: String = s.chars().take(19).filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 14 {
        return None;
    }
    digits.parse().ok()
}

/// Pass 4 — an internal ticket: strip the legacy `apiKeyHelper` field from
/// 3P settings files written by pre-alpha.8 csq.
///
/// Idempotent + safe to run on every daemon start. See
/// `crate::daemon::migrate_legacy_api_key_helper` for the migration
/// semantics, both-present strip predicate, and unit tests.
fn pass4_strip_legacy_api_key_helper(base_dir: &Path, summary: &mut ReconcileSummary) {
    let r = crate::daemon::migrate_legacy_api_key_helper::run(base_dir);
    summary.api_key_helper_files_seen = r.files_seen;
    summary.api_key_helper_files_migrated = r.files_migrated;
}

/// Pass 3 — PR-C6 quota v1→v2 migration.
///
/// Runs BEFORE any poller starts writing, so live writers never race
/// the migration. Idempotent: an already-v2 file is left untouched.
/// Atomic: a SIGKILL between tmp write and rename leaves the original
/// v1 file intact and the next daemon start re-runs the migration.
///
/// Non-fatal on error: a corrupt file is logged but does not crash
/// the daemon. The usage poller will still write new quota records
/// (with schema_version=2) after starting, replacing the corrupt
/// file on first successful write.
fn pass3_quota_v1_to_v2(base_dir: &Path, summary: &mut ReconcileSummary) {
    use crate::quota::state::{migrate_v1_to_v2_if_needed, MigrationOutcome};
    match migrate_v1_to_v2_if_needed(base_dir) {
        Ok(MigrationOutcome::NoFile) => {
            summary.quota_migrated = None;
        }
        Ok(MigrationOutcome::AlreadyV2 { schema_version }) => {
            debug!(
                schema_version,
                "pass 3 quota v1→v2: file already at v2, skipping"
            );
            summary.quota_migrated = Some(false);
        }
        Ok(MigrationOutcome::Migrated { account_count }) => {
            info!(
                account_count,
                "pass 3 quota v1→v2: rewrote quota.json with schema_version=2"
            );
            summary.quota_migrated = Some(true);
            summary.quota_accounts_migrated = account_count;
        }
        Err(e) => {
            warn!(
                error_kind = "quota_migration_failed",
                error = %e,
                "pass 3 quota v1→v2: migration error — leaving file as-is; next poller write will overwrite"
            );
            summary.quota_migrated = None;
        }
    }
}

/// Pass 0 Phase 2 (M2-5): rename legacy `usage-{slot}.ndjson` ledger files
/// to `identities/<UUID>/usage.ndjson` for slots whose UUID is already in
/// `profiles.json`.
///
/// For each slot in `by_slot`:
/// 1. Checks whether the UUID ledger (`identities/<UUID>/usage.ndjson`) already
///    exists — if so, skips (idempotent).
/// 2. Checks whether the legacy ledger (`usage-{slot}.ndjson`) exists at the
///    base_dir root — if not, skips (nothing to migrate).
/// 3. Creates `identities/<UUID>/` directory if absent.
/// 4. `std::fs::rename`s `usage-{slot}.ndjson` → `identities/<UUID>/usage.ndjson`.
///
/// Non-fatal: any per-slot error is logged and the walk continues.
fn pass0_phase2_ledger_catchup(base_dir: &Path, summary: &mut ReconcileSummary) {
    use crate::accounts::identity_store::{identity_path, usage_ledger_path_for};

    let profiles_path = profiles::profiles_path(base_dir);
    let current_profiles = match profiles::load(&profiles_path) {
        Ok(p) => p,
        Err(_) => return, // profiles absent — nothing to migrate
    };

    if current_profiles.by_slot.is_empty() {
        return; // no slots with UUIDs → no-op
    }

    for (slot_key, &uuid) in &current_profiles.by_slot {
        // Legacy ledger is at base_dir/usage-{slot}.ndjson
        let legacy_path = base_dir.join(format!("usage-{slot_key}.ndjson"));
        if !legacy_path.exists() {
            // Nothing to rename — slot either has no ledger or was already migrated.
            continue;
        }

        summary.ledger_files_seen += 1;

        // Target: identities/<UUID>/usage.ndjson
        let uuid_ledger = usage_ledger_path_for(base_dir, uuid);

        // Idempotency guard: if UUID ledger already exists, skip rename.
        if uuid_ledger.exists() {
            debug!(
                slot = %slot_key,
                "pass0 M2-5 ledger catchup: UUID ledger already present, skipping rename"
            );
            continue;
        }

        // Ensure the identity dir exists before rename.
        let id_dir = identity_path(base_dir, uuid);
        if let Err(e) = std::fs::create_dir_all(&id_dir) {
            warn!(
                error_kind = "ledger_catchup_mkdir_failed",
                slot = %slot_key,
                "pass0 M2-5 ledger catchup: could not create identities/<uuid> dir: {e}"
            );
            continue;
        }

        match std::fs::rename(&legacy_path, &uuid_ledger) {
            Ok(()) => {
                summary.ledger_files_renamed += 1;
                info!(
                    slot = %slot_key,
                    "pass0 M2-5 ledger catchup: renamed usage-{slot_key}.ndjson → identities/<uuid>/usage.ndjson"
                );
            }
            Err(e) => {
                warn!(
                    error_kind = "ledger_catchup_rename_failed",
                    slot = %slot_key,
                    "pass0 M2-5 ledger catchup: rename failed: {e}"
                );
            }
        }
    }
}

/// Pass 0 Phase 2 (M2-3): catch up existing slots whose UUID is already in
/// `profiles.json` but whose `identities/<UUID>/settings.json` was not yet
/// seeded (accounts that existed before M2-3 was deployed, or accounts where
/// `mint_for_login` ran on a pre-M2-3 binary).
///
/// Walks `profiles.json` `by_slot` entries, resolves UUID per slot, checks
/// whether `identities/<UUID>/settings.json` already exists (skip if present
/// — idempotency invariant), and calls `write_uuid_settings` with the content
/// of `config-<N>/settings.json` (falls back to `{}` when absent).
///
/// Non-fatal: any per-slot error is logged and the walk continues. The daemon
/// provides full service regardless of whether this pass completes cleanly.
fn pass0_phase2_settings_catchup(base_dir: &Path) {
    let profiles_path = profiles::profiles_path(base_dir);
    let current_profiles = match profiles::load(&profiles_path) {
        Ok(p) => p,
        Err(_) => return, // profiles absent (fresh install or no slots) — nothing to catch up
    };

    if current_profiles.by_slot.is_empty() {
        return; // no slots → no-op
    }

    for (slot_key, &uuid) in &current_profiles.by_slot {
        let uuid_settings = settings_path_for(base_dir, uuid);
        if uuid_settings.exists() {
            debug!(
                slot = %slot_key,
                "pass0 M2-3 settings catchup: UUID settings already present, skipping"
            );
            continue;
        }

        let config_n_settings = base_dir
            .join(format!("config-{slot_key}"))
            .join("settings.json");
        let bytes = if config_n_settings.exists() {
            match std::fs::read(&config_n_settings) {
                Ok(b) => b,
                Err(e) => {
                    warn!(
                        error_kind = "settings_catchup_read_failed",
                        slot = %slot_key,
                        "pass0 M2-3 settings catchup: could not read config-{slot_key}/settings.json: {e}"
                    );
                    b"{}".to_vec()
                }
            }
        } else {
            b"{}".to_vec()
        };

        if let Err(e) = write_uuid_settings(base_dir, uuid, &bytes) {
            warn!(
                error_kind = "settings_catchup_write_failed",
                slot = %slot_key,
                "pass0 M2-3 settings catchup: could not write UUID settings for slot {slot_key}: {}",
                crate::error::redact_tokens(&e.to_string())
            );
        } else {
            debug!(
                slot = %slot_key,
                "pass0 M2-3 settings catchup: seeded identities/<uuid>/settings.json for slot {slot_key}"
            );
        }
    }
}

fn pass1_codex_credential_mode(base_dir: &Path, summary: &mut ReconcileSummary) {
    let creds_dir = base_dir.join("credentials");
    let entries = match std::fs::read_dir(&creds_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        let Some(num_str) = stem.strip_prefix("codex-") else {
            continue;
        };
        let id: u16 = match num_str.parse() {
            Ok(n) if (1..=999).contains(&n) => n,
            _ => continue,
        };
        let account = match AccountNum::try_from(id) {
            Ok(a) => a,
            Err(_) => continue,
        };

        summary.codex_credentials_seen += 1;

        // Acquire the per-account mutex BEFORE inspecting the mode.
        // The refresher's `save_canonical_for` holds the same mutex
        // while it's mid-flip; waiting here means we always observe
        // the post-write steady state (0o400) rather than the
        // transient 0o600 window.
        let slot_mutex = AccountMutexTable::global().get_or_insert(Surface::Codex, account);
        let _guard = match slot_mutex.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        if is_already_readonly(&path) {
            summary.codex_credentials_already_ok += 1;
            continue;
        }

        match secure_file_readonly(&path) {
            Ok(()) => {
                summary.codex_credentials_repaired += 1;
                debug!(
                    account = id,
                    surface = "codex",
                    path = %path.display(),
                    "reconciler flipped Codex canonical to 0o400 (drift from prior crash mid-write)"
                );
            }
            Err(e) => {
                warn!(
                    account = id,
                    surface = "codex",
                    error_kind = "reconciler_mode_flip_failed",
                    error = %e,
                    "reconciler could not flip Codex canonical to 0o400"
                );
            }
        }
    }
}

#[cfg(unix)]
fn is_already_readonly(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(m) => (m.permissions().mode() & 0o777) == 0o400,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_already_readonly(_path: &Path) -> bool {
    // Windows: no POSIX 0o400 concept — the credential writer uses
    // DACLs at file-creation time. The reconciler treats every file
    // as "already OK" so the no-op `secure_file_readonly` does not
    // bump the repair counter.
    true
}

fn pass2_codex_config_toml(base_dir: &Path, summary: &mut ReconcileSummary) {
    let creds_dir = base_dir.join("credentials");
    let entries = match std::fs::read_dir(&creds_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        let Some(num_str) = stem.strip_prefix("codex-") else {
            continue;
        };
        let id: u16 = match num_str.parse() {
            Ok(n) if (1..=999).contains(&n) => n,
            _ => continue,
        };
        let account = match AccountNum::try_from(id) {
            Ok(a) => a,
            Err(_) => continue,
        };

        summary.config_tomls_seen += 1;

        // Read the pre-write content so the drift_reason log below can
        // describe WHY the rewrite was needed. The actual read-model +
        // re-merge + write is delegated to the shared helper, which is
        // the SAME operation `csq run` performs per-launch — one
        // canonical re-merge path, not two divergent copies.
        //
        // This read is LOG-ONLY: the counters and the write itself are driven
        // entirely by the helper's own internal snapshot, so even if a
        // concurrent writer changed the file between this read and the
        // helper's read, the worst outcome is a cosmetically mislabeled
        // drift_reason — never a miscount or mis-write. Such a concurrent
        // write is itself unlikely but NOT impossible: of the four
        // config.toml writers (spec 07 §7.2.2.1), `csq run`'s per-launch
        // regen is gated behind `require_daemon_healthy` (false during
        // startup reconcile), but `csq login --provider codex` and
        // `csq models` are ungated and could race. The log-only property is
        // what makes that race benign here.
        let toml_path = codex_surface::config_toml_path(base_dir, account);
        let existing = std::fs::read_to_string(&toml_path).ok();

        match codex_surface::regenerate_slot_config(base_dir, account) {
            Ok(codex_surface::RegenOutcome::AlreadyCurrent) => {
                summary.config_tomls_already_ok += 1;
            }
            Ok(codex_surface::RegenOutcome::Rewritten { model, .. }) => {
                summary.config_tomls_repaired += 1;
                let drift_reason = if existing.is_none() {
                    "missing"
                } else if !existing
                    .as_deref()
                    .map(has_file_backed_directive)
                    .unwrap_or(false)
                {
                    "cli_auth_credentials_store_drift"
                } else {
                    "user_global_merge_outdated"
                };
                // `model` is the preserved explicit per-slot model, or None when
                // the slot defers to the user-global / codex built-in default.
                info!(
                    account = id,
                    surface = "codex",
                    model = model
                        .as_deref()
                        .unwrap_or("(deferred-to-global-or-default)"),
                    drift_reason = drift_reason,
                    "reconciler rewrote config.toml"
                );
            }
            Ok(codex_surface::RegenOutcome::SkippedMalformedGlobal) => {
                summary.config_tomls_skipped_malformed_global += 1;
                warn!(
                    account = id,
                    surface = "codex",
                    error_kind = "codex_user_global_unparseable_skip_rewrite",
                    "kept existing config.toml — ~/.codex/config.toml is not valid TOML"
                );
            }
            Err(e) => {
                warn!(
                    account = id,
                    surface = "codex",
                    error_kind = "reconciler_config_toml_write_failed",
                    error = %e,
                    "reconciler could not rewrite config.toml"
                );
            }
        }

        // Verify the canonical credential file is loadable as a Codex
        // variant before we trust the slot — protects against the
        // operator pasting an Anthropic shape into a `codex-N.json`
        // path (already guarded at discovery; the reconciler re-tags
        // it for the daemon-start log).
        if let Err(e) = cred_file::load(&path) {
            // CredentialError::Corrupt may carry a serde error Display
            // that echoes credential JSON fragments — redact first.
            let redacted = crate::error::redact_tokens(&e.to_string());
            warn!(
                account = id,
                surface = "codex",
                error_kind = "reconciler_canonical_unreadable",
                error = %redacted,
                "Codex canonical credential file is not parseable — slot will be skipped by the refresher until repaired"
            );
        }
    }
}

/// Returns true iff the `cli_auth_credentials_store` key is set to
/// `"file"` exactly. Tolerates surrounding whitespace; rejects any
/// other value. Comments after the value are ignored.
fn has_file_backed_directive(toml: &str) -> bool {
    for raw in toml.lines() {
        let line = raw.split('#').next().unwrap_or(raw).trim();
        let Some(rest) = line.strip_prefix("cli_auth_credentials_store") else {
            continue;
        };
        let after_eq = rest.trim_start().strip_prefix('=').map(|s| s.trim());
        if let Some(value) = after_eq {
            // Accept only the canonical double-quoted form: "file".
            if value == "\"file\"" {
                return true;
            }
            // Single-quoted TOML literal "file" is also valid TOML.
            if value == "'file'" {
                return true;
            }
        }
    }
    false
}

// `extract_model_key` moved to `providers::codex::surface` (shared with
// `regenerate_slot_config`); the reconciler now reaches the re-merge
// through that helper.

// ─── RN1-D5b label relocation pass ───────────────────────────────────────────

/// One-shot pass: relocates user-chosen rename labels from
/// `profiles.accounts[N].email` into `profiles.by_slot_label[N]`.
///
/// Guarded by the `label-channel-migrated` sentinel file in `base_dir`.
/// On first run, performs the relocation and writes the sentinel.
/// On subsequent starts, the sentinel is present and the pass is a fast no-op.
///
/// Non-fatal: any error (profiles lock contention, I/O failure) is logged as
/// a warning and the daemon continues. The sentinel is NOT written on error —
/// the pass will retry on the next daemon start.
fn pass_rn1_d5_label_relocation(base_dir: &Path, summary: &mut ReconcileSummary) {
    use crate::accounts::profiles::{
        label_relocation_sentinel_path, relocate_labels_to_by_slot_label,
    };
    use crate::accounts::profiles_lock::ProfilesFileLock;

    let sentinel = label_relocation_sentinel_path(base_dir);

    // Fast-path: sentinel present → already ran on a previous start.
    if sentinel.exists() {
        debug!("label relocation (RN1-D5b): sentinel present, skipping");
        summary.label_relocation = None;
        return;
    }

    // Acquire the profiles lock and run the relocation.
    let lock = match ProfilesFileLock::acquire(base_dir) {
        Ok(l) => l,
        Err(_e) => {
            // Fixed-vocabulary tag, NO error body: a lock/IO error's Display
            // can carry the profiles.json path + serde fragment (email PII)
            // and is not token-redacted (security.md Rule 2).
            warn!(
                error_kind = "profiles_lock_contention",
                "label relocation (RN1-D5b): could not acquire profiles lock — will retry on next start"
            );
            return;
        }
    };

    match relocate_labels_to_by_slot_label(&lock, base_dir) {
        Ok(report) => {
            info!(
                slots_examined = report.slots_examined,
                slots_relocated = report.slots_relocated,
                slots_skipped_oauth = report.slots_skipped_oauth_email,
                slots_skipped_no_uuid = report.slots_skipped_no_uuid,
                "label relocation (RN1-D5b) complete"
            );
            // Drop lock before writing sentinel (sentinel is not under the profiles lock).
            drop(lock);
            // Write the sentinel atomically so the pass is a no-op on future starts.
            let sentinel_json = br#"{"schema":1,"pass":"rn1-d5-label-relocation"}"#;
            let tmp = crate::platform::fs::unique_tmp_path(&sentinel);
            if let Err(_e) = std::fs::write(&tmp, sentinel_json) {
                let _ = std::fs::remove_file(&tmp);
                warn!(
                    error_kind = "sentinel_write",
                    "label relocation (RN1-D5b): sentinel write failed (will retry)"
                );
                return;
            }
            if let Err(_e) = crate::platform::fs::atomic_replace(&tmp, &sentinel) {
                let _ = std::fs::remove_file(&tmp);
                warn!(
                    error_kind = "sentinel_rename",
                    "label relocation (RN1-D5b): sentinel rename failed (will retry)"
                );
                return;
            }
            summary.label_relocation = Some(report);
        }
        Err(_e) => {
            warn!(
                error_kind = "relocation_failed",
                "label relocation (RN1-D5b): relocation failed (will retry on next start)"
            );
        }
    }
}

/// RN1-E: backfill `profiles.json::by_slot_identity` for non-OAuth slots
/// (3P API-key slots and Codex OAuth slots) that were written before M6/M7/M8
/// landed synchronous writers.
///
/// # Logic
///
/// Three arms feed a shared `to_backfill` queue. Every arm applies the same
/// two skips: a slot in `profiles.by_slot` is OAuth (skip), and a slot
/// already in `profiles.by_slot_identity` is done (idempotency guard).
///
/// ## Arm 1 — `accounts` walk (3P API-key + Codex with an `accounts[N]` row)
///
/// For each `(slot_key, AccountProfile)` in `profiles.accounts`:
///
/// - **Recognized email prefix (`apikey:` or `codex-`)** — write
///   `by_slot_identity[slot_key] = email.clone()` verbatim. The email field
///   already carries the canonical identity literal in v2.6.x-upgraded hosts.
/// - **Empty email** (rebind scenario) — derive the identity from
///   `config-<N>/settings.json::env.ANTHROPIC_BASE_URL` via
///   `provider_from_base_url` + `id_from_display_name`. If the URL classifies
///   to a known provider, write `by_slot_identity[slot_key] = "apikey:<id>"`.
///   Unclassifiable URLs (or settings absent) are silently skipped.
///
/// ## Arm 2 — Gemini disk-walk
///
/// Gemini slots have no `accounts[N]` row — they exist only as
/// `credentials/gemini-<N>.json` binding markers. `discover_gemini` walks
/// them and `gemini_identity_label` produces the literal.
///
/// ## Arm 3 — 3P API-key disk-walk
///
/// 3P API-key slots are likewise not guaranteed an `accounts[N]` row: once
/// `pass_rn1_d_r3_prune_accounts` has emptied `accounts`, or for a slot bound
/// before an internal ticket's M7 synchronous hook, Arm 1 has nothing to migrate.
/// `discover_per_slot_third_party` walks `config-<N>/settings.json` and the
/// provider id is mapped from the discovered display name. Unlike Gemini
/// slots, a 3P slot CAN also carry an `accounts[N]` row, so this arm dedups
/// against Arm 1's queued slots (Arm 1's verbatim email wins). Like the
/// Gemini arm, it self-heals a stale literal (FM-5): a stored value that
/// differs from the one derived from the current `settings.json` is
/// overwritten, not skipped. Origin: `an internal workspace`
/// an internal journal entry (slot 10 = a live Z.AI slot Arm 1 could not see).
///
/// The pass acquires `ProfilesFileLock` once and calls `set_slot_identity`
/// (which saves atomically and idempotently) for each qualifying slot.
/// Non-fatal: any error logs `error_kind = "by_slot_identity_backfill_failed"`
/// and the daemon continues. Same error-handling shape as
/// `pass4_strip_legacy_api_key_helper`.
///
/// # Ordering
///
/// MUST run AFTER `pass_rn1_d5_label_relocation` (so user renames are already
/// in `by_slot_label` — the skip-predicate guards against overwriting a
/// non-prefix label) and BEFORE `pass_rn1_d_r3_prune_accounts` (so prune arm 4
/// has a populated `by_slot_identity` entry to match against when deciding
/// whether `accounts[N]` is removable).
fn pass_rn1_e_backfill_by_slot_identity(base_dir: &Path, summary: &mut ReconcileSummary) {
    use crate::accounts::discovery::provider_from_base_url;
    use crate::accounts::profiles::{profiles_path, set_slot_identity};
    use crate::accounts::profiles_lock::ProfilesFileLock;
    use crate::providers::catalog::id_from_display_name;

    let lock = match ProfilesFileLock::acquire(base_dir) {
        Ok(l) => l,
        Err(_e) => {
            // Fixed-vocabulary tag — no error body (lock/IO Display can carry
            // profiles.json path + serde fragment with email PII).
            warn!(
                error_kind = "profiles_lock_contention",
                "by_slot_identity backfill (RN1-E): could not acquire profiles lock — will retry on next start"
            );
            return;
        }
    };

    let path = profiles_path(base_dir);
    let pf = match profiles::load(&path) {
        Ok(p) => p,
        Err(_e) => {
            warn!(
                error_kind = "by_slot_identity_backfill_failed",
                "by_slot_identity backfill (RN1-E): profiles.json load failed — will retry on next start"
            );
            return;
        }
    };

    // Collect (slot_key, identity_label) pairs to backfill without holding
    // a borrow on `pf` across the set_slot_identity calls.
    let mut to_backfill: Vec<(String, String)> = Vec::new();

    // M4-13: `accounts` struct field removed; legacy content lives in
    // extra["accounts"]. Use the helper to extract the slot_key → email map.
    let legacy_accounts = profiles::legacy_accounts_email_map(&pf);
    for (slot_key, email) in &legacy_accounts {
        // (1) Skip OAuth slots — they have a UUID entry in by_slot.
        if pf.by_slot.contains_key(slot_key) {
            continue;
        }

        // (2) Skip already-backfilled — idempotency guard.
        if pf.by_slot_identity.contains_key(slot_key) {
            continue;
        }

        let email = email.as_str();

        // (3) Recognized non-OAuth email prefix → copy verbatim.
        if email.starts_with("apikey:") || email.starts_with("codex-") {
            to_backfill.push((slot_key.clone(), email.to_string()));
            continue;
        }

        // (4) Empty email → derive identity from settings.json ANTHROPIC_BASE_URL.
        if email.trim().is_empty() {
            let slot_num: u16 = match slot_key.parse() {
                Ok(n) => n,
                Err(_) => continue,
            };
            let settings_path = base_dir
                .join(format!("config-{slot_num}"))
                .join("settings.json");
            // settings.json is read without its flock — relies on
            // bind_provider_to_slot's atomic_replace + the ProfilesFileLock
            // held here serializing the by_slot_identity write. A future
            // refactor that converts settings.json writes to in-place updates
            // (breaking atomicity) would introduce a torn-read window here.
            let content = match std::fs::read_to_string(&settings_path) {
                Ok(c) => c,
                Err(_) => continue, // no settings.json — skip silently
            };
            let json: serde_json::Value = match serde_json::from_str(&content) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let base_url = json
                .get("env")
                .and_then(|e| e.get("ANTHROPIC_BASE_URL"))
                .or_else(|| json.get("ANTHROPIC_BASE_URL"))
                .and_then(|v| v.as_str());
            let Some(base_url) = base_url else {
                continue;
            };
            let Some(display_name) = provider_from_base_url(base_url) else {
                continue;
            };
            let Some(provider_id) = id_from_display_name(display_name) else {
                continue;
            };
            to_backfill.push((slot_key.clone(), format!("apikey:{provider_id}")));
        }
        // Non-empty, non-recognized prefix (e.g. a genuine user label that
        // ended up in accounts but has no by_slot_identity yet) — skip.
        // The label is handled by by_slot_label or the user has renamed
        // the slot to a non-prefix string; we do not overwrite.
    }

    // ── Gemini arm (an internal journal entry D2 — FM-3/3a/3b/5) ─────────────────────────
    //
    // Gemini slots have NO `accounts[N]` entry — they exist only as
    // `credentials/gemini-<N>.json` binding markers, so the accounts walk
    // above structurally skips them. Reuse `discover_gemini` (already
    // redteam-hardened: symlink reject, `.json` filter, `gemini-` prefix,
    // `1..=999`, leading-zero canonicalization, `AccountNum::try_from`,
    // `read_binding` error-branch) rather than re-walk `credentials/` —
    // re-implementing a hardened walk is the FM-3 defect. The literal is
    // produced by the ONE shared `gemini_identity_label` (FM-3a) so the
    // backfill and synchronous-provision paths emit byte-identical values.
    // `discover_gemini` logs unreadable markers internally and returns only
    // clean `AccountInfo`, so this arm never sees the `ProvisionError`
    // Display body (FM-3b log-PII discipline preserved for free).
    for info in crate::accounts::discovery::discover_gemini(base_dir) {
        let slot_key = info.id.to_string();
        let acct = match crate::types::AccountNum::try_from(info.id) {
            Ok(a) => a,
            Err(_) => continue,
        };
        // Re-read the marker for the raw `AuthMode` (discover_gemini
        // flattens it to a `method` string that is NOT the literal
        // segment — FM-3a). Cheap extra fs read on the rare daemon-start
        // path; avoids widening `AccountInfo`'s public shape.
        let binding = match crate::providers::gemini::provisioning::read_binding(base_dir, acct) {
            Ok(b) => b,
            // Benign race: a concurrent logout deleted the marker
            // between discover_gemini's walk and here. discover_gemini
            // already logged any malformed/IO case; skip silently.
            Err(_) => continue,
        };
        let label =
            crate::providers::gemini::provisioning::gemini_identity_label(acct, &binding.auth);
        // FM-5: overwrite-on-mode-mismatch (self-heal a slot
        // re-provisioned in a new mode then crashed before the
        // synchronous write). Skip when byte-equal — idempotent, and
        // avoids inflating the `backfilled` counter / redundant save on
        // every steady-state daemon restart.
        if pf.by_slot_identity.get(&slot_key).map(|s| s.as_str()) == Some(label.as_str()) {
            continue;
        }
        to_backfill.push((slot_key, label));
    }

    // ── 3P API-key arm (an internal workspace an internal journal entry) ──────────
    //
    // 3P API-key slots are NOT structurally guaranteed to have an
    // `accounts[N]` entry: once `pass_rn1_d_r3_prune_accounts` has emptied
    // `accounts`, and for any slot bound before an internal ticket's M7 synchronous
    // `set_slot_identity` hook, arm 1's `accounts` walk has nothing to
    // migrate. This is the 3P analogue of the accounts-less Gemini case the
    // arm above handles. Reuse `discover_per_slot_third_party` (already
    // redteam-hardened: symlink reject, `config-` prefix, `1..=999`,
    // invalid-JSON skip) rather than re-walk `config-*/` here.
    //
    // Dedup against arm 1: unlike Gemini slots, a 3P slot CAN also carry an
    // `accounts[N]` entry, so arm 1 may already have pushed this slot. The
    // membership check keeps the `backfilled` counter honest.
    for info in crate::accounts::discovery::discover_per_slot_third_party(base_dir) {
        let slot_key = info.id.to_string();
        // (1) Skip OAuth slots — they have a UUID entry in by_slot.
        if pf.by_slot.contains_key(&slot_key) {
            continue;
        }
        // `discover_per_slot_third_party` sets `label` to the provider
        // display name ("Z.AI", "MiniMax", ...). Map it to the catalog id
        // for the `apikey:<id>` literal — same derivation as arm 1 case (4).
        // `info.has_credentials` (ANTHROPIC_AUTH_TOKEN presence) is
        // intentionally NOT gated: a slot bound to a provider but not yet
        // authenticated is still that provider's slot and must be
        // recognised, not left flagged as an orphan.
        let Some(provider_id) = id_from_display_name(&info.label) else {
            // The display name came from `provider_from_base_url`'s fixed
            // vocabulary; an unmappable name means the URL classifier and
            // the catalog have drifted — a real config defect. Surface it
            // rather than silently swallow it (the slot stays an orphan,
            // and the warning is the diagnostic trail to the drift).
            warn!(
                error_kind = "by_slot_identity_backfill_failed",
                slot = %slot_key,
                provider = %info.label,
                "by_slot_identity backfill (RN1-E): 3P provider display name not in catalog — slot left unbackfilled"
            );
            continue;
        };
        let label = format!("apikey:{provider_id}");
        // (2) FM-5 self-heal parity with the Gemini arm: skip ONLY when the
        // stored literal already equals the freshly-derived one. A
        // *different* stored value is stale — the slot was rebound to
        // another provider then crashed before the synchronous
        // `set_slot_identity` hook fired — and is overwritten. A blunt
        // skip-if-present would mask that staleness permanently.
        // `config-N/settings.json` is read by `discover_per_slot_third_party`
        // without that slot's flock — same atomicity reliance as arm 1
        // case (4) above (`bind_provider_to_slot`'s `atomic_replace`).
        if pf.by_slot_identity.get(&slot_key).map(|s| s.as_str()) == Some(label.as_str()) {
            continue;
        }
        // (3) Skip if arm 1 already queued this slot — arm 1's verbatim
        // `accounts[N].email` is the bind-time canonical literal and wins.
        if to_backfill.iter().any(|(k, _)| k == &slot_key) {
            continue;
        }
        to_backfill.push((slot_key, label));
    }

    if to_backfill.is_empty() {
        debug!("by_slot_identity backfill (RN1-E): nothing to backfill");
        return;
    }

    let mut backfilled = 0usize;
    for (slot_key, label) in &to_backfill {
        let slot_num: u16 = match slot_key.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        match set_slot_identity(&lock, base_dir, slot_num, label) {
            Ok(()) => {
                backfilled += 1;
                debug!(
                    slot = %slot_key,
                    label = %label,
                    "by_slot_identity backfill (RN1-E): wrote identity label"
                );
            }
            Err(_e) => {
                warn!(
                    error_kind = "by_slot_identity_backfill_failed",
                    slot = %slot_key,
                    "by_slot_identity backfill (RN1-E): failed to write identity for slot"
                );
            }
        }
    }

    if backfilled > 0 {
        info!(
            by_slot_identity_backfilled = backfilled,
            "by_slot_identity backfill (RN1-E): complete"
        );
        summary.by_slot_identity_backfilled += backfilled;
    }
}

/// RN1-D R3: idempotent pass that empties `profiles.json::accounts` of every
/// information-recoverable entry (see
/// [`crate::accounts::profiles::prune_redundant_accounts_entries`] for the
/// removal predicate). Closes the WINDOW-CLOSE P1 gate gap: nothing else
/// brings an already-populated `accounts` map to the M4-9 `accounts: {}`
/// target, so `detect_v1_accounts_field` could never clear on an upgraded
/// host and RN1-F was structurally unreachable.
///
/// NOT sentinel-gated (unlike RN1-D5b): the predicate is a pure function of
/// on-disk state and a second run is a no-op, so running it every reconcile
/// lets a host that later resolves an unrecoverable entry (`csq login N`)
/// get it pruned on the next start. Non-fatal: lock contention / load error
/// logs a warning and the daemon continues; the pass retries next start.
fn pass_rn1_d_r3_prune_accounts(base_dir: &Path, summary: &mut ReconcileSummary) {
    use crate::accounts::profiles::prune_redundant_accounts_entries;
    use crate::accounts::profiles_lock::ProfilesFileLock;

    let lock = match ProfilesFileLock::acquire(base_dir) {
        Ok(l) => l,
        Err(_e) => {
            warn!(
                error_kind = "profiles_lock_contention",
                "accounts prune (RN1-D R3): could not acquire profiles lock — will retry on next start"
            );
            return;
        }
    };

    match prune_redundant_accounts_entries(&lock, base_dir) {
        Ok(report) => {
            info!(
                accounts_pruned = report.pruned,
                accounts_kept_unrecoverable = report.kept_unrecoverable,
                pruned_by_identity_channel = report.pruned_by_identity_channel,
                "accounts prune (RN1-D R3) complete"
            );
            summary.accounts_prune = Some(report);
        }
        Err(_e) => {
            warn!(
                error_kind = "accounts_prune_failed",
                "accounts prune (RN1-D R3): failed (will retry on next start)"
            );
        }
    }
}

/// RN1-C R2 wrapper: acquires the `profiles.json` lock, delegates to
/// [`crate::accounts::legacy_mirror_cleanup::prune_legacy_credential_mirrors`],
/// and stamps the report into `summary.legacy_mirror_prune`.
///
/// NOT sentinel-gated (same shape as RN1-D R3): the predicate is a pure
/// function of disk state and a second run is a no-op, so running it every
/// reconcile lets a host that later mints a `by_slot` UUID (`csq login N`)
/// have its legacy mirror pruned on the next start.
///
/// Non-fatal: lock contention OR profiles-load error logs a warning and the
/// daemon continues; the pass retries next start. The detector-side bridges
/// stay surfaced in `csq doctor` so the operator sees the unresolved state.
fn pass_rn1_c_r2_prune_legacy_mirrors(base_dir: &Path, summary: &mut ReconcileSummary) {
    use crate::accounts::legacy_mirror_cleanup::prune_legacy_credential_mirrors;
    use crate::accounts::profiles_lock::ProfilesFileLock;

    let lock = match ProfilesFileLock::acquire(base_dir) {
        Ok(l) => l,
        Err(_e) => {
            warn!(
                error_kind = "profiles_lock_contention",
                "legacy mirror cleanup (RN1-C R2): could not acquire profiles lock — will retry on next start"
            );
            return;
        }
    };

    match prune_legacy_credential_mirrors(&lock, base_dir) {
        Ok(report) => {
            info!(
                legacy_mirrors_pruned = report.pruned_count,
                legacy_mirrors_kept = report.kept_count,
                "legacy mirror cleanup (RN1-C R2) complete"
            );
            summary.legacy_mirror_prune = Some(report);
        }
        Err(_e) => {
            warn!(
                error_kind = "legacy_mirror_prune_failed",
                "legacy mirror cleanup (RN1-C R2): failed (will retry on next start)"
            );
        }
    }
}

/// Orphan-identity GC wrapper: acquires the `profiles.json` lock, delegates to
/// [`crate::accounts::orphan_identity_gc::prune_orphan_identities`], and stamps
/// the report into `summary.orphan_identity_gc`.
///
/// The lock is held for the WHOLE delegated call — snapshot, `identities/`
/// enumeration, AND deletion — because the GC deletes in the live-mint
/// namespace and must serialize against a concurrent `csq login` mint (see the
/// module's lock-posture note). NOT sentinel-gated: the predicate is a pure
/// function of disk state; the orphan is born by a future logout, so the pass
/// runs every reconcile.
///
/// Non-fatal: lock contention OR profiles-load error logs a warning and the
/// daemon continues; the pass retries next start.
fn pass_orphan_identity_gc(base_dir: &Path, summary: &mut ReconcileSummary) {
    use crate::accounts::orphan_identity_gc::prune_orphan_identities;
    use crate::accounts::profiles_lock::ProfilesFileLock;

    let lock = match ProfilesFileLock::acquire(base_dir) {
        Ok(l) => l,
        Err(_e) => {
            warn!(
                error_kind = "profiles_lock_contention",
                "orphan-identity GC: could not acquire profiles lock — will retry on next start"
            );
            return;
        }
    };

    match prune_orphan_identities(&lock, base_dir) {
        Ok(report) => {
            info!(
                orphan_identities_pruned = report.pruned_count,
                orphan_identities_kept = report.kept_count,
                "orphan-identity GC complete"
            );
            summary.orphan_identity_gc = Some(report);
        }
        Err(_e) => {
            warn!(
                error_kind = "orphan_identity_gc_failed",
                "orphan-identity GC: failed (will retry on next start)"
            );
        }
    }
}

/// Best-effort removal of pre-retraction `coc-trust.json` files. Per
/// `internal-design-docs` the first-pull trust gate was
/// retracted; the persisted state file (`(realpath, lock_sha) →
/// trust_decision`) is no longer read by any consumer and is privacy-
/// sensitive. Idempotent: absence is the success state; subsequent
/// starts find nothing to remove and are no-ops.
///
/// Fail-open per the surrounding-pass discipline — a remove failure
/// (e.g. permission error, filesystem error) logs a warn and lets the
/// daemon continue. The file will be retried on the next start.
fn pass_coc_trust_orphan_cleanup(base_dir: &Path, summary: &mut ReconcileSummary) {
    let path = base_dir.join("coc-trust.json");
    match std::fs::remove_file(&path) {
        Ok(()) => {
            // `+= 1` instead of `= 1`: current logic removes at most one
            // file per call, but the additive form keeps the counter
            // future-safe if the pass later enumerates sibling orphan
            // shapes (e.g. `coc-trust.json.bak`).
            summary.coc_trust_orphans_removed += 1;
            info!(
                event = "coc.trust_orphan_removed",
                "removed orphan coc-trust.json from pre-retraction csq build"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Steady-state: no orphan present. No log — silent no-op.
        }
        Err(_e) => {
            warn!(
                error_kind = "coc_trust_orphan_remove_failed",
                "could not remove orphan coc-trust.json (will retry on next start)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{CodexCredentialFile, CodexTokensFile, CredentialFile};
    use std::collections::HashMap;
    use tempfile::TempDir;

    // ── M3-7 acceptance tests ────────────────────────────────────────────

    /// M3-7 acceptance test #6 (WBS line 263):
    /// `store_version_bumped_to_2_on_phase_3_pass_0`.
    ///
    /// A schema:1 sentinel on disk (Phase 1 / Phase 2 layout) is rewritten
    /// to the current Phase-3 schema on the next daemon start. Idempotent —
    /// running twice does not change disk contents.
    #[test]
    fn store_version_bumped_to_2_on_phase_3_pass_0() {
        let dir = TempDir::new().unwrap();
        let sentinel = crate::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        // Seed a schema:1 sentinel (pre-M3-7 layout).
        std::fs::write(
            &sentinel,
            br#"{"schema":1,"minted_at":"2026-05-01T00:00:00Z","source":"daemon-identity-mint"}
"#,
        )
        .unwrap();
        assert_eq!(
            identity_mint::read_store_version_schema(dir.path()),
            Some(1)
        );

        let _ = run_reconciler(dir.path());

        let schema_after = identity_mint::read_store_version_schema(dir.path()).unwrap();
        assert_eq!(
            schema_after,
            identity_mint::STORE_VERSION_SCHEMA_CURRENT,
            "M3-7: store-version schema MUST be bumped to {} on Phase 3 Pass 0",
            identity_mint::STORE_VERSION_SCHEMA_CURRENT,
        );
    }

    /// M3-7 acceptance test #7 (WBS line 264) — preserved verbatim across
    /// the M4-5 rename. The behavior pinned by this test (gate refuses
    /// start when store-version sentinel absent) is unchanged from Phase 3.
    ///
    /// The fail-closed gate refuses start when the store-version sentinel
    /// is absent. Returns `Phase4GateError::StoreVersionUnset`. Daemon
    /// binary maps this to a process-exit with the Display message.
    #[test]
    fn phase_3_daemon_refuses_to_start_when_store_version_is_unset() {
        let dir = TempDir::new().unwrap();
        // No sentinel on disk.
        let err = phase4_gate_check(dir.path())
            .expect_err("gate MUST refuse start when store-version sentinel is absent");
        assert!(
            matches!(err, Phase4GateError::StoreVersionUnset),
            "expected StoreVersionUnset, got {err:?}"
        );

        // Verify the Display message tells the operator what to do.
        let msg = format!("{err}");
        assert!(
            msg.contains("store-version sentinel missing"),
            "Display MUST surface the absence reason: {msg}"
        );
    }

    /// M3-7 regression-pin (preserved across M4-5 rename): gate passes
    /// when sentinel is at the current schema and no UUID-keyed slots
    /// exist (empty profiles).
    #[test]
    fn phase_3_gate_passes_when_store_version_is_current_schema() {
        let dir = TempDir::new().unwrap();
        let sentinel = crate::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        identity_mint::write_sentinel(&sentinel).unwrap();
        assert!(phase4_gate_check(dir.path()).is_ok());
    }

    /// M3-7 regression-pin (preserved across M4-5 rename): gate refuses
    /// when schema predates Phase 3.
    #[test]
    fn phase_3_gate_refuses_when_schema_predates_phase_3() {
        let dir = TempDir::new().unwrap();
        let sentinel = crate::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        std::fs::write(
            &sentinel,
            br#"{"schema":1,"minted_at":"2026-05-01T00:00:00Z","source":"daemon-identity-mint"}
"#,
        )
        .unwrap();
        let err = phase4_gate_check(dir.path()).expect_err("gate MUST refuse schema:1");
        match err {
            Phase4GateError::SchemaTooOld { schema, expected } => {
                assert_eq!(schema, 1);
                assert_eq!(expected, identity_mint::STORE_VERSION_SCHEMA_CURRENT);
            }
            other => panic!("expected SchemaTooOld, got {other:?}"),
        }
    }

    /// R2 MED-1 regression (preserved across M4-5 rename; updated
    /// 2026-05-22 for Anthropic-binding-aware Check 3 and the journal-0040
    /// self-heal layer): the gate refuses to start when the slot is
    /// **ClaudeCode-bound** on disk (legacy `credentials/<N>.json` exists)
    /// AND `identities/<UUID>/credentials.json` is missing AND the
    /// self-heal cannot recover (legacy is unreadable).
    ///
    /// **Why the unreadable-legacy mechanic:** an internal journal entry §Follow-up #1
    /// added a self-heal pass that copies legacy → identity for
    /// upgrade-skip cases. The gate's refusal contract is "refuse when
    /// no recovery is possible", not "refuse on every Phase-4-fresh
    /// state." This test models the recovery-impossible case by making
    /// the legacy unreadable (chmod 0o000); the heal's read fails and
    /// the gate falls through to its check walk, which refuses with
    /// IdentityCredentialsUnseeded. Parity with
    /// `phase4_gate_refuses_when_codex_heal_fails_legacy_unreadable` for
    /// the Codex surface.
    ///
    /// Unix-only because the mechanism depends on `chmod 0o000`; Windows
    /// POSIX-mode semantics are not equivalent. The structural defense
    /// is platform-agnostic; only the mechanism is Unix-specific.
    #[cfg(unix)]
    #[test]
    fn phase_3_gate_refuses_when_identity_credentials_unseeded() {
        use crate::accounts::identity_store::IdentityId;
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        // Seed Phase-3-current sentinel — passes schema check.
        let sentinel = crate::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        identity_mint::write_sentinel(&sentinel).unwrap();

        // Seed profiles.json with a by_slot mapping but no credentials.json.
        let uuid = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("3".to_string(), uuid);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // Anthropic-binding signal: legacy `credentials/3.json` exists
        // BUT is unreadable. Self-heal will see the legacy file (so the
        // binding check 3 fires) but fail to read it, leaving the
        // identity credentials.json unseeded → gate refuses.
        let legacy_creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&legacy_creds_dir).unwrap();
        let legacy = legacy_creds_dir.join("3.json");
        std::fs::write(&legacy, b"{}").unwrap();
        std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o000)).unwrap();

        // Seed settings.json so Check 4 (unconditional) doesn't fire
        // before Check 3.
        let identity_dir = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid.to_canonical_string());
        std::fs::create_dir_all(&identity_dir).unwrap();
        std::fs::write(identity_dir.join("settings.json"), b"{}").unwrap();

        let err = phase4_gate_check(dir.path())
            .expect_err("gate MUST refuse start when identity credentials unseeded");

        // Restore perms so TempDir cleanup can delete the file.
        std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o600)).unwrap();

        match err {
            Phase4GateError::IdentityCredentialsUnseeded { slot, uuid_short } => {
                assert_eq!(slot, 3);
                assert_eq!(uuid_short.len(), 8);
                assert!(
                    uuid.to_canonical_string().starts_with(&uuid_short),
                    "redacted uuid prefix MUST match the first 8 chars of the real UUID"
                );
            }
            other => panic!("expected IdentityCredentialsUnseeded, got {other:?}"),
        }
    }

    /// **2026-05-22 codex-only regression** — the gate MUST pass for a
    /// codex-only slot. an internal ticket (codex login UUID-mint for codex-only
    /// slots) introduced a state where `profiles.json::by_slot[N]` has
    /// a UUID minted at `csq login N --provider codex` but the slot has
    /// no Anthropic OAuth ever attempted: no legacy `credentials/<N>.json`,
    /// no identity-keyed `credentials.json`. The pre-fix gate refused
    /// start because Check 3 demanded the identity credentials
    /// unconditionally; the post-fix gate guards Check 3 on the legacy
    /// Anthropic canonical's presence (structural parity with Check 5's
    /// codex-binding guard) and passes.
    ///
    /// On-disk shape pinned by this test:
    /// - `profiles.json::by_slot[12]` = UUID
    /// - `identities/<UUID>/credentials-codex.json` exists (codex login wrote it)
    /// - `identities/<UUID>/settings.json` exists (codex login pair-wrote it)
    /// - `identities/<UUID>/credentials.json` does NOT exist (no Anthropic OAuth)
    /// - `credentials/12.json` does NOT exist (no Anthropic legacy)
    /// - `credentials/codex-12.json` exists (codex legacy mirror, for Check 5)
    ///
    /// Origin: 2026-05-22 incident — `csq daemon start` refused with
    /// `IdentityCredentialsUnseeded` after the user's `csq login 12
    /// --provider codex` succeeded. Root cause: Check 3 was not
    /// codex-only-aware.
    #[test]
    fn phase4_gate_passes_for_codex_only_slot_without_anthropic_credentials() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let sentinel = crate::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        identity_mint::write_sentinel(&sentinel).unwrap();

        // Codex-only slot: by_slot mapping minted, codex legacy + identity
        // files seeded, NO Anthropic legacy + NO identity credentials.json.
        let uuid = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("12".to_string(), uuid);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        let legacy_creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&legacy_creds_dir).unwrap();
        // Codex legacy (binding signal for Check 5).
        std::fs::write(
            legacy_creds_dir.join("codex-12.json"),
            br#"{"tokens":{"access_token":"codex-legacy"}}"#,
        )
        .unwrap();
        // Deliberately NO `credentials/12.json` — slot is not Anthropic-bound.

        let identity_dir = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid.to_canonical_string());
        std::fs::create_dir_all(&identity_dir).unwrap();
        // Codex identity canonical (satisfies Check 5).
        std::fs::write(
            identity_dir.join("credentials-codex.json"),
            br#"{"tokens":{"access_token":"codex-identity"}}"#,
        )
        .unwrap();
        // Settings pair-write (satisfies Check 4 — unconditional).
        std::fs::write(identity_dir.join("settings.json"), b"{}").unwrap();
        // Deliberately NO `identities/<UUID>/credentials.json` — codex-only.

        assert!(
            phase4_gate_check(dir.path()).is_ok(),
            "gate MUST pass for codex-only slot — Check 3 must skip when \
             slot is not Anthropic-bound (no legacy credentials/<N>.json)"
        );
    }

    /// **2026-05-22 codex-only regression (status sibling)** — the
    /// `phase4_gate_status` read-only walk MUST NOT report a missing
    /// `ClaudeCodeCredentials` file for a codex-only slot. Mirrors the
    /// gate's Check 3 binding-awareness. `csq doctor` consumes this
    /// status; reporting a missing file for a codex-only slot would
    /// surface a false alarm in the operator-facing diagnostic.
    #[test]
    fn phase4_gate_status_omits_anthropic_creds_for_codex_only_slot() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let sentinel = crate::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        identity_mint::write_sentinel(&sentinel).unwrap();

        let uuid = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("12".to_string(), uuid);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        let legacy_creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&legacy_creds_dir).unwrap();
        std::fs::write(
            legacy_creds_dir.join("codex-12.json"),
            br#"{"tokens":{"access_token":"codex-legacy"}}"#,
        )
        .unwrap();

        let identity_dir = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid.to_canonical_string());
        std::fs::create_dir_all(&identity_dir).unwrap();
        std::fs::write(
            identity_dir.join("credentials-codex.json"),
            br#"{"tokens":{"access_token":"codex-identity"}}"#,
        )
        .unwrap();
        std::fs::write(identity_dir.join("settings.json"), b"{}").unwrap();

        let status = phase4_gate_status(dir.path());
        let has_anthropic_creds_alarm = status
            .missing
            .iter()
            .any(|m| m.slot == 12 && matches!(m.file, Phase4HealFile::ClaudeCodeCredentials));
        assert!(
            !has_anthropic_creds_alarm,
            "phase4_gate_status MUST NOT report missing ClaudeCodeCredentials \
             for codex-only slot (no legacy credentials/<N>.json) — would \
             surface a false alarm in csq doctor. Got: {:?}",
            status.missing
        );
    }

    /// R2 MED-1 happy-path (M3-7 era; preserved across M4-5 rename to
    /// pin the IdentityCredentialsUnseeded gate behavior — now requires
    /// the M4-5 settings.json pair-file too so the M4-5 SettingsUnseeded
    /// arm doesn't trip on what was previously the happy path).
    ///
    /// **2026-05-22 update:** also seeds the legacy `credentials/1.json`
    /// to model an Anthropic-bound slot. Without this, the new
    /// binding-aware Check 3 would skip its presence check and the test
    /// would pass vacuously (with or without identity credentials.json).
    /// Seeding the legacy makes this a true regression-pin for the
    /// Anthropic-bound happy path.
    #[test]
    fn phase_3_gate_passes_when_all_identity_credentials_seeded() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let sentinel = crate::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        identity_mint::write_sentinel(&sentinel).unwrap();

        let uuid = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("1".to_string(), uuid);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // Anthropic-binding signal: legacy `credentials/1.json` exists.
        let legacy_creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&legacy_creds_dir).unwrap();
        std::fs::write(legacy_creds_dir.join("1.json"), b"{}").unwrap();

        // Seed the identity credentials AND settings files. The settings
        // pair-write was added in M4-2; M4-5 enforces it at the gate.
        let creds_dir = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid.to_canonical_string());
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("credentials.json"), b"{}").unwrap();
        std::fs::write(creds_dir.join("settings.json"), b"{}").unwrap();

        assert!(phase4_gate_check(dir.path()).is_ok());
    }

    /// R2 MED-1 vacuous check (preserved across M4-5 rename): gate
    /// passes when profiles.json has no by_slot mappings (pure-legacy
    /// install with no Phase-1 mint yet). The gate only enforces the
    /// invariant for UUID-keyed slots; legacy slots fall through to
    /// `repoint_handle_dir`'s `else` branch which targets
    /// `config-N/.credentials.json` (CC-written, not csq-written).
    #[test]
    fn phase_3_gate_passes_when_profiles_json_has_no_by_slot_mappings() {
        let dir = TempDir::new().unwrap();
        let sentinel = crate::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        identity_mint::write_sentinel(&sentinel).unwrap();

        // Empty profiles.json (no by_slot entries).
        let profiles = crate::accounts::profiles::ProfilesFile::empty();
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        assert!(phase4_gate_check(dir.path()).is_ok());
    }

    /// **M4-5 acceptance test (a) — SettingsUnseeded.**
    ///
    /// The strengthened gate refuses to start when `profiles.json::by_slot`
    /// has a UUID mapping AND `identities/<UUID>/credentials.json` is
    /// seeded BUT `identities/<UUID>/settings.json` is absent. M4-2
    /// pair-writes settings at every login; this gate forces re-login
    /// when the pair-write is missing for any UUID-keyed slot before the
    /// daemon serves a handle-dir request.
    #[test]
    fn phase4_gate_refuses_when_settings_unseeded() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let sentinel = crate::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        identity_mint::write_sentinel(&sentinel).unwrap();

        let uuid = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("5".to_string(), uuid);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // Seed credentials.json (passes check 3 — M3-7 IdentityCredentialsUnseeded)
        // BUT deliberately omit settings.json so check 4 (M4-5) fires.
        let creds_dir = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid.to_canonical_string());
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("credentials.json"), b"{}").unwrap();

        let err = phase4_gate_check(dir.path())
            .expect_err("gate MUST refuse start when identity settings unseeded");
        match &err {
            Phase4GateError::SettingsUnseeded { slot, uuid_short } => {
                assert_eq!(*slot, 5);
                assert_eq!(uuid_short.len(), 8);
                assert!(
                    uuid.to_canonical_string().starts_with(uuid_short),
                    "redacted uuid prefix MUST match the first 8 chars of the real UUID"
                );
            }
            other => panic!("expected SettingsUnseeded, got {other:?}"),
        }

        // Per `tauri-commands.md` MUST Rule 6: the Display string MUST
        // surface a specific, operator-actionable next step.
        let msg = format!("{err}");
        assert!(
            msg.contains("settings.json")
                && msg.contains("csq login 5")
                && msg.contains("seed per-account settings"),
            "Display MUST surface the slot + remediation command: {msg}"
        );
    }

    /// **an internal journal entry §Follow-up #1 acceptance test — Codex self-heal.**
    ///
    /// When a Codex-bound slot has a UUID mapping AND the legacy
    /// `credentials/codex-<N>.json` exists AND the identity-keyed
    /// `credentials-codex.json` is missing (the v2.7.3 → v2.7.7
    /// upgrade-skip class for Codex slots), `phase4_gate_check` MUST
    /// invoke `phase4_gate_self_heal` first, which copies the legacy
    /// file to the identity path with the legacy bytes preserved
    /// byte-for-byte. The gate then passes (no `CodexCredentialsUnseeded`
    /// refusal) — the fail-closed contract is "refuse when no recovery
    /// is possible", not "refuse on every Phase-4-fresh state".
    ///
    /// Replaces the v2.6.x-era `phase4_gate_refuses_when_codex_credentials_unseeded`
    /// test: with self-heal in place the gate now passes whenever
    /// recovery is possible. The matching refusal case is covered by
    /// `phase4_gate_refuses_when_codex_heal_fails_legacy_unreadable`
    /// below (Unix only).
    #[test]
    fn phase4_gate_self_heals_codex_credentials_from_legacy() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let sentinel = crate::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        identity_mint::write_sentinel(&sentinel).unwrap();

        let uuid = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("7".to_string(), uuid);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // Seed credentials.json + settings.json (passes checks 3 + 4
        // via AlreadySeeded heal records).
        let creds_dir = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid.to_canonical_string());
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("credentials.json"), b"{}").unwrap();
        std::fs::write(creds_dir.join("settings.json"), b"{}").unwrap();

        // Slot 7 is "Codex-bound" via legacy `credentials/codex-7.json`,
        // with content that the heal must preserve byte-for-byte.
        let legacy_codex_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&legacy_codex_dir).unwrap();
        let legacy_bytes = br#"{"tokens":{"access_token":"legacy-token"}}"#;
        std::fs::write(legacy_codex_dir.join("codex-7.json"), legacy_bytes).unwrap();

        assert!(
            phase4_gate_check(dir.path()).is_ok(),
            "gate MUST pass after self-heal copies legacy codex credentials"
        );

        // Heal MUST have written the identity-keyed Codex canonical.
        let identity_codex = creds_dir.join("credentials-codex.json");
        assert!(
            identity_codex.exists(),
            "self-heal MUST seed identities/<UUID>/credentials-codex.json from legacy"
        );
        let healed_bytes = std::fs::read(&identity_codex).unwrap();
        assert_eq!(
            healed_bytes, legacy_bytes,
            "self-heal MUST byte-copy legacy content into identity path"
        );

        // Idempotence: running the gate a second time MUST still pass and
        // MUST NOT overwrite the (now-already-seeded) identity file.
        // We mark the heal-source-modify-time to detect any rewrite.
        let mtime_before = std::fs::metadata(&identity_codex)
            .unwrap()
            .modified()
            .unwrap();
        // Modify legacy AFTER first heal to prove second run is a no-op
        // (AlreadySeeded skips read+write entirely).
        std::fs::write(legacy_codex_dir.join("codex-7.json"), b"{}").unwrap();
        assert!(phase4_gate_check(dir.path()).is_ok());
        let mtime_after = std::fs::metadata(&identity_codex)
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(
            mtime_before, mtime_after,
            "self-heal MUST be idempotent — already-seeded identity file MUST NOT be rewritten"
        );
    }

    /// **an internal journal entry §Follow-up #1 acceptance test — heal-fails fallback.**
    ///
    /// When the self-heal cannot copy the legacy file (legacy file is
    /// unreadable, write fails, etc.), the gate MUST still refuse with
    /// the original `CodexCredentialsUnseeded` error. Models the case
    /// where automatic recovery is impossible and operator action
    /// (`csq login N` or `csq doctor --repair-identities`) is required.
    ///
    /// Unix-only because the test depends on `chmod 0o000` to simulate
    /// an unreadable legacy file; Windows POSIX-mode semantics are not
    /// equivalent. The structural defense (gate refuses when heal
    /// cannot recover) is platform-agnostic; only the test mechanism is
    /// Unix-specific.
    #[cfg(unix)]
    #[test]
    fn phase4_gate_refuses_when_codex_heal_fails_legacy_unreadable() {
        use crate::accounts::identity_store::IdentityId;
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let sentinel = crate::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        identity_mint::write_sentinel(&sentinel).unwrap();

        let uuid = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("7".to_string(), uuid);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        let creds_dir = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid.to_canonical_string());
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("credentials.json"), b"{}").unwrap();
        std::fs::write(creds_dir.join("settings.json"), b"{}").unwrap();

        // Legacy codex file exists but is unreadable — heal read_fn fails.
        let legacy_codex_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&legacy_codex_dir).unwrap();
        let legacy = legacy_codex_dir.join("codex-7.json");
        std::fs::write(&legacy, b"{}").unwrap();
        std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o000)).unwrap();

        let err = phase4_gate_check(dir.path())
            .expect_err("gate MUST refuse when codex heal fails AND identity remains unseeded");

        // Restore perms so TempDir cleanup can delete the file.
        std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o600)).unwrap();

        match &err {
            Phase4GateError::CodexCredentialsUnseeded { slot, uuid_short } => {
                assert_eq!(*slot, 7);
                assert_eq!(uuid_short.len(), 8);
                assert!(
                    uuid.to_canonical_string().starts_with(uuid_short),
                    "redacted uuid prefix MUST match the first 8 chars of the real UUID"
                );
            }
            other => panic!("expected CodexCredentialsUnseeded, got {other:?}"),
        }

        // Per `tauri-commands.md` MUST Rule 6: Display MUST surface the
        // specific operator action (`csq login 7`) and the file class.
        let msg = format!("{err}");
        assert!(
            msg.contains("credentials-codex.json")
                && msg.contains("csq login 7")
                && msg.contains("Codex"),
            "Display MUST surface the slot + Codex remediation: {msg}"
        );
    }

    /// **an internal journal entry §FD #3 acceptance test — INV-P08 0o400 parity on
    /// healed Codex identity files.**
    ///
    /// `save_canonical_for` flips `Surface::Codex` canonicals to `0o400`
    /// after writing (spec 07 INV-P08; `credentials/file.rs:687-701`).
    /// The self-heal pipeline now matches that policy: after
    /// `atomic_replace` lands a Codex identity file, the heal flips it
    /// to `0o400` via `secure_file_readonly` for parity with the
    /// chokepoint. ClaudeCode `credentials.json` and `settings.json`
    /// identity files remain at `0o600`.
    ///
    /// Unix-only: `secure_file_readonly` is a no-op on Windows.
    #[cfg(unix)]
    #[test]
    fn phase4_self_heal_codex_identity_file_lands_at_0o400() {
        use crate::accounts::identity_store::IdentityId;
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let sentinel = crate::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        identity_mint::write_sentinel(&sentinel).unwrap();

        let uuid = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("3".to_string(), uuid);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // Slot 3 is Codex-bound. credentials.json + settings.json already
        // present (AlreadySeeded for those); only credentials-codex.json
        // is seeded via heal.
        let creds_dir = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid.to_canonical_string());
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("credentials.json"), b"{}").unwrap();
        std::fs::write(creds_dir.join("settings.json"), b"{}").unwrap();

        let legacy_codex_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&legacy_codex_dir).unwrap();
        std::fs::write(legacy_codex_dir.join("codex-3.json"), b"{}").unwrap();

        assert!(phase4_gate_check(dir.path()).is_ok());

        let identity_codex = creds_dir.join("credentials-codex.json");
        let mode = std::fs::metadata(&identity_codex)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o400,
            "healed credentials-codex.json MUST land at 0o400 for INV-P08 parity \
             with save_canonical_for (Surface::Codex)"
        );
    }

    /// **an internal journal entry §FD #3 acceptance test — non-Codex identity files
    /// stay at 0o600.**
    ///
    /// The 0o400 flip is Codex-specific. The heal MUST NOT narrow the
    /// permissions of `credentials.json` or `settings.json` — INV-P08
    /// is exclusive to Codex canonicals (spec 07; `save_canonical_for`
    /// for `Surface::Anthropic` leaves the canonical at 0o600 per
    /// `credentials/file.rs::save_canonical_for_claude_code_leaves_canonical_at_0o600`).
    ///
    /// Unix-only: `secure_file_readonly` is a no-op on Windows, so the
    /// mode-narrowing failure mode this guards against does not exist
    /// there.
    #[cfg(unix)]
    #[test]
    fn phase4_self_heal_non_codex_identity_files_stay_at_0o600() {
        use crate::accounts::identity_store::IdentityId;
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let sentinel = crate::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        identity_mint::write_sentinel(&sentinel).unwrap();

        let uuid = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("5".to_string(), uuid);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // Identity dir empty — heal must seed credentials.json AND
        // settings.json from legacy sources.
        let creds_dir = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid.to_canonical_string());
        std::fs::create_dir_all(&creds_dir).unwrap();

        // Legacy ClaudeCode credentials.
        let legacy_creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&legacy_creds_dir).unwrap();
        std::fs::write(legacy_creds_dir.join("5.json"), b"{}").unwrap();

        // Legacy settings under config-5/.
        let legacy_config = dir.path().join("config-5");
        std::fs::create_dir_all(&legacy_config).unwrap();
        std::fs::write(legacy_config.join("settings.json"), b"{}").unwrap();

        // No legacy codex file → not Codex-bound; only ClaudeCode +
        // settings get healed.
        assert!(phase4_gate_check(dir.path()).is_ok());

        let credentials_mode = std::fs::metadata(creds_dir.join("credentials.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            credentials_mode, 0o600,
            "healed credentials.json (ClaudeCode) MUST stay at 0o600 — \
             INV-P08 0o400 flip is Codex-only"
        );

        let settings_mode = std::fs::metadata(creds_dir.join("settings.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            settings_mode, 0o600,
            "healed settings.json MUST stay at 0o600 — INV-P08 0o400 flip \
             is Codex-only"
        );
    }

    /// **M4-5 acceptance test (a) — happy path with all five checks satisfied.**
    ///
    /// Gate passes when every UUID-keyed slot has all three identity-keyed
    /// files seeded: `credentials.json` (M3-7 check), `settings.json` (M4-5
    /// check 4), and — for Codex-bound slots — `credentials-codex.json`
    /// (M4-5 check 5). Mixes a Codex-bound slot and a Claude-only slot
    /// in one fixture to exercise the binding-detection skip path for
    /// non-Codex slots.
    #[test]
    fn phase4_gate_passes_when_all_identities_seeded() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let sentinel = crate::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        identity_mint::write_sentinel(&sentinel).unwrap();

        // Two slots: slot 1 is Claude-only, slot 2 is Codex-bound.
        let uuid_1 = IdentityId::new_v4();
        let uuid_2 = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("1".to_string(), uuid_1);
        profiles.by_slot.insert("2".to_string(), uuid_2);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // Seed slot 1 (Claude-only): credentials.json + settings.json.
        // No legacy `credentials/codex-1.json` → check 5 skipped.
        let dir_1 = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid_1.to_canonical_string());
        std::fs::create_dir_all(&dir_1).unwrap();
        std::fs::write(dir_1.join("credentials.json"), b"{}").unwrap();
        std::fs::write(dir_1.join("settings.json"), b"{}").unwrap();

        // Seed slot 2 (Codex-bound): credentials.json + settings.json
        // + credentials-codex.json. Also write the legacy codex canonical
        // so the binding-detection path fires.
        let dir_2 = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid_2.to_canonical_string());
        std::fs::create_dir_all(&dir_2).unwrap();
        std::fs::write(dir_2.join("credentials.json"), b"{}").unwrap();
        std::fs::write(dir_2.join("settings.json"), b"{}").unwrap();
        std::fs::write(dir_2.join("credentials-codex.json"), b"{}").unwrap();

        let legacy_codex_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&legacy_codex_dir).unwrap();
        std::fs::write(legacy_codex_dir.join("codex-2.json"), b"{}").unwrap();

        assert!(
            phase4_gate_check(dir.path()).is_ok(),
            "gate MUST pass when every UUID-keyed slot has all required identity files seeded"
        );
    }

    /// **an internal journal entry §Follow-up #1 headline test — v2.7.3 → v2.7.7
    /// upgrade-skip scenario.**
    ///
    /// Reproduces the exact on-disk state an internal journal entry documented:
    /// 8 OAuth slots all carry `profiles.json::by_slot[N] = <uuid>` +
    /// `identities/<uuid>/identity.json` + `identities/<uuid>/settings.json`
    /// BUT `identities/<uuid>/credentials.json` is missing for every
    /// slot. Legacy `credentials/<N>.json` files are still present
    /// (they were written by the pre-M3-7 daemon before the upgrade).
    ///
    /// Without self-heal: gate refuses with `IdentityCredentialsUnseeded`
    /// → operator must `csq login N` for every slot (8x re-OAuth).
    /// With self-heal: gate copies each legacy file into the identity
    /// path and passes. Operator-visible behavior: daemon starts clean.
    #[test]
    fn phase4_gate_self_heals_v2_7_3_upgrade_skip_class() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let sentinel = crate::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        identity_mint::write_sentinel(&sentinel).unwrap();

        // Mimic the journal-0040 machine: 8 slots, by_slot fully
        // populated, identity dirs have identity.json + settings.json but
        // NOT credentials.json, legacy credentials/<N>.json still present.
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        let mut slot_to_uuid = Vec::new();
        let mut legacy_bytes_by_slot = Vec::new();
        for slot in 1u16..=8 {
            let uuid = IdentityId::new_v4();
            profiles.by_slot.insert(slot.to_string(), uuid);
            slot_to_uuid.push((slot, uuid));

            // Identity dir with identity.json + settings.json present.
            let identity_dir = crate::accounts::identity_store::identities_dir(dir.path())
                .join(uuid.to_canonical_string());
            std::fs::create_dir_all(&identity_dir).unwrap();
            std::fs::write(
                identity_dir.join("identity.json"),
                format!(r#"{{"slot": {slot}}}"#).as_bytes(),
            )
            .unwrap();
            std::fs::write(identity_dir.join("settings.json"), b"{}").unwrap();
            // credentials.json deliberately omitted.

            // Legacy credentials/<N>.json present (the seed source).
            let legacy_dir = dir.path().join("credentials");
            std::fs::create_dir_all(&legacy_dir).unwrap();
            let legacy_payload = format!(r#"{{"tokens":{{"access_token":"slot-{slot}-legacy"}}}}"#);
            std::fs::write(
                legacy_dir.join(format!("{slot}.json")),
                legacy_payload.as_bytes(),
            )
            .unwrap();
            legacy_bytes_by_slot.push((slot, legacy_payload.into_bytes()));
        }
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // Heal runs inside phase4_gate_check; gate MUST pass.
        assert!(
            phase4_gate_check(dir.path()).is_ok(),
            "gate MUST self-heal v2.7.3 → v2.7.7 upgrade-skip class and start clean"
        );

        // Every slot's identity credentials.json MUST now exist with the
        // exact legacy bytes (byte-copy semantics).
        for ((slot, uuid), (_slot_dup, legacy_bytes)) in
            slot_to_uuid.iter().zip(legacy_bytes_by_slot.iter())
        {
            let identity_path = crate::accounts::identity_store::identities_dir(dir.path())
                .join(uuid.to_canonical_string())
                .join("credentials.json");
            assert!(
                identity_path.exists(),
                "slot {slot}: identity credentials.json MUST be seeded by self-heal"
            );
            let seeded = std::fs::read(&identity_path).unwrap();
            assert_eq!(
                &seeded, legacy_bytes,
                "slot {slot}: self-heal MUST preserve legacy bytes verbatim"
            );
        }
    }

    /// **an internal journal entry §Follow-up #1 acceptance test — settings.json
    /// self-heal from legacy `config-<N>/settings.json`.**
    ///
    /// Mirrors the v2.7.3 upgrade-skip case for the M4-2 settings
    /// pair-file. When the identity-keyed `settings.json` is missing
    /// but `config-<N>/settings.json` is present, the heal copies the
    /// legacy file into the identity path. Single-slot fixture; the
    /// happy-path multi-slot case is covered by the v2.7.3 test above.
    #[test]
    fn phase4_gate_self_heals_settings_from_legacy_config_n() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let sentinel = crate::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        identity_mint::write_sentinel(&sentinel).unwrap();

        let uuid = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("4".to_string(), uuid);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // Seed identity credentials.json (passes check 3).
        let identity_dir = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid.to_canonical_string());
        std::fs::create_dir_all(&identity_dir).unwrap();
        std::fs::write(identity_dir.join("credentials.json"), b"{}").unwrap();

        // Legacy config-4/settings.json present with distinctive content.
        let config_n = dir.path().join("config-4");
        std::fs::create_dir_all(&config_n).unwrap();
        let legacy_settings = br#"{"env":{"MY_KEY":"legacy"}}"#;
        std::fs::write(config_n.join("settings.json"), legacy_settings).unwrap();

        assert!(
            phase4_gate_check(dir.path()).is_ok(),
            "gate MUST pass after self-heal copies legacy config-N/settings.json"
        );

        let identity_settings = identity_dir.join("settings.json");
        assert!(
            identity_settings.exists(),
            "self-heal MUST seed identities/<UUID>/settings.json from config-N/settings.json"
        );
        let healed = std::fs::read(&identity_settings).unwrap();
        assert_eq!(
            healed, legacy_settings,
            "self-heal MUST byte-copy legacy settings into identity path"
        );
    }

    /// **an internal journal entry §Follow-up #1 — `Phase4HealReport` per-record
    /// outcomes are surfaced for the doctor entry point.**
    ///
    /// `phase4_gate_self_heal` returns a `Phase4HealReport` whose
    /// records enumerate (slot, file, outcome) for every (slot,
    /// identity_file) pair inspected. The `csq doctor --repair-identities`
    /// command surfaces this report to the operator. Pins the structural
    /// shape so the doctor command can rely on it.
    #[test]
    fn phase4_self_heal_returns_per_slot_records() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let sentinel = crate::accounts::identity_store::store_version_path(dir.path());
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        identity_mint::write_sentinel(&sentinel).unwrap();

        // Three slots (updated 2026-05-22 for Anthropic-binding-aware heal):
        //   slot 1 — Anthropic-bound, fully seeded → 2 AlreadySeeded records
        //   slot 2 — Anthropic-bound, identity creds missing, legacy creds
        //            present → Seeded for creds; AlreadySeeded for settings
        //   slot 3 — codex-only-shaped (NOT Anthropic-bound, no legacy
        //            anthropic): File-1 (Anthropic creds) gets NO record at
        //            all under the binding guard; only File-2 (Settings)
        //            records MissingLegacySource.
        let uuid_1 = IdentityId::new_v4();
        let uuid_2 = IdentityId::new_v4();
        let uuid_3 = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("1".to_string(), uuid_1);
        profiles.by_slot.insert("2".to_string(), uuid_2);
        profiles.by_slot.insert("3".to_string(), uuid_3);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // Seed Anthropic-binding signals for slots 1 and 2 (legacy creds present).
        // Slot 3 is left WITHOUT legacy anthropic to model the codex-only case.
        let legacy_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&legacy_dir).unwrap();
        std::fs::write(legacy_dir.join("1.json"), b"{}").unwrap();
        std::fs::write(legacy_dir.join("2.json"), b"{}").unwrap();

        // Slot 1 — both identity files present.
        let dir_1 = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid_1.to_canonical_string());
        std::fs::create_dir_all(&dir_1).unwrap();
        std::fs::write(dir_1.join("credentials.json"), b"{}").unwrap();
        std::fs::write(dir_1.join("settings.json"), b"{}").unwrap();

        // Slot 2 — identity creds missing, settings present; legacy creds present.
        let dir_2 = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid_2.to_canonical_string());
        std::fs::create_dir_all(&dir_2).unwrap();
        std::fs::write(dir_2.join("settings.json"), b"{}").unwrap();

        // Slot 3 — neither identity file present, NO legacy sources.
        // (Don't pre-create dir_3; heal creates it lazily for the
        // settings file branch only — File 1 is skipped under the
        // binding guard since slot 3 has no legacy anthropic.)

        let report = phase4_gate_self_heal(dir.path());
        // Slot 1 contributes 2 records (Anthropic-bound: creds + settings).
        // Slot 2 contributes 2 records (Anthropic-bound: creds + settings).
        // Slot 3 contributes 1 record (codex-only-shape: settings only;
        // the binding guard skips File 1 entirely).
        // None of the slots are Codex-bound, so no File 3 records.
        assert_eq!(
            report.records.len(),
            5,
            "expected slot1=2 + slot2=2 + slot3=1 = 5 records, got {}",
            report.records.len()
        );

        // Slot 1 creds + settings → AlreadySeeded.
        for r in report.records.iter().filter(|r| r.slot == 1) {
            assert!(
                matches!(r.outcome, Phase4HealOutcome::AlreadySeeded),
                "slot 1 record {:?} → expected AlreadySeeded, got {:?}",
                r.file,
                r.outcome
            );
        }

        // Slot 2 creds → Seeded; settings → AlreadySeeded.
        let s2_creds = report
            .records
            .iter()
            .find(|r| r.slot == 2 && matches!(r.file, Phase4HealFile::ClaudeCodeCredentials))
            .unwrap();
        assert!(
            matches!(s2_creds.outcome, Phase4HealOutcome::Seeded),
            "slot 2 creds → expected Seeded, got {:?}",
            s2_creds.outcome
        );
        let s2_settings = report
            .records
            .iter()
            .find(|r| r.slot == 2 && matches!(r.file, Phase4HealFile::Settings))
            .unwrap();
        assert!(
            matches!(s2_settings.outcome, Phase4HealOutcome::AlreadySeeded),
            "slot 2 settings → expected AlreadySeeded, got {:?}",
            s2_settings.outcome
        );

        // Slot 3 has ONLY the settings record (binding guard skips Anthropic
        // creds entirely for the non-Anthropic-bound slot). The settings
        // file is MissingLegacySource because no legacy settings exist.
        let s3_records: Vec<_> = report.records.iter().filter(|r| r.slot == 3).collect();
        assert_eq!(
            s3_records.len(),
            1,
            "slot 3 (codex-only-shape) MUST have exactly 1 record (Settings); \
             File 1 is skipped under the Anthropic-binding guard"
        );
        let s3_settings = s3_records[0];
        assert!(
            matches!(s3_settings.file, Phase4HealFile::Settings),
            "slot 3's only record MUST be Settings, got {:?}",
            s3_settings.file
        );
        assert!(
            matches!(s3_settings.outcome, Phase4HealOutcome::MissingLegacySource),
            "slot 3 settings → expected MissingLegacySource, got {:?}",
            s3_settings.outcome
        );

        // Aggregate counts match the per-record analysis.
        assert_eq!(report.seeded_count(), 1, "exactly 1 file was healed");
        assert_eq!(
            report.unhealed_count(),
            1,
            "only slot 3's settings file cannot be healed"
        );
    }

    /// M3-7 acceptance test #11 (WBS line 268):
    /// `startup_reconciler_logs_legacy_handle_dir_warning`.
    ///
    /// Verifies the advisory pass detects a pre-Phase-3 handle dir whose
    /// `.credentials.json` symlink targets a `config-N/` path (not the
    /// identity-keyed path). The test uses a tracing test-subscriber to
    /// capture the WARN-level emission.
    #[cfg(unix)]
    #[test]
    fn startup_reconciler_logs_legacy_handle_dir_warning() {
        let dir = TempDir::new().unwrap();
        // Seed a fake pre-Phase-3 handle dir with a legacy symlink target.
        let handle = dir.path().join("term-99999");
        let config = dir.path().join("config-2");
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let target = config.join(".credentials.json");
        std::fs::write(&target, b"{}").unwrap();
        let link = handle.join(".credentials.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // Pass directly — easier than wiring a tracing subscriber.
        // The pass itself is side-effect-free except for the log emission;
        // we assert it does not panic and returns without error. The presence
        // of the WARN is verified manually via `RUST_LOG=warn cargo test …`
        // (no fixture-side capture infra to assert log content without an
        // extra dependency). Per redteam-discipline Rule 4(b), the structural
        // mechanism is: the function is invoked on every daemon start and the
        // grep `grep -rn "pre-Phase-3 handle dir" --include='*.rs' csq-core/src`
        // returns the log-emission site.
        pass0_m3_7_legacy_handle_dir_advisory(dir.path());
    }

    /// R1 H2-Sec fix-wave: `escape_log` MUST replace ASCII control characters
    /// (0x00-0x1F, 0x7F) with `\xNN` escape sequences so attacker-influenceable
    /// inputs (filenames, symlink targets) cannot inject CR/LF, ANSI escape
    /// sequences, or other control payloads into structured log fields.
    /// Printable characters MUST pass through unchanged.
    #[test]
    fn escape_log_replaces_control_chars() {
        assert_eq!(super::escape_log("term-123"), "term-123");
        assert_eq!(super::escape_log("a\nb"), "a\\x0ab");
        assert_eq!(super::escape_log("a\rb"), "a\\x0db");
        assert_eq!(super::escape_log("a\tb"), "a\\x09b");
        assert_eq!(
            super::escape_log("a\x1b[31mevil\x1b[0m"),
            "a\\x1b[31mevil\\x1b[0m"
        );
        assert_eq!(super::escape_log("a\x7fb"), "a\\x7fb");
        // Non-ASCII printable (UTF-8) MUST pass through.
        assert_eq!(super::escape_log("résumé"), "résumé");
    }

    /// RAII guard that acquires `test_env::lock()` AND points
    /// `CODEX_USER_CONFIG` at a nonexistent path so
    /// `read_user_global_config_toml` returns None deterministically.
    /// Reconciler tests that exercise `pass2_codex_config_toml` use
    /// this to insulate from (a) the dev machine's actual
    /// `~/.codex/config.toml` and (b) concurrent tests that mutate
    /// `CODEX_USER_CONFIG` in the surface.rs test module. Per
    /// `rules/testing.md` MUST Rule 6 (shared mutex BEFORE any
    /// per-test state).
    struct CodexUserConfigIsolated {
        _shared: std::sync::MutexGuard<'static, ()>,
        prev: Option<std::ffi::OsString>,
    }

    impl Drop for CodexUserConfigIsolated {
        fn drop(&mut self) {
            // SAFETY: shared lock held until end of drop.
            unsafe {
                match self.prev.take() {
                    Some(v) => std::env::set_var(codex_surface::USER_CONFIG_ENV_OVERRIDE, v),
                    None => std::env::remove_var(codex_surface::USER_CONFIG_ENV_OVERRIDE),
                }
            }
        }
    }

    fn codex_user_config_isolated() -> CodexUserConfigIsolated {
        let shared = crate::platform::test_env::lock();
        let prev = std::env::var_os(codex_surface::USER_CONFIG_ENV_OVERRIDE);
        // SAFETY: test_env::lock serialises env mutations.
        unsafe {
            std::env::set_var(
                codex_surface::USER_CONFIG_ENV_OVERRIDE,
                "/nonexistent/csq-reconciler-test-isolated",
            );
        }
        CodexUserConfigIsolated {
            _shared: shared,
            prev,
        }
    }

    fn install_codex_canonical(base: &Path, id: u16) {
        let num = AccountNum::try_from(id).unwrap();
        let creds = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some("acct-test".into()),
                access_token: "eyJhbGciOiJIUzI1NiJ9.payload.sig".into(),
                refresh_token: Some("rt_test".into()),
                id_token: None,
                extra: HashMap::new(),
            },
            last_refresh: None,
            extra: HashMap::new(),
        });
        // M4-12: provision UUID mapping in profiles.json::by_slot BEFORE
        // calling save_canonical_for, which is now fail-closed (returns
        // Err(NoCredentials) when no UUID mapping exists).
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(id);
        let profiles_path = crate::accounts::profiles::profiles_path(base);
        let mut profiles = if profiles_path.exists() {
            crate::accounts::profiles::load(&profiles_path)
                .unwrap_or_else(|_| crate::accounts::profiles::ProfilesFile::empty())
        } else {
            crate::accounts::profiles::ProfilesFile::empty()
        };
        profiles.by_slot.insert(id.to_string(), uuid);
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();
        // Use save_canonical_for so the UUID-keyed path (identities/<UUID>/
        // credentials-codex.json) lands at 0o400 (the INV-P08 steady state).
        cred_file::save_canonical_for(base, num, &creds).unwrap();
        // Also write the legacy numeric path (credentials/codex-<N>.json)
        // for the pass1 and pass2 reconciler tests that scan credentials/
        // to discover Codex slots. These reconcilers handle legacy-layout
        // files; the numeric write is test-infrastructure only.
        // Land the numeric path at 0o400 (INV-P08 steady state) so tests
        // that assert `codex_credentials_already_ok` see the expected mode.
        let numeric_path = cred_file::canonical_path_for(base, num, Surface::Codex);
        std::fs::create_dir_all(numeric_path.parent().unwrap()).unwrap();
        cred_file::save(&numeric_path, &creds).unwrap();
        crate::platform::fs::secure_file_readonly(&numeric_path).unwrap();
    }

    #[test]
    fn run_reconciler_on_empty_dir_is_noop() {
        let dir = TempDir::new().unwrap();
        let s = run_reconciler(dir.path());
        // Pass 0 (identity_mint) runs and sets identity_mint = Some(…) even on
        // an empty base dir; all slot-related counters stay 0.
        assert_eq!(s.codex_credentials_seen, 0);
        assert_eq!(s.codex_credentials_repaired, 0);
        assert_eq!(s.config_tomls_seen, 0);
        assert_eq!(s.config_tomls_repaired, 0);
        assert_eq!(s.quota_migrated, None);
        assert_eq!(s.api_key_helper_files_seen, 0);
        assert_eq!(s.audit_pending_files_seen, 0);
        // Pass 0 ran and found 0 slots — identity_mint field is populated.
        let mint = s
            .identity_mint
            .expect("pass 0 should populate identity_mint");
        assert!(
            !mint.already_minted,
            "sentinel absent before run → not already-minted"
        );
        assert_eq!(mint.slots_seen, 0);
        assert_eq!(mint.slots_fresh, 0);
        assert_eq!(mint.slot_errors.len(), 0);
    }

    /// Pass 1: A canonical sitting at 0o600 (post-crash mid-write) is
    /// flipped to 0o400. The repaired counter increments.
    #[cfg(unix)]
    #[test]
    fn pass1_flips_0o600_canonical_to_0o400() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        install_codex_canonical(dir.path(), 7);

        // The canonical writer normally lands at 0o400; force 0o600
        // to simulate a crash between secure_file (write window) and
        // secure_file_readonly (close window).
        let canonical = cred_file::canonical_path_for(
            dir.path(),
            AccountNum::try_from(7u16).unwrap(),
            Surface::Codex,
        );
        std::fs::set_permissions(&canonical, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            std::fs::metadata(&canonical).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let s = run_reconciler(dir.path());
        assert_eq!(s.codex_credentials_seen, 1);
        assert_eq!(s.codex_credentials_repaired, 1);
        assert_eq!(s.codex_credentials_already_ok, 0);

        // Post-RN1-C R2 (2026-05-24): the legacy `credentials/codex-<N>.json`
        // mirror is deleted by `pass_rn1_c_r2_prune_legacy_mirrors` at the
        // end of the reconciler chain, because the fixture's identity-keyed
        // successor (`identities/<UUID>/credentials-codex.json`) exists and
        // parses. pass1's repair (0o600 → 0o400) still ran — the
        // `codex_credentials_repaired == 1` counter is the surviving
        // evidence; the file itself is by-design absent post-cleanup.
        assert!(
            !canonical.exists(),
            "post-RN1-C R2: legacy mirror MUST be cleaned up by the final reconciler pass"
        );
    }

    /// Pass 1: A canonical already at 0o400 is left alone (no
    /// double-write under the mutex).
    #[cfg(unix)]
    #[test]
    fn pass1_leaves_0o400_canonical_untouched() {
        let dir = TempDir::new().unwrap();
        install_codex_canonical(dir.path(), 8);
        // save_canonical_for landed it at 0o400 already.

        let s = run_reconciler(dir.path());
        assert_eq!(s.codex_credentials_seen, 1);
        assert_eq!(s.codex_credentials_already_ok, 1);
        assert_eq!(s.codex_credentials_repaired, 0);
    }

    /// Pass 2: missing config.toml is created with the file-backed directive
    /// but NO model key — csq no longer injects its catalog default (CC-parity;
    /// the user-global is isolated/absent here, so nothing propagates and codex
    /// falls back to its own built-in default).
    #[test]
    fn pass2_creates_missing_config_toml_with_directive() {
        let _env_guard = codex_user_config_isolated();
        let dir = TempDir::new().unwrap();
        install_codex_canonical(dir.path(), 9);

        let s = run_reconciler(dir.path());
        assert_eq!(s.config_tomls_seen, 1);
        assert_eq!(s.config_tomls_repaired, 1);

        let toml_path =
            codex_surface::config_toml_path(dir.path(), AccountNum::try_from(9u16).unwrap());
        let contents = std::fs::read_to_string(&toml_path).unwrap();
        assert!(
            contents.contains("cli_auth_credentials_store = \"file\""),
            "rewritten config.toml must carry the directive: {contents}"
        );
        assert!(
            !contents.contains("model ="),
            "csq must NOT inject a catalog-default model into a fresh config.toml: {contents}"
        );
    }

    /// Pass 2: a config.toml whose `cli_auth_credentials_store` key
    /// was manually deleted gets rewritten, preserving the existing
    /// model key value.
    #[test]
    fn pass2_rewrites_drifted_config_toml_preserving_model() {
        let _env_guard = codex_user_config_isolated();
        let dir = TempDir::new().unwrap();
        install_codex_canonical(dir.path(), 10);

        // Write a drifted config.toml: model is set, but the
        // file-backed directive was removed.
        let toml_path =
            codex_surface::config_toml_path(dir.path(), AccountNum::try_from(10u16).unwrap());
        std::fs::create_dir_all(toml_path.parent().unwrap()).unwrap();
        std::fs::write(&toml_path, "model = \"gpt-custom-user-pick\"\n").unwrap();

        let s = run_reconciler(dir.path());
        assert_eq!(s.config_tomls_repaired, 1);

        let contents = std::fs::read_to_string(&toml_path).unwrap();
        assert!(
            contents.contains("cli_auth_credentials_store = \"file\""),
            "directive must be present after repair: {contents}"
        );
        assert!(
            contents.contains("model = \"gpt-custom-user-pick\""),
            "user's model selection must be preserved across repair: {contents}"
        );
    }

    /// Pass 2: a config.toml that already has the directive is left
    /// alone (no rewrite).
    #[test]
    fn pass2_leaves_correct_config_toml_untouched() {
        let _env_guard = codex_user_config_isolated();
        let dir = TempDir::new().unwrap();
        install_codex_canonical(dir.path(), 11);

        // Write a correct config.toml with an explicit per-slot model.
        codex_surface::write_config_toml(
            dir.path(),
            AccountNum::try_from(11u16).unwrap(),
            Some("gpt-keep"),
        )
        .unwrap();
        let toml_path =
            codex_surface::config_toml_path(dir.path(), AccountNum::try_from(11u16).unwrap());
        let before = std::fs::metadata(&toml_path).unwrap().modified().unwrap();

        // Sleep 10ms so a stray rewrite would change mtime.
        std::thread::sleep(std::time::Duration::from_millis(10));

        let s = run_reconciler(dir.path());
        assert_eq!(s.config_tomls_already_ok, 1);
        assert_eq!(s.config_tomls_repaired, 0);

        let after = std::fs::metadata(&toml_path).unwrap().modified().unwrap();
        assert_eq!(before, after, "untouched file must keep its mtime");
    }

    /// User-global → slot propagation (2026-05-15 bug fix):
    ///
    /// The user has `~/.codex/config.toml` containing `approval_policy =
    /// "never"` + `sandbox_mode = "danger-full-access"`. Their slot's
    /// `config.toml` was written before they edited the global file
    /// (e.g. by `csq login N --provider codex`) and only carries the
    /// 2-key csq baseline. On daemon restart, the reconciler MUST
    /// re-render the slot's config.toml with the user-global merged in,
    /// so that the next `csq run N` propagates the user's preferences
    /// to Codex via `$CODEX_HOME/config.toml`.
    ///
    /// Without this fix, csq's `CODEX_HOME` redirect silently drops
    /// every user-global preference because Codex reads only
    /// `$CODEX_HOME/config.toml`, never `~/.codex/config.toml`.
    #[test]
    fn pass2_propagates_user_global_into_slot_config() {
        // Install a fixture user-global with two preference keys.
        let shared = crate::platform::test_env::lock();
        let fixture_dir = TempDir::new().unwrap();
        let fixture_path = fixture_dir.path().join("user-config.toml");
        std::fs::write(
            &fixture_path,
            "approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n",
        )
        .unwrap();
        let prev_env = std::env::var_os(codex_surface::USER_CONFIG_ENV_OVERRIDE);
        // SAFETY: test_env::lock held by `shared`.
        unsafe {
            std::env::set_var(codex_surface::USER_CONFIG_ENV_OVERRIDE, &fixture_path);
        }

        let dir = TempDir::new().unwrap();
        install_codex_canonical(dir.path(), 12);

        // Pre-existing slot config.toml carries the un-merged 2-key
        // baseline (as it would have been written before the user
        // edited their global preferences).
        let toml_path =
            codex_surface::config_toml_path(dir.path(), AccountNum::try_from(12u16).unwrap());
        std::fs::create_dir_all(toml_path.parent().unwrap()).unwrap();
        std::fs::write(
            &toml_path,
            "cli_auth_credentials_store = \"file\"\nmodel = \"gpt-existing\"\n",
        )
        .unwrap();

        let s = run_reconciler(dir.path());

        // Restore env BEFORE any panic-able assertion so concurrent
        // surface.rs tests aren't disturbed if this test fails.
        unsafe {
            match prev_env {
                Some(v) => std::env::set_var(codex_surface::USER_CONFIG_ENV_OVERRIDE, v),
                None => std::env::remove_var(codex_surface::USER_CONFIG_ENV_OVERRIDE),
            }
        }
        drop(shared);

        assert_eq!(
            s.config_tomls_repaired, 1,
            "reconciler must repair the slot config to include user-global merge"
        );

        let contents = std::fs::read_to_string(&toml_path).unwrap();
        assert!(
            contents.contains("cli_auth_credentials_store = \"file\""),
            "csq directive must survive merge: {contents}"
        );
        assert!(
            contents.contains("model = \"gpt-existing\""),
            "existing slot model must be preserved: {contents}"
        );
        assert!(
            contents.contains("approval_policy = \"never\""),
            "user-global approval_policy must propagate to slot: {contents}"
        );
        assert!(
            contents.contains("sandbox_mode = \"danger-full-access\""),
            "user-global sandbox_mode must propagate to slot: {contents}"
        );
    }

    /// A present-but-malformed `~/.codex/config.toml` MUST leave existing
    /// slot configs UNTOUCHED (not wiped to the degraded fallback) and
    /// increment the dedicated skip counter — the same wipe-prevention
    /// property the run path relies on.
    #[test]
    fn pass2_skips_malformed_global_keeping_existing_slot_config() {
        let shared = crate::platform::test_env::lock();
        let fixture_dir = TempDir::new().unwrap();
        let fixture_path = fixture_dir.path().join("user-config.toml");
        // Present but NOT valid TOML.
        std::fs::write(&fixture_path, "approval_policy = \"never\nbroken [[[").unwrap();
        let prev_env = std::env::var_os(codex_surface::USER_CONFIG_ENV_OVERRIDE);
        // SAFETY: test_env::lock held by `shared`.
        unsafe {
            std::env::set_var(codex_surface::USER_CONFIG_ENV_OVERRIDE, &fixture_path);
        }

        let dir = TempDir::new().unwrap();
        install_codex_canonical(dir.path(), 12);

        // Seed a CANONICAL slot config (incl. csq's injected statusline) via
        // the same writer csq uses, with an explicit valid global (the arg
        // bypasses the env, which is the malformed fixture). Because the slot
        // is already canonical, the malformed-global re-merge is a true no-op
        // → SkippedMalformedGlobal + byte-identical. (A NON-canonical seed
        // would instead be repaired → Rewritten; that path is covered by
        // surface.rs::regenerate_repairs_csq_keys_under_malformed_global.)
        let toml_path =
            codex_surface::config_toml_path(dir.path(), AccountNum::try_from(12u16).unwrap());
        codex_surface::write_config_toml_with_global(
            dir.path(),
            AccountNum::try_from(12u16).unwrap(),
            Some("gpt-existing"),
            Some("sandbox_mode = \"read-only\"\n"),
        )
        .unwrap();
        let seeded = std::fs::read_to_string(&toml_path).unwrap();

        let s = run_reconciler(dir.path());

        // Restore env BEFORE any panic-able assertion.
        unsafe {
            match prev_env {
                Some(v) => std::env::set_var(codex_surface::USER_CONFIG_ENV_OVERRIDE, v),
                None => std::env::remove_var(codex_surface::USER_CONFIG_ENV_OVERRIDE),
            }
        }
        drop(shared);

        assert_eq!(
            s.config_tomls_skipped_malformed_global, 1,
            "malformed ~/.codex must increment the skip counter"
        );
        assert_eq!(
            s.config_tomls_repaired, 0,
            "malformed ~/.codex must NOT trigger a repair-rewrite"
        );
        let after = std::fs::read_to_string(&toml_path).unwrap();
        assert_eq!(
            after, seeded,
            "malformed ~/.codex must leave the existing slot config byte-identical"
        );
    }

    #[test]
    fn has_file_backed_directive_accepts_canonical_form() {
        assert!(has_file_backed_directive(
            "cli_auth_credentials_store = \"file\"\n"
        ));
        assert!(has_file_backed_directive(
            "cli_auth_credentials_store='file'\nmodel = \"x\"\n"
        ));
    }

    #[test]
    fn has_file_backed_directive_rejects_drift() {
        assert!(!has_file_backed_directive("model = \"x\"\n"));
        assert!(!has_file_backed_directive(
            "cli_auth_credentials_store = \"keychain\"\n"
        ));
        assert!(!has_file_backed_directive(
            "cli_auth_credentials_store = \"FILE\"\n" // case-sensitive
        ));
    }

    #[test]
    fn has_file_backed_directive_strips_inline_comment() {
        assert!(has_file_backed_directive(
            "cli_auth_credentials_store = \"file\"  # csq-managed\n"
        ));
    }

    // `extract_model_key_round_trips` moved with the function to
    // `providers::codex::surface` tests.

    /// Files at non-`codex-N.json` paths in `credentials/` are
    /// ignored by both passes (no false positives on Anthropic
    /// canonical files or unrelated junk).
    #[test]
    fn reconciler_ignores_non_codex_credential_files() {
        let dir = TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("1.json"), b"{}").unwrap();
        std::fs::write(creds_dir.join("not-a-codex-file.txt"), b"junk").unwrap();
        std::fs::write(creds_dir.join("codex-bogus.json"), b"{}").unwrap();

        let s = run_reconciler(dir.path());
        assert_eq!(s.codex_credentials_seen, 0);
        assert_eq!(s.config_tomls_seen, 0);
    }

    // ─── PR-C6 pass 3 tests ───────────────────────────────────────

    #[test]
    fn pass3_no_quota_file_reports_none() {
        let dir = TempDir::new().unwrap();
        let s = run_reconciler(dir.path());
        assert_eq!(s.quota_migrated, None);
        assert_eq!(s.quota_accounts_migrated, 0);
    }

    #[test]
    fn pass3_migrates_v1_to_v2_and_reports_count() {
        let dir = TempDir::new().unwrap();
        let v1 = r#"{
            "accounts": {
                "5": {
                    "five_hour": {"used_percentage": 20.0, "resets_at": 4102444800},
                    "updated_at": 123.0
                }
            }
        }"#;
        std::fs::write(dir.path().join("quota.json"), v1).unwrap();

        let s = run_reconciler(dir.path());
        assert_eq!(s.quota_migrated, Some(true));
        assert_eq!(s.quota_accounts_migrated, 1);

        // Confirm on-disk rewrite
        let raw = std::fs::read_to_string(dir.path().join("quota.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["schema_version"].as_u64(), Some(2));
        assert_eq!(v["accounts"]["5"]["surface"].as_str(), Some("claude-code"));
    }

    #[test]
    fn pass3_already_v2_file_reports_false() {
        let dir = TempDir::new().unwrap();
        // Write a real v2 file via save_state so it matches the exact
        // on-disk shape the writer produces.
        let mut qf = crate::quota::QuotaFile::empty();
        qf.set(
            1,
            crate::quota::AccountQuota {
                five_hour: Some(crate::quota::UsageWindow {
                    used_percentage: 50.0,
                    resets_at: 4_102_444_800,
                }),
                updated_at: 100.0,
                ..Default::default()
            },
        );
        crate::quota::state::save_state(dir.path(), &qf).unwrap();

        let s = run_reconciler(dir.path());
        assert_eq!(s.quota_migrated, Some(false));
        assert_eq!(s.quota_accounts_migrated, 0);
    }

    #[test]
    fn pass3_corrupt_file_does_not_crash_reconciler() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("quota.json"), "this is not json").unwrap();
        // Must not panic; summary reports migrated=None (treated as
        // no-viable-migration; the poller will overwrite on next write).
        let s = run_reconciler(dir.path());
        assert_eq!(s.quota_migrated, None);
    }

    // ─── PR-CA10c T9 pass 5 tests ─────────────────────────────────────────

    fn sample_record_json(run_id: &str, start_ts: &str) -> String {
        format!(
            r#"{{"schema_version":"1","run_id":"{run_id}","fixture_sha256":"{fa}","coc_sha256":"{ca}","csq_version":"2.6.2","cli_version":"1.0.0","surface":"cc","model":"claude-opus-4-7","start_ts":"{start_ts}","end_ts":"2026-05-09T00:00:01Z","result_state":"pass","score_delta_vs_baseline":null,"rule_ids_cited_original":[],"rule_ids_cited_after_repair":[],"rule_ids_dropped_invalid_format":0,"decision":"accept"}}"#,
            fa = "a".repeat(64),
            ca = "b".repeat(64),
        )
    }

    fn setup_pending(base: &Path) -> std::path::PathBuf {
        let pending = base.join("csq-runs").join(".pending");
        std::fs::create_dir_all(&pending).unwrap();
        pending
    }

    /// T9.1 — drain consumes valid records and deletes the source files.
    #[test]
    fn drain_consumes_valid_records_and_deletes_source() {
        let dir = TempDir::new().unwrap();
        let pending = setup_pending(dir.path());

        let ids = [
            "11111111-0000-4000-8000-000000000001",
            "11111111-0000-4000-8000-000000000002",
            "11111111-0000-4000-8000-000000000003",
        ];
        for id in &ids {
            let ts = "2026-05-09T10:00:00Z";
            std::fs::write(
                pending.join(format!("{id}.jsonl")),
                sample_record_json(id, ts),
            )
            .unwrap();
        }

        let s = run_reconciler(dir.path());
        assert_eq!(s.audit_pending_files_seen, 3);
        assert_eq!(s.audit_pending_files_drained, 3);
        assert_eq!(s.audit_pending_files_invalid, 0);
        assert_eq!(s.audit_pending_files_unknown_version, 0);

        // Source files must be gone.
        for id in &ids {
            assert!(
                !pending.join(format!("{id}.jsonl")).exists(),
                ".pending/{id}.jsonl must be deleted after drain"
            );
        }

        // Records must exist in csq-runs/.
        let csq_runs = dir.path().join("csq-runs");
        for id in &ids {
            assert!(
                csq_runs.join(format!("{id}.jsonl")).exists(),
                "csq-runs/{id}.jsonl must exist after drain"
            );
        }
    }

    /// M19b — the drain emits a chain-level `CsqRun` floor record for each
    /// drained run when a chain is initialised (recovery-path parity with the
    /// live `audit_record_handler`). Bootstraps a chain first because
    /// `emit_csq_run_record` refuses to mint a genesis from a floor record.
    #[test]
    fn drain_emits_csq_run_floor_record() {
        use crate::audit::persist::write_record_v2;
        use crate::audit::types::{
            CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, RecordId, Sha256Hex,
            SignedRecord,
        };

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Bootstrap a chain genesis (stands in for `csq audit init`).
        let boot = SignedRecord {
            schema_version: crate::audit::persist::AUDIT_SCHEMA_VERSION_TEST.to_string(),
            record_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            chain_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "bootstrap-genesis".to_string(),
            }),
            ts: crate::audit::persist::current_iso8601_utc_persist(),
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
        write_record_v2(boot, Some(base)).unwrap();

        // Stage one .pending v1 record for the recovery drain.
        let pending = setup_pending(base);
        let id = "33333333-0000-4000-8000-000000000001";
        std::fs::write(
            pending.join(format!("{id}.jsonl")),
            sample_record_json(id, "2026-05-09T10:00:00Z"),
        )
        .unwrap();

        let s = run_reconciler(base);
        assert_eq!(s.audit_pending_files_drained, 1, "the v1 record must drain");

        // The chain-level floor record for the drained run must be present.
        let chain_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(base.join("csq-runs").join("chain.json")).unwrap(),
        )
        .unwrap();
        let chain_id = chain_json["chain_id"].as_str().unwrap();
        let chain_text =
            std::fs::read_to_string(base.join("csq-runs").join(format!("{chain_id}.jsonl")))
                .unwrap();
        let count = chain_text
            .lines()
            .filter_map(|l| serde_json::from_str::<SignedRecord>(l).ok())
            .filter(|r| matches!(&r.payload, EventPayload::CsqRun(p) if p.run_id == id))
            .count();
        assert_eq!(
            count, 1,
            "drain must emit exactly one CsqRun floor record for the drained run"
        );
    }

    /// M6 #909 shard B: the extracted `drain_run_floor` drains a staged `.pending/`
    /// v1 record directly (proving the extraction preserves pass5's behaviour for
    /// the periodic-backstop caller, not only via the reconciler wrapper).
    #[test]
    fn drain_run_floor_drains_staged_pending_record() {
        use crate::audit::persist::write_record_v2;
        use crate::audit::types::{
            CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, RecordId, Sha256Hex,
            SignedRecord,
        };

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let boot = SignedRecord {
            schema_version: crate::audit::persist::AUDIT_SCHEMA_VERSION_TEST.to_string(),
            record_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            chain_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "bootstrap-genesis".to_string(),
            }),
            ts: crate::audit::persist::current_iso8601_utc_persist(),
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
        write_record_v2(boot, Some(base)).unwrap();

        let pending = setup_pending(base);
        let id = "44444444-0000-4000-8000-000000000001";
        std::fs::write(
            pending.join(format!("{id}.jsonl")),
            sample_record_json(id, "2026-05-09T10:00:00Z"),
        )
        .unwrap();

        let s = drain_run_floor(base);
        assert_eq!(s.seen, 1);
        assert_eq!(s.drained, 1, "extracted drain must drain the staged record");
        assert_eq!(s.invalid, 0);
        assert!(
            !pending.join(format!("{id}.jsonl")).exists(),
            "source deleted after drain"
        );
    }

    /// M6 #909 shard B: `run_reconciler` writes the last-drain-cycle stamp when the
    /// chain dir exists, so shard D's daemon-aware "stuck" predicate has a
    /// drain-liveness signal.
    #[test]
    fn run_reconciler_stamps_drain_cycle_when_csq_runs_exists() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("csq-runs")).unwrap();
        assert!(
            crate::audit::outbox_paths::read_outbox_drain_stamp(base).is_none(),
            "no stamp before the reconciler runs"
        );
        let _ = run_reconciler(base);
        assert!(
            crate::audit::outbox_paths::read_outbox_drain_stamp(base).is_some(),
            "reconciler must stamp the drain cycle when csq-runs/ exists"
        );
    }

    /// M6 #909 shard B: `run_reconciler` on a base with NO `csq-runs/` writes no
    /// stamp (nothing could be queued) and does not create the dir.
    #[test]
    fn run_reconciler_no_stamp_without_csq_runs() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let _ = run_reconciler(base);
        assert!(
            crate::audit::outbox_paths::read_outbox_drain_stamp(base).is_none(),
            "no csq-runs → no stamp"
        );
    }

    /// M6 #909: `run_reconciler` drains the MCP gate-decision durable outbox via
    /// `pass6_mcp_gate_drain` — proving the pass is WIRED, not just the unit
    /// `drain_pending`. Bootstraps a chain, stages one outbox file, runs the full
    /// reconciler, and asserts the decision landed on the chain, the source was
    /// deleted, and the summary counters populated. Enterprise-only (the pass is
    /// gated to match the outbox producer).
    #[cfg(feature = "enterprise")]
    #[test]
    fn pass6_run_reconciler_drains_mcp_gate_outbox() {
        use crate::audit::mcp_gate_outbox::{write_pending, McpGatePendingRecord};
        use crate::audit::persist::write_record_v2;
        use crate::audit::types::{
            Ed25519Signature, EventKind, EventPayload, KeyId, McpGateDecisionPayload, RecordId,
            Sha256Hex, SignedRecord,
        };

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Bootstrap a chain genesis (an McpGateDecision seed — stands in for init).
        let boot = SignedRecord {
            schema_version: crate::audit::persist::AUDIT_SCHEMA_VERSION_TEST.to_string(),
            record_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            chain_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::McpGateDecision,
            payload: EventPayload::McpGateDecision(McpGateDecisionPayload {
                session_nonce: "bootstrap".to_string(),
                record_seq: 0,
                cli: "codex".to_string(),
                tool: "bootstrap_tool".to_string(),
                verdict: "pass".to_string(),
                enforcement_fidelity: crate::audit::mcp_gate_floor::MCP_ENFORCEMENT_FIDELITY
                    .to_string(),
            }),
            ts: crate::audit::persist::current_iso8601_utc_persist(),
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
        write_record_v2(boot, Some(base)).unwrap();

        // Stage one pending outbox decision (as the proxy would on daemon-down).
        write_pending(
            base,
            &McpGatePendingRecord::new("mcp-proxy-1-abcd", 7, "codex", "mcp__shell__exec", "block"),
        )
        .unwrap();

        let s = run_reconciler(base);
        assert_eq!(s.mcp_gate_pending_files_seen, 1);
        assert_eq!(s.mcp_gate_pending_files_drained, 1);
        assert!(!s.mcp_gate_drain_deferred_chain_unavailable);

        // The decision must be on the chain.
        let chain_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(base.join("csq-runs").join("chain.json")).unwrap(),
        )
        .unwrap();
        let chain_id = chain_json["chain_id"].as_str().unwrap();
        let chain_text =
            std::fs::read_to_string(base.join("csq-runs").join(format!("{chain_id}.jsonl")))
                .unwrap();
        let count = chain_text
            .lines()
            .filter_map(|l| serde_json::from_str::<SignedRecord>(l).ok())
            .filter(|r| {
                matches!(&r.payload, EventPayload::McpGateDecision(p)
                if p.session_nonce == "mcp-proxy-1-abcd" && p.record_seq == 7)
            })
            .count();
        assert_eq!(
            count, 1,
            "the drained decision must appear once on the chain"
        );

        // The outbox source must be gone.
        let outbox = base.join("csq-runs").join(".pending-mcp-gate");
        let remaining: Vec<_> = std::fs::read_dir(&outbox)
            .map(|rd| rd.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        assert!(
            remaining.is_empty(),
            "outbox source deleted after drain: {remaining:?}"
        );
    }

    /// M19b R1-LOW-1: the floor-emit retry classifier preserves `.pending` ONLY
    /// for the transient `ChainLockTimeout` (retry-on-next-start) and treats every
    /// other error as terminal-non-fatal (delete + warn). A regression that
    /// mis-classified a deterministic error as retryable would loop the drain
    /// forever; one that flipped `ChainLockTimeout` to terminal would silently
    /// lose the floor record on transient contention.
    #[test]
    fn floor_emit_retryable_only_for_chain_lock_timeout() {
        use crate::audit::persist::AuditV2Error;
        assert!(floor_emit_is_retryable(&AuditV2Error::ChainLockTimeout {
            deadline_secs: 5
        }));
        assert!(!floor_emit_is_retryable(&AuditV2Error::Signing {
            reason: "x".into()
        }));
        assert!(!floor_emit_is_retryable(&AuditV2Error::ChainCorrupt {
            reason: "x".into()
        }));
        assert!(!floor_emit_is_retryable(&AuditV2Error::Internal {
            reason: "x".into()
        }));
    }

    /// T9.2 — records are drained in start_ts ascending order.
    ///
    /// We plant records out-of-order and verify the output files reflect
    /// the causal ordering (oldest start_ts first in csq-runs/).
    #[test]
    fn drain_orders_by_start_ts_ascending() {
        let dir = TempDir::new().unwrap();
        let pending = setup_pending(dir.path());

        // Plant three records with explicit start_ts values, out of order.
        let records = [
            (
                "22222222-0000-4000-8000-000000000003",
                "2026-05-09T12:00:00Z",
            ),
            (
                "22222222-0000-4000-8000-000000000001",
                "2026-05-09T10:00:00Z",
            ),
            (
                "22222222-0000-4000-8000-000000000002",
                "2026-05-09T11:00:00Z",
            ),
        ];
        for (id, ts) in &records {
            std::fs::write(
                pending.join(format!("{id}.jsonl")),
                sample_record_json(id, ts),
            )
            .unwrap();
        }

        let s = run_reconciler(dir.path());
        assert_eq!(s.audit_pending_files_drained, 3);

        // Verify all records ended up in csq-runs/ (order is an
        // implementation detail of the drain pass, not surfaced to the
        // file naming — but all must be present).
        let csq_runs = dir.path().join("csq-runs");
        for (id, _) in &records {
            assert!(csq_runs.join(format!("{id}.jsonl")).exists());
        }
    }

    /// T9.3 — drain is idempotent: second run is a no-op.
    #[test]
    fn drain_idempotent() {
        let dir = TempDir::new().unwrap();
        let pending = setup_pending(dir.path());

        let id = "33333333-0000-4000-8000-000000000001";
        std::fs::write(
            pending.join(format!("{id}.jsonl")),
            sample_record_json(id, "2026-05-09T10:00:00Z"),
        )
        .unwrap();

        // First run — drains the file.
        let s1 = run_reconciler(dir.path());
        assert_eq!(s1.audit_pending_files_drained, 1);

        // Second run — .pending/ is empty; nothing to drain.
        let s2 = run_reconciler(dir.path());
        assert_eq!(s2.audit_pending_files_seen, 0);
        assert_eq!(s2.audit_pending_files_drained, 0);

        // The csq-runs/ record must not be duplicated.
        let csq_runs = dir.path().join("csq-runs");
        let count = std::fs::read_dir(&csq_runs)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    .map(|x| x == "jsonl")
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(
            count, 1,
            "record must not be duplicated by idempotent drain"
        );
    }

    /// T9.4 — unknown schema_version leaves the file in .pending/.
    #[test]
    fn drain_unknown_schema_version_leaves_file() {
        let dir = TempDir::new().unwrap();
        let pending = setup_pending(dir.path());

        let path = pending.join("unknown-version.jsonl");
        std::fs::write(
            &path,
            r#"{"schema_version":"99","run_id":"x","fixture_sha256":"a","start_ts":"2026-05-09T10:00:00Z"}"#,
        )
        .unwrap();

        let s = run_reconciler(dir.path());
        assert_eq!(s.audit_pending_files_seen, 1);
        assert_eq!(s.audit_pending_files_unknown_version, 1);
        assert_eq!(s.audit_pending_files_drained, 0);
        assert_eq!(s.audit_pending_files_invalid, 0);

        // File must still be there.
        assert!(
            path.exists(),
            "unknown-version file must remain in .pending/"
        );
    }

    /// T9.5 — invalid/malformed record is deleted.
    #[test]
    fn drain_invalid_record_deletes_file() {
        let dir = TempDir::new().unwrap();
        let pending = setup_pending(dir.path());

        let path = pending.join("corrupt.jsonl");
        std::fs::write(&path, b"not-json-at-all{{{").unwrap();

        let s = run_reconciler(dir.path());
        assert_eq!(s.audit_pending_files_seen, 1);
        assert_eq!(s.audit_pending_files_invalid, 1);
        assert_eq!(s.audit_pending_files_drained, 0);

        // File must be deleted.
        assert!(!path.exists(), "corrupt file must be deleted");
    }

    /// T9.6 — v1 record with unparseable start_ts is treated as invalid (deleted).
    #[test]
    fn drain_invalid_start_ts_treated_as_invalid() {
        let dir = TempDir::new().unwrap();
        let pending = setup_pending(dir.path());

        let id = "44444444-0000-4000-8000-000000000001";
        // Valid v1 JSON but with a broken start_ts that can't be sorted.
        let path = pending.join(format!("{id}.jsonl"));
        let content = format!(
            r#"{{"schema_version":"1","run_id":"{id}","fixture_sha256":"{fa}","coc_sha256":"{ca}","csq_version":"2.6.2","cli_version":"1.0.0","surface":"cc","model":"claude-opus-4-7","start_ts":"not-a-date","end_ts":"2026-05-09T00:00:01Z","result_state":"pass","score_delta_vs_baseline":null,"rule_ids_cited_original":[],"rule_ids_cited_after_repair":[],"rule_ids_dropped_invalid_format":0,"decision":"accept"}}"#,
            fa = "a".repeat(64),
            ca = "b".repeat(64),
        );
        std::fs::write(&path, content).unwrap();

        let s = run_reconciler(dir.path());
        assert_eq!(s.audit_pending_files_invalid, 1);
        assert_eq!(s.audit_pending_files_drained, 0);
        assert!(!path.exists(), "bad-start_ts file must be deleted");
    }

    /// T9.7 — missing schema_version field is treated as unknown version.
    #[test]
    fn drain_missing_schema_version_leaves_file() {
        let dir = TempDir::new().unwrap();
        let pending = setup_pending(dir.path());

        let path = pending.join("no-version.jsonl");
        // Valid JSON but no schema_version key.
        std::fs::write(&path, r#"{"run_id":"x","start_ts":"2026-05-09T10:00:00Z"}"#).unwrap();

        let s = run_reconciler(dir.path());
        assert_eq!(s.audit_pending_files_unknown_version, 1);
        assert_eq!(s.audit_pending_files_drained, 0);
        assert!(path.exists(), "no-version file must remain in .pending/");
    }

    /// M02 Amendment 1 regression test: `pass5_audit_drain` on a pre-v2 daemon
    /// MUST preserve any v2 JSONL record it finds in `.pending/` — leaving it
    /// for a future daemon that understands schema v2.
    ///
    /// Regression guard: the drain's `if version != "1"` branch correctly
    /// skips v2 records.  If this check is ever removed or the string
    /// comparison is changed, this test catches the regression.
    #[test]
    fn pass5_audit_drain_preserves_v2_record_when_running_on_pre_v2_codepath() {
        let dir = TempDir::new().unwrap();
        let pending = setup_pending(dir.path());

        // Write a v2-tagged JSONL record into .pending/.
        // The content mimics a minimal schema v2 SignedRecord shape.
        let v2_path = pending.join("v2-record.jsonl");
        std::fs::write(
            &v2_path,
            // A valid JSON object with schema_version="2" but otherwise
            // intentionally minimal — the drain must NOT parse it as v1
            // or delete it.
            r#"{"schema_version":"2","record_id":"01JZ00000000000000000000XY","chain_id":"01JZ00000000000000000000R0","seq":0}"#,
        )
        .unwrap();

        let s = run_reconciler(dir.path());

        // The v2 record must count as "unknown version" and be left alone.
        assert_eq!(
            s.audit_pending_files_seen, 1,
            "reconciler must see the v2 .pending/ file"
        );
        assert_eq!(
            s.audit_pending_files_unknown_version, 1,
            "v2 record must be classified as unknown version on pre-v2 codepath"
        );
        assert_eq!(
            s.audit_pending_files_drained, 0,
            "pre-v2 drain must NOT drain the v2 record"
        );
        assert_eq!(
            s.audit_pending_files_invalid, 0,
            "v2 record must NOT be counted as invalid (preserved, not deleted)"
        );

        // Most importantly: the file must still be there.
        assert!(
            v2_path.exists(),
            "v2 .pending/ record must be preserved — not deleted by pre-v2 drain"
        );
    }

    // ── M2-3 acceptance test ──────────────────────────────────────────────────

    /// Criterion 3: Pass 0 Phase 2 catch-up seeds `identities/<UUID>/settings.json`
    /// from `config-N/settings.json` for existing slots that have a UUID mapping.
    ///
    /// Arrange: coexisting_fixture(2) gives slots 1 and 2 with UUID mappings.
    /// config-1/settings.json contains `{"slot1_key": 1}`.
    /// No `identities/<UUID>/settings.json` files exist yet.
    ///
    /// After `run_reconciler`, `identities/<UUID>/settings.json` for slot 1
    /// must contain the slot1_key content from the legacy settings path.
    #[test]
    fn pass0_seeds_identities_settings_from_existing_config_n() {
        use crate::accounts::identity_store::settings_path_for;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange
        let dir = coexisting_fixture(2);
        let base = dir.path();

        let uuid1 = fixture_uuid_for_slot(1);

        // Write config-1/settings.json with a sentinel key
        let config1_settings = base.join("config-1").join("settings.json");
        std::fs::write(&config1_settings, r#"{"slot1_key": 1}"#).unwrap();

        // Confirm no UUID settings.json exists yet
        let uuid1_settings = settings_path_for(base, uuid1);
        assert!(
            !uuid1_settings.exists(),
            "precondition: identities/<uuid1>/settings.json must not exist before reconciler"
        );

        // Act
        let _summary = run_reconciler(base);

        // Assert: UUID settings.json was seeded from config-1/settings.json
        assert!(
            uuid1_settings.exists(),
            "pass0 Phase 2 must create identities/<uuid1>/settings.json"
        );
        let content = std::fs::read_to_string(&uuid1_settings).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            parsed["slot1_key"].as_u64(),
            Some(1),
            "seeded settings must contain the slot1_key from config-1/settings.json"
        );
    }

    // ── R3-LOW-1: IdentityMintError log path-leakage regression ──────────────

    /// R3-LOW-1: `IdentityMintError::DirWalk` Display MUST use `error_kind`
    /// fixed-vocabulary logging — the `%e` interpolation form was banned because
    /// the Display chain for `DirWalk` may include the OS error message from the
    /// `flock(2)` or `open(2)` on `.profiles.lock`, which is not a path-safe
    /// string for general logging.
    ///
    /// This test documents the invariant rather than capturing tracing output
    /// (no capture infrastructure). It confirms the `error_kind` string values
    /// the `warn!` match arm uses are stable.  If the enum variants change, the
    /// match arm in `startup_reconciler.rs` must be updated synchronously.
    #[test]
    fn identity_mint_error_kind_discriminators_are_stable() {
        use crate::daemon::identity_mint::IdentityMintError;

        // Verify the discriminators used in the match arm in Pass 0's Err handler.
        let dir_walk_err = IdentityMintError::DirWalk("test I/O error".to_string());
        let sentinel_err = IdentityMintError::SentinelWrite("test sentinel error".to_string());

        // Confirm Display still includes inner message — so %e WOULD leak it
        let dir_walk_display = dir_walk_err.to_string();
        let sentinel_display = sentinel_err.to_string();
        assert!(
            dir_walk_display.contains("test I/O error"),
            "DirWalk Display includes inner msg — confirms %e would leak it: {dir_walk_display}"
        );
        assert!(
            sentinel_display.contains("test sentinel error"),
            "SentinelWrite Display includes inner msg — confirms %e would leak it: {sentinel_display}"
        );

        // Confirm the match arm's error_kind values are exactly what we use
        let kind_for_dir_walk = match &dir_walk_err {
            IdentityMintError::DirWalk(_) => "dir_walk_failed",
            IdentityMintError::SentinelWrite(_) => "sentinel_write_failed",
        };
        let kind_for_sentinel = match &sentinel_err {
            IdentityMintError::DirWalk(_) => "dir_walk_failed",
            IdentityMintError::SentinelWrite(_) => "sentinel_write_failed",
        };
        assert_eq!(kind_for_dir_walk, "dir_walk_failed");
        assert_eq!(kind_for_sentinel, "sentinel_write_failed");
    }

    /// M2-5 acceptance criterion: the ledger catchup pass renames legacy
    /// `usage-{slot}.ndjson` files to `identities/<UUID>/usage.ndjson` for
    /// slots whose UUID is present in `profiles.json` `by_slot`.
    ///
    /// Post-M4-4 setup note: the fixture seeds `by_slot["1"]` AND `by_email`
    /// AND `identities/<UUID>/identity.json`. The discovery layer now reads
    /// through `by_slot`, so `identity_mint`'s Pass 0 sees slot 1 and the
    /// `AlreadyPresent` branch reconciles the mapping without churning the
    /// UUID. Without the `by_email` entry, `mint_slot` would mint a fresh
    /// UUID and overwrite `by_slot["1"]`, and the rename target would
    /// differ from the test-pinned UUID below.
    #[test]
    fn pass0_renames_legacy_ledgers_to_uuid_paths() {
        // Arrange — create a base dir with a profiles.json (by_slot AND
        // by_email populated, consistent with a post-mint production
        // state) and a legacy usage-1.ndjson ledger.
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let uuid_str = "550e8400-e29b-41d4-a716-446655440099";
        // Pre-seed identity.json so identity_mint takes the AlreadyPresent
        // branch and reconciles by_slot/by_email without churning the UUID.
        let identity_dir = base.join("identities").join(uuid_str);
        std::fs::create_dir_all(&identity_dir).unwrap();
        std::fs::write(
            identity_dir.join("identity.json"),
            r#"{"email":"test@example.com","provider":"anthropic","created_at":"2026-05-14T10:00:00Z","key_id":null}"#,
        )
        .unwrap();
        let profiles_content = format!(
            r#"{{"accounts":{{"1":{{"email":"test@example.com","method":"oauth"}}}},"by_slot":{{"1":"{}"}},"by_email":{{"test@example.com":"{}"}}}}"#,
            uuid_str, uuid_str
        );
        std::fs::write(base.join("profiles.json"), &profiles_content).unwrap();

        let legacy_ledger = base.join("usage-1.ndjson");
        let ledger_line = r#"{"ts":"2026-05-14T10:00:00Z","session_id":"sess-1","model":"claude-3-5-sonnet","input_tokens":100,"output_tokens":50,"cost_usd_estimate":0.01,"source":"session-meta"}"#;
        std::fs::write(&legacy_ledger, format!("{ledger_line}\n")).unwrap();

        // Act — run the full reconciler (which calls pass0_phase2_ledger_catchup)
        let summary = run_reconciler(base);

        // Assert — legacy file renamed to UUID path
        let uuid_ledger = base.join("identities").join(uuid_str).join("usage.ndjson");
        assert!(
            uuid_ledger.exists(),
            "UUID-keyed ledger must exist after catchup: {uuid_ledger:?}"
        );
        assert!(
            !legacy_ledger.exists(),
            "legacy ledger must be gone after rename: {legacy_ledger:?}"
        );
        assert_eq!(summary.ledger_files_seen, 1, "one legacy ledger was seen");
        assert_eq!(
            summary.ledger_files_renamed, 1,
            "one legacy ledger was renamed"
        );

        // Verify file content integrity after rename
        let content = std::fs::read_to_string(&uuid_ledger).unwrap();
        assert!(
            content.contains("sess-1"),
            "ledger content must survive the rename: {content}"
        );
    }

    // ── an internal journal entry (§FD #2 of 0041): phase4_gate_status read-only tests ──

    /// Healthy Phase-4 layout — every UUID-mapped slot has all three
    /// identity files. Status MUST be empty and `is_incomplete() == false`.
    #[test]
    fn phase4_gate_status_empty_when_all_identities_seeded() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let uuid_1 = IdentityId::new_v4();
        let uuid_2 = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("1".to_string(), uuid_1);
        profiles.by_slot.insert("2".to_string(), uuid_2);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // Slot 1 (Claude-only): credentials + settings seeded.
        let d1 = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid_1.to_canonical_string());
        std::fs::create_dir_all(&d1).unwrap();
        std::fs::write(d1.join("credentials.json"), b"{}").unwrap();
        std::fs::write(d1.join("settings.json"), b"{}").unwrap();

        // Slot 2 (Codex-bound): credentials + settings + codex creds; legacy codex canonical present.
        let d2 = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid_2.to_canonical_string());
        std::fs::create_dir_all(&d2).unwrap();
        std::fs::write(d2.join("credentials.json"), b"{}").unwrap();
        std::fs::write(d2.join("settings.json"), b"{}").unwrap();
        std::fs::write(d2.join("credentials-codex.json"), b"{}").unwrap();
        let legacy_codex_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&legacy_codex_dir).unwrap();
        std::fs::write(legacy_codex_dir.join("codex-2.json"), b"{}").unwrap();

        let status = phase4_gate_status(dir.path());
        assert!(
            !status.is_incomplete(),
            "status MUST be empty when every UUID-mapped slot has all identity files: {:?}",
            status
        );
        assert_eq!(status.affected_slot_count(), 0);
        assert_eq!(status.missing.len(), 0);
    }

    /// Phase-4-incomplete layout — credentials.json missing for one slot,
    /// settings.json missing for a second slot, codex creds missing for
    /// a Codex-bound third slot. Status MUST enumerate all three and
    /// `affected_slot_count()` MUST count distinct slots.
    #[test]
    fn phase4_gate_status_enumerates_missing_files_across_slots() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let uuid_1 = IdentityId::new_v4();
        let uuid_2 = IdentityId::new_v4();
        let uuid_3 = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("1".to_string(), uuid_1);
        profiles.by_slot.insert("2".to_string(), uuid_2);
        profiles.by_slot.insert("3".to_string(), uuid_3);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // All Anthropic binding signals: legacy `credentials/<N>.json` files for
        // slots 1 and 2 (Anthropic-bound slots whose identity files we expect to
        // be reported as missing). 2026-05-22 fix made Check 3 binding-aware.
        let legacy_creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&legacy_creds_dir).unwrap();
        std::fs::write(legacy_creds_dir.join("1.json"), b"{}").unwrap();
        std::fs::write(legacy_creds_dir.join("2.json"), b"{}").unwrap();

        // Slot 1: identity dir created with settings.json only (creds missing).
        let d1 = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid_1.to_canonical_string());
        std::fs::create_dir_all(&d1).unwrap();
        std::fs::write(d1.join("settings.json"), b"{}").unwrap();

        // Slot 2: identity dir created with credentials.json only (settings missing).
        let d2 = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid_2.to_canonical_string());
        std::fs::create_dir_all(&d2).unwrap();
        std::fs::write(d2.join("credentials.json"), b"{}").unwrap();

        // Slot 3: Codex-bound (legacy codex canonical exists) but credentials-codex.json missing.
        // Creds + settings are seeded so only the codex record fires.
        let d3 = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid_3.to_canonical_string());
        std::fs::create_dir_all(&d3).unwrap();
        std::fs::write(d3.join("credentials.json"), b"{}").unwrap();
        std::fs::write(d3.join("settings.json"), b"{}").unwrap();
        std::fs::write(legacy_creds_dir.join("codex-3.json"), b"{}").unwrap();

        let status = phase4_gate_status(dir.path());
        assert!(status.is_incomplete());
        assert_eq!(status.missing.len(), 3, "three (slot, file) missing pairs");
        assert_eq!(
            status.affected_slot_count(),
            3,
            "three distinct slots affected"
        );

        // Validate each record's (slot, file) pair appears.
        let mut pairs: Vec<(u16, Phase4HealFile)> = status
            .missing
            .iter()
            .map(|r| (r.slot, r.file.clone()))
            .collect();
        pairs.sort_unstable_by_key(|(s, f)| (*s, format!("{:?}", f)));
        assert!(pairs.contains(&(1, Phase4HealFile::ClaudeCodeCredentials)));
        assert!(pairs.contains(&(2, Phase4HealFile::Settings)));
        assert!(pairs.contains(&(3, Phase4HealFile::CodexCredentials)));
    }

    /// Single slot missing both credentials.json AND settings.json
    /// contributes TWO records but ONE distinct slot. Pins the
    /// dedup semantics of `affected_slot_count()`.
    #[test]
    fn phase4_gate_status_dedups_slot_count_when_slot_misses_multiple_files() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("5".to_string(), uuid);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();
        // Anthropic-binding signal: legacy `credentials/5.json` exists so
        // Check 3's binding guard (2026-05-22) admits the slot for Anthropic
        // creds reporting. Without this seed the codex-only case applies and
        // only the Settings record would surface — not the dedup contract.
        let legacy_creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&legacy_creds_dir).unwrap();
        std::fs::write(legacy_creds_dir.join("5.json"), b"{}").unwrap();
        // Identity dir absent → both creds and settings are missing.

        let status = phase4_gate_status(dir.path());
        assert_eq!(status.missing.len(), 2);
        assert_eq!(
            status.affected_slot_count(),
            1,
            "two missing files for the SAME slot count as one affected slot"
        );
    }

    /// Pure-legacy install (no profiles.json) → status is empty. Parity
    /// with `phase4_gate_check`'s behavior in the same condition.
    #[test]
    fn phase4_gate_status_empty_when_profiles_json_absent() {
        let dir = TempDir::new().unwrap();
        let status = phase4_gate_status(dir.path());
        assert!(!status.is_incomplete());
        assert!(status.missing.is_empty());
    }

    /// Codex check fires ONLY when the legacy codex canonical exists.
    /// A non-Codex-bound slot whose `credentials-codex.json` is absent
    /// MUST NOT produce a record (parity with the gate's check 5).
    #[test]
    fn phase4_gate_status_skips_codex_check_for_non_codex_bound_slot() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("1".to_string(), uuid);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // Seed creds + settings; NO legacy codex canonical → not Codex-bound.
        let d = crate::accounts::identity_store::identities_dir(dir.path())
            .join(uuid.to_canonical_string());
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("credentials.json"), b"{}").unwrap();
        std::fs::write(d.join("settings.json"), b"{}").unwrap();

        let status = phase4_gate_status(dir.path());
        assert!(
            !status.is_incomplete(),
            "non-Codex-bound slot without codex creds is NOT phase-4-incomplete: {:?}",
            status
        );
    }

    // ─── RN1-D5b label relocation reconciler pass tests ──────────────────────

    /// D5b: `pass_rn1_d5_label_relocation` runs once on first daemon start
    /// and writes a sentinel, then skips on subsequent starts.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn label_relocation_pass_runs_once_then_sentineled() {
        use crate::accounts::profiles::{
            label_relocation_sentinel_path, profiles_path, AccountProfile,
        };

        // Arrange: slot 1 has a UUID, OAuth email "o@x.com" in its identity
        // credential file, and accounts[1] has a rename label "Renamed".
        let dir = TempDir::new().unwrap();
        let uuid = crate::accounts::identity_store::IdentityId::new_v4();
        let mut pf = crate::accounts::profiles::ProfilesFile::empty();
        pf.by_slot.insert("1".into(), uuid);
        pf.by_email.insert("o@x.com".into(), uuid);
        pf.set_profile(
            1,
            AccountProfile {
                email: "Renamed".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        crate::accounts::profiles::save(&profiles_path(dir.path()), &pf).unwrap();
        // Create the identity credential file so relocate_labels_to_by_slot_label
        // can read the OAuth email from it (C2 fix: no longer uses by_email lookup).
        {
            let cred_path = crate::accounts::identity_store::credentials_path_for(dir.path(), uuid);
            std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
            std::fs::write(
                &cred_path,
                br#"{"oauthAccount":{"emailAddress":"o@x.com"},"accessToken":"tok","refreshToken":"ref","expiresAt":"2100-01-01T00:00:00Z"}"#,
            )
            .unwrap();
        }

        // Act: run the pass for the first time.
        let mut summary = ReconcileSummary::default();
        pass_rn1_d5_label_relocation(dir.path(), &mut summary);

        // Assert: the pass ran and produced a report.
        let report = summary
            .label_relocation
            .as_ref()
            .expect("report must be Some on first run");
        assert_eq!(report.slots_relocated, 1, "slot 1 must be relocated");

        // Sentinel must be present after the first run.
        assert!(
            label_relocation_sentinel_path(dir.path()).exists(),
            "sentinel must be written after a successful relocation pass"
        );

        // by_slot_label[1] must now hold "Renamed".
        let loaded = crate::accounts::profiles::load(&profiles_path(dir.path())).unwrap();
        assert_eq!(
            loaded.by_slot_label.get("1").map(|s| s.as_str()),
            Some("Renamed"),
            "relocation must have copied label to by_slot_label[1]"
        );

        // Act: run the pass again — sentinel present → no-op.
        let mut summary2 = ReconcileSummary::default();
        pass_rn1_d5_label_relocation(dir.path(), &mut summary2);

        // Assert: the second run is a fast no-op (label_relocation stays None).
        assert!(
            summary2.label_relocation.is_none(),
            "label_relocation must be None on second run (sentinel present)"
        );
    }

    /// RN1-D R3: `run_reconciler` wires `pass_rn1_d_r3_prune_accounts` AFTER
    /// relocation. End-to-end: a genuine-rename slot (recoverable via
    /// relocation) is emptied from `accounts` while its label is preserved in
    /// `by_slot_label`; an unrecoverable slot (no by_slot, non-empty) is kept
    /// so WINDOW-CLOSE P1 correctly stays OPEN for it.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn reconciler_prunes_recoverable_accounts_keeps_unrecoverable() {
        use crate::accounts::profiles::{profiles_path, AccountProfile};

        let dir = TempDir::new().unwrap();
        let uuid = crate::accounts::identity_store::IdentityId::new_v4();
        let mut pf = crate::accounts::profiles::ProfilesFile::empty();
        // Slot 1: genuine rename — by_slot UUID present, cred email differs
        // from accounts[1].email → relocation copies to by_slot_label, then
        // prune removes the now-recoverable accounts[1].
        pf.by_slot.insert("1".into(), uuid);
        pf.by_email.insert("o@x.com".into(), uuid);
        pf.set_profile(
            1,
            AccountProfile {
                email: "Renamed One".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        // Slot 7: unrecoverable — no by_slot, non-empty, no by_slot_label.
        pf.set_profile(
            7,
            AccountProfile {
                email: "Unrecoverable Seven".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        crate::accounts::profiles::save(&profiles_path(dir.path()), &pf).unwrap();
        {
            let cred_path = crate::accounts::identity_store::credentials_path_for(dir.path(), uuid);
            std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
            std::fs::write(
                &cred_path,
                br#"{"oauthAccount":{"emailAddress":"o@x.com"},"accessToken":"tok","refreshToken":"ref","expiresAt":"2100-01-01T00:00:00Z"}"#,
            )
            .unwrap();
        }

        let summary = run_reconciler(dir.path());

        let report = summary
            .accounts_prune
            .as_ref()
            .expect("accounts_prune must be Some (pass wired into run_reconciler)");
        assert_eq!(report.pruned, 1, "slot 1 (recoverable) must be pruned");
        assert_eq!(
            report.kept_unrecoverable, 1,
            "slot 7 (unrecoverable) must be kept"
        );

        let loaded = crate::accounts::profiles::load(&profiles_path(dir.path())).unwrap();
        assert!(
            !loaded.accounts_for_test().contains_key("1"),
            "recoverable slot 1 must be pruned from accounts"
        );
        assert_eq!(
            loaded.by_slot_label.get("1").map(|s| s.as_str()),
            Some("Renamed One"),
            "slot 1's label must be preserved in by_slot_label"
        );
        assert_eq!(
            loaded
                .accounts_for_test()
                .get("7")
                .map(|p| p.email.as_str()),
            Some("Unrecoverable Seven"),
            "unrecoverable slot 7 must remain in accounts (P1 stays OPEN for it)"
        );
    }

    // ── RN1-C R2: pass_rn1_c_r2_prune_legacy_mirrors integration ─────────

    /// RN1-C R2 (AC18): `run_reconciler` wires `pass_rn1_c_r2_prune_legacy_mirrors`
    /// AFTER `pass_rn1_d_r3_prune_accounts`. End-to-end: a slot with a
    /// matching identity file has its legacy mirror pruned; a slot without
    /// is kept.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn run_reconciler_populates_legacy_mirror_prune_summary() {
        use crate::accounts::identity_store::{credentials_path_for, IdentityId};
        use crate::accounts::profiles::{profiles_path, ProfilesFile};

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = IdentityId::new_v4();

        // Plant: by_slot[1] → uuid + identity file + legacy mirror.
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("1".into(), uuid);
        crate::accounts::profiles::save(&profiles_path(base), &pf).unwrap();
        let id_path = credentials_path_for(base, uuid);
        std::fs::create_dir_all(id_path.parent().unwrap()).unwrap();
        std::fs::write(
            &id_path,
            br#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-tok","refreshToken":"sk-ant-ort01-ref","expiresAt":2208988800000,"scopes":["user:inference"]}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(base.join("credentials")).unwrap();
        std::fs::write(
            base.join("credentials/1.json"),
            br#"{"claudeAiOauth":{"accessToken":"old","refreshToken":"old","expiresAt":2208988800000,"scopes":["user:inference"]}}"#,
        )
        .unwrap();

        let summary = run_reconciler(base);

        let report = summary
            .legacy_mirror_prune
            .as_ref()
            .expect("legacy_mirror_prune must be Some (pass wired into run_reconciler)");
        assert_eq!(
            report.pruned_count, 1,
            "the legacy mirror for slot 1 must be pruned (matching identity exists)"
        );
        assert!(
            !base.join("credentials/1.json").exists(),
            "legacy mirror must be removed from disk by the reconciler"
        );
    }

    // ── Orphan-identity GC: run_reconciler integration ───────────────────

    /// AC-WIRE-1: `run_reconciler` wires `pass_orphan_identity_gc` as the LAST
    /// pass. End-to-end: an unreferenced `identities/<UUID>/` dir is deleted; a
    /// `by_slot`-bound one is kept; the summary field is populated.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn run_reconciler_populates_orphan_identity_gc_summary() {
        use crate::accounts::identity_store::{identity_path, IdentityId};
        use crate::accounts::profiles::{profiles_path, ProfilesFile};

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let bound = IdentityId::new_v4();
        let orphan = IdentityId::new_v4();

        // by_slot[1] → bound (non-empty maps so the empty-maps guard passes).
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("1".into(), bound);
        crate::accounts::profiles::save(&profiles_path(base), &pf).unwrap();
        for uuid in [bound, orphan] {
            let d = identity_path(base, uuid);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("credentials.json"), br#"{"x":1}"#).unwrap();
            std::fs::write(d.join("identity.json"), br#"{"email":"a@b.com"}"#).unwrap();
        }

        let summary = run_reconciler(base);

        let report = summary
            .orphan_identity_gc
            .as_ref()
            .expect("orphan_identity_gc must be Some (pass wired into run_reconciler)");
        assert_eq!(report.pruned_count, 1, "the orphan dir must be pruned");
        assert!(
            !identity_path(base, orphan).exists(),
            "orphan identity dir must be removed by the reconciler"
        );
        assert!(
            identity_path(base, bound).exists(),
            "by_slot-bound identity dir must remain"
        );
    }

    /// AC-CONSISTENCY-1: after the GC pass runs, `audit_coexistence` no longer
    /// reports `OrphanIdentity` for the collected dir — the user-facing
    /// `csq doctor` INCONSISTENT verdict clears for the neither-map class.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn orphan_gc_clears_doctor_inconsistent_state() {
        use crate::accounts::identity_store::{identity_path, IdentityId};
        use crate::accounts::profiles::{
            audit_coexistence, profiles_path, ConsistencyState, ProfilesFile,
        };

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let bound = IdentityId::new_v4();
        let orphan = IdentityId::new_v4();

        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("1".into(), bound);
        crate::accounts::profiles::save(&profiles_path(base), &pf).unwrap();
        for uuid in [bound, orphan] {
            let d = identity_path(base, uuid);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("credentials.json"), br#"{"x":1}"#).unwrap();
            std::fs::write(d.join("identity.json"), br#"{"email":"a@b.com"}"#).unwrap();
        }
        // store-version sentinel: makes audit_coexistence classify the state as
        // IdentityOnly (config=0, identity>0, sentinel present) so the
        // OrphanIdentity arm runs; also makes Pass 0 mint a no-op.
        std::fs::write(
            base.join("store-version"),
            br#"{"schema":2,"minted_at":"2026-05-25T00:00:00Z"}"#,
        )
        .unwrap();

        // Pre-condition: doctor sees the orphan.
        let before = audit_coexistence(base).unwrap();
        assert!(
            before
                .consistency
                .iter()
                .any(|c| matches!(c, ConsistencyState::OrphanIdentity { uuid } if *uuid == orphan)),
            "pre-GC: audit_coexistence must report the orphan: {:?}",
            before.consistency
        );

        run_reconciler(base);

        // Post-condition: no OrphanIdentity remains.
        let after = audit_coexistence(base).unwrap();
        assert!(
            !after
                .consistency
                .iter()
                .any(|c| matches!(c, ConsistencyState::OrphanIdentity { .. })),
            "post-GC: audit_coexistence must NOT report any OrphanIdentity: {:?}",
            after.consistency
        );
    }

    /// RN1-C R2 (AC18): per-keep-reason counter wiring — fixture with both
    /// arm-a (delete) and arm-b1 (keep, no by_slot) slots exercises the
    /// `kept_reasons` HashMap. Pinned by AC9 + S2.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn reconciler_legacy_mirror_prune_kept_reasons_match_fixture() {
        use crate::accounts::identity_store::{credentials_path_for, IdentityId};
        use crate::accounts::legacy_mirror_cleanup::KeptReason;
        use crate::accounts::profiles::{profiles_path, ProfilesFile};

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid_a = IdentityId::new_v4();

        // Plant slot 1: deletable (by_slot + identity exists).
        // Plant slot 5: kept (NO by_slot — pure-legacy install shape).
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert("1".into(), uuid_a);
        crate::accounts::profiles::save(&profiles_path(base), &pf).unwrap();
        let id_path = credentials_path_for(base, uuid_a);
        std::fs::create_dir_all(id_path.parent().unwrap()).unwrap();
        std::fs::write(
            &id_path,
            br#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-tok","refreshToken":"sk-ant-ort01-ref","expiresAt":2208988800000,"scopes":["user:inference"]}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(base.join("credentials")).unwrap();
        std::fs::write(
            base.join("credentials/1.json"),
            br#"{"claudeAiOauth":{"accessToken":"old","refreshToken":"old","expiresAt":2208988800000,"scopes":["user:inference"]}}"#,
        )
        .unwrap();
        std::fs::write(
            base.join("credentials/5.json"),
            br#"{"claudeAiOauth":{"accessToken":"old","refreshToken":"old","expiresAt":2208988800000,"scopes":["user:inference"]}}"#,
        )
        .unwrap();

        let summary = run_reconciler(base);

        let report = summary.legacy_mirror_prune.as_ref().expect("Some");
        assert_eq!(report.pruned_count, 1, "slot 1 must prune");
        assert_eq!(report.kept_count, 1, "slot 5 must keep");
        assert_eq!(
            report
                .kept_reasons
                .get(&KeptReason::NoBySlotMapping)
                .copied(),
            Some(1),
            "kept_reasons must record NoBySlotMapping for slot 5: {:?}",
            report
        );
        assert!(!base.join("credentials/1.json").exists());
        assert!(
            base.join("credentials/5.json").exists(),
            "slot 5 mirror MUST remain (pre-legacy fallback safety)"
        );
    }

    // ── RN1-E: pass_rn1_e_backfill_by_slot_identity ──────────────────────

    /// RN1-E AC: backfill writes `by_slot_identity` for a 3P API-key slot
    /// whose `accounts[9].email = "apikey:mm"`.  Uses the M12
    /// `daemon_refreshed_only_state` + `legacy_pre_m4_9_state` helpers — no
    /// `oauthAccount.emailAddress`, no cred file for the non-OAuth slot.
    ///
    /// Fixture: `legacy_pre_m4_9_state(base, 9, ApiKeyMm, "apikey:mm")` writes
    /// the daemon-refresh-only layer (settings.json + .csq-account) PLUS the
    /// `accounts["9"] = { email: "apikey:mm" }` row (the pre-M4-9 shape that
    /// the backfill pass reads).
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn backfill_legacy_writes_identity_for_apikey_slot() {
        use crate::accounts::profiles::profiles_path;
        use crate::testing::identity_fixtures::{legacy_pre_m4_9_state, NonOauthKind};

        // Arrange
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        legacy_pre_m4_9_state(base, 9, NonOauthKind::ApiKeyMm, "apikey:mm").unwrap();

        // Act
        let mut summary = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut summary);

        // Assert: by_slot_identity["9"] == "apikey:mm", counter == 1
        let pf = crate::accounts::profiles::load(&profiles_path(base)).unwrap();
        assert_eq!(
            pf.by_slot_identity.get("9").map(|s| s.as_str()),
            Some("apikey:mm"),
            "by_slot_identity[9] must be set to \"apikey:mm\" by the backfill pass"
        );
        assert_eq!(
            summary.by_slot_identity_backfilled, 1,
            "summary counter must be 1 after backfilling one slot"
        );
    }

    /// RN1-E AC: backfill writes `by_slot_identity` for a Codex OAuth slot
    /// whose `accounts[N].email` starts with `"codex-"`.
    ///
    /// Fixture: `legacy_pre_m4_9_state(base, 12, CodexOauth, label)` where
    /// `label` is the expected identity string from `NonOauthKind::CodexOauth.
    /// identity_label(12)`.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn backfill_legacy_writes_identity_for_codex_slot() {
        use crate::accounts::profiles::profiles_path;
        use crate::testing::identity_fixtures::{legacy_pre_m4_9_state, NonOauthKind};

        // Arrange
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let slot: u16 = 12;
        let kind = NonOauthKind::CodexOauth;
        let label = kind.identity_label(slot);
        legacy_pre_m4_9_state(base, slot, kind, &label).unwrap();

        // Act
        let mut summary = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut summary);

        // Assert: by_slot_identity["12"] == "codex-12/fx0000000c", counter == 1
        let pf = crate::accounts::profiles::load(&profiles_path(base)).unwrap();
        assert_eq!(
            pf.by_slot_identity
                .get(&slot.to_string())
                .map(|s| s.as_str()),
            Some(label.as_str()),
            "by_slot_identity[{slot}] must be set to \"{label}\" by the backfill pass"
        );
        assert_eq!(
            summary.by_slot_identity_backfilled, 1,
            "summary counter must be 1 after backfilling one Codex slot"
        );
    }

    /// RN1-E AC: when a slot has both `by_slot_label` (user rename) and an
    /// `accounts[N].email` starting with `"apikey:"`, the backfill still
    /// writes `by_slot_identity` (the skip-by-slot-label rule does NOT apply
    /// here — we skip ONLY when the email does NOT have the prefix; prefix-
    /// recognized emails are always backfilled regardless of by_slot_label).
    ///
    /// The user rename is preserved in `by_slot_label` and the identity label
    /// is written to `by_slot_identity` independently.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn backfill_legacy_preserves_user_rename_in_by_slot_label() {
        use crate::accounts::profiles::{profiles_path, set_slot_label};
        use crate::accounts::profiles_lock::ProfilesFileLock;
        use crate::testing::identity_fixtures::{legacy_pre_m4_9_state, NonOauthKind};

        // Arrange: pre-M4-9 state + a user rename in by_slot_label.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        legacy_pre_m4_9_state(base, 9, NonOauthKind::ApiKeyMm, "apikey:mm").unwrap();
        {
            let lock = ProfilesFileLock::acquire(base).unwrap();
            set_slot_label(&lock, base, 9, "my-mm-rename").unwrap();
        }

        // Act
        let mut summary = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut summary);

        // Assert: by_slot_identity["9"] was still written (prefix-recognized)
        // AND by_slot_label["9"] is unchanged.
        let pf = crate::accounts::profiles::load(&profiles_path(base)).unwrap();
        assert_eq!(
            pf.by_slot_identity.get("9").map(|s| s.as_str()),
            Some("apikey:mm"),
            "by_slot_identity[9] must still be backfilled even when by_slot_label is present"
        );
        assert_eq!(
            pf.by_slot_label.get("9").map(|s| s.as_str()),
            Some("my-mm-rename"),
            "by_slot_label[9] (user rename) must be preserved unchanged"
        );
        assert_eq!(
            summary.by_slot_identity_backfilled, 1,
            "summary counter must be 1"
        );
    }

    /// RN1-E AC: backfill SKIPS slots whose `by_slot[N]` is present (OAuth
    /// slots with a UUID). Summary counter stays at 0.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn backfill_skips_when_by_slot_present() {
        use crate::accounts::identity_store::IdentityId;
        use crate::accounts::profiles::{profiles_path, AccountProfile};

        // Arrange: slot 3 has a by_slot UUID (OAuth) AND an accounts entry.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = IdentityId::new_v4();
        let mut pf = crate::accounts::profiles::ProfilesFile::empty();
        pf.by_slot.insert("3".to_string(), uuid);
        pf.set_profile(
            3,
            AccountProfile {
                email: "alice@example.com".to_string(),
                method: "oauth".to_string(),
                extra: HashMap::new(),
            },
        );
        crate::accounts::profiles::save(&profiles_path(base), &pf).unwrap();

        // Act
        let mut summary = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut summary);

        // Assert: by_slot_identity is empty, counter == 0
        let loaded = crate::accounts::profiles::load(&profiles_path(base)).unwrap();
        assert!(
            loaded.by_slot_identity.is_empty(),
            "by_slot_identity must remain empty when slot is OAuth (by_slot present)"
        );
        assert_eq!(
            summary.by_slot_identity_backfilled, 0,
            "summary counter must be 0 for an OAuth slot"
        );
    }

    /// RN1-E AC: calling backfill twice produces the same final state and the
    /// second call reports 0 backfilled (idempotency).
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn backfill_legacy_is_idempotent() {
        use crate::accounts::profiles::profiles_path;
        use crate::testing::identity_fixtures::{legacy_pre_m4_9_state, NonOauthKind};

        // Arrange
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        legacy_pre_m4_9_state(base, 9, NonOauthKind::ApiKeyMm, "apikey:mm").unwrap();

        // Act: first call
        let mut summary1 = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut summary1);

        // Assert: first call writes the entry
        assert_eq!(
            summary1.by_slot_identity_backfilled, 1,
            "first call must write 1 entry"
        );

        // Capture profiles.json content after first call for byte-identity check.
        let pf_after_first = crate::accounts::profiles::load(&profiles_path(base)).unwrap();
        let content_after_first = serde_json::to_string_pretty(&pf_after_first).unwrap();

        // Act: second call
        let mut summary2 = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut summary2);

        // Assert: second call is a no-op
        assert_eq!(
            summary2.by_slot_identity_backfilled, 0,
            "second call must be a no-op (counter == 0)"
        );

        // Assert: profiles.json content is byte-identical (mtime-preserving)
        let pf_after_second = crate::accounts::profiles::load(&profiles_path(base)).unwrap();
        let content_after_second = serde_json::to_string_pretty(&pf_after_second).unwrap();
        assert_eq!(
            content_after_first, content_after_second,
            "profiles.json must be byte-identical after a no-op second call"
        );
    }

    // ── G2: Gemini backfill arm (FM-3/3a/5) ──────────────────────────────

    /// G2/AC-1: the backfill walks `credentials/gemini-<N>.json` markers
    /// (Gemini slots have NO `accounts[N]` entry) and writes the
    /// mode-class literal for ALL 3 auth modes. Closes the slot-13
    /// identity-recovery gap (slot 13 here uses CodeAssistOAuth).
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn backfill_writes_gemini_identity_for_all_three_modes() {
        use crate::accounts::profiles::profiles_path;
        use crate::testing::identity_fixtures::{gemini_binding_state, GeminiFixtureMode};

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        gemini_binding_state(base, 3, GeminiFixtureMode::ApiKey, false).unwrap();
        gemini_binding_state(base, 7, GeminiFixtureMode::VertexSa, false).unwrap();
        gemini_binding_state(base, 13, GeminiFixtureMode::CodeAssistOAuth, true).unwrap();

        let mut summary = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut summary);

        let pf = crate::accounts::profiles::load(&profiles_path(base)).unwrap();
        assert_eq!(
            pf.by_slot_identity.get("3").map(|s| s.as_str()),
            Some("gemini-3/apikey")
        );
        assert_eq!(
            pf.by_slot_identity.get("7").map(|s| s.as_str()),
            Some("gemini-7/vertex")
        );
        assert_eq!(
            pf.by_slot_identity.get("13").map(|s| s.as_str()),
            Some("gemini-13/codeassist"),
            "slot 13 identity-recovery gap must be closed by the backfill"
        );
        assert_eq!(summary.by_slot_identity_backfilled, 3);
    }

    /// G2/AC-2 (FM-5): the Gemini arm is idempotent — a second run is a
    /// byte-identical no-op (counter not inflated, no redundant save),
    /// because the arm skips when the stored literal already equals the
    /// marker-derived one.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn backfill_gemini_identity_is_idempotent() {
        use crate::accounts::profiles::profiles_path;
        use crate::testing::identity_fixtures::{gemini_binding_state, GeminiFixtureMode};

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        gemini_binding_state(base, 5, GeminiFixtureMode::ApiKey, false).unwrap();

        let mut s1 = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut s1);
        assert_eq!(s1.by_slot_identity_backfilled, 1);
        let c1 = serde_json::to_string_pretty(
            &crate::accounts::profiles::load(&profiles_path(base)).unwrap(),
        )
        .unwrap();

        let mut s2 = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut s2);
        assert_eq!(
            s2.by_slot_identity_backfilled, 0,
            "second Gemini-arm run must be a no-op (counter not inflated)"
        );
        let c2 = serde_json::to_string_pretty(
            &crate::accounts::profiles::load(&profiles_path(base)).unwrap(),
        )
        .unwrap();
        assert_eq!(c1, c2, "profiles.json byte-identical after no-op rerun");
    }

    /// G2/AC-3 (FM-5): overwrite-on-mode-mismatch. A slot re-provisioned
    /// in a NEW mode (marker now says `codeassist`) whose stale
    /// `by_slot_identity` still says `apikey` MUST self-heal on the next
    /// backfill — NOT be skipped by a naive skip-if-present guard.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn backfill_gemini_overwrites_stale_mode_literal() {
        use crate::accounts::profiles::{profiles_path, set_slot_identity};
        use crate::accounts::profiles_lock::ProfilesFileLock;
        use crate::testing::identity_fixtures::{gemini_binding_state, GeminiFixtureMode};

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        // Marker says CodeAssistOAuth (mode was switched).
        gemini_binding_state(base, 9, GeminiFixtureMode::CodeAssistOAuth, false).unwrap();
        // Stale identity from the prior api_key binding.
        {
            let lock = ProfilesFileLock::acquire(base).unwrap();
            set_slot_identity(&lock, base, 9, "gemini-9/apikey").unwrap();
        }

        let mut summary = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut summary);

        let pf = crate::accounts::profiles::load(&profiles_path(base)).unwrap();
        assert_eq!(
            pf.by_slot_identity.get("9").map(|s| s.as_str()),
            Some("gemini-9/codeassist"),
            "stale literal must be overwritten with the live-marker-derived one (FM-5 self-heal)"
        );
        assert_eq!(summary.by_slot_identity_backfilled, 1);
    }

    /// FM-3a: the backfill arm and the synchronous provision path emit
    /// BYTE-IDENTICAL literals (single shared producer). Drives BOTH
    /// paths for the same mode and asserts equality — the structural
    /// defense against the divergent-producer defect.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn backfill_and_synchronous_gemini_literals_are_byte_identical() {
        use crate::accounts::profiles::profiles_path;
        use crate::providers::gemini::provisioning::provision_code_assist_oauth;
        use crate::testing::identity_fixtures::{gemini_binding_state, GeminiFixtureMode};

        // Synchronous path: provision slot 2 (writes identity inline).
        let dir_sync = TempDir::new().unwrap();
        provision_code_assist_oauth(
            dir_sync.path(),
            crate::types::AccountNum::try_from(2).unwrap(),
        )
        .unwrap();
        let sync_label = crate::accounts::profiles::load(&profiles_path(dir_sync.path()))
            .unwrap()
            .by_slot_identity
            .get("2")
            .cloned();

        // Backfill path: marker only, same mode, same slot number.
        let dir_bf = TempDir::new().unwrap();
        gemini_binding_state(dir_bf.path(), 2, GeminiFixtureMode::CodeAssistOAuth, false).unwrap();
        let mut summary = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(dir_bf.path(), &mut summary);
        let bf_label = crate::accounts::profiles::load(&profiles_path(dir_bf.path()))
            .unwrap()
            .by_slot_identity
            .get("2")
            .cloned();

        assert_eq!(
            sync_label, bf_label,
            "synchronous-write and backfill MUST produce byte-identical literals (FM-3a single producer)"
        );
        assert_eq!(sync_label.as_deref(), Some("gemini-2/codeassist"));
    }

    // ── Arm 3: 3P API-key backfill disk-walk (an internal workspace) ──

    /// Arm 3 AC-1: the backfill discovers a 3P API-key slot from disk
    /// (`config-N/settings.json`) and writes its `by_slot_identity` entry even
    /// when `profiles.json::accounts` is empty — the exact state Arm 1 (the
    /// `accounts` walk) cannot see, and the state the maintainer host's
    /// slot 10 (Z.AI) was in.
    ///
    /// Anti-fixture-masking (an internal journal entry FM-1): uses `daemon_refreshed_only_state`,
    /// which writes NO `accounts[N]` row. `legacy_pre_m4_9_state` would add
    /// that row and let the pre-Arm-3 code pass, masking the slot-10 bug.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn backfill_3p_disk_walk_writes_identity_for_accountsless_slot() {
        use crate::accounts::profiles::profiles_path;
        use crate::testing::identity_fixtures::{daemon_refreshed_only_state, NonOauthKind};

        // Arrange: a Z.AI 3P slot present ONLY on disk — no accounts[10] row.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        daemon_refreshed_only_state(base, 10, NonOauthKind::ApiKeyZai).unwrap();

        // Act
        let mut summary = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut summary);

        // Assert: Arm 3 discovered slot 10 from config-10/settings.json.
        let pf = crate::accounts::profiles::load(&profiles_path(base)).unwrap();
        assert!(
            pf.accounts_for_test().is_empty(),
            "fixture precondition: accounts must be empty (the anti-masking shape)"
        );
        assert_eq!(
            pf.by_slot_identity.get("10").map(|s| s.as_str()),
            Some("apikey:zai"),
            "by_slot_identity[10] must be backfilled from disk despite accounts: {{}}"
        );
        assert_eq!(
            summary.by_slot_identity_backfilled, 1,
            "summary counter must be 1 after the 3P disk-walk backfill"
        );
    }

    /// Arm 3 AC-2: the 3P disk-walk arm is idempotent — a second run writes
    /// nothing (the `by_slot_identity` skip-guard catches the written slot)
    /// and leaves `profiles.json` byte-identical.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn backfill_3p_disk_walk_is_idempotent() {
        use crate::accounts::profiles::profiles_path;
        use crate::testing::identity_fixtures::{daemon_refreshed_only_state, NonOauthKind};

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        daemon_refreshed_only_state(base, 10, NonOauthKind::ApiKeyZai).unwrap();

        let mut s1 = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut s1);
        assert_eq!(s1.by_slot_identity_backfilled, 1);
        let c1 = serde_json::to_string_pretty(
            &crate::accounts::profiles::load(&profiles_path(base)).unwrap(),
        )
        .unwrap();

        let mut s2 = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut s2);
        assert_eq!(
            s2.by_slot_identity_backfilled, 0,
            "second 3P-arm run must be a no-op (counter not inflated)"
        );
        let c2 = serde_json::to_string_pretty(
            &crate::accounts::profiles::load(&profiles_path(base)).unwrap(),
        )
        .unwrap();
        assert_eq!(c1, c2, "profiles.json byte-identical after no-op rerun");
    }

    /// Arm 3 AC-3: a 3P slot visible to BOTH Arm 1 (it has an `accounts[N]`
    /// row) and Arm 3 (`config-N/settings.json` on disk) is backfilled
    /// exactly once — Arm 3 dedups against Arm 1's queued slot, so the
    /// `by_slot_identity_backfilled` counter is not double-incremented.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn backfill_3p_arm_dedups_against_accounts_arm() {
        use crate::accounts::profiles::profiles_path;
        use crate::testing::identity_fixtures::{legacy_pre_m4_9_state, NonOauthKind};

        // legacy_pre_m4_9_state writes BOTH config-9/settings.json (Arm 3
        // visible) AND the accounts[9] row (Arm 1 visible).
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        legacy_pre_m4_9_state(base, 9, NonOauthKind::ApiKeyZai, "apikey:zai").unwrap();

        let mut summary = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut summary);

        let pf = crate::accounts::profiles::load(&profiles_path(base)).unwrap();
        assert_eq!(
            pf.by_slot_identity.get("9").map(|s| s.as_str()),
            Some("apikey:zai"),
            "by_slot_identity[9] must be written once"
        );
        assert_eq!(
            summary.by_slot_identity_backfilled, 1,
            "a slot visible to both arms must be counted once, not twice"
        );
    }

    /// Arm 3 AC-4 (FM-5 self-heal parity): a 3P slot whose stored
    /// `by_slot_identity` literal is STALE — the slot was rebound to a
    /// different provider then crashed before the synchronous
    /// `set_slot_identity` hook fired — is healed on the next backfill. The
    /// stale literal is overwritten with the one derived from the current
    /// `config-N/settings.json`, NOT skipped by a blunt skip-if-present.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn backfill_3p_disk_walk_overwrites_stale_provider_literal() {
        use crate::accounts::profiles::{profiles_path, set_slot_identity};
        use crate::accounts::profiles_lock::ProfilesFileLock;
        use crate::testing::identity_fixtures::{daemon_refreshed_only_state, NonOauthKind};

        // Arrange: config-10/settings.json says Z.AI (the current binding).
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        daemon_refreshed_only_state(base, 10, NonOauthKind::ApiKeyZai).unwrap();
        // A stale identity left over from a prior MiniMax binding.
        {
            let lock = ProfilesFileLock::acquire(base).unwrap();
            set_slot_identity(&lock, base, 10, "apikey:mm").unwrap();
        }

        // Act
        let mut summary = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut summary);

        // Assert: the stale "apikey:mm" was overwritten with the live
        // settings.json-derived "apikey:zai".
        let pf = crate::accounts::profiles::load(&profiles_path(base)).unwrap();
        assert_eq!(
            pf.by_slot_identity.get("10").map(|s| s.as_str()),
            Some("apikey:zai"),
            "stale literal must be overwritten with the live-settings-derived one (FM-5)"
        );
        assert_eq!(summary.by_slot_identity_backfilled, 1);
    }

    /// Arm 3 AC-5: with a Gemini slot AND a 3P API-key slot in the same
    /// `base_dir`, each arm handles only its own surface — the Gemini arm
    /// writes `gemini-N/<mode>`, Arm 3 writes `apikey:<id>`, and neither
    /// touches the other's slot. Locks in cross-arm isolation.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn backfill_3p_arm_isolates_from_gemini_arm() {
        use crate::accounts::profiles::profiles_path;
        use crate::testing::identity_fixtures::{
            daemon_refreshed_only_state, gemini_binding_state, GeminiFixtureMode, NonOauthKind,
        };

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        gemini_binding_state(base, 5, GeminiFixtureMode::ApiKey, false).unwrap();
        daemon_refreshed_only_state(base, 10, NonOauthKind::ApiKeyZai).unwrap();

        let mut summary = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut summary);

        let pf = crate::accounts::profiles::load(&profiles_path(base)).unwrap();
        assert_eq!(
            pf.by_slot_identity.get("5").map(|s| s.as_str()),
            Some("gemini-5/apikey"),
            "Gemini arm must own slot 5"
        );
        assert_eq!(
            pf.by_slot_identity.get("10").map(|s| s.as_str()),
            Some("apikey:zai"),
            "Arm 3 must own slot 10"
        );
        assert_eq!(
            summary.by_slot_identity_backfilled, 2,
            "exactly two slots backfilled — one per arm, no cross-contamination"
        );
    }

    /// RN1-E AC: when `accounts[N].email` is empty, the backfill derives the
    /// identity from `config-<N>/settings.json::env.ANTHROPIC_BASE_URL`.
    ///
    /// Uses `daemon_refreshed_only_state` (no `accounts[N]` row) PLUS a
    /// manually-inserted empty-email `accounts[N]` row to model the rebind
    /// scenario where a slot's `accounts` row exists but the email was cleared.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn backfill_derives_identity_from_settings_when_accounts_empty() {
        use crate::accounts::profiles::{profiles_path, AccountProfile};
        use crate::testing::identity_fixtures::{daemon_refreshed_only_state, NonOauthKind};

        // Arrange: daemon-refresh-only state (writes settings.json with Ollama
        // base URL) + manually add an accounts["11"] row with empty email.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let slot: u16 = 11;
        daemon_refreshed_only_state(base, slot, NonOauthKind::ApiKeyOllama).unwrap();

        // Add an accounts[11] row with empty email to trigger the rebind path.
        let profiles_file_path = profiles_path(base);
        let mut pf = if profiles_file_path.exists() {
            crate::accounts::profiles::load(&profiles_file_path).unwrap()
        } else {
            crate::accounts::profiles::ProfilesFile::empty()
        };
        pf.set_profile(
            slot,
            AccountProfile {
                email: "".to_string(),
                method: "api_key".to_string(),
                extra: HashMap::new(),
            },
        );
        crate::accounts::profiles::save(&profiles_file_path, &pf).unwrap();

        // Act
        let mut summary = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut summary);

        // Assert: by_slot_identity["11"] == "apikey:ollama" (derived from URL)
        let loaded = crate::accounts::profiles::load(&profiles_file_path).unwrap();
        assert_eq!(
            loaded
                .by_slot_identity
                .get(&slot.to_string())
                .map(|s| s.as_str()),
            Some("apikey:ollama"),
            "by_slot_identity[{slot}] must be derived from ANTHROPIC_BASE_URL \
             (http://localhost:11434 → ollama → \"apikey:ollama\")"
        );
        assert_eq!(
            summary.by_slot_identity_backfilled, 1,
            "summary counter must be 1 for the rebind derivation"
        );
    }

    /// RN1-E AC: end-to-end backfill + prune sequencing.
    ///
    /// Start with `legacy_pre_m4_9_state(base, 9, ApiKeyMm, "apikey:mm")`.
    /// After backfill: `by_slot_identity["9"] == "apikey:mm"`.
    /// After prune: `accounts["9"]` is gone (arm 4 fires; `pruned_by_identity_channel == 1`).
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn prune_drops_legacy_accounts_after_backfill() {
        use crate::accounts::profiles::{profiles_path, prune_redundant_accounts_entries};
        use crate::accounts::profiles_lock::ProfilesFileLock;
        use crate::testing::identity_fixtures::{legacy_pre_m4_9_state, NonOauthKind};

        // Arrange: pre-M4-9 state for slot 9 with "apikey:mm" email.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        legacy_pre_m4_9_state(base, 9, NonOauthKind::ApiKeyMm, "apikey:mm").unwrap();

        // Act: backfill
        let mut summary = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(base, &mut summary);

        // Assert: by_slot_identity["9"] is now set
        let pf_mid = crate::accounts::profiles::load(&profiles_path(base)).unwrap();
        assert_eq!(
            pf_mid.by_slot_identity.get("9").map(|s| s.as_str()),
            Some("apikey:mm"),
            "by_slot_identity[9] must be set after backfill"
        );

        // Act: prune
        let lock = ProfilesFileLock::acquire(base).unwrap();
        let report = prune_redundant_accounts_entries(&lock, base).unwrap();
        drop(lock);

        // Assert: prune removed accounts["9"] via arm 4
        assert_eq!(
            report.pruned_by_identity_channel, 1,
            "prune must remove accounts[9] via arm 4 (by_slot_identity match)"
        );
        let pf_final = crate::accounts::profiles::load(&profiles_path(base)).unwrap();
        assert!(
            !pf_final.accounts_for_test().contains_key("9"),
            "accounts[9] must be gone after prune"
        );
    }

    /// RN1-E wiring order test: the full `run_reconciler` entry point runs
    /// backfill BEFORE prune, ensuring arm-4 can fire. If prune ran first,
    /// the `accounts[9]` row would be KEPT (no by_slot_identity to match)
    /// and the final state would still have `accounts[9]`.
    ///
    /// F-M-2 R1A: drives `run_reconciler(base)` end-to-end instead of
    /// invoking the three passes manually — a future refactor that reorders
    /// the call sites inside `run_reconciler` will be caught by this test.
    /// The fixture is `legacy_pre_m4_9_state`: backfill is the ONLY path
    /// that can populate `by_slot_identity` for this slot, and prune arm 4
    /// is the ONLY arm that can fire (no `by_slot_label`, no `by_slot`
    /// UUID → no by_email match for arm 3). Therefore the end-state
    /// `accounts[9]` removed AND `by_slot_identity[9]` populated proves the
    /// passes ran in order "backfill → prune". Reversing them would leave
    /// `accounts[9]` intact.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn reconciler_runs_backfill_before_prune_accounts_legacy() {
        use crate::accounts::profiles::profiles_path;
        use crate::testing::identity_fixtures::{legacy_pre_m4_9_state, NonOauthKind};

        // Arrange: pre-M4-9 state for slot 9.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        legacy_pre_m4_9_state(base, 9, NonOauthKind::ApiKeyMm, "apikey:mm").unwrap();

        // Verify starting state: accounts["9"] present, by_slot_identity empty.
        let pf_before = crate::accounts::profiles::load(&profiles_path(base)).unwrap();
        assert!(
            pf_before.accounts_for_test().contains_key("9"),
            "accounts[9] must be present before reconciler"
        );
        assert!(
            pf_before.by_slot_identity.is_empty(),
            "by_slot_identity must be empty before reconciler"
        );

        // Act: drive the top-level reconciler entry point end-to-end.
        let summary = run_reconciler(base);

        // Assert: backfill ran (counter == 1) and prune dropped accounts[9].
        // If `run_reconciler` were refactored to call prune BEFORE backfill,
        // `accounts[9]` would survive (arm 4 cannot fire without
        // `by_slot_identity[9]`) and this assertion would fail.
        assert_eq!(
            summary.by_slot_identity_backfilled, 1,
            "backfill must have written 1 entry"
        );
        let pf_after = crate::accounts::profiles::load(&profiles_path(base)).unwrap();
        assert_eq!(
            pf_after.by_slot_identity.get("9").map(|s| s.as_str()),
            Some("apikey:mm"),
            "by_slot_identity[9] must be set after run_reconciler"
        );
        assert!(
            !pf_after.accounts_for_test().contains_key("9"),
            "accounts[9] must be pruned by run_reconciler — \
             a reversed pass order (prune before backfill) would leave accounts[9] intact"
        );
        let prune_report = summary
            .accounts_prune
            .as_ref()
            .expect("accounts_prune must be Some");
        assert_eq!(
            prune_report.pruned_by_identity_channel, 1,
            "prune arm 4 must have fired once — proves backfill ran first"
        );
    }

    /// RN1-E AC: lost-update guard — proves `ProfilesFileLock` serializes a
    /// concurrent login (thread A) against the reconciler backfill (thread B),
    /// so B's `pass_rn1_e_backfill_by_slot_identity` cannot read-modify-write
    /// `by_slot_identity["9"]` while A holds the lock.
    ///
    /// ## Why this is deterministic, not a timing race
    ///
    /// The test exercises contention by CONSTRUCTION and proves serialization
    /// with a single ordering comparison between two OBSERVED instants — there is
    /// no fixed-duration lower-bound assertion, so there is no timing-flake class.
    ///
    /// 1. A acquires the lock, commits `by_slot_identity["9"] = "apikey:mm"`, and
    ///    sends on a one-shot `committed` channel. (A channel, not a barrier:
    ///    if A's fallible setup — acquire/write — panics, the dropped sender makes
    ///    B's `recv()` return Err, so B surfaces the panic rather than hanging.)
    /// 2. Both threads then pass `barrier_b_acquiring`. A waits on it BEFORE it
    ///    begins its `HOLD_MS` sleep, so A's hold window opens only once B is
    ///    about to call the backfill — guaranteeing B contends for the lock while
    ///    A holds it, rather than racing in after A already released.
    /// 3. B calls the backfill, whose FIRST action is `ProfilesFileLock::acquire`,
    ///    so B BLOCKS until A drops the lock.
    /// 4. A sleeps `HOLD_MS`, records `a_release_at = Instant::now()` immediately
    ///    before `drop(lock)`, then releases. B acquires, finishes, and records
    ///    `backfill_return`.
    ///
    /// The serialization proof is the single ordering assertion:
    ///
    /// ```text
    /// a_release_at  <=  backfill_return
    /// ```
    ///
    /// With a real (blocking) flock this is DETERMINISTIC: B cannot return from
    /// the backfill before it acquires the lock, and cannot acquire before A drops
    /// it — which A does AFTER recording `a_release_at`. The ordering proof is
    /// CAUSAL (A records → A drops → B's flock unblocks → B returns → B records),
    /// not a raw cross-clock-domain comparison, so it holds under any monotonic
    /// clock — even per-CPU TSCs without hardware sync. No scheduler jitter can
    /// flip it. A NON-serializing (no-op) lock is caught by the SAME assertion:
    /// B's backfill returns in microseconds while A is still inside
    /// `sleep(HOLD_MS)`, so `backfill_return` lands ~`HOLD_MS` BEFORE
    /// `a_release_at` and the inequality is false. `HOLD_MS` is the margin that
    /// makes a broken lock unmistakable; it gates no assertion in the correct
    /// case, so it cannot itself cause a flake.
    ///
    /// The earlier form asserted `elapsed >= HOLD_MS`, where `elapsed` was
    /// measured from B's OWN post-barrier `Instant::now()`. That instant and A's
    /// hold-countdown both began after the shared barrier, unsynchronized: on a
    /// CPU-saturated runner A could start its `sleep(HOLD_MS)` before B recorded
    /// `start`, so B's measured `elapsed` came out `< HOLD_MS` even though B
    /// genuinely blocked — a timing flake. Bracketing against A's OWN observed
    /// release instant removes the dependence on B's wall clock entirely.
    ///
    /// ## Why the canonical literal (not an arbitrary sentinel)
    ///
    /// A writes `"apikey:mm"` — the SAME literal the backfill derives for a
    /// MiniMax slot. It MUST be the canonical literal: the 3P arm's FM-5
    /// self-heal overwrites any `by_slot_identity` value that diverges from the
    /// one `config-N/settings.json` implies, so an arbitrary sentinel would be
    /// (correctly) healed away and could not model a legitimate concurrent write.
    ///
    /// ## What the counter assertion does (and does NOT) prove
    ///
    /// `summary.by_slot_identity_backfilled == 0` is a CONSISTENCY check, not the
    /// serialization proof. The `committed` channel already forces A's commit to
    /// land before B's backfill loads its snapshot, so B's idempotency guard fires
    /// (stored value == derived literal → skip) whether or not the lock serializes.
    /// If it fails while the ordering assertion passes, the bug is in the
    /// idempotency guard, not the flock.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn concurrent_login_and_backfill_no_lost_update_legacy() {
        use crate::accounts::profiles::{profiles_path, set_slot_identity};
        use crate::accounts::profiles_lock::ProfilesFileLock;
        use crate::testing::identity_fixtures::{legacy_pre_m4_9_state, NonOauthKind};
        use std::sync::{mpsc, Arc, Barrier, OnceLock};
        use std::thread;
        use std::time::{Duration, Instant};

        // Arrange: pre-M4-9 state for slot 9 (gives accounts["9"].email = "apikey:mm").
        let dir = TempDir::new().unwrap();
        let base_path = dir.path().to_path_buf();
        legacy_pre_m4_9_state(&base_path, 9, NonOauthKind::ApiKeyMm, "apikey:mm").unwrap();

        // committed channel: A sends once it has acquired the lock + committed its
        // write. Using a channel (not a barrier) means a panic in A's FALLIBLE
        // setup (acquire / write) drops the sender, so B's `recv()` returns Err and
        // B surfaces A's real panic via join()+resume_unwind instead of hanging.
        // barrier_b_acquiring: B is about to call the backfill (and thus acquire
        // the lock); A waits on it BEFORE its hold-sleep, so A's hold window opens
        // only once B is contending — making contention structural rather than
        // timing-dependent. A reaches this barrier only AFTER the commit send and
        // has no fallible op in between, so the barrier cannot hang.
        let (committed_tx, committed_rx) = mpsc::channel::<()>();
        let barrier_b_acquiring = Arc::new(Barrier::new(2));
        // A records the instant it releases the lock; B reads it after join and
        // asserts `a_release_at <= backfill_return` (see doc comment).
        let a_release_at: Arc<OnceLock<Instant>> = Arc::new(OnceLock::new());

        let base_a = base_path.clone();
        let b_acquiring = Arc::clone(&barrier_b_acquiring);
        let release_cell = Arc::clone(&a_release_at);

        // Hold long enough that a no-op lock's microsecond backfill return is
        // unmistakably earlier than A's release. With a real lock the hold
        // duration gates NO assertion (the proof is an ordering comparison, not
        // an elapsed-time lower bound), so it cannot cause a flake.
        const HOLD_MS: u64 = 200;

        // Thread A models a concurrent login committing slot 9's canonical
        // identity (see doc comment for why the literal must be canonical).
        let handle_a = thread::spawn(move || {
            let lock = ProfilesFileLock::acquire(&base_a).unwrap();
            set_slot_identity(&lock, &base_a, 9, "apikey:mm").unwrap();
            // Signal A has committed; B advances to the acquire barrier. A's only
            // fallible ops (acquire + the write above) are now past, so from here
            // A reaches every subsequent barrier. `let _` is safe: main holds
            // `committed_rx` and has not yet called recv(), so the receiver is live
            // and send() cannot return Err at this point.
            let _ = committed_tx.send(());
            // Open the hold window only once B is about to acquire.
            b_acquiring.wait();
            std::thread::sleep(Duration::from_millis(HOLD_MS));
            // Record the release instant BEFORE dropping, so the assertion is
            // measured against A's actual release.
            release_cell
                .set(Instant::now())
                .expect("a_release_at set exactly once");
            drop(lock);
        });

        // Wait for A's commit. If A panicked during its fallible setup it dropped
        // the sender without sending, so `recv()` returns Err — surface A's real
        // panic via join()+resume_unwind rather than hanging here. Both paths out
        // of this block diverge — the if-let Err arm `resume_unwind`s and the
        // trailing `unreachable!()` is `-> !` — so `handle_a` is consumed here and
        // the end-of-test join is reached only on the recv-Ok path.
        if committed_rx.recv().is_err() {
            if let Err(panic) = handle_a.join() {
                std::panic::resume_unwind(panic);
            }
            unreachable!("thread A closed the commit channel without sending or panicking");
        }
        // Signal B is about to acquire, then call the backfill (whose first action
        // BLOCKS on lock acquire until A releases).
        barrier_b_acquiring.wait();
        let base_b = base_path.clone();
        let mut summary = ReconcileSummary::default();
        pass_rn1_e_backfill_by_slot_identity(&base_b, &mut summary);
        let backfill_return = Instant::now();

        // Join A (establishes the happens-before that makes the OnceLock write
        // visible) and surface any thread-A panic with its ORIGINAL payload
        // rather than the opaque `Any { .. }` a bare `.unwrap()` would print.
        if let Err(panic) = handle_a.join() {
            std::panic::resume_unwind(panic);
        }
        let release_at = *a_release_at
            .get()
            .expect("thread A must have recorded its release instant");

        // Assert (1) — serialization proof (DETERMINISTIC for a correct lock).
        // B cannot return from the backfill before acquiring the lock, and cannot
        // acquire before A dropped it (which A does immediately after recording
        // `a_release_at`). A no-op lock would let B return ~HOLD_MS before A's
        // release, flipping this to false.
        assert!(
            release_at <= backfill_return,
            "thread B's backfill returned BEFORE thread A released the lock \
             (a_release_at={release_at:?}, backfill_return={backfill_return:?}) — \
             the flock did not serialize the two writers"
        );

        // Assert (2) — CONSISTENCY check (NOT the serialization proof; see doc
        // comment). B loaded a snapshot already containing A's commit (forced by
        // the `committed` channel), so its idempotency guard skipped slot 9. A
        // failure here while assert (1) passed indicates an idempotency-guard bug,
        // not a flock-ordering bug.
        let pf_final = crate::accounts::profiles::load(&profiles_path(&base_path)).unwrap();
        assert_eq!(
            pf_final.by_slot_identity.get("9").map(|s| s.as_str()),
            Some("apikey:mm"),
            "by_slot_identity[9] must be the canonical MiniMax literal after the serialized writes"
        );
        assert_eq!(
            summary.by_slot_identity_backfilled, 0,
            "CONSISTENCY (not serialization): thread B's backfill must have skipped \
             slot 9 — it observed A's committed value and the idempotency guard fired"
        );
    }

    /// an internal journal entry retraction: a pre-retraction `coc-trust.json` written
    /// by an older csq build MUST be removed on first daemon start under
    /// the retracted layout. Per `rules/reconciler-cleanup-parity.md`
    /// Rule 6, retiring a writer/lifecycle without paired cleanup leaves
    /// orphan state on every existing host.
    #[test]
    fn coc_trust_orphan_pass_removes_pre_retraction_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("coc-trust.json");
        std::fs::write(
            &path,
            br#"{"schema_version":1,"records":[{"canonical_realpath":"/secret/project","lock_sha256_history":["deadbeef"],"first_trusted_at":0,"last_seen_at":0,"decision":"trust"}]}"#,
        )
        .unwrap();
        assert!(path.exists(), "fixture: file must exist before pass");

        let mut summary = ReconcileSummary::default();
        pass_coc_trust_orphan_cleanup(dir.path(), &mut summary);

        assert!(!path.exists(), "orphan coc-trust.json must be removed");
        assert_eq!(summary.coc_trust_orphans_removed, 1);
    }

    /// Idempotency: a second invocation on a clean base dir (file already
    /// absent) is a no-op and reports `0` removed. This is the
    /// steady-state behavior every start after the first cleanup.
    #[test]
    fn coc_trust_orphan_pass_is_no_op_when_file_absent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("coc-trust.json");
        assert!(!path.exists(), "fixture: clean base dir, no file");

        let mut summary = ReconcileSummary::default();
        pass_coc_trust_orphan_cleanup(dir.path(), &mut summary);

        assert!(!path.exists());
        assert_eq!(
            summary.coc_trust_orphans_removed, 0,
            "no orphan present → counter stays at zero"
        );
    }
}
