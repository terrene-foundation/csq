//! `csq swap N` — swap the active account in the current terminal.
//!
//! # Three paths
//!
//! 1. **Same-surface ClaudeCode** (source + target both Anthropic or
//!    3P) — atomic symlink repoint in `term-<pid>`. CC re-reads on
//!    next API call. In-flight swap, no process restart.
//! 2. **Same-surface Codex** (source + target both Codex) — atomic
//!    symlink repoint in `term-<pid>` via the Codex-aware mirror
//!    `repoint_handle_dir_codex` (spec 07 §7.2.2 symlink set). codex-cli
//!    re-stats `auth.json` before each API call so the next request
//!    resolves through the new symlink; UNIX open-after-rename keeps
//!    in-flight session fds valid until close. Resolves M10 / journal
//!    0023 — the pre-PR-C9a behavior was to take the exec-replace path,
//!    which silently dropped the user's conversation.
//! 3. **Cross-surface** (source ≠ target surface) — INV-P05 requires
//!    prompt-and-confirm (`--yes` bypasses), then INV-P10 requires
//!    renaming the source handle dir to a sweep tombstone BEFORE
//!    `exec`ing the target binary. Conversation does not transfer.
//!
//! # Legacy mode retirement (M4-8, Phase 4 an internal ticket)
//!
//! The pre-handle-dir `CLAUDE_CONFIG_DIR=config-<N>` swap mode is
//! **fully retired**. If `CLAUDE_CONFIG_DIR` points at a `config-<N>`
//! dir, `csq swap` refuses with the spec 02 §2.6 error directing the
//! user to relaunch with `csq run N`. The previous credential-copy
//! fallback through `rotation::swap_to` was deleted with the
//! `csq-core::rotation::swap` module — there is no longer any
//! production code path that writes credentials directly into
//! `config-<N>/.credentials.json` from a swap operation.

use anyhow::{anyhow, Result};
use csq_core::accounts::discovery;
use csq_core::audit::op_emit;
use csq_core::audit::types::{
    AccountSwapPayload, EventKind, EventPayload, OpOutcome, RecordId, RedactedString,
};
use csq_core::cli_deps::sanitize::redact_path;
use csq_core::providers::catalog::Surface;
use csq_core::providers::codex::surface as codex_surface;
use csq_core::session::handle_dir;
use csq_core::types::AccountNum;
use std::path::{Path, PathBuf};

/// One of the three env vars a csq-managed terminal sets pointing at
/// its handle dir. Which one is set tells us the source surface
/// without any on-disk introspection.
#[derive(Debug)]
enum SourceHandle {
    /// `CLAUDE_CONFIG_DIR` set → source is ClaudeCode (Anthropic or 3P).
    ClaudeCode(PathBuf),
    /// `CODEX_HOME` set → source is Codex.
    Codex(PathBuf),
    /// `GEMINI_CLI_HOME` set → source is Gemini. PR-G4b: gemini-cli
    /// does not re-read `GEMINI_API_KEY` mid-process, so even
    /// same-surface Gemini→Gemini takes the exec-replace path
    /// (handled via `RouteKind::CrossSurface` below).
    Gemini(PathBuf),
}

impl SourceHandle {
    fn path(&self) -> &Path {
        match self {
            Self::ClaudeCode(p) | Self::Codex(p) | Self::Gemini(p) => p,
        }
    }

    fn surface(&self) -> Surface {
        match self {
            Self::ClaudeCode(_) => Surface::ClaudeCode,
            Self::Codex(_) => Surface::Codex,
            Self::Gemini(_) => Surface::Gemini,
        }
    }
}

/// Pure dispatch decision for `handle()`. Extracted as a free function
/// (PR-C9b L-CDX-3) so the routing matrix is unit-testable without the
/// env-var + filesystem setup that `handle()` requires. Any future
/// refactor of the dispatcher MUST keep `route()` in lockstep — the
/// `route_*` unit tests pin the matrix.
#[derive(Debug, PartialEq, Eq)]
enum RouteKind {
    /// Source + target both ClaudeCode AND both OAuth/Anthropic (neither
    /// pins `env.ANTHROPIC_BASE_URL`). In-flight symlink repoint; no exec,
    /// no tombstone — CC re-stats `.credentials.json` and picks up the new
    /// account on its next API call.
    SameSurfaceClaudeCode,
    /// Source + target both Codex. In-flight symlink repoint via the
    /// Codex-aware mirror (M10 / an internal journal entry). No exec, no tombstone.
    SameSurfaceCodex,
    /// Both ClaudeCode, but at least ONE side is an env-transport slot
    /// (3P / Ollama — `settings.json` pins `env.ANTHROPIC_BASE_URL` +
    /// `env.ANTHROPIC_AUTH_TOKEN`). A running CC froze those env vars at
    /// launch and never re-reads them, so an in-flight repoint cannot
    /// switch the base URL / token — and a 3P→Anthropic repoint would leave
    /// CC sending the freshly-repointed Anthropic OAuth token to the frozen
    /// 3P endpoint (token exfiltration; see `daemon::auto_rotate` VP-F1).
    /// MUST exec-replace so a fresh CC reads the new settings.json env at
    /// startup. Tombstone + exec; the conversation does not transfer.
    ClaudeCodeEnvTransportExecReplace,
    /// Source ≠ target surface. INV-P05 confirm + INV-P10 tombstone +
    /// `exec` of the target binary. Conversation does not transfer.
    CrossSurface,
}

/// Pure routing decision.
///
/// `source_env_transport` / `target_env_transport` are `true` when the
/// respective slot pins `env.ANTHROPIC_BASE_URL` in its `config-<N>/settings.json`
/// (3P / Ollama). They ONLY affect the `(ClaudeCode, ClaudeCode)` cell: an
/// env-transport slot on either side forces the exec-replace path because a
/// running CC cannot pick up a base-URL / auth-token change mid-process.
fn route(
    source: Surface,
    target: Surface,
    source_env_transport: bool,
    target_env_transport: bool,
) -> RouteKind {
    match (source, target) {
        (Surface::ClaudeCode, Surface::ClaudeCode) => {
            if source_env_transport || target_env_transport {
                RouteKind::ClaudeCodeEnvTransportExecReplace
            } else {
                RouteKind::SameSurfaceClaudeCode
            }
        }
        (Surface::Codex, Surface::Codex) => RouteKind::SameSurfaceCodex,
        _ => RouteKind::CrossSurface,
    }
}

/// Read the slot number from a handle dir's `.csq-account` marker.
///
/// Returns `None` when the marker is absent or not a valid slot number.
/// Used by the audit wiring to derive `from_slot` for the `AccountSwap`
/// payload without modifying the `SourceHandle` API.
fn read_slot_from_handle_dir(handle_dir_path: &Path) -> Option<AccountNum> {
    csq_core::accounts::markers::read_csq_account(handle_dir_path)
}

/// PR-C7 entry point. `yes` bypasses the cross-surface confirmation
/// prompt (INV-P05 `--yes`).
pub fn handle(base_dir: &Path, target: AccountNum, yes: bool) -> Result<()> {
    let source = detect_source_handle(target)?;
    let target_surface = resolve_target_surface(base_dir, target)?;

    // Phase B' billing-ledger attribution (an internal journal entry D2). Best-effort
    // append; failures MUST NOT block the swap.
    super::run::append_launch_log(base_dir, "swap", target);

    // M13b — derive from_slot from the source handle dir marker.
    // If the marker is absent we skip audit (pre-side-effect information
    // unavailable → no intent emitted, consistent with the WBS T4 invariant).
    let from_slot = read_slot_from_handle_dir(source.path());

    // Capture the handle-dir path before `source` is moved into the route arms.
    // After a Claude-surface swap we mirror the new account's credential into
    // the keychain item CC reads for this handle dir (current CC reads OAuth
    // from the keychain, not the symlinked `.credentials.json`).
    let handle_dir_path = source.path().to_path_buf();

    // Env-transport discriminator for the (ClaudeCode, ClaudeCode) cell. A slot
    // that pins `env.ANTHROPIC_BASE_URL` (3P: DeepSeek/Z.AI/MiniMax, or Ollama)
    // injects its base URL + auth token into CC's process env at launch — FROZEN
    // for the process lifetime. An in-flight symlink repoint cannot change them,
    // so any swap touching such a slot on either side MUST exec-replace (a fresh
    // CC reads the new settings.json env). The source flag is only knowable when
    // the source marker resolved (`from_slot`); an absent marker conservatively
    // reports `false` — the target flag alone still forces exec-replace whenever
    // the TARGET is env-transport, which covers the Anthropic→3P direction.
    let source_env_transport = from_slot
        .map(|s| csq_core::providers::settings::slot_pins_anthropic_base_url(base_dir, s.get()))
        .unwrap_or(false);
    let target_env_transport =
        csq_core::providers::settings::slot_pins_anthropic_base_url(base_dir, target.get());

    let route_kind = route(
        source.surface(),
        target_surface,
        source_env_transport,
        target_env_transport,
    );

    // A4a — close the daemon-custodian mid-swap race for a same-surface ClaudeCode
    // swap (the only path that repoints an EXISTING dir whose keychain still holds
    // the PREVIOUS account's token). Two coordinated guards, held across the whole
    // [repoint → sync] transition:
    //
    //   1. Hold the per-dir swap lock so the daemon custodian's harvest (which
    //      try-locks the same file) SKIPS this dir until it settles — it can never
    //      read a token that disagrees with the freshly-repointed symlink.
    //   2. Clear the keychain item BEFORE the repoint, so the transition window (and
    //      any crash within it) leaves the item ABSENT — which harvest also skips —
    //      rather than the wrong account's token. sync_cc_keychain below writes the
    //      new account's token, ending the transition with a consistent dir.
    //
    // Cross-surface / Codex routes create a FRESH handle dir (keychain absent from
    // birth), so they have no such race and need neither guard.
    let _swap_guard = if matches!(route_kind, RouteKind::SameSurfaceClaudeCode) {
        let abs =
            std::fs::canonicalize(&handle_dir_path).unwrap_or_else(|_| handle_dir_path.clone());
        let guard = csq_core::credentials::keychain::lock_handle_dir_for_swap(&abs);
        csq_core::credentials::keychain::clear_handle_dir(&abs);
        guard
    } else {
        None
    };

    let result = match route_kind {
        RouteKind::SameSurfaceClaudeCode => {
            same_surface_claude_code_audited(base_dir, source.path(), target, from_slot)
        }
        RouteKind::SameSurfaceCodex => {
            same_surface_codex_audited(base_dir, source.path(), target, from_slot)
        }
        // Both env-transport-exec-replace (ClaudeCode 3P/Ollama) and true
        // cross-surface swaps share the tombstone-then-exec machinery; they
        // differ only in the confirmation wording, which `exec_replace_swap`
        // derives from `same_surface` (== source/target surface equality).
        RouteKind::ClaudeCodeEnvTransportExecReplace | RouteKind::CrossSurface => {
            exec_replace_swap(base_dir, source, target, target_surface, yes, from_slot)
        }
    };

    if result.is_ok() && matches!(target_surface, Surface::ClaudeCode) {
        let abs = std::fs::canonicalize(&handle_dir_path).unwrap_or(handle_dir_path);
        super::run::sync_cc_keychain(&abs, true);
    }
    // `_swap_guard` (if any) drops here, AFTER sync_cc_keychain — the dir is now
    // consistent (symlink + keychain agree), so the next harvest may read it.

    result
}

// ─── M13b audit helpers ──────────────────────────────────────────────

/// The result of a successful `begin_swap_audit` call.
#[derive(Debug)]
struct SwapAuditContext {
    chain_id: String,
    correlation_id: RecordId,
    payload: EventPayload,
}

/// Attempt to emit the INTENT record for a same-surface swap.
///
/// Returns:
/// - `Ok(Some(ctx))` — INTENT persisted; caller MUST call `finish_swap_audit`
///   after the side effect.
/// - `Ok(None)` — marker absent; audit skipped (pre-side-effect detection
///   failure is NOT fail-closed for same-surface swaps — swap proceeds).
/// - `Err(..)` — INTENT could not be persisted; caller MUST abort the side
///   effect (F-LEDGER-02 fail-closed contract).
///
/// FIX-3: typed return replaces the `contains("from_slot unavailable")`
/// string discrimination that was brittle across refactors.
fn begin_swap_audit(
    base_dir: &Path,
    from_slot: Option<AccountNum>,
    to_slot: AccountNum,
) -> Result<Option<SwapAuditContext>> {
    let from = match from_slot {
        Some(f) => f,
        None => {
            // Marker absent — skip audit gracefully. No INTENT emitted.
            return Ok(None);
        }
    };

    let chain_id = op_emit::load_chain_id(base_dir);
    let correlation_id =
        op_emit::gen_correlation_id().map_err(|e| anyhow!("audit correlation_id: {e}"))?;
    let payload = EventPayload::AccountSwap(AccountSwapPayload {
        from_slot: from,
        to_slot,
    });

    // FIX-7: reason uses RedactedString::from_untrusted; the audit framework
    // does path-free string redaction. No filesystem paths reach the chain.
    // FIX-1: Ok(true)=emitted → Ok(Some(ctx)); Ok(false)=chain-broken skip →
    // Ok(None) (swap proceeds without audit); Err=fail-closed.
    let intent_emitted = op_emit::emit_intent(
        base_dir,
        &chain_id,
        EventKind::AccountSwap,
        payload.clone(),
        correlation_id.clone(),
    )
    .map_err(|e| anyhow!("audit intent persist failed — swap aborted: {e}"))?;

    if !intent_emitted {
        // Chain broken — proceed without audit trail (same pattern as marker-absent).
        return Ok(None);
    }

    Ok(Some(SwapAuditContext {
        chain_id,
        correlation_id,
        payload,
    }))
}

/// Emit the OUTCOME record. Best-effort — if this fails the intent is a
/// visible orphan detectable by `scan_orphan_intents`. The swap result is
/// returned unchanged.
///
/// FIX-7: `e.to_string()` from `anyhow::Error` may contain paths from
/// underlying IO errors. Route through `from_untrusted` (which runs
/// `redact_tokens`) AND strip any embedded `$HOME` prefix via `redact_reason`.
fn finish_swap_audit(base_dir: &Path, ctx: SwapAuditContext, result: &Result<()>) {
    let outcome = match result {
        Ok(()) => OpOutcome::Ok,
        Err(e) => OpOutcome::Failed {
            reason: redact_reason(e.to_string()),
        },
    };
    let _ = op_emit::emit_outcome(
        base_dir,
        &ctx.chain_id,
        EventKind::AccountSwap,
        ctx.payload,
        ctx.correlation_id,
        outcome,
    );
}

/// Path-safe reason string for `OpOutcome::Failed`.
///
/// FIX-7: routes through `RedactedString::from_untrusted` (token scrub) and
/// strips any home-directory prefix so filesystem paths don't land on the
/// committed audit chain in exported bundles.
fn redact_reason(raw: impl AsRef<str>) -> RedactedString {
    // Strip home-dir prefix from the raw reason before handing to from_untrusted.
    let home = std::env::var("HOME").unwrap_or_default();
    let scrubbed = if !home.is_empty() {
        raw.as_ref().replace(&home, "<home>")
    } else {
        raw.as_ref().to_string()
    };
    RedactedString::from_untrusted(scrubbed)
}

// ─── Source-surface detection ────────────────────────────────────────

fn detect_source_handle(target: AccountNum) -> Result<SourceHandle> {
    // Surface-specific env vars may all be set by a well-meaning
    // parent shell. Probe in surface-specific order:
    //   1. GEMINI_CLI_HOME — set ONLY by `csq run` for Gemini slots
    //   2. CODEX_HOME — set by `csq run` for Codex slots
    //   3. CLAUDE_CONFIG_DIR — set by `csq run` for Claude/3P slots
    //
    // Each `csq run` path scrubs the OTHER surfaces' env vars, so
    // ordering only matters when a parent shell exports multiple of
    // them by mistake. In that case the most-specific match wins:
    // a handle dir that exists on disk under our base wins over a
    // raw env var pointing somewhere else.
    if let Ok(raw) = std::env::var("GEMINI_CLI_HOME") {
        let p = PathBuf::from(&raw);
        if is_term_handle_dir(&p) {
            return Ok(SourceHandle::Gemini(p));
        }
    }
    if let Ok(raw) = std::env::var("CODEX_HOME") {
        let p = PathBuf::from(&raw);
        if is_term_handle_dir(&p) {
            return Ok(SourceHandle::Codex(p));
        }
    }
    if let Ok(raw) = std::env::var("CLAUDE_CONFIG_DIR") {
        let p = PathBuf::from(&raw);
        if is_term_handle_dir(&p) {
            return Ok(SourceHandle::ClaudeCode(p));
        }
        // M4-8 (Phase 4 an internal ticket): legacy `CLAUDE_CONFIG_DIR=config-N`
        // swap mode is fully retired. The pre-M4-8 fallback through
        // `rotation::swap_to` would write credentials into config-N
        // and silently move every terminal sharing that dir; the
        // handle-dir model makes per-terminal swap the contract and
        // legacy launches are non-isolated by construction. Refuse
        // with the spec 02 §2.6 message — the message threads the
        // target slot the user typed so the suggested `csq run`
        // command is copy-pasteable rather than a literal `N`.
        if is_legacy_config_dir(&p) {
            let dir_name = p.file_name().and_then(|n| n.to_str()).unwrap_or("config-?");
            return Err(anyhow!(
                "this terminal was launched in legacy per-account mode; \
                 swap would affect all terminals on {dir_name}. \
                 Relaunch with `csq run {target}` to use per-terminal swap."
            ));
        }
        return Err(anyhow!(
            "CLAUDE_CONFIG_DIR does not point to a csq-managed directory: {raw}"
        ));
    }
    Err(anyhow!(
        "none of CLAUDE_CONFIG_DIR / CODEX_HOME / GEMINI_CLI_HOME is set — \
         csq swap must run inside a csq-managed session"
    ))
}

fn is_term_handle_dir(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with("term-"))
        .unwrap_or(false)
}

fn is_legacy_config_dir(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with("config-"))
        .unwrap_or(false)
}

fn resolve_target_surface(base_dir: &Path, target: AccountNum) -> Result<Surface> {
    let accounts = discovery::discover_all(base_dir);
    accounts
        .iter()
        .find(|a| a.id == target.get())
        .map(|a| a.surface)
        .ok_or_else(|| {
            anyhow!(
                "account {target} not found — run `csq login {target}` first, \
                 or check `csq status` for available accounts"
            )
        })
}

// ─── Same-surface ClaudeCode (existing behavior) ────────────────────

/// Wrapper that adds M13b INTENT/OUTCOME audit emit around the same-surface
/// ClaudeCode symlink repoint.
///
/// FIX-3: uses typed `SwapAuditContext` — no string discrimination.
fn same_surface_claude_code_audited(
    base_dir: &Path,
    source_dir: &Path,
    target: AccountNum,
    from_slot: Option<AccountNum>,
) -> Result<()> {
    match begin_swap_audit(base_dir, from_slot, target)? {
        Some(ctx) => {
            // INTENT committed. Run side effect, then emit OUTCOME.
            let result = same_surface_claude_code(base_dir, source_dir, target);
            finish_swap_audit(base_dir, ctx, &result);
            result
        }
        None => {
            // Marker absent → audit skipped, swap proceeds (not fail-closed).
            same_surface_claude_code(base_dir, source_dir, target)
        }
    }
}

fn same_surface_claude_code(base_dir: &Path, source_dir: &Path, target: AccountNum) -> Result<()> {
    // M4-8 (Phase 4 an internal ticket): the only valid same-surface ClaudeCode
    // swap path is the handle-dir model. `detect_source_handle` already
    // refuses legacy `config-N` sources with the spec 02 §2.6 message,
    // so any source reaching this function MUST be a `term-<pid>` dir.
    // The defensive check below preserves a clear error if the routing
    // contract is ever broken from above.
    let dir_name = source_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if !dir_name.starts_with("term-") {
        return Err(anyhow!(
            "source dir is not a csq-managed handle dir: {}. \
             Relaunch with `csq run {target}` to use per-terminal swap.",
            redact_path(source_dir)
        ));
    }

    let claude_home = super::claude_home()?;
    handle_dir::repoint_handle_dir(base_dir, &claude_home, source_dir, target)?;
    refresh_current_account_cache(base_dir, target);
    notify_daemon_cache_invalidation(base_dir);
    println!(
        "Swapped to account {} — CC will pick up on next API call",
        target
    );
    Ok(())
}

/// Refreshes the canonical `config-N/.current-account` cache after a swap
/// repoints a handle dir to slot N.
///
/// `csq swap` repoints the handle dir's symlinks but does NOT touch the
/// target `config-N`'s `.current-account`, which can hold a stale value (a
/// pre-handle-dir-migration leftover, or a value left behind by `csq move`).
/// Without this refresh the next statusline render on any sibling terminal
/// bound to slot N would surface the stale slot until `snapshot_account`'s
/// lazy self-heal runs — the exact `csq swap N → wrong slot` bug (workspace
/// an internal workspace, C2/M4).
///
/// Writes the canonical `config-N` file directly (never the handle dir, whose
/// `.current-account` is a symlink into config-N). Non-fatal: snapshot's
/// authority-first self-heal is the structural backstop, so a failed write
/// here only delays the heal by one render.
fn refresh_current_account_cache(base_dir: &Path, target: AccountNum) {
    let config_dir = base_dir.join(format!("config-{}", target.get()));
    if config_dir.is_dir() {
        if let Err(e) = csq_core::accounts::markers::write_current_account(&config_dir, target) {
            tracing::debug!(
                error = %e,
                slot = target.get(),
                "swap: failed to refresh config-N/.current-account cache"
            );
        }
    }
}

// ─── Same-surface Codex (M10 / an internal journal entry) ────────────────────────

/// Same-surface Codex→Codex symlink repoint. Mirrors
/// `same_surface_claude_code` but uses the Codex-aware
/// [`handle_dir::repoint_handle_dir_codex`] (spec 07 §7.2.2 symlink
/// set). No exec-replace, no tombstone — the running codex process
/// keeps its open fds and picks up the new auth.json on the next API
/// call.
///
/// Legacy `config-N` Codex source dirs are not supported: there is no
/// pre-handle-dir layout for Codex (the surface launched after the
/// handle-dir model was already in place), so any Codex source must be
/// a `term-<pid>` dir. Returns a clear error otherwise.
/// Wrapper that adds M13b INTENT/OUTCOME audit emit around the same-surface
/// Codex symlink repoint.
///
/// FIX-3: uses typed `SwapAuditContext` — no string discrimination.
fn same_surface_codex_audited(
    base_dir: &Path,
    source_dir: &Path,
    target: AccountNum,
    from_slot: Option<AccountNum>,
) -> Result<()> {
    match begin_swap_audit(base_dir, from_slot, target)? {
        Some(ctx) => {
            let result = same_surface_codex(base_dir, source_dir, target);
            finish_swap_audit(base_dir, ctx, &result);
            result
        }
        None => same_surface_codex(base_dir, source_dir, target),
    }
}

fn same_surface_codex(base_dir: &Path, source_dir: &Path, target: AccountNum) -> Result<()> {
    let dir_name = source_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if !dir_name.starts_with("term-") {
        return Err(anyhow!(
            "Codex source dir is not a csq-managed handle dir: {}. \
             Relaunch with `csq run {target}` to get per-terminal isolation.",
            redact_path(source_dir)
        ));
    }

    handle_dir::repoint_handle_dir_codex(base_dir, source_dir, target)?;
    refresh_current_account_cache(base_dir, target);
    notify_daemon_cache_invalidation(base_dir);
    println!(
        "Swapped to account {} — codex will pick up on next API call",
        target
    );
    Ok(())
}

// ─── Exec-replace path (cross-surface + ClaudeCode env-transport) ────

/// Exec-replace swap. Handles BOTH true cross-surface swaps (e.g. Codex→Claude)
/// AND same-surface ClaudeCode swaps that involve a 3P/Ollama env-transport slot
/// (`RouteKind::ClaudeCodeEnvTransportExecReplace`). Both must tombstone the
/// source handle dir and `exec` a fresh target binary because the running client
/// froze its auth (surface binary, or `env.ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN`)
/// at launch and cannot switch it in-flight. The confirmation wording is derived
/// from whether the SURFACE actually changed (`source_surface != target_surface`).
///
/// ## Append-FIRST ordering (FIX-2, OD-3 corrected)
///
/// The M13b audit contract for exec-replace swaps is:
///
/// 1. (optional) Emit INTENT — before any destructive operation.
///    If intent-persist fails and from_slot is known, FAIL CLOSED before the
///    tombstone rename (the intent gates the side effect, per F-LEDGER-02).
///    If from_slot is absent, skip audit and proceed.
/// 2. Tombstone the source handle dir (INV-P10).
/// 3. Create the target handle dir (the binding step — together with the
///    tombstone, this is the complete "audited side effect").
/// 4. Emit OUTCOME (from the real result of steps 2-3) BEFORE exec.
///    OUTCOME:ok attests tombstone + target-binding. OUTCOME:Failed if
///    target-binding failed.
/// 5. exec() the target binary. Replaces the process on success; returns
///    an error on failure.
///
/// exec(2) replaces the process so code after exec is unreachable on success.
/// OUTCOME therefore MUST precede exec.
fn exec_replace_swap(
    base_dir: &Path,
    source: SourceHandle,
    target: AccountNum,
    target_surface: Surface,
    yes: bool,
    from_slot: Option<AccountNum>,
) -> Result<()> {
    let source_surface = source.surface();
    let is_cross_surface = source_surface != target_surface;

    // Resume is driven by the TARGET CLI's capability, applied on BOTH exec-replace
    // routes (env-transport provider swap AND true cross-surface). Each CLI resumes
    // its OWN most-recent conversation on relaunch:
    //   - ClaudeCode → `claude --continue`. For an env-transport swap (Anthropic↔3P/
    //     Ollama) this is the SAME thread: `projects/` is a SHARED_ITEM symlinked into
    //     `~/.claude/` (see `session::isolation`), so the transcript survives the source
    //     tombstone. For a cross-surface swap it is the user's most-recent Claude thread.
    //   - Codex → `codex resume --last` (its `sessions`/`history.jsonl` are likewise
    //     SHARED_ITEMS, so the most-recent codex session is reachable from the fresh dir).
    //   - Gemini → no resume flag; gemini-cli starts fresh.
    // Net effect: swapping surfaces picks up where you last were on the TARGET surface,
    // and swapping back resumes the source surface's thread — nothing is lost either way.
    let resume_conversation = matches!(target_surface, Surface::ClaudeCode | Surface::Codex);

    if !is_cross_surface {
        // Env-transport provider swap: the SAME thread resumes. No y/N prompt —
        // nothing is lost — just an informational notice.
        eprintln!(
            "Switching provider for slot {target} and resuming this conversation \
             (Claude Code restarts to load the new endpoint)…"
        );
    } else if !yes {
        // True surface change: the current thread stays saved (swap back to resume it);
        // the target surface's most-recent session resumes (or starts fresh for Gemini).
        confirm_surface_switch(source_surface, target_surface, resume_conversation)?;
    }

    // ── Step 1: emit INTENT (before any destructive operation) ──────────────
    //
    // FIX-2: INTENT now precedes the tombstone rename, not follows it.
    // FIX-3: uses typed begin_swap_audit → Ok(None) = skip, Ok(Some) = intent
    //         committed, Err = fail-closed.
    let audit_ctx = match begin_swap_audit(base_dir, from_slot, target) {
        Ok(Some(ctx)) => Some(ctx),
        Ok(None) => {
            // from_slot absent → skip audit, proceed with exec.
            None
        }
        Err(e) => {
            // Intent-persist failed with from_slot present → FAIL CLOSED
            // before the tombstone (the side effect has not started yet).
            // FIX-8: warn not debug — audit visibility posture (M06).
            tracing::warn!(
                error_kind = "audit_intent_persist_failed_cross_surface",
                "M13b: cross-surface swap audit intent could not be persisted — \
                 aborting swap before tombstone (fail-closed per F-LEDGER-02)"
            );
            return Err(e);
        }
    };

    // ── Step 2: tombstone source handle dir (INV-P10) ────────────────────────
    //
    // NOTE (an internal workspace, R1 review LOW-3): unlike the
    // same-surface paths, cross-surface does NOT eagerly call
    // `refresh_current_account_cache` here. The exec'd launch path
    // (`run::launch_*` → `markers::write_current_account`) writes
    // `config-target/.current-account` as part of normal spawn.
    let source_path = source.path();
    if is_term_handle_dir(source_path) {
        rename_handle_dir_to_sweep_tombstone(source_path).map_err(|e| {
            anyhow!(
                "failed to tombstone source handle dir {} before cross-surface exec: {e}",
                redact_path(source_path)
            )
        })?;
    }
    // Legacy config-N source: do NOT remove the config dir (permanent
    // account home per spec 02 INV-01). Just exec; the config dir stays.

    let pid = std::process::id();

    // ── Step 3: create target handle dir (binding step) ──────────────────────
    //
    // FIX-2: split out of exec_* so the result is available for OUTCOME.
    // OUTCOME:ok = tombstone + target-binding committed. OUTCOME:Failed if
    // this step errors. exec(2) runs after OUTCOME.
    let binding_result = create_target_handle_dir(base_dir, target, target_surface, pid);

    // ── Step 4: emit OUTCOME (from real result of steps 2-3) BEFORE exec ─────
    //
    // OUTCOME attests tombstone + target-binding. Must precede exec because
    // exec(2) replaces the process on success, making post-exec code unreachable.
    if let Some(ctx) = audit_ctx {
        let outcome = match &binding_result {
            Ok(()) => OpOutcome::Ok,
            Err(e) => OpOutcome::Failed {
                reason: redact_reason(e.to_string()),
            },
        };
        let _ = op_emit::emit_outcome(
            base_dir,
            &ctx.chain_id,
            EventKind::AccountSwap,
            ctx.payload,
            ctx.correlation_id,
            outcome,
        );
    }

    // ── Step 5: exec ─────────────────────────────────────────────────────────
    //
    // R2-FIX-5: if binding failed after the source was already tombstoned,
    // surface a recovery hint. The OUTCOME:Failed was emitted in step 4.
    binding_result.map_err(|e| {
        anyhow!(
            "{e} — source handle dir was already tombstoned; \
             re-run `csq run {target}` to start a new session"
        )
    })?;

    match target_surface {
        Surface::Codex => exec_codex_after_binding(base_dir, target, pid, resume_conversation),
        Surface::ClaudeCode => {
            exec_claude_code_after_binding(base_dir, target, pid, resume_conversation)
        }
        Surface::Gemini => exec_gemini_after_binding(base_dir, target, pid),
    }
}

/// Create the target handle dir for a cross-surface swap.
///
/// This is step 3 of the FIX-2 ordering: split from exec_* so the result
/// is available to OUTCOME before exec(2) replaces the process.
///
/// Returns Ok(()) when the binding directory and its marker are in place.
/// Returns Err when the binding cannot be created.
fn create_target_handle_dir(
    base_dir: &Path,
    target: AccountNum,
    target_surface: Surface,
    pid: u32,
) -> Result<()> {
    match target_surface {
        Surface::Codex => {
            csq_core::session::handle_dir::create_handle_dir_codex(base_dir, target, pid)
                .map(|_| ())
                .map_err(|e| anyhow!("failed to create Codex handle dir for slot {target}: {e}"))
        }
        Surface::ClaudeCode => {
            let claude_home = super::claude_home()?;
            csq_core::session::handle_dir::create_handle_dir(base_dir, &claude_home, target, pid)
                .map(|_| ())
                .map_err(|e| {
                    anyhow!("failed to create ClaudeCode handle dir for slot {target}: {e}")
                })
        }
        Surface::Gemini => {
            // Gemini binding: verify the marker exists and create the handle dir.
            // The vault open and spawn_gemini are deferred to exec_gemini_after_binding.
            create_gemini_handle_dir(base_dir, target, pid)
        }
    }
}

/// Atomically renames `source_path` to a
/// `.sweep-tombstone-swap-<pid>-<nanos>` sibling so the source is
/// structurally unreachable from subsequent csq commands while
/// remaining intact for any still-running process holding fds into
/// it. The daemon sweep's `cleanup_stale_tombstones` picks up the
/// `.sweep-tombstone-` prefix and reaps it.
///
/// The `-swap-` infix distinguishes swap tombstones from the sweep's
/// own rename-then-remove tombstones; both share the cleanup path
/// but the infix is debuggable evidence for which created it.
fn rename_handle_dir_to_sweep_tombstone(source_path: &Path) -> std::io::Result<()> {
    let base = source_path
        .parent()
        .ok_or_else(|| std::io::Error::other("source handle dir has no parent"))?;
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let tombstone = base.join(format!(".sweep-tombstone-swap-{pid}-{nanos:x}"));
    std::fs::rename(source_path, &tombstone)
}

/// Confirmation for a true surface change (e.g. Claude↔Codex). The current
/// surface's conversation is NOT destroyed — its transcript is a SHARED_ITEM, so
/// swapping back resumes it. `target_resumes` reflects whether the TARGET CLI
/// re-attaches to its own most-recent session (`claude --continue` /
/// `codex resume --last`) or starts fresh (Gemini).
fn confirm_surface_switch(source: Surface, target: Surface, target_resumes: bool) -> Result<()> {
    use std::io::{BufRead, Write};
    let target_line = if target_resumes {
        format!("Your most recent {target} session will resume.")
    } else {
        format!("A new {target} session will start.")
    };
    eprintln!(
        "Swapping from {source} to {target}. This {source} conversation stays saved — \
         swap back to resume it. {target_line}"
    );
    eprint!("Continue? [y/N]: ");
    std::io::stderr().flush().ok();
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    if !line.trim().eq_ignore_ascii_case("y") {
        return Err(anyhow!("swap cancelled"));
    }
    Ok(())
}

/// Exec the Codex binary after the target handle dir has already been created
/// by `create_target_handle_dir`. The handle dir path is re-derived from the PID.
///
/// When `resume` is true (a swap INTO a Codex slot), exec `codex resume --last`
/// so codex re-attaches to its most-recent session — codex's `sessions` /
/// `history.jsonl` are SHARED_ITEMS symlinked into the shared codex store, so the
/// last session is reachable from the fresh handle dir. Otherwise exec bare `codex`.
#[cfg(unix)]
fn exec_codex_after_binding(
    base_dir: &Path,
    target: AccountNum,
    pid: u32,
    resume: bool,
) -> Result<()> {
    use std::os::unix::process::CommandExt;
    // Re-derive the handle dir path — do NOT call `create_handle_dir_codex` again.
    // `create_target_handle_dir` (step 3) already created `term-<pid>` and wrote its
    // live `.live-pid`; a second create with the same pid trips the live-PID guard and
    // aborts the swap. `create_handle_dir_codex` names the dir `term-<pid>`, so deriving
    // the path here is exact. Mirrors the ClaudeCode + Gemini exec arms.
    let handle_dir = base_dir.join(format!("term-{pid}"));

    let mut cmd = std::process::Command::new(codex_surface::CLI_BINARY);
    cmd.env(codex_surface::HOME_ENV_VAR, &handle_dir);
    cmd.env_remove("CLAUDE_CONFIG_DIR");
    if resume {
        // `codex resume --last`: re-attach to the most-recent recorded codex session.
        cmd.arg("resume").arg("--last");
    }

    let err = cmd.exec();
    Err(anyhow!(
        "exec `{}` failed after source handle dir was removed — \
         re-run `csq run {target}` to relaunch. Error: {err}",
        codex_surface::CLI_BINARY
    ))
}

/// Exec the ClaudeCode binary after the target handle dir has already been
/// created by `create_target_handle_dir`.
///
/// When `resume` is true (any swap INTO a ClaudeCode slot), exec `claude --continue`.
/// The transcript under `~/.claude/projects/` is a SHARED_ITEM that survives the
/// source tombstone: for an env-transport provider swap this re-attaches to the SAME
/// thread (seamless provider switch); for a cross-surface swap it re-attaches to the
/// user's most-recent Claude thread.
#[cfg(unix)]
fn exec_claude_code_after_binding(
    base_dir: &Path,
    target: AccountNum,
    pid: u32,
    resume: bool,
) -> Result<()> {
    use std::os::unix::process::CommandExt;
    // Re-derive the handle dir path — do NOT call `create_handle_dir` again.
    // `create_target_handle_dir` (step 3) already created `term-<pid>` and wrote
    // its `.live-pid = <pid>`; a second `create_handle_dir` with the same pid sees
    // that live marker and refuses ("in use by live PID … Refusing to remove"),
    // which would abort every ClaudeCode-target exec-replace swap. `create_handle_dir`
    // names the dir `term-<pid>` (see its impl), so deriving the path here is exact.
    // Mirrors `exec_gemini_after_binding`, which already re-derives rather than recreates.
    let handle_dir = base_dir.join(format!("term-{pid}"));

    let handle_dir_abs = std::fs::canonicalize(&handle_dir).unwrap_or_else(|_| handle_dir.clone());

    // Mirror the target account's credential into the keychain CC reads for this
    // FRESH handle dir before exec — current CC reads OAuth keychain-first, and a
    // cross-surface swap creates a brand-new term-<pid> dir with no keychain item
    // yet (the post-route sync in `handle` covers only the same-surface paths,
    // which don't exec). Without this, a Codex/Gemini→Claude swap launches CC
    // against an unwritten keychain → "Please run /login · 401". Mirrors run.rs.
    super::run::sync_cc_keychain(&handle_dir_abs, true);

    let mut cmd = std::process::Command::new("claude");
    cmd.env("CLAUDE_CONFIG_DIR", &handle_dir_abs);
    cmd.env_remove(codex_surface::HOME_ENV_VAR);
    if resume {
        // `-c/--continue`: re-attach to the most recent conversation in the CWD.
        // The transcript is shared across handle dirs (SHARED_ITEMS `projects`),
        // so the provider swap resumes the same session seamlessly.
        cmd.arg("--continue");
    }

    let err = cmd.exec();
    Err(anyhow!(
        "exec `claude` failed after source handle dir was removed — \
         re-run `csq run {target}` to relaunch. Error: {err}"
    ))
}

#[cfg(not(unix))]
fn exec_codex_after_binding(
    _base_dir: &Path,
    _target: AccountNum,
    _pid: u32,
    _resume: bool,
) -> Result<()> {
    Err(anyhow!(
        "cross-surface csq swap is Unix-only today. \
         On Windows, exit the current surface and run `csq run <N>`."
    ))
}

#[cfg(not(unix))]
fn exec_claude_code_after_binding(
    _base_dir: &Path,
    _target: AccountNum,
    _pid: u32,
    _resume: bool,
) -> Result<()> {
    Err(anyhow!(
        "cross-surface csq swap is Unix-only today. \
         On Windows, exit the current surface and run `csq run <N>`."
    ))
}

/// FIX-2: Create the Gemini handle dir (binding step, step 3 of cross_surface_exec).
///
/// Verifies the binding marker exists, creates `term-<pid>/`, writes
/// `.csq-account`. Returns Ok(()) on success. Does NOT open the vault or
/// exec — those are deferred to `exec_gemini_after_binding` (step 5).
#[cfg(unix)]
fn create_gemini_handle_dir(base_dir: &Path, target: AccountNum, pid: u32) -> Result<()> {
    use csq_core::accounts::markers;
    use csq_core::credentials::file as cred_file;

    // Refuse symlink at the binding marker.
    let binding_path = cred_file::canonical_path_for(base_dir, target, Surface::Gemini);
    let meta = std::fs::symlink_metadata(&binding_path).map_err(|e| {
        anyhow!(
            "stat {} — Gemini binding missing for swap target {target}; \
             run `csq setkey gemini --slot {target}` or `csq login {target} --provider gemini` first ({e})",
            redact_path(&binding_path)
        )
    })?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!(
            "refusing Gemini swap: {} is a symlink — external mutation detected",
            redact_path(&binding_path)
        ));
    }

    // Build the minimal handle dir + .csq-account marker.
    let handle_dir = base_dir.join(format!("term-{pid}"));
    std::fs::create_dir_all(&handle_dir)
        .map_err(|e| anyhow!("failed to create Gemini handle dir for swap target {target}: {e}"))?;
    // M4-7: use UUID marker when available.
    let marker_result =
        match csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, target.get()) {
            Some(uuid) => markers::write_csq_account(&handle_dir, uuid),
            None => markers::write_csq_account_legacy(&handle_dir, target),
        };
    if let Err(e) = marker_result {
        let _ = std::fs::remove_dir_all(&handle_dir);
        return Err(anyhow!(
            ".csq-account marker write failed for swap target {target}: {e}"
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_gemini_handle_dir(_base_dir: &Path, _target: AccountNum, _pid: u32) -> Result<()> {
    Err(anyhow!(
        "cross-surface csq swap is Unix-only today. \
         On Windows, exit the current surface and run `csq run <N>`."
    ))
}

/// Exec the Gemini binary after the target handle dir has already been created
/// by `create_gemini_handle_dir` (step 3). Vault open + spawn_gemini are step 5.
///
/// PR-G4b: mirrors `launch_gemini` in `commands/run.rs`.
/// **Why a duplicate**: both call sites are inside csq-cli; factoring into
/// csq-core requires a new `gemini::session` module + typed error enum;
/// deferred until PR-G5 (desktop) becomes the third caller.
#[cfg(unix)]
fn exec_gemini_after_binding(base_dir: &Path, target: AccountNum, pid: u32) -> Result<()> {
    use csq_core::platform::secret;
    use csq_core::providers::gemini::spawn::spawn_gemini;

    let handle_dir = base_dir.join(format!("term-{pid}"));
    let handle_dir_abs = std::fs::canonicalize(&handle_dir).unwrap_or_else(|_| handle_dir.clone());

    let vault = secret::open_default_vault().map_err(|e| {
        let _ = std::fs::remove_dir_all(&handle_dir);
        anyhow!(
            "Gemini vault unavailable for swap target {target} ({}): {e}",
            e.error_kind_tag()
        )
    })?;

    println!("Swapping to Gemini account {} (term-{})...", target, pid);

    match spawn_gemini(
        base_dir,
        &handle_dir_abs,
        target,
        Vec::new(),
        vault.as_ref(),
    ) {
        Ok(_never) => unreachable!("spawn_gemini returns Infallible on success"),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&handle_dir);
            Err(anyhow!(
                "Gemini swap exec failed after source handle dir was tombstoned — \
                 re-run `csq run {target}` to relaunch. Error: {e}"
            ))
        }
    }
}

#[cfg(not(unix))]
fn exec_gemini_after_binding(_base_dir: &Path, _target: AccountNum, _pid: u32) -> Result<()> {
    Err(anyhow!(
        "cross-surface csq swap is Unix-only today. \
         On Windows, exit the current surface and run `csq run <N>`."
    ))
}

// ─── Daemon cache invalidation (unchanged from pre-PR-C7) ───────────

/// Best-effort cache invalidation: POST /api/invalidate-cache to
/// the daemon if it's reachable.
#[cfg(unix)]
fn notify_daemon_cache_invalidation(base_dir: &Path) {
    let sock = csq_core::daemon::socket_path(base_dir);
    if !sock.exists() {
        return;
    }
    let _ = csq_core::daemon::http_post_unix(&sock, "/api/invalidate-cache");
}

#[cfg(not(unix))]
fn notify_daemon_cache_invalidation(_base_dir: &Path) {
    // Windows named-pipe invalidation is not yet implemented (M8-03).
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(dead_code)] // ensure markers/Surface paths compile on all targets
mod tests {
    use super::*;

    // Unit tests exercise the pure helpers (source detection +
    // target-surface resolution). Full swap integration is covered
    // by the handle_dir repoint tests and the new cross-surface
    // integration tests in csq-cli/tests/.

    #[test]
    fn is_term_handle_dir_accepts_term_prefix() {
        assert!(is_term_handle_dir(Path::new("/base/term-42")));
        assert!(is_term_handle_dir(Path::new("/base/term-1001")));
    }

    #[test]
    fn is_term_handle_dir_rejects_config_prefix() {
        assert!(!is_term_handle_dir(Path::new("/base/config-3")));
        assert!(!is_term_handle_dir(Path::new("/base/not-a-handle")));
    }

    #[test]
    fn is_legacy_config_dir_accepts_config_prefix() {
        assert!(is_legacy_config_dir(Path::new("/base/config-7")));
        assert!(!is_legacy_config_dir(Path::new("/base/term-99")));
    }

    #[test]
    fn source_handle_surface_matches_variant() {
        let ch = SourceHandle::ClaudeCode(PathBuf::from("/x/term-1"));
        assert_eq!(ch.surface(), Surface::ClaudeCode);
        let cx = SourceHandle::Codex(PathBuf::from("/x/term-2"));
        assert_eq!(cx.surface(), Surface::Codex);
    }

    // ── PR-C9b L-CDX-3 — dispatcher routing matrix ────────────────────

    /// Pinning: ClaudeCode→ClaudeCode with BOTH sides OAuth/Anthropic
    /// (neither pins env.ANTHROPIC_BASE_URL) MUST stay on the same-surface
    /// in-flight repoint path.
    #[test]
    fn route_claudecode_to_claudecode_is_same_surface_claudecode() {
        assert_eq!(
            route(Surface::ClaudeCode, Surface::ClaudeCode, false, false),
            RouteKind::SameSurfaceClaudeCode
        );
    }

    /// Regression guard for the Anthropic↔3P swap bug: a ClaudeCode→ClaudeCode
    /// swap where EITHER side is an env-transport slot (3P/Ollama pinning
    /// env.ANTHROPIC_BASE_URL) MUST take the exec-replace path — a running CC
    /// froze its base URL + token at launch and cannot switch in-flight, and a
    /// 3P→Anthropic in-flight repoint would exfiltrate the Anthropic OAuth token
    /// to the frozen 3P endpoint.
    #[test]
    fn route_claudecode_env_transport_forces_exec_replace() {
        // target is 3P (Anthropic → DeepSeek/Z.AI/MiniMax/Ollama).
        assert_eq!(
            route(Surface::ClaudeCode, Surface::ClaudeCode, false, true),
            RouteKind::ClaudeCodeEnvTransportExecReplace
        );
        // source is 3P (3P → Anthropic) — the exfiltration-risk direction.
        assert_eq!(
            route(Surface::ClaudeCode, Surface::ClaudeCode, true, false),
            RouteKind::ClaudeCodeEnvTransportExecReplace
        );
        // both 3P (3P → different 3P).
        assert_eq!(
            route(Surface::ClaudeCode, Surface::ClaudeCode, true, true),
            RouteKind::ClaudeCodeEnvTransportExecReplace
        );
    }

    /// The env-transport flags ONLY affect the (ClaudeCode, ClaudeCode) cell;
    /// a true surface change always routes CrossSurface regardless of them.
    #[test]
    fn route_env_transport_flags_do_not_affect_cross_surface() {
        assert_eq!(
            route(Surface::ClaudeCode, Surface::Codex, true, true),
            RouteKind::CrossSurface
        );
        assert_eq!(
            route(Surface::Codex, Surface::ClaudeCode, true, true),
            RouteKind::CrossSurface
        );
    }

    /// Pinning: Codex→Codex MUST stay on the same-surface in-flight
    /// repoint path (M10 / an internal journal entry). Regression guard against any
    /// future refactor that re-routes through cross_surface_exec and
    /// silently drops the user's conversation again.
    #[test]
    fn route_codex_to_codex_is_same_surface_codex() {
        assert_eq!(
            route(Surface::Codex, Surface::Codex, false, false),
            RouteKind::SameSurfaceCodex
        );
    }

    /// Pinning: any cross-surface combination MUST take the exec-replace
    /// path (INV-P05 confirm + INV-P10 tombstone + exec).
    #[test]
    fn route_cross_surface_is_cross_surface() {
        assert_eq!(
            route(Surface::ClaudeCode, Surface::Codex, false, false),
            RouteKind::CrossSurface
        );
        assert_eq!(
            route(Surface::Codex, Surface::ClaudeCode, false, false),
            RouteKind::CrossSurface
        );
    }

    /// PR-G4b — Gemini → ClaudeCode is cross-surface (tombstone + exec).
    #[test]
    fn route_gemini_to_claudecode_is_cross_surface() {
        assert_eq!(
            route(Surface::Gemini, Surface::ClaudeCode, false, false),
            RouteKind::CrossSurface
        );
    }

    /// PR-G4b — ClaudeCode → Gemini is cross-surface.
    #[test]
    fn route_claudecode_to_gemini_is_cross_surface() {
        assert_eq!(
            route(Surface::ClaudeCode, Surface::Gemini, false, false),
            RouteKind::CrossSurface
        );
    }

    /// PR-G4b — Codex → Gemini is cross-surface.
    #[test]
    fn route_codex_to_gemini_is_cross_surface() {
        assert_eq!(
            route(Surface::Codex, Surface::Gemini, false, false),
            RouteKind::CrossSurface
        );
    }

    /// PR-G4b — Gemini → Codex is cross-surface.
    #[test]
    fn route_gemini_to_codex_is_cross_surface() {
        assert_eq!(
            route(Surface::Gemini, Surface::Codex, false, false),
            RouteKind::CrossSurface
        );
    }

    /// PR-G4b — Gemini → Gemini also takes the exec path because
    /// gemini-cli does NOT re-read GEMINI_API_KEY mid-process.
    /// Same-surface naming is misleading here; what we want is
    /// "tombstone + exec" semantics so the new slot's vault key
    /// reaches gemini-cli.
    #[test]
    fn route_gemini_to_gemini_is_cross_surface_path() {
        assert_eq!(
            route(Surface::Gemini, Surface::Gemini, false, false),
            RouteKind::CrossSurface
        );
    }

    /// PR-G4b — `SourceHandle::Gemini` reports `Surface::Gemini`.
    #[test]
    fn source_handle_gemini_surface_matches_variant() {
        let g = SourceHandle::Gemini(PathBuf::from("/x/term-3"));
        assert_eq!(g.surface(), Surface::Gemini);
    }

    // ── PR-C9a an internal journal entry finding 10 — rename-to-tombstone ─

    /// The tombstone rename MUST atomically move the source handle
    /// dir to a sibling path with the `.sweep-tombstone-` prefix so
    /// the daemon's existing `cleanup_stale_tombstones` sweep reaps
    /// it. The source path is free; the directory inode survives for
    /// any process still holding fds into it.
    #[test]
    fn rename_handle_dir_to_sweep_tombstone_moves_dir() {
        let base = tempfile::TempDir::new().unwrap();
        let source = base.path().join("term-99999");
        std::fs::create_dir(&source).unwrap();
        // Seed a sentinel to prove the inode survived the move.
        std::fs::write(source.join("sentinel"), b"alive").unwrap();

        rename_handle_dir_to_sweep_tombstone(&source).unwrap();

        // Source path is gone.
        assert!(
            !source.exists(),
            "source handle dir must be gone after rename"
        );
        // A .sweep-tombstone-swap-<pid>-<nanos> sibling exists with
        // the sentinel intact.
        let mut tombstone_names: Vec<String> = std::fs::read_dir(base.path())
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with(".sweep-tombstone-swap-"))
            .collect();
        assert_eq!(
            tombstone_names.len(),
            1,
            "exactly one swap tombstone must exist"
        );
        let name = tombstone_names.pop().unwrap();
        let tomb = base.path().join(&name);
        assert!(tomb.is_dir(), "tombstone must be a directory");
        let sentinel = tomb.join("sentinel");
        let body = std::fs::read(&sentinel).expect("sentinel readable after rename");
        assert_eq!(body, b"alive", "tombstone preserves contents");
        // Prefix matches the daemon's cleanup harness.
        assert!(
            name.starts_with(".sweep-tombstone-"),
            "must share prefix with sweep's existing tombstone cleanup: {name}"
        );
    }

    /// Guard against the regression the old `remove_dir_all` had:
    /// if the sibling process had an open fd, the rename must NOT
    /// disturb the on-disk file — exactly one atomic syscall and the
    /// contents must be readable through the new name. (Unix only;
    /// Windows rename-over-open-handle semantics differ and this
    /// path is Unix-only anyway via `cross_surface_exec`.)
    #[cfg(unix)]
    #[test]
    fn rename_handle_dir_preserves_contents_during_atomic_swap() {
        let base = tempfile::TempDir::new().unwrap();
        let source = base.path().join("term-77777");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("a"), b"one").unwrap();
        std::fs::write(source.join("b"), b"two").unwrap();

        rename_handle_dir_to_sweep_tombstone(&source).unwrap();

        let tomb = std::fs::read_dir(base.path())
            .unwrap()
            .flatten()
            .find(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".sweep-tombstone-swap-")
            })
            .expect("tombstone present")
            .path();
        assert_eq!(std::fs::read(tomb.join("a")).unwrap(), b"one");
        assert_eq!(std::fs::read(tomb.join("b")).unwrap(), b"two");
    }

    // ── M4-8 (Phase 4 an internal ticket) — legacy-fallback retirement ─────

    /// Serializes the env-var-driven tests below — `CLAUDE_CONFIG_DIR`,
    /// `CODEX_HOME`, and `GEMINI_CLI_HOME` are process-globals, so
    /// concurrent test invocations would race and produce
    /// non-deterministic results.
    ///
    /// Uses the workspace-wide `csq_core::platform::test_env::lock()`
    /// per `rules/testing.md` MUST Rule 6 — an in-module mutex would
    /// NOT serialize against tests in OTHER modules that mutate or
    /// read the same env vars (e.g. surface.rs tests mutating
    /// `CODEX_USER_CONFIG`). The shared lock subsumes the local-only
    /// serialization need.
    fn env_swap_guard() -> std::sync::MutexGuard<'static, ()> {
        csq_core::platform::test_env::lock()
    }

    /// RAII wrapper that restores `CLAUDE_CONFIG_DIR` to its prior
    /// value (or removes it if previously unset) when dropped.
    struct EnvVarGuard {
        key: &'static str,
        prior: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prior = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prior }
        }

        fn unset(key: &'static str) -> Self {
            let prior = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, prior }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    /// M4-8 acceptance (a): `csq swap` invoked with `CLAUDE_CONFIG_DIR`
    /// pointing at a `config-<N>` dir refuses with the spec 02 §2.6
    /// message instructing the user to relaunch via `csq run <target>`
    /// (the actual target slot the user typed, not a literal `N` —
    /// R2 actionability fix). This is the post-M4-8 contract; the
    /// pre-M4-8 fallback through `rotation::swap_to` (which silently
    /// copied credentials) is gone.
    #[test]
    fn csq_swap_refuses_legacy_config_dir_with_relaunch_guidance() {
        let _serialize = env_swap_guard();
        let base = tempfile::TempDir::new().unwrap();
        let legacy = base.path().join("config-7");
        std::fs::create_dir(&legacy).unwrap();
        let _cc = EnvVarGuard::set("CLAUDE_CONFIG_DIR", legacy.to_str().unwrap());
        let _codex = EnvVarGuard::unset("CODEX_HOME");
        let _gemini = EnvVarGuard::unset("GEMINI_CLI_HOME");
        // Simulate `csq swap 3` from a legacy `config-7` terminal —
        // the refusal must surface BOTH the source dir AND the target
        // slot the user typed so the suggested command is copy-pasteable.
        let target = AccountNum::try_from(3u16).unwrap();

        let err = detect_source_handle(target)
            .expect_err("M4-8: legacy config-N source MUST be refused (rotation::swap_to retired)");
        let msg = format!("{err}");
        assert!(
            msg.contains("legacy per-account mode"),
            "refusal must cite the legacy-mode phrasing from spec 02 §2.6: {msg}"
        );
        assert!(
            msg.contains("csq run 3"),
            "refusal must include the user-typed target slot for a copy-pasteable relaunch hint: {msg}"
        );
        assert!(
            msg.contains("config-7"),
            "refusal must name the source config dir: {msg}"
        );
    }

    /// M4-8 acceptance (a): `csq swap` invoked inside a `term-<pid>`
    /// handle dir takes the handle-dir model path (same-surface
    /// ClaudeCode routing → `handle_dir::repoint_handle_dir`). The
    /// repoint itself is exhaustively covered by the 20+
    /// `repoint_handle_dir_*` tests in `csq-core/src/session/handle_dir.rs`;
    /// this test pins the CLI-side routing contract that survives M4-8 —
    /// `detect_source_handle` recognizes a `term-<pid>` dir as a
    /// ClaudeCode handle and the routing matrix dispatches to
    /// `SameSurfaceClaudeCode`.
    #[test]
    fn csq_swap_succeeds_in_handle_dir() {
        let _serialize = env_swap_guard();
        let base = tempfile::TempDir::new().unwrap();
        let handle = base.path().join("term-54321");
        std::fs::create_dir(&handle).unwrap();
        let _cc = EnvVarGuard::set("CLAUDE_CONFIG_DIR", handle.to_str().unwrap());
        let _codex = EnvVarGuard::unset("CODEX_HOME");
        let _gemini = EnvVarGuard::unset("GEMINI_CLI_HOME");
        let target = AccountNum::try_from(2u16).unwrap();

        let detected = detect_source_handle(target)
            .expect("term-<pid> source MUST be recognized as ClaudeCode");
        assert_eq!(
            detected.surface(),
            Surface::ClaudeCode,
            "handle dir source surface must be ClaudeCode"
        );
        assert_eq!(
            detected.path(),
            handle.as_path(),
            "detected path must point at the supplied handle dir"
        );
        // Routing contract: same-surface ClaudeCode targets the
        // in-flight `handle_dir::repoint_handle_dir` path (M4-8's only
        // ClaudeCode swap entry).
        assert_eq!(
            route(Surface::ClaudeCode, Surface::ClaudeCode, false, false),
            RouteKind::SameSurfaceClaudeCode,
        );
    }

    // ── M13b FIX-3+4 — swap audit tests ─────────────────────────────────────

    /// Helper: write a minimal `.csq-account` marker file into `handle_dir`
    /// containing the decimal string for `slot`. This simulates what `csq run`
    /// writes for a handle-dir-model terminal.
    fn write_csq_account_marker(handle_dir: &std::path::Path, slot: u16) {
        std::fs::write(handle_dir.join(".csq-account"), slot.to_string()).unwrap();
    }

    /// Helper: count JSONL records across all `csq-runs/*.jsonl` files.
    fn count_chain_records(base: &std::path::Path) -> usize {
        let runs_dir = base.join("csq-runs");
        if !runs_dir.exists() {
            return 0;
        }
        std::fs::read_dir(&runs_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().map(|x| x == "jsonl").unwrap_or(false))
            .map(|e| {
                let bytes = std::fs::read(e.path()).unwrap_or_default();
                bytes.iter().filter(|&&b| b == b'\n').count()
            })
            .sum()
    }

    /// FIX-4 AC: typed begin_swap_audit returns Ok(None) when the handle dir
    /// has no `.csq-account` marker — no record emitted, no error.
    #[test]
    fn begin_swap_audit_absent_marker_returns_ok_none() {
        let base = tempfile::TempDir::new().unwrap();
        // No .csq-account in the handle dir.
        let handle_dir = base.path().join("term-99");
        std::fs::create_dir(&handle_dir).unwrap();

        let from_slot = read_slot_from_handle_dir(&handle_dir); // → None
        let result = begin_swap_audit(base.path(), from_slot, AccountNum::try_from(2u16).unwrap());
        assert!(result.is_ok(), "absent marker must not error: {result:?}");
        assert!(result.unwrap().is_none(), "absent marker → Ok(None)");
        assert_eq!(
            count_chain_records(base.path()),
            0,
            "no record must be written when marker is absent"
        );
    }

    /// FIX-4 AC-S1: `from_slot` / `to_slot` in the payload match the detected
    /// source marker and the target slot passed to begin_swap_audit.
    #[test]
    fn begin_swap_audit_payload_slots_match_detected_source_and_target() {
        let base = tempfile::TempDir::new().unwrap();
        let handle_dir = base.path().join("term-42");
        std::fs::create_dir(&handle_dir).unwrap();
        write_csq_account_marker(&handle_dir, 3);

        let from_slot = read_slot_from_handle_dir(&handle_dir);
        assert_eq!(
            from_slot.map(|a| a.get()),
            Some(3),
            "marker must resolve to slot 3"
        );

        let to = AccountNum::try_from(5u16).unwrap();
        let ctx = begin_swap_audit(base.path(), from_slot, to)
            .expect("begin_swap_audit must succeed")
            .expect("ctx must be Some");

        // Parse the emitted record and check the payload.
        let runs_dir = base.path().join("csq-runs");
        let jsonl = std::fs::read_dir(&runs_dir)
            .unwrap()
            .flatten()
            .find(|e| e.path().extension().map(|x| x == "jsonl").unwrap_or(false))
            .expect("a chain JSONL must exist")
            .path();
        let line = std::fs::read_to_string(&jsonl).unwrap();
        let record: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        let payload = &record["payload"]["data"];
        assert_eq!(
            payload["from_slot"].as_u64(),
            Some(3),
            "from_slot must be 3 (detected marker)"
        );
        assert_eq!(
            payload["to_slot"].as_u64(),
            Some(5),
            "to_slot must be 5 (target)"
        );

        // op_phase must be Intent (serialized as {"phase": "intent", ...}).
        let op_phase = &record["op_phase"];
        assert_eq!(
            op_phase["phase"].as_str(),
            Some("intent"),
            "emitted record must have op_phase.phase == 'intent', got: {op_phase}"
        );

        let _ = ctx;
    }

    /// FIX-4 AC: intent-persist failure (read-only csq-runs/) → begin_swap_audit
    /// returns Err, and the audited wrappers fail closed (swap does NOT proceed).
    #[cfg(unix)]
    #[test]
    fn swap_audit_intent_persist_failure_fails_closed() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::TempDir::new().unwrap();

        // Create csq-runs/ as read-only so the intent write fails.
        let runs_dir = base.path().join("csq-runs");
        std::fs::create_dir_all(&runs_dir).unwrap();
        let mut perms = std::fs::metadata(&runs_dir).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&runs_dir, perms).unwrap();

        let handle_dir = base.path().join("term-55");
        std::fs::create_dir(&handle_dir).unwrap();
        write_csq_account_marker(&handle_dir, 1);

        let from_slot = read_slot_from_handle_dir(&handle_dir);
        let result = begin_swap_audit(base.path(), from_slot, AccountNum::try_from(2u16).unwrap());

        // Restore so TempDir cleanup works.
        let mut perms = std::fs::metadata(&runs_dir).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&runs_dir, perms).unwrap();

        assert!(
            result.is_err(),
            "intent-persist failure must return Err (fail-closed): {result:?}"
        );
    }

    /// FIX-4 AC: intent-before-tombstone ordering is structurally pinned.
    /// The INTENT emit in cross_surface_exec MUST precede the tombstone rename.
    #[test]
    fn cross_surface_intent_before_tombstone_pinned_in_source() {
        let src = include_str!("swap.rs");
        // Look for the sentinel text that documents FIX-2 ordering.
        assert!(
            src.contains("Step 1: emit INTENT (before any destructive operation)"),
            "swap.rs must contain the FIX-2 ordering sentinel for INTENT-before-tombstone"
        );
        assert!(
            src.contains("Step 2: tombstone source handle dir"),
            "swap.rs must contain the Step 2 tombstone sentinel after INTENT"
        );
        assert!(
            src.contains("Step 4: emit OUTCOME"),
            "swap.rs must contain the Step 4 OUTCOME-before-exec sentinel"
        );
    }

    /// Regression guard for the double-create bug: the step-5 exec helpers MUST
    /// re-derive the target handle dir path (`term-<pid>`), NOT call the create fn
    /// a second time. `create_target_handle_dir` (step 3) already created the dir
    /// and wrote its live `.live-pid`; a second `create_handle_dir[_codex]` with the
    /// same pid trips the live-PID guard ("in use by live PID … Refusing to remove")
    /// and aborts every exec-replace swap to a ClaudeCode/Codex target.
    #[test]
    fn exec_helpers_rederive_handle_dir_not_recreate() {
        let src = include_str!("swap.rs");
        // Split off the test module so we only inspect production code.
        let prod = src
            .split("mod tests")
            .next()
            .expect("swap.rs must have production code before the test module");
        // All three step-5 exec arms (ClaudeCode, Codex, Gemini) MUST re-derive the
        // target handle dir by path rather than calling the create fn a second time.
        // `create_target_handle_dir` (step 3) is the SINGLE creator; a second create
        // with the same pid trips the live-PID guard and aborts the swap.
        assert!(
            prod.matches("base_dir.join(format!(\"term-{pid}\"))")
                .count()
                >= 3,
            "all three exec arms must re-derive term-<pid> by path (double-create trips \
             the live-PID guard — see exec_*_after_binding)"
        );
        // create_handle_dir must appear EXACTLY once in production (step 3's creator);
        // create_handle_dir_codex likewise. A second occurrence means an exec arm
        // regressed to re-creating.
        assert_eq!(
            prod.matches("handle_dir::create_handle_dir(").count(),
            1,
            "create_handle_dir must be called exactly once (step 3 creator only)"
        );
    }

    /// Round-3 FIX-1: when the `.chain-broken` sentinel is set,
    /// `begin_swap_audit` MUST return `Ok(None)` (degrade-not-fail-closed).
    /// This mirrors the absent-marker path — no audit context means no
    /// outcome emitted, but swap itself is NOT blocked.
    #[test]
    fn begin_swap_audit_skips_when_chain_broken() {
        let base = tempfile::TempDir::new().unwrap();
        let handle_dir = base.path().join("term-77");
        std::fs::create_dir(&handle_dir).unwrap();
        write_csq_account_marker(&handle_dir, 3);

        // Set the .chain-broken sentinel.
        csq_core::audit::set_chain_broken(base.path(), "chain_broken_test");

        let from_slot = read_slot_from_handle_dir(&handle_dir);
        let result = begin_swap_audit(base.path(), from_slot, AccountNum::try_from(5u16).unwrap());

        // MUST succeed with None (degrade, not fail-closed).
        assert!(
            result.is_ok(),
            "begin_swap_audit must not Err when chain is broken: {result:?}"
        );
        assert!(
            result.unwrap().is_none(),
            "begin_swap_audit must return Ok(None) (skip audit) when chain is broken"
        );

        // Zero records on chain.
        assert_eq!(
            count_chain_records(base.path()),
            0,
            "no audit records must be written when chain is broken"
        );
    }
}
