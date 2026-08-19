//! Unified pre-bind slot-conflict guard — the single chokepoint every
//! **additive** slot-binding entry point routes through.
//!
//! # Why this module exists
//!
//! A csq slot is bound to exactly ONE surface: Anthropic OAuth, Codex,
//! Gemini, a native CLI (Kimi/Grok), or a third-party bearer provider. The
//! "reverse-clobber" bug class (an internal journal entry) is a binding entry point that
//! writes slot→surface X WITHOUT first refusing a slot already bound to an
//! incompatible surface — producing a dual-bind (double-lists in `csq ls`;
//! `csq run N` dispatches whichever surface wins precedence, orphaning the
//! other). It took redteam R1→R4 to enumerate the ~20 entry points because
//! detection was **hand-rolled at each guard**: native was taught to some
//! conflict-detection consumers and not others, one surface at a time.
//!
//! # The structural defense (an internal journal entry For-Discussion #1)
//!
//! 1. [`BoundSurface`] is the EXHAUSTIVE taxonomy of what a slot can be bound
//!    to. Every `match` on it is compiler-checked, so adding a sixth surface
//!    forces every guard to handle it — a new surface CANNOT be silently
//!    omitted from a guard.
//! 2. [`detect_bound_surface`] is the SINGLE union detector. No guard
//!    hand-rolls the per-surface predicates; they all source detection here.
//!    Enforced by `scripts/check-binding-guard-parity.py` (the
//!    `account-terminal-separation.md` MUST Rule 1 audit shape).
//! 3. [`refuse_if_slot_conflicts`] (surface-keyed) and
//!    [`refuse_if_provider_conflicts`] (provider-keyed, for the 3P case that
//!    needs finer-than-`Surface` granularity) are the two refusal entries
//!    every additive bind calls.
//!
//! # Additive vs replacing binds
//!
//! **Additive / marker binds** (native Kimi/Grok, Gemini, 3P setkey) overlay
//! a marker or settings block onto the slot and MUST refuse a cross-surface
//! binding — otherwise the slot carries two bindings. These route through
//! this module.
//!
//! **OAuth-login binds** (Anthropic, Codex) REPLACE the slot's identity
//! (fresh UUID in `by_slot`); logging in again is a legitimate re-bind, not a
//! dual-bind. Per GH an internal ticket, an OAuth-login onto a slot already carrying
//! an ADDITIVE marker binding (Gemini, native Kimi/Grok) silently CLEARS the
//! stale marker and proceeds — [`detect_stale_marker_binding`] (pure,
//! marker-sourced — safe to call at any point relative to the identity mint)
//! paired with [`clear_detected_marker_binding`] (acts on the
//! captured value, only on the login's success path) — mirroring the
//! shipped 3P-bearer precedent
//! ([`crate::accounts::third_party::unbind_provider_from_slot`], called by
//! `finalize_login`). This is a deliberate Option-A choice (extend the
//! cleanup) over Option B (refuse up-front, forcing an explicit `csq
//! logout`): refusing would be a login-UX regression inconsistent with the
//! silent 3P unbind already shipped. The detect/act split (rather than one
//! self-contained call) exists because a failed login must not destroy the
//! prior binding it never actually replaced — see
//! [`clear_detected_marker_binding`]'s doc comment.

use std::path::Path;

use crate::accounts::identity_store;
use crate::error::ConfigError;
use crate::providers::catalog::Surface;
use crate::providers::Provider;
use crate::types::AccountNum;

/// The complete taxonomy of what a slot can be bound to.
///
/// Exhaustive by construction: adding a surface here forces every `match` in
/// every guard to handle it (the compiler is the structural defense against
/// the "guard blindness" class — an internal journal entry). Distinct from
/// [`Surface`] in one load-bearing way: an Anthropic OAuth login and a
/// third-party bearer provider BOTH classify as [`Surface::ClaudeCode`] on
/// the wire, but they are DIFFERENT bindings ([`BoundSurface::ClaudeCode`] vs
/// [`BoundSurface::ThirdPartyBearer`]) — which is why `Surface` granularity
/// alone cannot tell a 3P re-key (allowed) from an Anthropic-OAuth clobber
/// (refused).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundSurface {
    /// Anthropic OAuth login — identity store `provider == "anthropic"` (or
    /// the pre-A++ `credentials/<N>.json` legacy mirror).
    ClaudeCode,
    /// Codex device-auth login — identity store `provider == "codex"` (or the
    /// pre-A++ `credentials/codex-<N>.json` legacy marker).
    Codex,
    /// Gemini binding marker (`credentials/gemini-<N>.json` — API-key / Vertex
    /// SA / Code-Assist OAuth).
    Gemini,
    /// A native-CLI surface (Kimi/Grok) — the credential-less binding marker
    /// `credentials/{kimi,grok}-<N>.json`. Carries the specific surface so
    /// callers can name it in the refusal message.
    Native(Surface),
    /// A third-party bearer provider (MiniMax / Z.AI / DeepSeek / Ollama / the
    /// *bearer* Kimi): a `config-<N>/settings.json` with `ANTHROPIC_BASE_URL`.
    /// On the wire it is [`Surface::ClaudeCode`] but it is a DISTINCT binding
    /// from an Anthropic OAuth login.
    ThirdPartyBearer,
}

impl BoundSurface {
    /// Stable lower-case tag for logs and UI labels.
    pub fn as_tag(&self) -> &'static str {
        match self {
            BoundSurface::ClaudeCode => "claude_code",
            BoundSurface::Codex => "codex",
            BoundSurface::Gemini => "gemini",
            BoundSurface::Native(surface) => surface.as_str(),
            BoundSurface::ThirdPartyBearer => "third_party",
        }
    }

    /// The wire [`Surface`] this binding presents as. `ThirdPartyBearer`
    /// collapses to [`Surface::ClaudeCode`] (it drives `claude` via a base-URL
    /// override) — preserving the prior `conflicting_bound_surface` return
    /// shape for the back-compat wrappers in `native` / `third_party`.
    pub fn to_surface(&self) -> Surface {
        match self {
            BoundSurface::ClaudeCode => Surface::ClaudeCode,
            BoundSurface::Codex => Surface::Codex,
            BoundSurface::Gemini => Surface::Gemini,
            BoundSurface::Native(surface) => *surface,
            BoundSurface::ThirdPartyBearer => Surface::ClaudeCode,
        }
    }

    /// Human-facing label for the [`ConfigError::SlotSurfaceConflict`] message.
    pub fn label(&self) -> &'static str {
        match self {
            BoundSurface::ClaudeCode => "Claude (Anthropic OAuth)",
            BoundSurface::Codex => "Codex",
            BoundSurface::Gemini => "Gemini",
            BoundSurface::Native(Surface::Kimi) => "Kimi (native CLI)",
            BoundSurface::Native(Surface::Grok) => "Grok (native CLI)",
            // Presentation-only fallback for a hypothetical future native
            // `Surface` variant. The top-level match on `BoundSurface` is still
            // exhaustive (a new BINDING KIND forces a compile error); only a new
            // native VENDOR under the existing `Native` payload lands here — a
            // generic-but-correct label, not a guard-blindness gap (redteam R2).
            BoundSurface::Native(_) => "a native CLI",
            BoundSurface::ThirdPartyBearer => "a third-party provider",
        }
    }
}

/// The SINGLE union detector: what is slot `slot` currently bound to?
///
/// Checked in a fixed precedence order (Codex → Anthropic → Gemini → native →
/// 3P bearer); for the (rare) dual-bound slot the higher-precedence binding is
/// reported — the `csq logout <N>` remediation is surface-agnostic, so the
/// single-surface message stays actionable either way.
///
/// This is the ONLY function permitted to call the per-surface detection
/// predicates. Every conflict guard sources detection here so no guard can be
/// blind to a surface (enforced by `scripts/check-binding-guard-parity.py`).
/// Identity-store-aware (`account-terminal-separation.md` MUST Rule 4): keys
/// on `by_slot` → `identities/<UUID>/` with the M4-12-retired legacy mirrors
/// kept only as a pre-A++ `symlink_metadata` fallback inside the predicates.
pub fn detect_bound_surface(base_dir: &Path, slot: AccountNum) -> Option<BoundSurface> {
    if identity_store::is_codex_bound_slot_identity_aware(base_dir, slot) {
        return Some(BoundSurface::Codex);
    }
    if identity_store::is_anthropic_bound_slot(base_dir, slot) {
        return Some(BoundSurface::ClaudeCode);
    }
    if crate::providers::gemini::provisioning::is_gemini_bound_slot(base_dir, slot) {
        return Some(BoundSurface::Gemini);
    }
    if let Some(surface) = crate::providers::native::native_surface_for_slot(base_dir, slot) {
        return Some(BoundSurface::Native(surface));
    }
    // 3P-bearer binding (MiniMax/Z.AI/DeepSeek/Ollama/the *bearer* Kimi) writes
    // `config-<N>/settings.json` with `ANTHROPIC_BASE_URL` and classifies as
    // `Surface::ClaudeCode`. None of the checks above see it, so it is detected
    // LAST — after the identity-store and marker surfaces.
    if crate::accounts::discovery::discover_per_slot_third_party(base_dir)
        .iter()
        .any(|a| a.id == slot.get())
    {
        return Some(BoundSurface::ThirdPartyBearer);
    }
    None
}

/// Detects a stale ADDITIVE marker binding (Gemini / native Kimi-Grok) on
/// `slot`. PURE — no side effect, nothing is deleted. The first half of the
/// OAuth-login (replacing) reverse-cleanup pair; the caller CAPTURES this
/// return value and passes it to [`clear_detected_marker_binding`] only once
/// the login has fully succeeded — see that function's doc comment for why
/// the two halves are split rather than one self-contained "detect and
/// clear" call.
///
/// GH an internal ticket: the `binding_guard` module closed the ADDITIVE-bind
/// direction structurally (native/Gemini/3P binds refuse a cross-surface
/// slot via [`refuse_if_slot_conflicts`] / [`refuse_if_provider_conflicts`]),
/// but the REPLACING-bind direction (`csq login N`, `csq login N --provider
/// codex`) left a Gemini or native marker in place after minting a fresh
/// Anthropic/Codex identity over it — producing a dual-bind (the slot
/// double-lists; `csq run N` dispatches whichever surface wins precedence,
/// orphaning the other). This closes that gap the same way
/// [`crate::accounts::third_party::unbind_provider_from_slot`] already
/// closes it for a 3P-bearer binding: silently unbind and let the login
/// proceed, rather than refuse up-front and force an explicit `csq logout`.
///
/// # Sourced directly from the marker predicates, NOT [`detect_bound_surface`]
///
/// an internal ticket regression: an earlier revision of this function delegated to
/// the [`detect_bound_surface`] union detector and filtered its result down
/// to the marker-based variants. That detector is precedence-ordered Codex →
/// Anthropic → Gemini → native → 3P, so it reports the HIGHEST-precedence
/// binding a slot carries — and an internal ticket's
/// [`crate::accounts::login::ensure_login_identity_minted`] mints
/// `by_slot[slot]` for the FRESH Anthropic identity BEFORE `finalize_login`
/// (and therefore this function) ever runs, on every production caller. A
/// delegated call therefore always saw Anthropic ahead of the stale Gemini
/// or native marker and reported `None` — this detection was DEAD CODE in
/// production; only the two hand-fixtured unit tests, which never call
/// `ensure_login_identity_minted`, exercised the "sees the marker" path.
/// Calling the [`crate::providers::gemini::provisioning::is_gemini_bound_slot`]
/// and [`crate::providers::native::native_surface_for_slot`] marker
/// predicates directly — bypassing precedence entirely — fixes this and
/// removes the "MUST run before the mint" ordering contract the delegated
/// form depended on: this function is now correct to call at ANY point
/// relative to the identity mint, in this function or any caller's.
///
/// Returns `None` for Codex/Anthropic/3P-bearer/free — those are not
/// additive markers this pair acts on (3P cleanup is
/// `unbind_provider_from_slot`, called separately; Codex/Anthropic are the
/// OAuth-login surfaces themselves — an idempotent re-login).
pub fn detect_stale_marker_binding(base_dir: &Path, slot: AccountNum) -> Option<BoundSurface> {
    if crate::providers::gemini::provisioning::is_gemini_bound_slot(base_dir, slot) {
        return Some(BoundSurface::Gemini);
    }
    if let Some(surface) = crate::providers::native::native_surface_for_slot(base_dir, slot) {
        return Some(BoundSurface::Native(surface));
    }
    None
}

/// Clears the marker binding `surface`, previously CAPTURED by
/// [`detect_stale_marker_binding`] before the identity mint. The caller MUST
/// invoke this ONLY on the login's success path — after every fallible step
/// of the login has already succeeded — never speculatively.
///
/// # Why capture-then-act, not detect-then-act
///
/// Security review of GH an internal ticket's first cut found: calling this
/// immediately after `detect_stale_marker_binding` (i.e. still pre-mint, pre
/// every later fallible step) deletes the prior binding EVEN WHEN the login
/// subsequently fails — e.g. `ProfilesFileLock::acquire` losing a race with a
/// concurrent daemon Pass 0. That leaves the slot with NEITHER the new OAuth
/// identity (the mint/save never completed) NOR the old Gemini/native
/// binding (already deleted) — strictly worse than the pre-fix refuse
/// behaviour, which left the prior binding untouched on failure. Splitting
/// detection (pure, pre-mint, so it isn't precedence-masked) from action
/// (post-success, using the CAPTURED value rather than a fresh detect, which
/// WOULD now be masked) removes that window while keeping the correct
/// pre-mint visibility.
///
/// Re-detecting instead of using the captured surface here would reintroduce
/// the precedence-masking bug `detect_stale_marker_binding` exists to avoid
/// — by the time this runs, `by_slot[slot]` resolves to the just-minted
/// identity.
///
/// # Gemini: vault entry deleted BEFORE the marker (H1, an internal ticket security review)
///
/// [`crate::providers::gemini::provisioning::unbind`]'s own doc: "Does NOT
/// touch the vault entry — callers that want a full unbind invoke
/// `Vault::delete` separately." An ApiKey-mode Gemini slot's real secret
/// lives in the OS keychain, findable ONLY by first reading the marker to
/// learn the auth mode ([`crate::providers::gemini::provisioning::delete_api_key_from_vault`]'s
/// doc). Removing the marker FIRST — the shape this function shipped with
/// before this fix, because this arm's precedence-masked predecessor was
/// dead code in production (see above) — makes that vault entry
/// permanently unfindable: a later `csq logout` gates its own vault sweep
/// on `is_gemini_bound_slot`, which the deleted marker now reports `false`
/// for, so the sweep never runs. This mirrors the ordering
/// `csq::desktop::commands::remove_account` already uses for the identical
/// reason (`delete_api_key_from_vault` before `gemini_unbind`): vault
/// delete precedes marker removal, and the marker is left in place on ANY
/// vault-step failure (`guard-reader-writer-parity.md` MUST-2 — a
/// destructive path proceeds only once "cannot complete" has been ruled
/// out; here that means the vault entry stays findable for the next login
/// attempt or an explicit `csq logout`, rather than being stranded).
///
/// Best-effort by design: a stale-marker cleanup failure MUST NOT block a
/// successful OAuth login — the fresh credential is already written and
/// authoritative. Failures are logged with a fixed-vocabulary `error_kind`
/// tag (`security.md` MUST-2 — no raw error `Display`, which can carry a
/// filesystem path, interpolated into the log line).
pub fn clear_detected_marker_binding(base_dir: &Path, slot: AccountNum, surface: BoundSurface) {
    // Exhaustive on purpose (NO wildcard): mirrors `detect_stale_marker_binding`'s
    // exhaustiveness guarantee. `detect_stale_marker_binding` never returns
    // Codex/ClaudeCode/ThirdPartyBearer, so those arms are defensive against
    // a caller passing an un-captured value — a no-op, not a panic, so a
    // programming error here can never turn into a login-time crash.
    match surface {
        BoundSurface::Gemini => match crate::platform::secret::open_default_vault() {
            Ok(vault) => clear_gemini_marker_with_vault(base_dir, slot, vault.as_ref()),
            Err(e) => tracing::warn!(
                account = slot.get(),
                error_kind = "stale_gemini_vault_unavailable",
                vault_error_kind = e.error_kind_tag(),
                "oauth login: vault unavailable — stale Gemini marker left in place \
                 so it stays findable (non-fatal)"
            ),
        },
        BoundSurface::Native(native_surface) => {
            match crate::providers::native::unbind(base_dir, slot, native_surface) {
                Ok(()) => tracing::info!(
                    account = slot.get(),
                    surface = native_surface.as_str(),
                    "oauth login: removed stale native binding marker"
                ),
                Err(e) => tracing::warn!(
                    account = slot.get(),
                    surface = native_surface.as_str(),
                    error_kind = "stale_native_marker_cleanup_failed",
                    native_error_kind = e.error_kind_tag(),
                    "oauth login: could not remove stale native binding marker (non-fatal)"
                ),
            }
        }
        BoundSurface::Codex | BoundSurface::ClaudeCode | BoundSurface::ThirdPartyBearer => {}
    }
}

/// Gemini marker-clear core: the vault entry is deleted BEFORE the marker,
/// and the marker is left in place (fail-closed) on any vault-step failure
/// — see [`clear_detected_marker_binding`]'s doc for why. Split out of
/// that function's `Gemini` arm so it is directly unit-testable against a
/// SHARED `Vault` instance: `open_default_vault()` under
/// `CSQ_SECRET_BACKEND=in-memory` hands back a fresh, unshared store on
/// every call, so a caller cannot observe deletion through it — only a
/// vault constructed once and passed in, as this function requires, makes
/// the postcondition checkable.
fn clear_gemini_marker_with_vault(
    base_dir: &Path,
    slot: AccountNum,
    vault: &dyn crate::platform::secret::Vault,
) {
    match crate::providers::gemini::provisioning::delete_api_key_from_vault(base_dir, slot, vault) {
        Ok(()) => match crate::providers::gemini::provisioning::unbind(base_dir, slot) {
            Ok(()) => tracing::info!(
                account = slot.get(),
                "oauth login: removed stale Gemini binding marker"
            ),
            Err(e) => tracing::warn!(
                account = slot.get(),
                error_kind = "stale_gemini_marker_cleanup_failed",
                provision_error_kind = e.error_kind_tag(),
                "oauth login: could not remove stale Gemini binding marker (non-fatal)"
            ),
        },
        Err(e) => tracing::warn!(
            account = slot.get(),
            error_kind = "stale_gemini_vault_cleanup_failed",
            vault_error_kind = e.error_kind_tag(),
            "oauth login: could not clear stale Gemini vault entry — marker left \
             in place so it stays findable (non-fatal)"
        ),
    }
}

/// Whether binding slot `slot` to the additive marker surface `target` would
/// clobber an existing DIFFERENT binding. `None` = free, or an idempotent
/// re-bind of the same surface. Used by the native and Gemini entry points.
pub fn conflicting_bound_surface(
    base_dir: &Path,
    slot: AccountNum,
    target: Surface,
) -> Option<BoundSurface> {
    let current = detect_bound_surface(base_dir, slot)?;
    if is_same_surface_bind(&current, target) {
        None
    } else {
        Some(current)
    }
}

/// Idempotency test for a surface-keyed additive bind: does `current` already
/// represent a binding to `target`? A `ThirdPartyBearer` never matches a
/// surface-keyed target (native/gemini binds are never 3P), and an
/// Anthropic-OAuth `ClaudeCode` binding is only idempotent for a `ClaudeCode`
/// target (which the additive entry points never pass).
fn is_same_surface_bind(current: &BoundSurface, target: Surface) -> bool {
    // Exhaustive on `current` (NO wildcard) so a sixth `BoundSurface` variant
    // forces an explicit idempotency decision here rather than silently
    // defaulting to "conflict" (over-refuse) — keeping the module's
    // compiler-exhaustiveness guarantee honest.
    match current {
        BoundSurface::ClaudeCode => target == Surface::ClaudeCode,
        BoundSurface::Codex => target == Surface::Codex,
        BoundSurface::Gemini => target == Surface::Gemini,
        BoundSurface::Native(existing) => *existing == target,
        // A 3P-bearer binding is never the target of a surface-keyed additive
        // bind (native/gemini), so it is always a conflict here.
        BoundSurface::ThirdPartyBearer => false,
    }
}

/// Refuse (with [`ConfigError::SlotSurfaceConflict`]) when binding slot `slot`
/// to the additive marker surface `target` would clobber a different binding.
///
/// The canonical guard for the native (Kimi/Grok) and Gemini entry points.
pub fn refuse_if_slot_conflicts(
    base_dir: &Path,
    slot: AccountNum,
    target: Surface,
) -> Result<(), ConfigError> {
    if let Some(bound) = conflicting_bound_surface(base_dir, slot, target) {
        return Err(ConfigError::SlotSurfaceConflict {
            slot: slot.get(),
            bound_surface: bound.label().to_string(),
        });
    }
    Ok(())
}

/// Whether binding third-party `provider` to `slot` would clobber a DIFFERENT
/// binding. A 3P→3P re-key (`current` is already a bearer) is allowed; an
/// OAuth / device-auth / marker surface is refused.
///
/// 3P providers all present as [`Surface::ClaudeCode`] on the wire, so the
/// `provider.surface` match arms below are effectively always the
/// `ThirdPartyBearer`/`ClaudeCode` cases — but the Codex/Gemini arms preserve
/// the exact semantics of the retired `third_party::conflicting_bound_surface`
/// (idempotent only when the provider's own surface equals the bound surface).
pub fn conflicting_bound_surface_for_provider(
    base_dir: &Path,
    slot: AccountNum,
    provider: &Provider,
) -> Option<BoundSurface> {
    let current = detect_bound_surface(base_dir, slot)?;
    let idempotent = match &current {
        // A 3P slot re-keyed to another 3P provider — allowed (settings overlay
        // replace, no OAuth to clobber).
        BoundSurface::ThirdPartyBearer => true,
        BoundSurface::Codex => provider.surface == Surface::Codex,
        BoundSurface::Gemini => provider.surface == Surface::Gemini,
        // Anthropic OAuth login: a 3P key write would silently override the
        // live subscription token — never idempotent (an internal ticket).
        BoundSurface::ClaudeCode => false,
        BoundSurface::Native(_) => false,
    };
    if idempotent {
        None
    } else {
        Some(current)
    }
}

/// Refuse (with [`ConfigError::SlotSurfaceConflict`]) when binding 3P
/// `provider` to `slot` would clobber a different binding. The canonical
/// guard for `third_party::bind_provider_to_slot` and its `setkey` callers.
pub fn refuse_if_provider_conflicts(
    base_dir: &Path,
    slot: AccountNum,
    provider: &Provider,
) -> Result<(), ConfigError> {
    if let Some(bound) = conflicting_bound_surface_for_provider(base_dir, slot, provider) {
        return Err(ConfigError::SlotSurfaceConflict {
            slot: slot.get(),
            bound_surface: bound.label().to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::gemini::provisioning::{
        write_binding as gemini_write, AuthMode, GeminiBinding,
    };
    use crate::providers::native::write_binding as native_write;
    use tempfile::TempDir;

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    // ── planting helpers (real writers so detection is exercised end-to-end) ──

    fn plant_codex(base: &Path, n: u16) {
        // Pre-A++ legacy marker — detected via the identity-store predicate's
        // `symlink_metadata` fallback.
        let dir = base.join("credentials");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("codex-{n}.json")), "{}").unwrap();
    }

    fn plant_anthropic(base: &Path, n: u16) {
        let dir = base.join("credentials");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{n}.json")), "{}").unwrap();
    }

    fn plant_gemini(base: &Path, n: u16) {
        gemini_write(base, slot(n), &GeminiBinding::new(AuthMode::ApiKey, "auto")).unwrap();
    }

    fn plant_3p(base: &Path, n: u16) {
        crate::accounts::third_party::bind_provider_to_slot(
            base,
            "deepseek",
            slot(n),
            Some("sk-deepseek-xxxxxxxx"),
            None,
        )
        .unwrap();
    }

    // ── detect_bound_surface: one arm per channel ───────────────────────────

    #[test]
    fn detect_returns_none_for_free_slot() {
        let dir = TempDir::new().unwrap();
        assert_eq!(detect_bound_surface(dir.path(), slot(1)), None);
    }

    #[test]
    fn detect_each_surface() {
        let dir = TempDir::new().unwrap();
        plant_codex(dir.path(), 1);
        plant_anthropic(dir.path(), 2);
        plant_gemini(dir.path(), 3);
        native_write(dir.path(), slot(4), Surface::Kimi).unwrap();
        native_write(dir.path(), slot(5), Surface::Grok).unwrap();
        plant_3p(dir.path(), 6);
        assert_eq!(
            detect_bound_surface(dir.path(), slot(1)),
            Some(BoundSurface::Codex)
        );
        assert_eq!(
            detect_bound_surface(dir.path(), slot(2)),
            Some(BoundSurface::ClaudeCode)
        );
        assert_eq!(
            detect_bound_surface(dir.path(), slot(3)),
            Some(BoundSurface::Gemini)
        );
        assert_eq!(
            detect_bound_surface(dir.path(), slot(4)),
            Some(BoundSurface::Native(Surface::Kimi))
        );
        assert_eq!(
            detect_bound_surface(dir.path(), slot(5)),
            Some(BoundSurface::Native(Surface::Grok))
        );
        assert_eq!(
            detect_bound_surface(dir.path(), slot(6)),
            Some(BoundSurface::ThirdPartyBearer)
        );
    }

    #[test]
    fn detect_precedence_codex_over_native_when_dual() {
        // Inconsistent dual-marker state resolves deterministically to the
        // higher-precedence surface (Codex first).
        let dir = TempDir::new().unwrap();
        plant_codex(dir.path(), 1);
        native_write(dir.path(), slot(1), Surface::Kimi).unwrap();
        assert_eq!(
            detect_bound_surface(dir.path(), slot(1)),
            Some(BoundSurface::Codex)
        );
    }

    // ── refuse_if_slot_conflicts: additive marker binds (native + gemini) ────

    #[test]
    fn native_bind_idempotent_and_cross_surface_refused() {
        let dir = TempDir::new().unwrap();
        // free → ok
        assert!(refuse_if_slot_conflicts(dir.path(), slot(1), Surface::Kimi).is_ok());
        // same native surface → idempotent ok
        native_write(dir.path(), slot(2), Surface::Kimi).unwrap();
        assert!(refuse_if_slot_conflicts(dir.path(), slot(2), Surface::Kimi).is_ok());
        // OTHER native surface → refused
        assert!(refuse_if_slot_conflicts(dir.path(), slot(2), Surface::Grok).is_err());
        // gemini slot → native refused
        plant_gemini(dir.path(), 3);
        assert!(refuse_if_slot_conflicts(dir.path(), slot(3), Surface::Kimi).is_err());
    }

    #[test]
    fn gemini_bind_refuses_third_party_bearer_slot() {
        // The gap the hand-rolled Gemini guard left open: a Gemini bind onto a
        // 3P-bearer slot was previously allowed (blind to 3P), creating a
        // dual-bind. The unified detector now refuses it.
        let dir = TempDir::new().unwrap();
        plant_3p(dir.path(), 1);
        let err = refuse_if_slot_conflicts(dir.path(), slot(1), Surface::Gemini);
        assert!(err.is_err(), "gemini-onto-3p must be refused");
    }

    #[test]
    fn gemini_bind_idempotent_on_gemini_slot() {
        let dir = TempDir::new().unwrap();
        plant_gemini(dir.path(), 1);
        assert!(refuse_if_slot_conflicts(dir.path(), slot(1), Surface::Gemini).is_ok());
    }

    // ── refuse_if_provider_conflicts: 3P re-key allowed, OAuth refused ───────

    #[test]
    fn provider_bind_allows_3p_rekey_refuses_oauth_and_native() {
        let dir = TempDir::new().unwrap();
        let mm = crate::providers::get_provider("mm").unwrap();
        // free → ok
        assert!(refuse_if_provider_conflicts(dir.path(), slot(1), mm).is_ok());
        // 3P slot re-keyed to another 3P provider → allowed
        plant_3p(dir.path(), 2);
        assert!(refuse_if_provider_conflicts(dir.path(), slot(2), mm).is_ok());
        // Anthropic OAuth slot → refused (a 3P key would override the live login)
        plant_anthropic(dir.path(), 3);
        assert!(refuse_if_provider_conflicts(dir.path(), slot(3), mm).is_err());
        // native slot → refused
        native_write(dir.path(), slot(4), Surface::Kimi).unwrap();
        assert!(refuse_if_provider_conflicts(dir.path(), slot(4), mm).is_err());
    }

    // ── detect_stale_marker_binding / clear_detected_marker_binding
    // (GH an internal ticket + the capture/act split from security review) ─────────

    // Runs `f` with `CSQ_SECRET_BACKEND=in-memory` so `open_default_vault()`
    // resolves the same backend on every platform instead of the real OS
    // keychain (macOS/Windows) or a D-Bus Secret Service that a headless CI
    // runner does not have (Linux). `platform::test_env::with_in_memory_secret_backend`
    // carries the full rationale. Was a local copy here until the same
    // dependency surfaced in three login tests; the shared version is
    // panic-safe (restores on unwind), which this one was not.
    use crate::platform::test_env::with_in_memory_secret_backend as with_in_memory_vault_backend;

    #[test]
    fn detect_stale_marker_finds_gemini_and_clear_removes_it() {
        let dir = TempDir::new().unwrap();
        plant_gemini(dir.path(), 1);
        let detected = detect_stale_marker_binding(dir.path(), slot(1));
        assert_eq!(detected, Some(BoundSurface::Gemini));
        // Detection is PURE — nothing removed yet.
        assert_eq!(
            detect_bound_surface(dir.path(), slot(1)),
            Some(BoundSurface::Gemini),
            "detect_stale_marker_binding must not have side effects"
        );
        // clear_detected_marker_binding's Gemini arm now opens a vault
        // (H1 fix) — force in-memory so this doesn't hit the real keychain.
        with_in_memory_vault_backend(|| {
            clear_detected_marker_binding(dir.path(), slot(1), detected.unwrap());
        });
        assert_eq!(
            detect_bound_surface(dir.path(), slot(1)),
            None,
            "the Gemini marker must be gone after clear_detected_marker_binding"
        );
    }

    // ── H1 (an internal ticket security review): Gemini vault entry must be deleted
    // BEFORE the marker, and the marker must be LEFT IN PLACE (fail-closed)
    // when the vault delete cannot be confirmed. `clear_gemini_marker_with_vault`
    // is the directly-testable core `clear_detected_marker_binding`'s Gemini
    // arm delegates to (see that function's doc for why: `open_default_vault()`
    // under `CSQ_SECRET_BACKEND=in-memory` hands back a fresh, UNSHARED store
    // per call, so the vault-empty postcondition is only observable against a
    // vault instance constructed once and passed in directly). ─────────────

    /// Test-only [`crate::platform::secret::Vault`] whose `delete` always
    /// fails, so the fail-closed ordering (marker survives a vault-delete
    /// failure) is directly exercisable without needing to break the real
    /// keychain or the in-memory backend.
    struct FailingDeleteVault;

    impl crate::platform::secret::Vault for FailingDeleteVault {
        fn set(
            &self,
            _slot: crate::platform::secret::SlotKey,
            _secret: &secrecy::SecretString,
        ) -> Result<(), crate::platform::secret::SecretError> {
            Ok(())
        }
        fn get(
            &self,
            slot: crate::platform::secret::SlotKey,
        ) -> Result<secrecy::SecretString, crate::platform::secret::SecretError> {
            Err(crate::platform::secret::SecretError::NotFound {
                surface: slot.surface,
                account: slot.account.get(),
            })
        }
        fn delete(
            &self,
            _slot: crate::platform::secret::SlotKey,
        ) -> Result<(), crate::platform::secret::SecretError> {
            Err(crate::platform::secret::SecretError::BackendUnavailable {
                reason: "test-forced failure".into(),
            })
        }
        fn list_slots(
            &self,
            _surface: &'static str,
        ) -> Result<Vec<AccountNum>, crate::platform::secret::SecretError> {
            Ok(vec![])
        }
        fn backend_id(&self) -> &'static str {
            "failing-test-vault"
        }
    }

    #[test]
    fn clear_gemini_marker_with_vault_deletes_vault_entry_before_marker() {
        use crate::platform::secret::in_memory::InMemoryVault;
        use crate::platform::secret::{SlotKey, Vault};
        use crate::providers::gemini::SURFACE_GEMINI;
        use secrecy::SecretString;

        let dir = TempDir::new().unwrap();
        plant_gemini(dir.path(), 1); // ApiKey-mode marker

        let vault = InMemoryVault::new();
        let key = SlotKey {
            surface: SURFACE_GEMINI,
            account: slot(1),
        };
        vault
            .set(
                key,
                &SecretString::new("AIzaFAKETESTKEYDONOTUSE0000000000000000".into()),
            )
            .unwrap();
        assert!(
            vault.get(key).is_ok(),
            "sanity: the vault must hold the key before clear"
        );

        clear_gemini_marker_with_vault(dir.path(), slot(1), &vault);

        assert!(
            matches!(
                vault.get(key),
                Err(crate::platform::secret::SecretError::NotFound { .. })
            ),
            "the vault entry must be gone after clear_gemini_marker_with_vault"
        );
        assert_eq!(
            detect_bound_surface(dir.path(), slot(1)),
            None,
            "the binding marker must also be gone once the vault delete succeeded"
        );
    }

    #[test]
    fn clear_gemini_marker_with_vault_leaves_marker_when_vault_delete_fails() {
        let dir = TempDir::new().unwrap();
        plant_gemini(dir.path(), 1);

        clear_gemini_marker_with_vault(dir.path(), slot(1), &FailingDeleteVault);

        // Fail-closed: the vault delete could not be confirmed, so the
        // marker MUST survive — leaving the (still-orphaned) vault entry
        // findable for the next login attempt or an explicit `csq logout`,
        // rather than stranding it (guard-reader-writer-parity.md MUST-2).
        assert_eq!(
            detect_bound_surface(dir.path(), slot(1)),
            Some(BoundSurface::Gemini),
            "the marker must be left in place when the vault delete fails"
        );
    }

    #[test]
    fn detect_stale_marker_finds_native_and_clear_removes_it() {
        let dir = TempDir::new().unwrap();
        native_write(dir.path(), slot(1), Surface::Kimi).unwrap();
        native_write(dir.path(), slot(2), Surface::Grok).unwrap();

        let d1 = detect_stale_marker_binding(dir.path(), slot(1));
        let d2 = detect_stale_marker_binding(dir.path(), slot(2));
        assert_eq!(d1, Some(BoundSurface::Native(Surface::Kimi)));
        assert_eq!(d2, Some(BoundSurface::Native(Surface::Grok)));

        clear_detected_marker_binding(dir.path(), slot(1), d1.unwrap());
        clear_detected_marker_binding(dir.path(), slot(2), d2.unwrap());
        assert_eq!(detect_bound_surface(dir.path(), slot(1)), None);
        assert_eq!(detect_bound_surface(dir.path(), slot(2)), None);
    }

    #[test]
    fn detect_stale_marker_returns_none_for_oauth_and_3p_and_free() {
        // Covers ALL remaining BoundSurface variants + free: Codex/Anthropic
        // are the OAuth-login surfaces themselves (idempotent re-login);
        // 3P-bearer cleanup is a separate function (`unbind_provider_from_slot`).
        // Pins each arm of the exhaustive match so a regression that moved a
        // non-marker variant into the detected side is caught.
        let dir = TempDir::new().unwrap();
        plant_codex(dir.path(), 1);
        plant_anthropic(dir.path(), 2);
        plant_3p(dir.path(), 3);
        assert_eq!(detect_stale_marker_binding(dir.path(), slot(1)), None);
        assert_eq!(detect_stale_marker_binding(dir.path(), slot(2)), None);
        assert_eq!(detect_stale_marker_binding(dir.path(), slot(3)), None);
        assert_eq!(
            detect_stale_marker_binding(dir.path(), slot(4)),
            None,
            "free slot must detect nothing"
        );
    }

    #[test]
    fn clear_detected_marker_binding_is_a_defensive_noop_on_non_marker_surfaces() {
        // `detect_stale_marker_binding` never returns these three, but the
        // exhaustive match on the ACTING half must still handle them —
        // defensively, as a no-op, so a caller passing an un-captured value
        // (a programming error) can never delete a live OAuth/3P binding nor
        // panic mid-login. Plant each, call clear with EVERY surface, assert
        // nothing was disturbed.
        let dir = TempDir::new().unwrap();
        plant_codex(dir.path(), 1);
        plant_anthropic(dir.path(), 2);
        plant_3p(dir.path(), 3);

        clear_detected_marker_binding(dir.path(), slot(1), BoundSurface::Codex);
        clear_detected_marker_binding(dir.path(), slot(2), BoundSurface::ClaudeCode);
        clear_detected_marker_binding(dir.path(), slot(3), BoundSurface::ThirdPartyBearer);

        assert_eq!(
            detect_bound_surface(dir.path(), slot(1)),
            Some(BoundSurface::Codex)
        );
        assert_eq!(
            detect_bound_surface(dir.path(), slot(2)),
            Some(BoundSurface::ClaudeCode)
        );
        assert_eq!(
            detect_bound_surface(dir.path(), slot(3)),
            Some(BoundSurface::ThirdPartyBearer)
        );
    }

    #[test]
    fn detect_precedence_all_adjacent_pairs() {
        // The 4-level detector order is Codex→Anthropic→Gemini→native→3P. Pin
        // the three adjacency pairs the redesign's ordering actually depends on
        // (a dual-marker inconsistent state resolves to the higher-precedence
        // surface) — redteam R3 M4.
        let dir = TempDir::new().unwrap();
        // Anthropic > Gemini
        plant_anthropic(dir.path(), 1);
        plant_gemini(dir.path(), 1);
        assert_eq!(
            detect_bound_surface(dir.path(), slot(1)),
            Some(BoundSurface::ClaudeCode)
        );
        // Gemini > native
        plant_gemini(dir.path(), 2);
        native_write(dir.path(), slot(2), Surface::Kimi).unwrap();
        assert_eq!(
            detect_bound_surface(dir.path(), slot(2)),
            Some(BoundSurface::Gemini)
        );
        // native > 3P bearer. Plant the 3P bind FIRST (on a free slot — the
        // provider guard would refuse it on a native-bound slot), THEN drop the
        // raw native marker on top (`write_binding` has no guard) to build the
        // inconsistent dual-marker state the precedence resolves.
        plant_3p(dir.path(), 3);
        native_write(dir.path(), slot(3), Surface::Grok).unwrap();
        assert_eq!(
            detect_bound_surface(dir.path(), slot(3)),
            Some(BoundSurface::Native(Surface::Grok))
        );
    }

    // ── label / to_surface fidelity for the SlotSurfaceConflict message ──────

    #[test]
    fn bound_surface_labels_and_wire_surface() {
        assert_eq!(BoundSurface::ClaudeCode.label(), "Claude (Anthropic OAuth)");
        assert_eq!(
            BoundSurface::Native(Surface::Kimi).label(),
            "Kimi (native CLI)"
        );
        assert_eq!(
            BoundSurface::ThirdPartyBearer.label(),
            "a third-party provider"
        );
        // A 3P-bearer binding presents as ClaudeCode on the wire (back-compat
        // for the `Option<Surface>` wrappers).
        assert_eq!(
            BoundSurface::ThirdPartyBearer.to_surface(),
            Surface::ClaudeCode
        );
        assert_eq!(
            BoundSurface::Native(Surface::Grok).to_surface(),
            Surface::Grok
        );
    }
}
