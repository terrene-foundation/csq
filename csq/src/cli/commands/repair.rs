//! `csq repair` (alias `repair-credentials`) — detect and optionally repair
//! credential + slot-attribution inconsistencies.
//!
//! Two independent passes run on every invocation:
//!
//! 1. **Credential contamination** — cross-slot refresh-token sharing
//!    (documented below).
//! 2. **Slot attribution** (workspace an internal workspace) — stale
//!    `config-N/.current-account` caches, which make `csq swap N` show the
//!    wrong slot. `--apply` rewrites each drifted cache to its canonical slot.
//!    (A `by_slot` orphan-prune was prototyped here and REMOVED — see the
//!    `AttributionIssue` doc-comment.)
//!
//! ### What contamination looks like
//!
//! When the fanout/rotation logic writes the same OAuth refresh
//! response to multiple slots, their `credentials/N.json` and
//! `config-N/.credentials.json` files end up sharing refresh
//! tokens. Each successful refresh rotates the token; only one
//! slot consumes the new value and the others now point at a
//! dead token that Anthropic rejects with `invalid_grant`.
//!
//! Symptoms: user sees "Expired — invalid token — re-login
//! needed" on multiple slots even though the daemon is running
//! and network is healthy. Logs show `broker_token_invalid`.
//!
//! ### Detection strategy (Phase 2, M2-7)
//!
//! For every pair of slots, compare refresh token prefixes across
//! three credential files per slot (where available):
//! - `identities/<UUID>/credentials.json` (UUID-canonical, A++ path)
//! - `credentials/{N}.json` (legacy canonical)
//! - `config-{N}/.credentials.json` (live mirror)
//!
//! Any two slots with matching prefixes in any of these files
//! are contaminated. A slot whose canonical and live files point
//! at different tokens is also flagged (likely a fanout miss).
//! A slot where the UUID-canonical token disagrees with the
//! legacy canonical is also flagged (A++ drift).
//!
//! ### Repair strategy
//!
//! By default, dry-run: just report the affected slots. With
//! `--apply`, deletes the contaminated `credentials/N.json` so
//! the next use triggers a fresh login via the Add Account flow.
//! Never deletes the live `config-N/.credentials.json` — those
//! are what CC itself is holding and blowing them away would
//! break active sessions.

use anyhow::{Context, Result};
use csq_core::accounts::identity_store::credentials_path_for;
use csq_core::accounts::markers;
use csq_core::accounts::profiles;
use csq_core::types::AccountNum;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A slot-attribution inconsistency surfaced by the `csq repair` pass 2.
///
/// Currently only stale `.current-account` caches. A prior `OrphanBySlot`
/// variant + `by_slot` prune was REMOVED (2026-06-01): it was built on the
/// false premise that a slot present in both `by_slot` and `by_slot_identity`
/// is an orphan. That is the NORMAL representation of a codex slot — codex
/// login mints `by_slot[N]=<codex-UUID>` AND `by_slot_identity[N]=<label>` —
/// and `by_slot[N]` is load-bearing for the codex slot's discoverability, so
/// pruning it makes the slot vanish from `csq status`. (Caught by the binary
/// smoke after 5 redteam passes accepted the bad premise; see memory
/// `discovery_by_slot_holds_codex_identities`.)
#[derive(Debug, Clone, PartialEq, Eq)]
enum AttributionIssue {
    /// `config-N/.current-account` holds `cached` ≠ N (stale fast-path cache).
    CurrentAccountDrift { slot: u16, cached: u16 },
}

impl AttributionIssue {
    fn describe(&self) -> String {
        match self {
            AttributionIssue::CurrentAccountDrift { slot, cached } => format!(
                "slot {slot:>3}  .current-account cache = {cached} (stale; should be {slot})"
            ),
        }
    }
}

/// Scans for slot-attribution issues. Enumerates EVERY issue so `--apply`
/// repairs them all in one pass, via the SAME shared drift predicate as
/// `csq doctor`'s `audit_coexistence` (reconciler-cleanup-parity Rule 4 — one
/// keep-set across consumers); doctor takes the first, repair repairs all.
fn scan_attribution(base_dir: &Path) -> Vec<AttributionIssue> {
    profiles::current_account_drifts(base_dir)
        .into_iter()
        .map(|(slot, cached)| AttributionIssue::CurrentAccountDrift { slot, cached })
        .collect()
}

/// Applies slot-attribution repairs. Returns the count actually repaired.
fn apply_attribution(base_dir: &Path, issues: &[AttributionIssue]) -> usize {
    let mut acted = 0usize;
    for issue in issues {
        match issue {
            AttributionIssue::CurrentAccountDrift { slot, .. } => {
                let cfg = base_dir.join(format!("config-{slot}"));
                let acct = match AccountNum::try_from(*slot) {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("  skipped config-{slot}/.current-account — invalid slot: {e}");
                        continue;
                    }
                };
                match markers::write_current_account(&cfg, acct) {
                    Ok(()) => {
                        println!("  repaired config-{slot}/.current-account → {slot}");
                        acted += 1;
                    }
                    Err(e) => eprintln!("  failed to repair config-{slot}/.current-account: {e}"),
                }
            }
        }
    }
    acted
}

/// A slot whose credentials need attention.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    slot: u16,
    canonical_prefix: Option<String>,
    live_prefix: Option<String>,
    kind: FindingKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FindingKind {
    /// Canonical and live disagree on refresh token — fanout miss.
    CanonicalLiveMismatch,
    /// Canonical token is shared with another slot.
    CanonicalSharedWith { other_slot: u16 },
    /// Live token is shared with another slot.
    LiveSharedWith { other_slot: u16 },
    /// UUID-canonical (`identities/<UUID>/credentials.json`) token
    /// disagrees with the legacy canonical (`credentials/N.json`).
    /// Phase 2 (M2-7) extension — see internal-design-docs
    /// 02-plans/03-phase2-readiness.md § M2-7.
    UuidLegacyDrift { uuid_prefix: String },
}

/// Public entry point. `apply = false` is a dry run. `heal_contaminated` opts
/// into the network store-token ownership pass (an internal ticket / #61).
pub fn handle(base_dir: &Path, apply: bool, heal_contaminated: bool) -> Result<()> {
    // ── Pass 1: cross-slot credential contamination (offline, prefix compare) ──
    let findings = scan(base_dir).context("scan failed")?;
    // ── Pass 2: slot-attribution drift + orphaned mappings (offline) ──
    let attribution = scan_attribution(base_dir);

    let offline_clean = findings.is_empty() && attribution.is_empty();
    if offline_clean {
        println!("✓ No credential or slot-attribution issues detected.");
    } else {
        print_contamination(&findings);
        print_attribution(&attribution);
    }

    // ── Pass 3 (opt-in, NETWORK): store-token cross-account contamination ──
    // Reuses the daemon's Cloudflare-safe Node transport + the custodian's
    // `/api/oauth/profile` ownership detector (an internal ticket follow-up). Off by
    // default so the offline passes stay fast and rate-limit-free. The same
    // `http_get` is reused at apply time to re-verify each slot immediately
    // before the irreversible delete (check-then-act — closes the scan→delete
    // TOCTOU window).
    let http_get: Option<csq_core::daemon::usage_poller::HttpGetFn> = if heal_contaminated {
        Some(std::sync::Arc::new(
            |url: &str, token: &str, headers: &[(&str, &str)]| {
                csq_core::http::get_bearer_node(url, token, headers)
            },
        ))
    } else {
        None
    };
    let contaminated = if let Some(http_get) = &http_get {
        let c = scan_contaminated(base_dir, http_get);
        print_contaminated(&c);
        c
    } else {
        Vec::new()
    };

    if offline_clean && contaminated.is_empty() {
        return Ok(());
    }

    if !apply {
        println!();
        println!("Dry run — no files modified. Re-run with `--apply` to repair");
        print!("(delete contaminated canonical credentials, rewrite stale .current-account caches");
        if heal_contaminated {
            print!(", clear foreign store tokens");
        }
        println!(").");
        return Ok(());
    }

    // ── Apply ──
    let mut total = 0usize;
    total += apply_contamination(base_dir, &findings);
    total += apply_attribution(base_dir, &attribution);
    if let Some(http_get) = &http_get {
        total += apply_contaminated_heal(base_dir, &contaminated, http_get);
    }
    println!();
    println!("Applied {total} repair(s).");
    if !findings.is_empty() || !contaminated.is_empty() {
        println!("Run the Add Account flow (or `csq login N`) to re-authenticate");
        println!("any slot whose contaminated credentials were removed.");
    }
    Ok(())
}

/// A slot whose Anthropic **store** token was server-confirmed to belong to a
/// DIFFERENT account than its `identity.json` anchor (an internal ticket cross-slot
/// scramble class). Heal = clear the store credential, then `csq login <slot>`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ContaminatedSlot {
    slot: u16,
    /// The slot's display label (email) — never a filesystem path.
    label: String,
}

/// Network scan (pass 3): per Anthropic slot, run the custodian's
/// `/api/oauth/profile` ownership check and keep only the slots whose store
/// token is server-CONFIRMED foreign. `Owned` and `Unknown` (revoked / no
/// runtime / transport / rate-limited) are NEVER healed — fail-closed on doubt.
/// `http_get` is injected so the scan is unit-testable without the network.
fn scan_contaminated(
    base_dir: &Path,
    http_get: &csq_core::daemon::usage_poller::HttpGetFn,
) -> Vec<ContaminatedSlot> {
    use csq_core::daemon::custodian::{check_slot_store_token_ownership, SlotOwnership};
    let mut out = Vec::new();
    for a in csq_core::accounts::discovery::discover_anthropic(base_dir) {
        let slot = match AccountNum::try_from(a.id) {
            Ok(s) => s,
            Err(e) => {
                // Symmetric with apply_contaminated_heal's skip logging; unreachable
                // in practice (discover_anthropic constrains ids to 1..=999).
                eprintln!("  skipped slot {} — invalid slot: {e}", a.id);
                continue;
            }
        };
        if check_slot_store_token_ownership(base_dir, slot, http_get) == SlotOwnership::Contaminated
        {
            out.push(ContaminatedSlot {
                slot: a.id,
                label: a.label.clone(),
            });
        }
    }
    out
}

/// Prints the pass-3 store-token contamination findings.
fn print_contaminated(slots: &[ContaminatedSlot]) {
    if slots.is_empty() {
        println!("✓ No contaminated store tokens detected.");
        return;
    }
    println!("Detected {} contaminated store token(s):", slots.len());
    for c in slots {
        println!(
            "  slot {:>3}  ({}) store token belongs to a DIFFERENT account \
             — heal clears it, then `csq login {}`",
            c.slot, c.label, c.slot
        );
    }
}

/// Applies pass-3 heal: for each contaminated slot, RE-VERIFIES ownership against
/// `/api/oauth/profile` immediately before deleting (check-then-act, closing the
/// scan→delete TOCTOU window — a token the daemon adopted after the scan is
/// re-checked, and only a still-`Contaminated` verdict proceeds; `Owned`/`Unknown`
/// skip, fail-closed on doubt). On confirm, clears the slot so the next
/// `csq login N` re-authenticates a clean token.
///
/// Deletes TWO files for the slot, both resolved for THIS slot only:
///  1. the store the daemon polls — [`slot_store_credential_path`] (UUID-keyed
///     `identities/<UUID>/credentials.json`, or legacy `credentials/N.json`), the
///     exact path the detector read; and
///  2. the legacy `credentials/N.json` ClaudeCode canonical — the source
///     [`phase4_gate_self_heal`] copies back into the identity store on the next
///     daemon start. Leaving it would RESURRECT the (possibly still-contaminated)
///     token and re-trip the gate; deleting it also makes phase4 Check 3 skip the
///     slot (no legacy anthropic canonical → not ClaudeCode-bound-on-disk → no
///     daemon-start refusal). When (1) already IS the legacy path (no UUID), the
///     second remove is a benign idempotent no-op.
///
/// Never touches another slot's identity dir, never the slot's `identity.json` or
/// `settings.json` (anchor/label/settings survive so re-login re-mints against the
/// correct account and phase4 Check 4 stays satisfied), and never the keychain
/// (that is login's job — it re-syncs on the next `csq login`). Also clears the
/// slot's `broker_failed` sentinel (`sentinel-clearing-parity.md` Rule 1 names
/// `csq repair --apply` as a resolution boundary) so a stale flag from the
/// contaminated token does not outlive the heal in `csq doctor`.
///
/// **Why the third store-ingest path — `refresh::sync::backsync` — cannot
/// resurrect the token.** `backsync` is live on every `csq statusline` render and
/// promotes a live `.credentials.json` into the store when it is fresher, so with
/// the store now empty a future-dated live file WOULD be promoted. But the live
/// file `statusline` hands `backsync` is the TERMINAL's handle-dir
/// `.credentials.json` (`current_config_dir()`), which in the M3-7 handle-dir
/// model is a SYMLINK into the store we just deleted — so `credentials::load`
/// fails and `backsync` returns `Ok(false)`, promoting nothing. The store stays
/// empty until `csq login` (no auto-self-heal; the honest "needs login" state). A
/// foreign token cannot reach the store through this path either: CC is
/// keychain-first, so an in-session `/login` to another account writes the foreign
/// token to the per-config-dir KEYCHAIN (the vector the custodian's ingest gate
/// guards — `csq-core/src/daemon/custodian.rs` §"the wrong-account guard"), NOT to
/// the handle-dir file, which stays a symlink. `config-N/.credentials.json` is left
/// in place (as pass-1 does — CC may hold it, and it is not the handle-dir symlink
/// target that `backsync` reads); it cannot re-seed a foreign token because the
/// `config-N` file is same-account-path-keyed per that same threat model.
///
/// **Scope note (deliberate):** the heal is CLI-operator-initiated only. The
/// daemon/desktop do NOT auto-heal — auto-deleting credentials on a background
/// tick is a higher-blast-radius action that MUST require explicit operator
/// intent. The desktop still SURFACES contamination read-only via the same
/// detector (`csq doctor --check-token-owners`).
///
/// [`phase4_gate_self_heal`]: csq_core::daemon::startup_reconciler
/// [`slot_store_credential_path`]: csq_core::daemon::custodian::slot_store_credential_path
///
/// Returns the count of slots whose store was actually cleared.
fn apply_contaminated_heal(
    base_dir: &Path,
    slots: &[ContaminatedSlot],
    http_get: &csq_core::daemon::usage_poller::HttpGetFn,
) -> usize {
    use csq_core::daemon::custodian::{
        check_slot_store_token_ownership, slot_store_credential_path, SlotOwnership,
    };
    let mut cleared = 0usize;
    for c in slots {
        let acct = match AccountNum::try_from(c.slot) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("  skipped slot {} — invalid slot: {e}", c.slot);
                continue;
            }
        };
        // Re-verify under a fresh read right before the irreversible delete.
        if check_slot_store_token_ownership(base_dir, acct, http_get) != SlotOwnership::Contaminated
        {
            println!(
                "  slot {} no longer confirmed contaminated — skipped (self-healed or \
                 unverifiable)",
                c.slot
            );
            continue;
        }
        // (1) the store the daemon polls; (2) the legacy self-heal source.
        // In practice a Contaminated slot is ALWAYS UUID-mapped —
        // `check_slot_store_token_ownership` fail-closes to `Unknown` (never
        // `Contaminated`) without an `identity.json` anchor, which only a
        // UUID-mapped slot has — so `store_path` is the UUID-keyed file and
        // `legacy_path` is the distinct `credentials/N.json`. The dedup guard
        // below is defensive for the no-UUID case that the re-check above cannot
        // actually reach.
        let store_path = slot_store_credential_path(base_dir, acct);
        let legacy_path = csq_core::credentials::file::canonical_path(base_dir, acct);
        let mut removed_any = false;
        let mut had_io_error = false;
        for path in [&store_path, &legacy_path] {
            match std::fs::remove_file(path) {
                Ok(()) => removed_any = true,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    had_io_error = true;
                    eprintln!("  failed to clear a store file for slot {}: {e}", c.slot);
                }
            }
            if store_path == legacy_path {
                break; // no-UUID slot: the two paths are identical, remove once.
            }
        }
        let outcome = heal_outcome(removed_any, had_io_error);
        // Both `Cleared` and `AlreadyAbsent` confirm the contaminated token is gone
        // (removed now, or already absent) → retire any stale broker_failed flag
        // (`sentinel-clearing-parity.md` Rule 1 resolution boundary). `NotHealed`
        // (a file survived an IO error) is NOT a resolution — leave the flag.
        // Single callsite keeps the Rule-1 audit's one-caller/one-callsite invariant.
        if outcome != HealOutcome::NotHealed {
            csq_core::refresh::sentinel::clear_broker_failed(base_dir, acct);
        }
        match outcome {
            HealOutcome::NotHealed => {
                // At least one target could not be removed (permission/IO error,
                // already logged above). BLOCKING even when the UUID store WAS
                // removed: a surviving legacy `credentials/N.json` is exactly the
                // phase4_gate_self_heal source that resurrects the contaminated
                // token on the next daemon start. Do NOT report "cleared" or count.
                eprintln!(
                    "  slot {} NOT healed — a store file could not be removed (see \
                     errors above); a surviving credentials/{}.json would resurrect \
                     the token",
                    c.slot, c.slot
                );
            }
            HealOutcome::Cleared => {
                println!(
                    "  cleared contaminated store token for slot {} ({})",
                    c.slot, c.label
                );
                cleared += 1;
            }
            HealOutcome::AlreadyAbsent => {
                println!(
                    "  slot {} store token already absent — nothing to clear",
                    c.slot
                );
            }
        }
    }
    cleared
}

/// The three terminal outcomes of a per-slot heal delete, decided from whether any
/// file was actually removed and whether any non-`NotFound` I/O error occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HealOutcome {
    /// Every target removed cleanly (or was already gone AND at least one delete
    /// succeeded) — the slot is healed; clear the sentinel and count it.
    Cleared,
    /// A file could not be removed (permission/IO error). BLOCKING regardless of a
    /// partial success: a surviving `credentials/N.json` resurrects the token via
    /// phase4_gate_self_heal, so the slot is NOT healed — no count, no sentinel clear.
    NotHealed,
    /// Nothing was removed and no error occurred — every target was already absent.
    AlreadyAbsent,
}

/// Pure decision for [`apply_contaminated_heal`]'s per-slot outcome. `had_io_error`
/// takes precedence over `removed_any` so a partial delete (store gone, legacy
/// self-heal source un-removable) is reported as NOT healed rather than a false
/// success — the exact resurrection window a naive `if removed_any` first-check
/// would mask (redteam R4).
fn heal_outcome(removed_any: bool, had_io_error: bool) -> HealOutcome {
    if had_io_error {
        HealOutcome::NotHealed
    } else if removed_any {
        HealOutcome::Cleared
    } else {
        HealOutcome::AlreadyAbsent
    }
}

/// Prints the credential-contamination findings (pass 1).
fn print_contamination(findings: &[Finding]) {
    if findings.is_empty() {
        println!("✓ No credential contamination detected.");
        return;
    }
    println!("Detected {} credential issue(s):", findings.len());
    for f in findings {
        let kind_desc = match &f.kind {
            FindingKind::CanonicalLiveMismatch => "canonical ≠ live (fanout miss)".to_string(),
            FindingKind::CanonicalSharedWith { other_slot } => {
                format!("canonical shared with slot {other_slot}")
            }
            FindingKind::LiveSharedWith { other_slot } => {
                format!("live shared with slot {other_slot}")
            }
            FindingKind::UuidLegacyDrift { uuid_prefix } => {
                format!("uuid-canonical ≠ legacy (A++ drift; uuid={uuid_prefix}...)")
            }
        };
        println!(
            "  slot {:>3}  {:<35}  canonical={:<12}  live={:<12}",
            f.slot,
            kind_desc,
            f.canonical_prefix.as_deref().unwrap_or("(none)"),
            f.live_prefix.as_deref().unwrap_or("(none)"),
        );
    }
}

/// Applies pass-1 repairs: delete contaminated canonical `credentials/N.json`.
/// Never touches the live `config-N/.credentials.json` (CC may be holding it).
/// Returns the count removed.
fn apply_contamination(base_dir: &Path, findings: &[Finding]) -> usize {
    let mut removed = 0usize;
    for f in findings {
        let path = base_dir
            .join("credentials")
            .join(format!("{}.json", f.slot));
        match std::fs::remove_file(&path) {
            Ok(()) => {
                println!("  removed {}", path.display());
                removed += 1;
            }
            Err(e) => {
                eprintln!("  failed to remove {}: {e}", path.display());
            }
        }
    }
    removed
}

/// Prints the slot-attribution issues (pass 2).
fn print_attribution(issues: &[AttributionIssue]) {
    if issues.is_empty() {
        println!("✓ No slot-attribution issues detected.");
        return;
    }
    println!("Detected {} slot-attribution issue(s):", issues.len());
    for issue in issues {
        println!("  {}", issue.describe());
    }
}

/// Per-slot credential prefix triple. Using a named struct eliminates
/// positional tuple destructuring across four passes and the `#[allow]`
/// needed to suppress clippy::type_complexity on the raw tuple form.
///
/// All three fields are prefixes only — the first 24 chars of the
/// `claudeAiOauth.refreshToken` — so we never hold full tokens in memory.
struct CredentialPrefixes {
    /// From `credentials/{N}.json` (legacy canonical write).
    canonical_legacy: Option<String>,
    /// From `config-{N}/.credentials.json` (live mirror read by CC).
    live_legacy: Option<String>,
    /// From `identities/<UUID>/credentials.json` (UUID-canonical, Phase 2+).
    uuid_canonical: Option<String>,
}

/// Scans `base_dir` for contamination findings. Separated from
/// `handle` for unit testability.
fn scan(base_dir: &Path) -> Result<Vec<Finding>> {
    // Load each slot's UUID-canonical + legacy canonical + live
    // refresh token prefix.  Prefix-only so we never hold full
    // tokens in memory.
    let mut per_slot: HashMap<u16, CredentialPrefixes> = HashMap::new();
    for slot in 1u16..=999 {
        let canonical = base_dir.join("credentials").join(format!("{slot}.json"));
        // READER: reads `config-{slot}/.credentials.json` live mirror content.
        // The config-N/ path here is a PATH-BUILDER pointing at the live file;
        // we intentionally compare the live mirror, not the UUID-canonical, so
        // this site stays unchanged through Phase 2.
        // See internal-design-docs § M2-7.
        let live = base_dir
            .join(format!("config-{slot}"))
            .join(".credentials.json");
        let canonical_legacy = read_rt_prefix(&canonical);
        let live_legacy = read_rt_prefix(&live);

        // Phase 2 (M2-7): also check UUID-canonical credential file when the
        // slot has a UUID mapping in profiles.json.
        let uuid_canonical = profiles::resolve_slot_to_uuid(base_dir, slot)
            .map(|uuid_id| credentials_path_for(base_dir, uuid_id))
            .and_then(|uuid_cred_path| read_rt_prefix(&uuid_cred_path));

        if canonical_legacy.is_none() && live_legacy.is_none() && uuid_canonical.is_none() {
            continue;
        }
        per_slot.insert(
            slot,
            CredentialPrefixes {
                canonical_legacy,
                live_legacy,
                uuid_canonical,
            },
        );
    }

    let mut findings = Vec::new();

    // Pass 0 (M2-7): UUID-canonical ≠ legacy canonical → A++ drift.
    // Fires only when both files exist AND their prefixes disagree.
    for (&slot, prefixes) in &per_slot {
        if let (Some(c), Some(u)) = (&prefixes.canonical_legacy, &prefixes.uuid_canonical) {
            if c != u {
                findings.push(Finding {
                    slot,
                    canonical_prefix: Some(c.clone()),
                    live_prefix: prefixes.live_legacy.clone(),
                    kind: FindingKind::UuidLegacyDrift {
                        uuid_prefix: u.clone(),
                    },
                });
            }
        }
    }

    // Pass 0b RETIRED (an internal workspace, 2026-06-01): the
    // `uuid_canonical ≠ live_legacy` check flagged every healthy post-M3-7
    // Anthropic OAuth slot as "A++ drift". `config-N/.credentials.json`
    // (`live_legacy`) is a TRANSIENT login landing-spot, not a maintained
    // mirror: M3-7 retired the daemon's live-mirror PUSH (`refresh/sync.rs`),
    // so after the first daemon refresh the canonical UUID token diverges from
    // the now-frozen `config-N` token BY DESIGN. CC sessions read the canonical
    // token through their handle-dir symlink (`term-<pid>/.credentials.json →
    // identities/<UUID>/credentials.json`), never `config-N`. The daemon's
    // `backsync` DOES read `config-N` but only promotes it when it is NEWER
    // (monotonicity guard, sync.rs:104) — a stale older `config-N` is ignored,
    // and a newer one self-heals on the next tick. So the divergence is never
    // actionable, and Pass 0b's only remediation (`apply_contamination`) deletes
    // `credentials/N.json` — a DIFFERENT file that is absent post-M4-12 — so it
    // could not even fix what it flagged. Pass 0 (legacy `credentials/N.json` vs
    // UUID) still catches real drift on un-migrated hosts; the cross-slot
    // contamination passes (2/3) are unchanged. Origin: 2026-06-01 host slots
    // 1-8 each flagged + user report.

    // Pass 1: canonical ≠ live for any slot → fanout miss.
    for (&slot, prefixes) in &per_slot {
        if let (Some(c), Some(l)) = (&prefixes.canonical_legacy, &prefixes.live_legacy) {
            if c != l {
                findings.push(Finding {
                    slot,
                    canonical_prefix: Some(c.clone()),
                    live_prefix: Some(l.clone()),
                    kind: FindingKind::CanonicalLiveMismatch,
                });
            }
        }
    }

    // Pass 2: canonical tokens shared across slots.
    let mut canon_by_token: HashMap<String, Vec<u16>> = HashMap::new();
    for (&slot, prefixes) in &per_slot {
        if let Some(c) = &prefixes.canonical_legacy {
            canon_by_token.entry(c.clone()).or_default().push(slot);
        }
    }
    for (_, slots) in canon_by_token.iter() {
        if slots.len() < 2 {
            continue;
        }
        let mut sorted = slots.clone();
        sorted.sort();
        for (i, &slot) in sorted.iter().enumerate() {
            let other = sorted[if i == 0 { 1 } else { 0 }];
            findings.push(Finding {
                slot,
                canonical_prefix: per_slot[&slot].canonical_legacy.clone(),
                live_prefix: per_slot[&slot].live_legacy.clone(),
                kind: FindingKind::CanonicalSharedWith { other_slot: other },
            });
        }
    }

    // Pass 3: live tokens shared across slots.
    let mut live_by_token: HashMap<String, Vec<u16>> = HashMap::new();
    for (&slot, prefixes) in &per_slot {
        if let Some(l) = &prefixes.live_legacy {
            live_by_token.entry(l.clone()).or_default().push(slot);
        }
    }
    for (_, slots) in live_by_token.iter() {
        if slots.len() < 2 {
            continue;
        }
        let mut sorted = slots.clone();
        sorted.sort();
        for (i, &slot) in sorted.iter().enumerate() {
            let other = sorted[if i == 0 { 1 } else { 0 }];
            findings.push(Finding {
                slot,
                canonical_prefix: per_slot[&slot].canonical_legacy.clone(),
                live_prefix: per_slot[&slot].live_legacy.clone(),
                kind: FindingKind::LiveSharedWith { other_slot: other },
            });
        }
    }

    // Stable ordering for deterministic output.
    findings.sort_by_key(|f| (f.slot, format!("{:?}", f.kind)));
    findings.dedup();
    Ok(findings)
}

/// Reads the first 24 characters of the `claudeAiOauth.refreshToken`
/// field in a credential file. Used as a stable, safe identity for
/// cross-slot comparison — short enough to not hold a full token
/// in memory, long enough to detect any realistic collision.
///
/// Returns `None` if the file doesn't exist, is unreadable, or
/// doesn't have the expected shape.
fn read_rt_prefix(path: &PathBuf) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    let rt = json.get("claudeAiOauth")?.get("refreshToken")?.as_str()?;
    Some(rt.chars().take(24).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use csq_core::accounts::identity_store::credentials_path_for;
    #[cfg(any(test, feature = "test-utils"))]
    use csq_core::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
    use tempfile::TempDir;

    /// Writes a legacy credential file (canonical or live) with the given refresh token.
    /// Uses the `claudeAiOauth` wrapper that `read_rt_prefix` expects.
    fn write_creds(base: &Path, slot: u16, refresh_token: &str, live: bool) {
        let path = if live {
            let dir = base.join(format!("config-{slot}"));
            std::fs::create_dir_all(&dir).unwrap();
            dir.join(".credentials.json")
        } else {
            let dir = base.join("credentials");
            std::fs::create_dir_all(&dir).unwrap();
            dir.join(format!("{slot}.json"))
        };
        let json = format!(
            r#"{{"claudeAiOauth":{{"accessToken":"sk-ant-oat01-x","refreshToken":"{refresh_token}","expiresAt":1000}}}}"#
        );
        std::fs::write(path, json).unwrap();
    }

    /// Writes a UUID-canonical credential file at
    /// `identities/<fixture_uuid_for_slot(slot)>/credentials.json`.
    /// Uses the deterministic fixture UUID for the slot so tests that
    /// also populate `profiles.json` map to the same UUID.
    #[cfg(any(test, feature = "test-utils"))]
    fn write_uuid_creds(base: &Path, slot: u16, refresh_token: &str) {
        let uuid = fixture_uuid_for_slot(slot);
        let path = credentials_path_for(base, uuid);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let json = format!(
            r#"{{"claudeAiOauth":{{"accessToken":"sk-ant-oat01-x","refreshToken":"{refresh_token}","expiresAt":1000}}}}"#
        );
        std::fs::write(&path, json).unwrap();
    }

    #[test]
    fn scan_clean_state_returns_no_findings() {
        let dir = TempDir::new().unwrap();
        write_creds(dir.path(), 1, "sk-ant-ort01-aaaaaaaaaaaa", false);
        write_creds(dir.path(), 1, "sk-ant-ort01-aaaaaaaaaaaa", true);
        write_creds(dir.path(), 2, "sk-ant-ort01-bbbbbbbbbbbb", false);
        write_creds(dir.path(), 2, "sk-ant-ort01-bbbbbbbbbbbb", true);

        let findings = scan(dir.path()).unwrap();
        assert!(findings.is_empty(), "clean state should have no findings");
    }

    #[test]
    fn scan_detects_canonical_live_mismatch() {
        let dir = TempDir::new().unwrap();
        write_creds(dir.path(), 5, "sk-ant-ort01-canonical-one", false);
        write_creds(dir.path(), 5, "sk-ant-ort01-live-one", true);

        let findings = scan(dir.path()).unwrap();
        assert!(findings
            .iter()
            .any(|f| f.slot == 5 && f.kind == FindingKind::CanonicalLiveMismatch));
    }

    #[test]
    fn scan_detects_canonical_shared_across_slots() {
        let dir = TempDir::new().unwrap();
        // Slots 3 and 8 both have the same canonical refresh token.
        write_creds(dir.path(), 3, "sk-ant-ort01-SNK8-mdPlJU-shared", false);
        write_creds(dir.path(), 8, "sk-ant-ort01-SNK8-mdPlJU-shared", false);

        let findings = scan(dir.path()).unwrap();
        assert!(findings
            .iter()
            .any(|f| f.slot == 3
                && matches!(f.kind, FindingKind::CanonicalSharedWith { other_slot: 8 })));
        assert!(findings
            .iter()
            .any(|f| f.slot == 8
                && matches!(f.kind, FindingKind::CanonicalSharedWith { other_slot: 3 })));
    }

    #[test]
    fn scan_detects_live_shared_across_slots() {
        let dir = TempDir::new().unwrap();
        write_creds(dir.path(), 2, "sk-ant-ort01-different-canon", false);
        write_creds(dir.path(), 3, "sk-ant-ort01-different-canon2", false);
        // Both live files point at the same token (CC rotated
        // and wrote to multiple live paths somehow).
        write_creds(dir.path(), 2, "sk-ant-ort01-shared-live-token", true);
        write_creds(dir.path(), 3, "sk-ant-ort01-shared-live-token", true);

        let findings = scan(dir.path()).unwrap();
        assert!(findings.iter().any(
            |f| f.slot == 2 && matches!(f.kind, FindingKind::LiveSharedWith { other_slot: 3 })
        ));
    }

    #[test]
    fn scan_skips_slots_with_no_credentials() {
        let dir = TempDir::new().unwrap();
        // No files for any slot.
        let findings = scan(dir.path()).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn read_rt_prefix_caps_at_24_chars() {
        let dir = TempDir::new().unwrap();
        write_creds(
            dir.path(),
            9,
            "sk-ant-ort01-this-is-a-very-long-token-that-should-be-capped",
            false,
        );
        let prefix = read_rt_prefix(&dir.path().join("credentials/9.json")).unwrap();
        assert_eq!(prefix.len(), 24);
    }

    #[test]
    fn read_rt_prefix_returns_none_on_missing() {
        let dir = TempDir::new().unwrap();
        let result = read_rt_prefix(&dir.path().join("nonexistent"));
        assert!(result.is_none());
    }

    #[test]
    fn read_rt_prefix_returns_none_on_malformed_json() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json at all").unwrap();
        assert!(read_rt_prefix(&path).is_none());
    }

    /// M2-7 acceptance criterion: the scanner compares UUID-canonical,
    /// legacy canonical, and live legacy credentials for each slot.
    /// When the UUID-canonical token disagrees with the legacy canonical
    /// a `UuidLegacyDrift` finding is surfaced.
    ///
    /// Arrangement (under coexisting_fixture for the slot→UUID mapping):
    /// - slot 2: legacy canonical + live = same token (no legacy contamination)
    /// - slot 2: UUID-canonical has a DIFFERENT token (A++ drift)
    /// - slot 3: all three files consistent (clean — should not appear)
    ///
    /// Verifies that the Phase 2 comparison surface "UUID + legacy canon +
    /// live" catches mismatches in any pair.
    ///
    /// See internal-design-docs § M2-7.
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn repair_credentials_detects_drift_across_uuid_and_legacy() {
        use csq_core::testing::identity_fixtures::coexisting_fixture;

        // Arrange: use coexisting_fixture(3) to set up slots 1–3 with consistent
        // profiles.json (slot→UUID) and config-N/ dirs. The fixture writes stub
        // credentials that read_rt_prefix won't match (wrong JSON shape), so we
        // augment by overwriting the credential files with claudeAiOauth-shaped
        // content that the scanner can parse.
        let dir = coexisting_fixture(3);
        let base = dir.path();

        // Slot 2: legacy canonical + live are consistent; UUID diverges → drift.
        write_creds(base, 2, "sk-ant-ort01-legacy-slot2-token", false); // canonical
        write_creds(base, 2, "sk-ant-ort01-legacy-slot2-token", true); // live
        write_uuid_creds(base, 2, "sk-ant-ort01-uuid-slot2-different"); // UUID — different!

        // Slot 3: all three consistent → no finding.
        write_creds(base, 3, "sk-ant-ort01-slot3-same-token", false);
        write_creds(base, 3, "sk-ant-ort01-slot3-same-token", true);
        write_uuid_creds(base, 3, "sk-ant-ort01-slot3-same-token");
        // (profiles.json for slots 1–3 is already written by coexisting_fixture)

        // Act
        let findings = scan(base).unwrap();

        // Assert: slot 2 produces a UuidLegacyDrift finding
        let drift_finding = findings
            .iter()
            .find(|f| f.slot == 2 && matches!(f.kind, FindingKind::UuidLegacyDrift { .. }));
        assert!(
            drift_finding.is_some(),
            "expected UuidLegacyDrift finding for slot 2, got: {findings:?}"
        );

        // Assert: the uuid_prefix in the finding matches the UUID file token prefix
        if let Some(Finding {
            kind: FindingKind::UuidLegacyDrift { uuid_prefix },
            ..
        }) = drift_finding
        {
            assert!(
                "sk-ant-ort01-uuid-slot2-different".starts_with(uuid_prefix.as_str()),
                "uuid_prefix should be leading 24 chars of the UUID token, got: {uuid_prefix}"
            );
        }

        // Assert: slot 3 (consistent) produces no finding
        assert!(
            !findings.iter().any(|f| f.slot == 3),
            "slot 3 is consistent — must not appear in findings"
        );
    }

    /// Regression (an internal workspace, 2026-06-01): a HEALTHY
    /// post-M4-12 Anthropic OAuth slot must produce NO finding. Shape:
    /// `credentials/N.json` pruned (canonical_legacy = None), a STALE
    /// `config-N/.credentials.json` left from before the first daemon refresh
    /// (live_legacy = old token), and the live daemon-refreshed UUID canonical
    /// (uuid_canonical = different, current token). Before Pass 0b was retired,
    /// this fired a spurious "A++ drift" finding for every such slot (the user
    /// saw 6). The divergence is the designed steady state post-M3-7 — `config-N`
    /// is a transient login landing-spot, not a maintained mirror — so the scan
    /// must classify it as consistent.
    #[test]
    fn healthy_post_m4_12_oauth_slot_with_stale_config_mirror_is_not_flagged() {
        use csq_core::testing::identity_fixtures::coexisting_fixture;

        let dir = coexisting_fixture(3);
        let base = dir.path();

        // Slot 1: NO credentials/1.json (pruned post-M4-12 → canonical_legacy None,
        // since the fixture's stub is unparseable by read_rt_prefix). A stale
        // config-1/.credentials.json + a different (current) UUID-canonical token.
        write_creds(base, 1, "sk-ant-ort01-stale-config-mirror-tok", true); // live (stale)
        write_uuid_creds(base, 1, "sk-ant-ort01-current-daemon-refreshed"); // UUID (current, differs)

        let findings = scan(base).unwrap();

        assert!(
            !findings.iter().any(|f| f.slot == 1),
            "healthy post-M4-12 slot 1 (no legacy canonical, stale config-N mirror, \
             current UUID token) must NOT be flagged — the uuid≠config-N divergence \
             is the designed post-M3-7 steady state; got: {findings:?}"
        );
    }

    // ── an internal workspace M5b: pass-2 (attribution) tests ──

    #[test]
    fn scan_attribution_detects_current_account_drift() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let cfg2 = base.join("config-2");
        std::fs::create_dir_all(&cfg2).unwrap();
        std::fs::write(cfg2.join(".current-account"), "8").unwrap(); // stale
        let cfg3 = base.join("config-3");
        std::fs::create_dir_all(&cfg3).unwrap();
        std::fs::write(cfg3.join(".current-account"), "3").unwrap(); // consistent

        let issues = scan_attribution(base);
        assert!(
            issues.iter().any(|i| matches!(
                i,
                AttributionIssue::CurrentAccountDrift { slot: 2, cached: 8 }
            )),
            "stale config-2 (cached 8) must be flagged: {issues:?}"
        );
        assert!(
            !issues
                .iter()
                .any(|i| matches!(i, AttributionIssue::CurrentAccountDrift { slot: 3, .. })),
            "consistent config-3 must NOT be flagged"
        );
    }

    // ── Pass 3: store-token contamination heal (#955 / #61) ──

    #[test]
    fn heal_outcome_io_error_blocks_success_even_on_partial_removal() {
        // redteam R4: the resurrection-window regression. A partial delete (store
        // removed, legacy self-heal source un-removable) MUST report NotHealed,
        // NOT a false "Cleared" — else the surviving credentials/N.json resurrects
        // the token on the next daemon start.
        assert_eq!(
            heal_outcome(true, true),
            HealOutcome::NotHealed,
            "removed store but hit an IO error on the other file → NOT healed"
        );
        assert_eq!(
            heal_outcome(false, true),
            HealOutcome::NotHealed,
            "nothing removed + IO error → NOT healed"
        );
        assert_eq!(
            heal_outcome(true, false),
            HealOutcome::Cleared,
            "clean removal → Cleared"
        );
        assert_eq!(
            heal_outcome(false, false),
            HealOutcome::AlreadyAbsent,
            "all targets already absent, no error → AlreadyAbsent"
        );
    }

    /// `/api/oauth/profile` stub returning a fixed account email for every token.
    #[cfg(any(test, feature = "test-utils"))]
    fn profile_http_get(email: &'static str) -> csq_core::daemon::usage_poller::HttpGetFn {
        std::sync::Arc::new(move |_u: &str, _t: &str, _h: &[(&str, &str)]| {
            Ok((
                200u16,
                format!(r#"{{"account":{{"uuid":"u","email":"{email}"}}}}"#).into_bytes(),
            ))
        })
    }

    /// Seed slot `slot` (already in `coexisting_fixture`'s `by_slot`) with a full
    /// Anthropic identity: overwrite `identity.json` anchor to `anchor`, write the
    /// UUID-keyed store credentials, the legacy `credentials/N.json` self-heal
    /// source, and `settings.json` (so phase4 Check 4 is satisfied).
    #[cfg(any(test, feature = "test-utils"))]
    fn seed_full_anthropic_slot(base: &Path, slot: u16, anchor: &str) {
        use csq_core::accounts::identity_store::{identity_json_path_for, settings_path_for};
        let uuid = fixture_uuid_for_slot(slot);
        std::fs::write(
            identity_json_path_for(base, uuid),
            format!(
                r#"{{"email":"{anchor}","provider":"anthropic","created_at":"t","key_id":null}}"#
            ),
        )
        .unwrap();
        write_uuid_creds(base, slot, "sk-ant-ort01-store-token"); // identities/<UUID>/credentials.json
        write_creds(base, slot, "sk-ant-ort01-legacy-token", false); // credentials/N.json (self-heal src)
        std::fs::write(settings_path_for(base, uuid), "{}").unwrap();
        // Bump the store-version sentinel to the current schema so phase4
        // Check 1/2 pass (coexisting_fixture writes an older schema).
        std::fs::write(
            csq_core::accounts::identity_store::store_version_path(base),
            format!(
                r#"{{"schema":{},"minted_at":"t","source":"test"}}"#,
                csq_core::daemon::identity_mint::STORE_VERSION_SCHEMA_CURRENT
            ),
        )
        .unwrap();
    }

    #[test]
    fn apply_contaminated_heal_clears_store_and_legacy_source_and_keeps_gate_open() {
        // Single-slot coexisting fixture (by_slot[1] + store-version). Seed slot 1
        // fully, then heal it under a stub reporting a FOREIGN account email.
        let dir = coexisting_fixture(1);
        let base = dir.path();
        seed_full_anthropic_slot(base, 1, "owner@anchor.test");
        let uuid = fixture_uuid_for_slot(1);
        let store = credentials_path_for(base, uuid);
        let legacy = base.join("credentials").join("1.json");
        assert!(
            store.exists() && legacy.exists(),
            "fixture seeded both files"
        );

        // Foreign email (≠ anchor) → detector + re-check both return Contaminated.
        let g = profile_http_get("stranger@foreign.test");
        let cleared = apply_contaminated_heal(
            base,
            &[ContaminatedSlot {
                slot: 1,
                label: "owner@anchor.test".into(),
            }],
            &g,
        );

        assert_eq!(cleared, 1, "the confirmed-contaminated slot is cleared");
        assert!(!store.exists(), "UUID-keyed store MUST be removed");
        assert!(
            !legacy.exists(),
            "legacy credentials/1.json (phase4 self-heal source) MUST be removed \
             so the next daemon start cannot resurrect the contaminated token"
        );
        // F2 proof: the post-heal on-disk shape must NOT block daemon start.
        let gate = csq_core::daemon::startup_reconciler::phase4_gate_check(base);
        assert!(
            gate.is_ok(),
            "healed slot (no legacy anthropic canonical, settings present) must pass \
             the phase4 gate — daemon starts, slot cleanly awaits `csq login`; got: {gate:?}"
        );
    }

    #[test]
    fn apply_contaminated_heal_skips_slot_that_reverifies_not_contaminated() {
        // Re-check gate (TOCTOU close): a slot whose store the daemon healed between
        // scan and apply now re-verifies Owned → the heal MUST NOT delete it.
        let dir = coexisting_fixture(1);
        let base = dir.path();
        seed_full_anthropic_slot(base, 1, "owner@anchor.test");
        let uuid = fixture_uuid_for_slot(1);
        let store = credentials_path_for(base, uuid);

        // Stub now reports the token as OWNED by the anchor (re-check → Owned).
        let g = profile_http_get("owner@anchor.test");
        let cleared = apply_contaminated_heal(
            base,
            &[ContaminatedSlot {
                slot: 1,
                label: "owner@anchor.test".into(),
            }],
            &g,
        );
        assert_eq!(cleared, 0, "a re-verified-Owned slot is not healed");
        assert!(
            store.exists(),
            "store MUST survive when re-check is not Contaminated"
        );
    }

    #[test]
    fn apply_contaminated_heal_skips_absent_store_via_recheck() {
        // No store credentials for the slot → detector fail-closes to Unknown →
        // re-check skips (never a false delete), never panics.
        let dir = coexisting_fixture(1);
        let base = dir.path();
        // (no seed — identity.json exists from the fixture, but no store creds)
        let g = profile_http_get("stranger@foreign.test");
        let cleared = apply_contaminated_heal(
            dir.path(),
            &[ContaminatedSlot {
                slot: 1,
                label: "z@x.com".into(),
            }],
            &g,
        );
        assert_eq!(cleared, 0, "no store → Unknown → skipped, nothing removed");
        let _ = base;
    }

    #[test]
    fn apply_attribution_rewrites_drifted_current_account() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let cfg2 = base.join("config-2");
        std::fs::create_dir_all(&cfg2).unwrap();
        std::fs::write(cfg2.join(".current-account"), "8").unwrap();

        let issues = scan_attribution(base);
        assert_eq!(apply_attribution(base, &issues), 1);
        assert_eq!(
            markers::read_current_account(&cfg2).map(|a| a.get()),
            Some(2),
            "drifted cache must be rewritten to the canonical slot"
        );
    }
}
