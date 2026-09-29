//! `csq sessions share` — migrate a provider's conversation history into
//! the cross-slot shared store so `resume` survives `csq swap`.
//!
//! The actual merge/migration logic lives in
//! `csq_core::session::shared_state` — this module is the operator-facing
//! report formatter + dispatch over the requested surface(s).

use anyhow::{bail, Result};
use csq_core::providers::catalog::Surface;
use csq_core::session::shared_state::codex_sqlite::{
    CodexSqliteReport, SqliteDbOutcome, SqliteDbRole,
};
use csq_core::session::shared_state::{self, EntryReport, SlotReport};
use csq_core::types::AccountNum;
use std::path::Path;

/// Handles `csq sessions share [--surface <name>] [--dry-run] [--force]`.
///
/// `--force` bypasses the live-writer guard (`shared_state::ensure_no_live_writers`)
/// and MUST name a surface explicitly — bulk-overriding the guard across every
/// surface at once is refused, since the whole point of naming it is that the
/// operator has personally confirmed THAT surface's session is safe to migrate
/// around. `--dry-run` is read-only and is never gated by the guard, so it works
/// the same with or without `--force`.
pub fn handle_share(base: &Path, surface: Option<&str>, dry_run: bool, force: bool) -> Result<()> {
    if force && surface.is_none() {
        bail!(
            "--force requires --surface to be named explicitly (codex, kimi, or grok) — \
             overriding the live-writer guard for every surface at once is refused"
        );
    }

    let surfaces: Vec<Surface> = match surface {
        Some(tag) => {
            let s =
                Surface::from_tag(tag).ok_or_else(|| anyhow::anyhow!("unknown surface: {tag}"))?;
            if shared_state::spec_for(s).is_none() {
                bail!(
                    "csq sessions share does not support surface {tag} \
                     (supported: codex, kimi, grok)"
                );
            }
            vec![s]
        }
        None => shared_state::ALL_SHARED_SPECS
            .iter()
            .map(|spec| spec.surface)
            .collect(),
    };

    if dry_run {
        println!("csq sessions share --dry-run — no changes will be made\n");
    }

    let mut any_slots = false;
    let mut codex_sqlite_report: Option<CodexSqliteReport> = None;
    for surface in surfaces {
        if force && !dry_run {
            // Name exactly what is being overridden, per the maintainer's
            // requirement — a silent override is indistinguishable from no
            // guard at all. For codex this now covers BOTH halves of the
            // share (S-M2: one lock acquire, one live-writer scan), so the
            // message says so rather than implying only the symlink half.
            let what = if surface == Surface::Codex {
                "codex's session store (symlinked history AND cross-slot sqlite state)".to_string()
            } else {
                surface.to_string()
            };
            match shared_state::detect_live_writers(base, surface) {
                Ok(live) if live.is_empty() => {}
                Ok(live) => {
                    let pids = live
                        .iter()
                        .map(|w| w.pid.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    println!(
                        "--force: overriding the live-writer guard for {what} \
                         (detected pid(s): {pids}) — proceeding WITHOUT the safety check"
                    );
                }
                Err(_) => {
                    println!(
                        "--force: overriding the live-writer guard for {what} \
                         (liveness could not be determined) — proceeding WITHOUT the safety check"
                    );
                }
            }
        }

        // S-M2: codex's symlink-based entries and its separate sqlite-state
        // merge run under ONE acquire of the codex share lock and ONE
        // live-writer scan (`share_codex_surface_and_sqlite`) — previously
        // only the sqlite half took the exclusive lock at all, leaving the
        // symlink half unlocked and thus repointable out from under a live
        // `csq run` codex session in the window between the two.
        let reports = if surface == Surface::Codex {
            let (slot_reports, sqlite_report) =
                shared_state::share_codex_surface_and_sqlite(base, dry_run, force)
                    .map_err(|e| anyhow::anyhow!("{surface}: {e}"))?;
            codex_sqlite_report = Some(sqlite_report);
            slot_reports
        } else {
            shared_state::share_surface(base, surface, dry_run, force)
                .map_err(|e| anyhow::anyhow!("{surface}: {e}"))?
        };
        if reports.is_empty() {
            println!("{surface}: no slots found");
            continue;
        }
        any_slots = true;
        for report in &reports {
            print_slot_report(report, dry_run);
        }
    }

    if !any_slots {
        println!(
            "No codex, kimi, or grok slots found under {}",
            base.display()
        );
    }

    // Codex's schema-versioned sqlite state (thread names/`resume` recency,
    // and codex-cli's rebuildable projection cache) is a SEPARATE merge from
    // the symlink-based entries above — see
    // `csq_core::session::shared_state::codex_sqlite` for why. Both halves
    // ran together above (`share_codex_surface_and_sqlite`) when codex was
    // requested; this only prints the sqlite half's report.
    if let Some(report) = codex_sqlite_report {
        print_codex_sqlite_report(&report, dry_run);
    }

    Ok(())
}

fn print_codex_sqlite_report(report: &CodexSqliteReport, dry_run: bool) {
    if report.databases.is_empty() {
        return;
    }
    println!("== codex sqlite state ==");
    for db in &report.databases {
        let role = match db.role {
            SqliteDbRole::State => "state (thread names/recency)",
            SqliteDbRole::KeptPerSlot => "kept per-slot",
        };
        let verb = if dry_run { "would" } else { "did" };
        let detail = match &db.outcome {
            SqliteDbOutcome::AlreadyShared => "already shared".to_string(),
            SqliteDbOutcome::Merged { slots_merged } => {
                format!("{verb} merge {slots_merged} slot(s)' copies")
            }
            SqliteDbOutcome::KeptPerSlot { slots } => {
                format!("left untouched in {slots} slot(s) (no cross-slot value established)")
            }
        };
        println!("  {} [{role}]: {detail}", db.basename);
    }
}

fn print_slot_report(report: &SlotReport, dry_run: bool) {
    println!("== {} slot {} ==", report.surface, report.slot);
    for entry in &report.entries {
        print_entry_report(entry, dry_run);
    }
}

fn print_entry_report(entry: &EntryReport, dry_run: bool) {
    if entry.already_shared {
        println!("  {}: already shared", entry.relpath);
        return;
    }

    let verb = if dry_run { "would move" } else { "moved" };
    let mut parts = vec![format!(
        "{verb} {} file(s), {} byte(s)",
        entry.files_moved, entry.bytes_moved
    )];
    if entry.lines_added > 0 || entry.lines_deduped > 0 {
        parts.push(format!(
            "{} line(s) added, {} deduped",
            entry.lines_added, entry.lines_deduped
        ));
    }
    if entry.duplicates_removed > 0 {
        parts.push(format!(
            "{} exact duplicate(s) removed",
            entry.duplicates_removed
        ));
    }
    if entry.conflicts_kept_both > 0 {
        parts.push(format!(
            "{} conflicting file(s) kept under a suffixed name",
            entry.conflicts_kept_both
        ));
    }
    if entry.partial {
        parts.push("PARTIAL — some content could not be relocated; re-run to retry".to_string());
    }
    println!("  {}: {}", entry.relpath, parts.join("; "));
}

// ── Post-login auto-share (ledger #5) ───────────────────────────────────
//
// `csq sessions share` migrates the slots that exist WHEN IT RUNS. A slot
// logged in afterwards keeps a private history, and nothing surfaces that
// until an operator notices transcripts missing across slots. The login
// handlers therefore call [`share_after_login`] on their success path so a
// new slot joins the store the moment it is created.
//
// Everything here is advisory: the operator has just authenticated, and no
// migration outcome may cost them that. The return type is deliberately
// infallible — there is no `Result` for a caller to `?` by accident.

/// What the post-login share attempt did for one slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareOutcome {
    /// The surface declares no `SharedStateSpec` (ClaudeCode, Gemini) —
    /// there is nothing to share and nothing was touched.
    NotSupported,
    /// Every declared entry was already a symlink to the shared target.
    AlreadyShared,
    /// `entries` declared entries were migrated (or seeded + linked, for a
    /// brand-new slot with no local history yet).
    Shared { entries: usize, partial: bool },
    /// The live-writer guard refused. NOT shared — this is the expected
    /// outcome for kimi/grok today, whose liveness cannot be determined.
    Skipped { reason: String },
    /// The migration itself errored. NOT shared.
    Failed { reason: String },
}

/// [`ShareOutcome`] plus the identity it applies to, so the operator-facing
/// line is rendered from one place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostLoginShare {
    pub surface: Surface,
    pub slot: AccountNum,
    pub outcome: ShareOutcome,
}

impl std::fmt::Display for PostLoginShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            surface,
            slot,
            outcome,
        } = self;
        match outcome {
            ShareOutcome::NotSupported => write!(
                f,
                "sessions: cross-slot session sharing is not supported for {surface} — \
                 slot {slot}'s history stays where {surface} put it"
            ),
            ShareOutcome::AlreadyShared => write!(
                f,
                "sessions: slot {slot} is already in the shared {surface} session store"
            ),
            ShareOutcome::Shared { entries, partial } => {
                write!(
                    f,
                    "sessions: slot {slot} joined the shared {surface} session store \
                     ({entries} entr{} migrated)",
                    if *entries == 1 { "y" } else { "ies" }
                )?;
                if *partial {
                    write!(
                        f,
                        " — PARTIAL: some content could not be relocated; \
                         re-run `csq sessions share --surface {}`",
                        surface.as_str()
                    )?;
                }
                Ok(())
            }
            // Both of the negative arms name the surface tag in the retry
            // command: a bare "run csq sessions share" would re-scan every
            // surface, which is not what failed here.
            ShareOutcome::Skipped { reason } => write!(
                f,
                "sessions: slot {slot} was NOT added to the shared {surface} session store \
                 — {reason} Re-run `csq sessions share --surface {}` once no {surface} \
                 session is running.",
                surface.as_str()
            ),
            ShareOutcome::Failed { reason } => write!(
                f,
                "sessions: slot {slot} was NOT added to the shared {surface} session store \
                 — {reason}. Re-run `csq sessions share --surface {}`.",
                surface.as_str()
            ),
        }
    }
}

/// Join a freshly-logged-in slot to the cross-slot shared session store.
///
/// Call this ONLY on a login's success path. Never fails: every error is
/// folded into a reported [`ShareOutcome`], because a migration problem must
/// not cost the operator an authentication they just completed.
///
/// The live-writer guard is honoured with `force = false` — a login never
/// implicitly overrides it. For kimi/grok that guard currently cannot
/// determine liveness at all, so this reports [`ShareOutcome::Skipped`] and
/// migrates nothing; that refusal is the intended behaviour, and it is
/// printed rather than swallowed.
#[must_use]
pub fn share_after_login(base: &Path, slot: AccountNum, surface: Surface) -> PostLoginShare {
    share_after_login_inner(base, slot, surface, |base, surface| {
        shared_state::ensure_no_live_writers(base, surface, false)
    })
}

/// [`share_after_login`] with the live-writer guard INJECTED.
///
/// The real guard shells out to `ps`, so its verdict depends on whatever the
/// host happens to be running — untestable, and on a developer machine with
/// codex open it would refuse. Tests drive this entry point directly with a
/// stub verdict; production always routes through [`share_after_login`].
fn share_after_login_inner<G>(
    base: &Path,
    slot: AccountNum,
    surface: Surface,
    guard: G,
) -> PostLoginShare
where
    G: FnOnce(&Path, Surface) -> Result<(), shared_state::ShareError>,
{
    let outcome = compute(base, slot, surface, guard);
    PostLoginShare {
        surface,
        slot,
        outcome,
    }
}

fn compute<G>(base: &Path, slot: AccountNum, surface: Surface, guard: G) -> ShareOutcome
where
    G: FnOnce(&Path, Surface) -> Result<(), shared_state::ShareError>,
{
    if shared_state::spec_for(surface).is_none() {
        return ShareOutcome::NotSupported;
    }

    // Idempotence probe FIRST, and deliberately as a dry run: dry runs are
    // read-only and are never gated by the live-writer guard, so a re-login
    // on an already-shared slot is a clean no-op even while a session of
    // that surface is up. Checking after the guard would report "skipped"
    // for a slot that needed nothing.
    match shared_state::share_slot(base, surface, slot, true) {
        Err(e) => return ShareOutcome::Failed { reason: reason(&e) },
        Ok(plan) if plan.entries.iter().all(|e| e.already_shared) => {
            return ShareOutcome::AlreadyShared
        }
        Ok(_) => {}
    }

    if let Err(e) = guard(base, surface) {
        return ShareOutcome::Skipped { reason: reason(&e) };
    }

    match shared_state::share_slot(base, surface, slot, false) {
        Ok(report) => ShareOutcome::Shared {
            entries: report.entries.iter().filter(|e| !e.already_shared).count(),
            partial: report.entries.iter().any(|e| e.partial),
        },
        Err(e) => ShareOutcome::Failed { reason: reason(&e) },
    }
}

/// Error text for the operator. Passed through `redact_tokens` on principle
/// (`security.md` MUST-2) — these messages carry paths and pids today, but
/// the redaction is what keeps that true if a future variant interpolates a
/// response body.
fn reason(e: &shared_state::ShareError) -> String {
    csq_core::error::redact_tokens(&e.to_string())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use csq_core::session::shared_state::ShareError;
    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).expect("valid slot")
    }

    /// A guard that lets the migration proceed. Injected so the verdict does
    /// not depend on whether the host running the suite happens to have a
    /// codex session open.
    fn allow(_: &Path, _: Surface) -> Result<(), ShareError> {
        Ok(())
    }

    /// The codex spec's four declared entries, in spec order.
    const CODEX_ENTRIES: [&str; 4] = [
        "codex-sessions",
        "codex-session_index.jsonl",
        "codex-history.jsonl",
        "codex-thread-writer-locks",
    ];

    // ── Case 1: a fresh slot on a spec'd surface actually shares ──────────
    // Asserts the on-disk EFFECT (the slot path is now a symlink into the
    // shared store, and the transcript is readable through it), not that a
    // function was called.

    #[test]
    fn fresh_codex_slot_joins_the_shared_store() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let home = base.join("config-4");
        fs::create_dir_all(home.join("codex-sessions")).unwrap();
        fs::write(home.join("codex-sessions/rollout.jsonl"), b"{\"turn\":1}\n").unwrap();

        let report = share_after_login_inner(base, slot(4), Surface::Codex, allow);

        assert!(
            matches!(
                report.outcome,
                ShareOutcome::Shared {
                    entries: 4,
                    partial: false
                }
            ),
            "expected all four codex entries shared, got {:?}",
            report.outcome
        );

        let linked = home.join("codex-sessions");
        assert!(
            linked.symlink_metadata().unwrap().file_type().is_symlink(),
            "slot path was not converted to a symlink"
        );
        assert_eq!(
            fs::read_link(&linked).unwrap(),
            base.join("shared-state/codex/codex-sessions"),
            "symlink does not point at the shared store"
        );
        assert_eq!(
            fs::read_to_string(base.join("shared-state/codex/codex-sessions/rollout.jsonl"))
                .unwrap(),
            "{\"turn\":1}\n",
            "transcript did not reach the shared store"
        );
        assert!(report.to_string().contains("joined the shared"));
    }

    /// A brand-new slot with no transcripts yet still joins, so its FIRST
    /// session is written into the shared store rather than privately.
    #[test]
    fn codex_slot_with_no_history_yet_still_joins() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        fs::create_dir_all(base.join("config-7")).unwrap();

        let report = share_after_login_inner(base, slot(7), Surface::Codex, allow);

        assert!(
            matches!(report.outcome, ShareOutcome::Shared { entries: 4, .. }),
            "got {:?}",
            report.outcome
        );
        for relpath in CODEX_ENTRIES {
            let p = base.join("config-7").join(relpath);
            assert!(
                p.symlink_metadata().unwrap().file_type().is_symlink(),
                "{relpath} was not linked"
            );
        }
    }

    // ── Case 2: a surface with no spec does nothing, and says so ──────────

    #[test]
    fn surface_without_a_spec_shares_nothing_and_says_so() {
        for surface in [Surface::ClaudeCode, Surface::Gemini] {
            let tmp = TempDir::new().unwrap();
            let base = tmp.path();
            fs::create_dir_all(base.join("config-2")).unwrap();

            let report = share_after_login_inner(base, slot(2), surface, allow);

            assert_eq!(
                report.outcome,
                ShareOutcome::NotSupported,
                "{surface} should have no spec"
            );
            assert!(
                !base.join("shared-state").exists(),
                "{surface} touched the shared store"
            );
            let line = report.to_string();
            assert!(line.contains("not supported"), "unhelpful line: {line}");
            assert!(!line.contains("joined"), "misleading line: {line}");
        }
    }

    // ── Case 3: a share failure is REPORTED, never propagated ─────────────

    #[test]
    fn share_failure_is_reported_and_does_not_fail_the_login() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let home = base.join("config-5");
        fs::create_dir_all(&home).unwrap();
        // Declared as a directory entry; a plain file is a shape the
        // migration refuses to guess at.
        fs::write(home.join("codex-sessions"), b"not a directory").unwrap();

        // `share_after_login` returns a value, not a `Result` — there is
        // nothing here for a login handler to `?` on. That is the property
        // under test; the assertions below pin the reporting half.
        let report = share_after_login_inner(base, slot(5), Surface::Codex, allow);

        match &report.outcome {
            ShareOutcome::Failed { reason } => {
                assert!(
                    reason.contains("codex-sessions"),
                    "reason does not name the entry: {reason}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        let line = report.to_string();
        assert!(line.contains("was NOT added"), "unhelpful line: {line}");
        assert!(
            line.contains("csq sessions share --surface codex"),
            "no retry instruction: {line}"
        );
        // The bad entry is left exactly as the operator had it.
        assert!(home.join("codex-sessions").is_file());
    }

    // ── Case 4: re-login on an already-shared slot is a clean no-op ───────

    #[test]
    fn relogin_on_an_already_shared_slot_is_a_no_op() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let home = base.join("config-9");
        let shared = base.join("shared-state/codex");
        fs::create_dir_all(&home).unwrap();
        // Built directly, NOT by calling share once, so this case stays
        // independent of the migration step it is meant to be unaffected by.
        fs::create_dir_all(shared.join("codex-sessions")).unwrap();
        fs::create_dir_all(shared.join("codex-thread-writer-locks")).unwrap();
        fs::write(shared.join("codex-session_index.jsonl"), b"").unwrap();
        fs::write(shared.join("codex-history.jsonl"), b"").unwrap();
        for relpath in CODEX_ENTRIES {
            symlink(shared.join(relpath), home.join(relpath)).unwrap();
        }

        // The guard panics if consulted: an already-shared slot must not be
        // gated on liveness, since it performs no write at all.
        let report = share_after_login_inner(base, slot(9), Surface::Codex, |_, _| {
            panic!("live-writer guard consulted on an already-shared slot")
        });

        assert_eq!(report.outcome, ShareOutcome::AlreadyShared);
        assert!(report.to_string().contains("already in the shared"));
        for relpath in CODEX_ENTRIES {
            assert_eq!(
                fs::read_link(home.join(relpath)).unwrap(),
                shared.join(relpath),
                "{relpath} was repointed"
            );
        }
    }

    // ── Case 5: the live-writer guard refuses -> skip, migrate nothing ────
    // This is kimi/grok's real behaviour today (liveness undeterminable).

    #[test]
    fn guard_refusal_skips_and_migrates_nothing() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        let home = base.join("native-homes/kimi-3");
        fs::create_dir_all(home.join("sessions")).unwrap();
        fs::write(home.join("sessions/a.jsonl"), b"x\n").unwrap();

        let report = share_after_login_inner(base, slot(3), Surface::Kimi, |_, surface| {
            Err(ShareError::LiveWritersUndeterminable(surface))
        });

        match &report.outcome {
            ShareOutcome::Skipped { reason } => assert!(
                reason.contains("could not determine"),
                "reason does not explain the refusal: {reason}"
            ),
            other => panic!("expected Skipped, got {other:?}"),
        }
        let line = report.to_string();
        assert!(line.contains("was NOT added"), "misleading line: {line}");
        assert!(!line.contains("joined"), "misleading line: {line}");
        assert!(
            home.join("sessions").symlink_metadata().unwrap().is_dir(),
            "content was migrated despite the guard refusing"
        );
        assert!(
            !base.join("shared-state/kimi/sessions").exists(),
            "shared store was written despite the guard refusing"
        );
    }
}
