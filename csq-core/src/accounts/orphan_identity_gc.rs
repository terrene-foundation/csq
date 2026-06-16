//! Orphan-identity directory garbage collection.
//!
//! `csq logout N` (and a renumber that drops the last reference) removes a
//! slot's `by_slot`/`by_email`/`by_slot_identity` entries, its canonical
//! credential files, and its `config-N/` dir — but historically left the
//! `identities/<UUID>/` directory on disk. Nothing ever collected it:
//! `daemon::identity_mint::sweep_orphan_identities` only `warn!`d and was
//! sentinel-gated, so on an established install it never re-fired. The result
//! is `csq doctor` reporting `Identity store: ⚠ INCONSISTENT:
//! OrphanIdentity(<UUID>)` and dead credential dirs accumulating on disk.
//!
//! This module ships `prune_orphan_identities` — the GC half. It is the 3rd
//! member of the "lifecycle-event-retired-without-paired-cleanup" family
//! (siblings: `accounts::profiles::prune_redundant_accounts_entries` /
//! RN1-D R3, `accounts::legacy_mirror_cleanup::prune_legacy_credential_mirrors`
//! / RN1-C R2). The logout source-fix (in `accounts::logout`) closes the
//! producer; this pass collects the existing backlog + any crash/race orphans.
//!
//! # Predicate (per `identities/<UUID>/` directory)
//!
//! Delete iff the directory name parses as an [`IdentityId`] AND that UUID is
//! referenced by NEITHER `profiles.json::by_slot` NOR `by_email`. Otherwise
//! KEEP. The reachable set is `by_slot.values() ∪ by_email.values()`, typed
//! as `HashSet<IdentityId>` — never string-compared.
//!
//! - `by_email` is part of the reachable set because the mint reuse path
//!   (`daemon::identity_mint::mint_slot`) re-adopts an identity by email; a
//!   dir in `by_email` is reuse-eligible → KEEP.
//! - `by_slot_identity` values are LABELS (`"apikey:mm"`,
//!   `"codex-12/3bf322e8"`, `"gemini-9/codeassist"`), NOT UUIDs — they never
//!   name an `identities/<UUID>/` dir and are NOT consulted. A live Codex slot
//!   is reachable because `mint_for_codex_login` writes `by_slot[N] = UUID`
//!   (and `save_canonical_for` fail-closes without it), so the union predicate
//!   keeps it. This is the FM1-CRITICAL safety invariant.
//!
//! # Whole-pass fail-closed guards (KEEP everything — never delete-on-doubt)
//!
//! The pass deletes NOTHING (returns the default report) when ANY holds:
//!
//! 1. `profiles.json` is absent / unreadable / unparseable — a load failure
//!    must NOT be read as "every identity is orphaned".
//! 2. `by_slot` AND `by_email` are both empty — a fresh / pre-mint install
//!    where every dir would look orphaned (ported from the R2-LOW-1 guard in
//!    the retired `sweep_orphan_identities`).
//! 3. The on-disk `store-version` schema is GREATER than this build's
//!    [`STORE_VERSION_SCHEMA_CURRENT`] — a newer daemon may key identities
//!    through a channel that rides in `ProfilesFile::extra`, invisible to this
//!    build's union; deleting would destroy creds the newer daemon considers
//!    live.
//!
//! # Live-handle-dir guard (defense-in-depth)
//!
//! Before deleting an orphan dir, the pass scans `term-*` handle dirs; if any
//! LIVE handle dir's credential symlink resolves into the candidate
//! `identities/<UUID>/` dir, the dir is KEPT (`LiveHandleDir`). The scanned
//! link names MUST match what `session::handle_dir` creates: `.credentials.json`
//! (ClaudeCode) and `auth.json` (Codex — `create_handle_dir_codex`). A
//! `read_dir` failure during the scan fails CLOSED (treated as possibly-live →
//! KEEP).
//!
//! This is **defense-in-depth, not the primary guard.** The primary defense
//! against deleting a live slot's creds is two-fold: (a) a live, bound slot's
//! UUID is in `by_slot` (so the union predicate KEEPs it before the scan runs),
//! and (b) `logout_account` refuses (`InUse`) while any live terminal is bound,
//! so a UUID only becomes orphaned AFTER a logout that already proved no live
//! binding. The remaining window this scan covers is the narrow same-user race
//! where a pre-existing live terminal's symlink still resolves into a UUID that
//! has since left both maps (e.g. a `.csq-account` marker that became unreadable
//! so logout's in-use guard `continue`d past it). A concurrent
//! `create_handle_dir`/`repoint_handle_dir` cannot point a NEW handle dir at an
//! orphan UUID because those resolve through `by_slot` (absent for an orphan);
//! only a stale pre-logout handle dir can, which this scan catches.
//!
//! # Lock posture (DEVIATION from `legacy_mirror_cleanup` — load-bearing)
//!
//! The caller (the reconciler wrapper) holds the supplied [`ProfilesFileLock`]
//! for the ENTIRE duration of this call: the profiles snapshot, the
//! `identities/` enumeration, AND every `remove_dir_all`. This is REQUIRED and
//! MUST NOT be refactored to a "snapshot-under-lock then delete lock-free"
//! shape. Unlike `legacy_mirror_cleanup` — which deletes in the write-DEAD
//! `credentials/<N>.json` namespace (M4-12 retired the writer) — this pass
//! deletes in the LIVE-MINT `identities/` namespace. A concurrent `csq login`
//! mint writes its `by_slot`/`by_email` mapping FIRST then creates the dir; it
//! must hold the same `ProfilesFileLock` to do so. Holding the lock across the
//! whole pass makes the GC and the mint mutually exclusive, closing the TOCTOU
//! where a stale snapshot + a freshly-minted dir would race to a wrongful
//! delete.
//!
//! # Idempotency
//!
//! Pure function of disk state; a second run is a no-op. NOT sentinel-gated —
//! the orphan is born by a FUTURE logout, long after any one-shot sentinel
//! would have fired, so the pass runs every reconciler tick.

use crate::accounts::identity_store::{identities_dir, identity_path, IdentityId};
use crate::accounts::profiles::{self, ProfilesFile};
use crate::accounts::profiles_lock::ProfilesFileLock;
use crate::daemon::identity_mint::{read_store_version_schema, STORE_VERSION_SCHEMA_CURRENT};
use crate::error::ConfigError;
use std::collections::HashSet;
use std::path::Path;
use std::str::FromStr;

/// Per-pass report surfaced into `ReconcileSummary::orphan_identity_gc`.
///
/// `pruned_count` + `kept_count` is the total UUID-named directory count the
/// pass evaluated. `kept_reasons` carries the keep-arm taxonomy for
/// operator-visible debugging via the daemon structured log.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OrphanIdentityGcReport {
    /// Identity dirs unreferenced by both maps (and not live) → deleted.
    pub pruned_count: usize,
    /// Identity dirs kept because the predicate could not prove orphanhood.
    pub kept_count: usize,
    /// Distribution of keep reasons. Sum equals `kept_count`.
    pub kept_reasons: std::collections::HashMap<OrphanKeptReason, usize>,
}

/// Keep-arm taxonomy. Per S2 (`operator-surface-verification.md` Rule 6) the
/// variants carry NO path field — paths route to the structured log via
/// tracing fields only, never into operator-facing `csq doctor` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum OrphanKeptReason {
    /// UUID present in `by_slot` — an actively-bound identity. KEEP.
    ReferencedBySlot,
    /// UUID present in `by_email` but not `by_slot` — reuse-eligible (mint
    /// re-adopts by email). KEEP.
    ReferencedByEmail,
    /// A live `term-*` handle dir symlinks into this dir. KEEP (the union
    /// predicate said orphan, but a running CC still reads it).
    LiveHandleDir,
    /// `remove_dir_all` returned an I/O error (EACCES, EROFS, etc.). Dir
    /// stays on disk; predicate retries next reconciler tick.
    IoError,
}

/// Internal per-directory classification.
enum Action {
    Delete,
    Keep(OrphanKeptReason),
}

/// Garbage-collect orphan `identities/<UUID>/` directories. See module-level
/// docs for the predicate, fail-closed guards, live-handle-dir guard, and the
/// load-bearing lock-posture deviation.
///
/// **Lock contract:** `_lock` (the caller-held [`ProfilesFileLock`]) MUST
/// remain held for the entire call — snapshot, enumeration, AND deletion. Do
/// NOT refactor to release after the snapshot (see module docs).
pub fn prune_orphan_identities(
    _lock: &ProfilesFileLock,
    base_dir: &Path,
) -> Result<OrphanIdentityGcReport, ConfigError> {
    let mut report = OrphanIdentityGcReport::default();

    // Guard 1 — profiles absent/unreadable/unparseable → KEEP everything.
    // A load failure must never be read as "all identities are orphaned".
    let profiles_path = profiles::profiles_path(base_dir);
    let pf = match profiles::load(&profiles_path) {
        Ok(p) => p,
        Err(_) => return Ok(report),
    };

    // Guard 2 — fresh / pre-mint install: both maps empty → KEEP everything.
    if pf.by_slot.is_empty() && pf.by_email.is_empty() {
        return Ok(report);
    }

    // Guard 3 — version-skew fail-closed: a newer daemon's UUID channel may
    // ride in `extra`, invisible to this build's union. Deleting could destroy
    // creds the newer daemon considers live.
    if let Some(schema) = read_store_version_schema(base_dir) {
        if schema > STORE_VERSION_SCHEMA_CURRENT {
            return Ok(report);
        }
    }

    // Reachable set: by_slot ∪ by_email. Typed as HashSet<IdentityId>, never
    // string-compared. `by_slot_identity` (labels, not UUIDs) is NOT consulted.
    let reachable: HashSet<IdentityId> = pf
        .by_slot
        .values()
        .copied()
        .chain(pf.by_email.values().copied())
        .collect();

    // Enumerate identities/. Missing or unreadable dir → no-op success.
    let id_dir = identities_dir(base_dir);
    let entries = match std::fs::read_dir(&id_dir) {
        Ok(e) => e,
        Err(_) => return Ok(report),
    };

    for entry in entries.flatten() {
        // Only directories named as a valid IdentityId are candidates.
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue, // non-UTF8 — never an identity dir we wrote
        };
        let Ok(uuid) = IdentityId::from_str(&name) else {
            continue; // non-UUID dir name — not ours
        };

        match classify(&pf, &reachable, base_dir, uuid) {
            Action::Delete => {
                let dir = identity_path(base_dir, uuid);
                match std::fs::remove_dir_all(&dir) {
                    Ok(()) => report.pruned_count += 1,
                    // Race with `csq logout`/sweeper — already gone. Success.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        report.pruned_count += 1;
                    }
                    Err(_) => record_keep(&mut report, OrphanKeptReason::IoError),
                }
            }
            Action::Keep(reason) => record_keep(&mut report, reason),
        }
    }

    Ok(report)
}

/// Classify ONE identity dir as Delete or Keep+reason. The reachable-set
/// membership check is the union predicate; the live-handle-dir scan is the
/// defense-in-depth guard applied only to otherwise-deletable candidates.
fn classify(
    pf: &ProfilesFile,
    reachable: &HashSet<IdentityId>,
    base_dir: &Path,
    uuid: IdentityId,
) -> Action {
    // arm (keep-1): bound in by_slot.
    if pf.by_slot.values().any(|u| *u == uuid) {
        return Action::Keep(OrphanKeptReason::ReferencedBySlot);
    }
    // arm (keep-2): reuse-eligible via by_email (but not by_slot).
    if reachable.contains(&uuid) {
        return Action::Keep(OrphanKeptReason::ReferencedByEmail);
    }
    // arm (keep-3): a live terminal still reads this dir's creds.
    if live_handle_dir_points_into(base_dir, uuid) {
        return Action::Keep(OrphanKeptReason::LiveHandleDir);
    }
    // Unreferenced by both maps and not live → true orphan.
    Action::Delete
}

/// Returns `true` when any LIVE `term-*` handle dir's credential symlink
/// resolves into `identities/<uuid>/`. Defense-in-depth so the irreversible
/// delete does not depend transitively on logout's point-in-time in-use guard.
fn live_handle_dir_points_into(base_dir: &Path, uuid: IdentityId) -> bool {
    use crate::accounts::markers;
    use crate::platform::process::is_pid_alive;

    let target_dir = identity_path(base_dir, uuid);
    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        // Fail CLOSED: a transient read_dir failure must KEEP the dir (treat as
        // possibly-live), never flip the defense-in-depth guard off and allow
        // an irreversible delete. Consistent with the whole-pass guards.
        Err(_) => return true,
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
        // Liveness: prefer the .live-pid marker, fall back to the dir-name PID
        // (mirrors `logout::scan_live_handle_dirs_for_account`).
        let pid = markers::read_live_pid(&path)
            .or_else(|| name.strip_prefix("term-").and_then(|s| s.parse().ok()));
        let Some(pid) = pid else { continue };
        if !is_pid_alive(pid) {
            continue;
        }
        // Resolve the credential symlinks and check whether any points into the
        // candidate identity dir. Link names MUST match what `session::handle_dir`
        // actually creates: `.credentials.json` for the ClaudeCode surface
        // (`create_handle_dir`, → `identities/<UUID>/credentials.json`) and
        // `auth.json` for the Codex surface (`create_handle_dir_codex`, →
        // `identities/<UUID>/credentials-codex.json`). Both targets are absolute
        // under the same `base_dir`, so `starts_with(target_dir)` matches. A
        // future handle-dir link rename MUST be reflected here — see the
        // `live_codex_auth_json_handle_dir_keeps_orphan` regression test.
        for link_name in [".credentials.json", "auth.json"] {
            let link = path.join(link_name);
            if let Ok(t) = std::fs::read_link(&link) {
                if t.starts_with(&target_dir) {
                    return true;
                }
            }
        }
    }
    false
}

fn record_keep(report: &mut OrphanIdentityGcReport, reason: OrphanKeptReason) {
    report.kept_count += 1;
    *report.kept_reasons.entry(reason).or_insert(0) += 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::identity_store::identity_path;
    use crate::accounts::profiles::{profiles_path, save};
    use std::path::Path;
    use tempfile::TempDir;

    /// Plant an `identities/<uuid>/` dir with a token-bearing credentials.json
    /// (opaque bytes to the predicate — it never parses them).
    fn plant_identity_dir(base: &Path, uuid: IdentityId) {
        let dir = identity_path(base, uuid);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("credentials.json"),
            br#"{"claudeAiOauth":{"accessToken":"x"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("identity.json"),
            br#"{"email":"a@b.com","provider":"anthropic"}"#,
        )
        .unwrap();
    }

    fn write_profiles(
        base: &Path,
        by_slot: &[(&str, IdentityId)],
        by_email: &[(&str, IdentityId)],
    ) {
        let mut pf = ProfilesFile::empty();
        for (slot, uuid) in by_slot {
            pf.by_slot.insert((*slot).into(), *uuid);
        }
        for (email, uuid) in by_email {
            pf.by_email.insert((*email).into(), *uuid);
        }
        save(&profiles_path(base), &pf).unwrap();
    }

    fn write_store_version(base: &Path, schema: u32) {
        std::fs::write(
            base.join("store-version"),
            format!("{{\"schema\":{schema},\"minted_at\":\"2026-05-25T00:00:00Z\"}}\n"),
        )
        .unwrap();
    }

    // ── AC-GC-1: true orphan (neither map) deleted ─────────────────────────

    #[test]
    fn orphan_dir_pruned_when_in_neither_map() {
        let dir = TempDir::new().unwrap();
        let orphan = IdentityId::new_v4();
        let bound = IdentityId::new_v4();
        plant_identity_dir(dir.path(), orphan);
        plant_identity_dir(dir.path(), bound);
        // Only `bound` is referenced; profiles is non-empty so guard-2 passes.
        write_profiles(dir.path(), &[("1", bound)], &[("a@b.com", bound)]);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_orphan_identities(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 1, "orphan must be deleted: {report:?}");
        assert!(!identity_path(dir.path(), orphan).exists());
        assert!(
            identity_path(dir.path(), bound).exists(),
            "bound identity must remain"
        );
    }

    // ── AC-GC-2: by_slot-referenced KEPT ───────────────────────────────────

    #[test]
    fn dir_kept_when_referenced_by_slot() {
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let other = IdentityId::new_v4();
        plant_identity_dir(dir.path(), uuid);
        // by_slot references uuid; by_email references a different uuid so the
        // map is non-empty without masking the by_slot arm.
        write_profiles(dir.path(), &[("1", uuid)], &[("x@y.com", other)]);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_orphan_identities(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 0);
        assert_eq!(
            report
                .kept_reasons
                .get(&OrphanKeptReason::ReferencedBySlot)
                .copied(),
            Some(1),
            "{report:?}"
        );
        assert!(identity_path(dir.path(), uuid).exists());
    }

    // ── AC-GC-3: by_email-only KEPT (reuse-eligible) ───────────────────────

    #[test]
    fn dir_kept_when_referenced_by_email_only() {
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let slot_uuid = IdentityId::new_v4();
        plant_identity_dir(dir.path(), uuid);
        // uuid is in by_email but NOT by_slot — a rollback/half-logout straggler
        // that is reuse-eligible. by_slot non-empty (different uuid) so guard-2
        // passes.
        write_profiles(dir.path(), &[("2", slot_uuid)], &[("reuse@me.com", uuid)]);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_orphan_identities(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 0);
        assert_eq!(
            report
                .kept_reasons
                .get(&OrphanKeptReason::ReferencedByEmail)
                .copied(),
            Some(1),
            "by_email reuse-eligible must KEEP: {report:?}"
        );
        assert!(identity_path(dir.path(), uuid).exists());
    }

    // ── AC-GC-5: idempotency ───────────────────────────────────────────────

    #[test]
    fn orphan_gc_prune_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let orphan = IdentityId::new_v4();
        let bound = IdentityId::new_v4();
        plant_identity_dir(dir.path(), orphan);
        plant_identity_dir(dir.path(), bound);
        write_profiles(dir.path(), &[("1", bound)], &[]);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let first = prune_orphan_identities(&lock, dir.path()).unwrap();
        let second = prune_orphan_identities(&lock, dir.path()).unwrap();

        assert_eq!(first.pruned_count, 1);
        assert_eq!(second.pruned_count, 0, "second run must delete nothing");
        // The bound identity is correctly kept on EVERY run — idempotency is
        // about no further deletions, not an empty kept set.
        assert_eq!(second.kept_count, 1);
        assert_eq!(
            second
                .kept_reasons
                .get(&OrphanKeptReason::ReferencedBySlot)
                .copied(),
            Some(1)
        );
    }

    // ── AC-GC-6: empty-maps guard (fresh install) ──────────────────────────

    #[test]
    fn empty_maps_guard_keeps_everything() {
        let dir = TempDir::new().unwrap();
        let a = IdentityId::new_v4();
        let b = IdentityId::new_v4();
        plant_identity_dir(dir.path(), a);
        plant_identity_dir(dir.path(), b);
        // Empty profiles — every dir would look orphaned. Guard-2 must skip.
        save(&profiles_path(dir.path()), &ProfilesFile::empty()).unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_orphan_identities(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 0, "fresh-install guard must KEEP all");
        assert_eq!(report.kept_count, 0);
        assert!(identity_path(dir.path(), a).exists());
        assert!(identity_path(dir.path(), b).exists());
    }

    // ── AC-GC-7: identities/ absent → no-op ────────────────────────────────

    #[test]
    fn no_op_when_identities_dir_absent() {
        let dir = TempDir::new().unwrap();
        let bound = IdentityId::new_v4();
        write_profiles(dir.path(), &[("1", bound)], &[]);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_orphan_identities(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 0);
        assert_eq!(report.kept_count, 0);
    }

    // ── AC-GC-8: non-UUID dir name skipped ─────────────────────────────────

    #[test]
    fn non_uuid_dir_name_skipped() {
        let dir = TempDir::new().unwrap();
        let bound = IdentityId::new_v4();
        plant_identity_dir(dir.path(), bound);
        // A junk dir under identities/ that is not a UUID.
        std::fs::create_dir_all(identities_dir(dir.path()).join("tmp-junk")).unwrap();
        write_profiles(dir.path(), &[("1", bound)], &[]);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_orphan_identities(&lock, dir.path()).unwrap();

        // The junk dir is neither pruned nor counted as kept (skipped before
        // classification); the bound dir is kept.
        assert_eq!(report.pruned_count, 0);
        assert!(
            identities_dir(dir.path()).join("tmp-junk").exists(),
            "non-UUID dir must be left untouched"
        );
    }

    // ── AC-GC-9: partial-failure (EACCES) → IoError keep, batch continues ──

    #[test]
    #[cfg(unix)]
    fn remove_dir_all_eacces_recorded_as_io_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let orphan = IdentityId::new_v4();
        let slot_uuid = IdentityId::new_v4();
        plant_identity_dir(dir.path(), orphan);
        write_profiles(dir.path(), &[("1", slot_uuid)], &[]);

        // Make identities/ read-only so remove_dir_all of the child fails
        // (POSIX unlink needs WRITE on the parent).
        let id_root = identities_dir(dir.path());
        let original = std::fs::metadata(&id_root).unwrap().permissions().mode();
        let mut perms = std::fs::metadata(&id_root).unwrap().permissions();
        perms.set_mode(0o500);
        std::fs::set_permissions(&id_root, perms).unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_orphan_identities(&lock, dir.path()).unwrap();

        // Restore so TempDir Drop can clean up.
        let mut restore = std::fs::metadata(&id_root).unwrap().permissions();
        restore.set_mode(original);
        std::fs::set_permissions(&id_root, restore).unwrap();

        assert_eq!(report.pruned_count, 0);
        assert_eq!(
            report.kept_reasons.get(&OrphanKeptReason::IoError).copied(),
            Some(1),
            "EACCES must be recorded as IoError, not panic: {report:?}"
        );
        assert!(
            identity_path(dir.path(), orphan).exists(),
            "dir must remain on disk after failed delete"
        );
    }

    // ── AC-GC-10: schema-ceiling → whole-pass skip ─────────────────────────

    #[test]
    fn schema_ceiling_skips_whole_pass() {
        let dir = TempDir::new().unwrap();
        let orphan = IdentityId::new_v4();
        let bound = IdentityId::new_v4();
        plant_identity_dir(dir.path(), orphan);
        write_profiles(dir.path(), &[("1", bound)], &[]);
        // On-disk schema newer than this build → fail closed.
        write_store_version(dir.path(), STORE_VERSION_SCHEMA_CURRENT + 1);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_orphan_identities(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 0, "version-skew must KEEP all");
        assert!(identity_path(dir.path(), orphan).exists());
    }

    #[test]
    fn current_schema_does_not_skip() {
        let dir = TempDir::new().unwrap();
        let orphan = IdentityId::new_v4();
        let bound = IdentityId::new_v4();
        plant_identity_dir(dir.path(), orphan);
        plant_identity_dir(dir.path(), bound);
        write_profiles(dir.path(), &[("1", bound)], &[]);
        write_store_version(dir.path(), STORE_VERSION_SCHEMA_CURRENT);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_orphan_identities(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 1, "current schema must proceed");
    }

    // ── AC-GC-11: live-handle-dir symlink → KEPT ───────────────────────────

    #[test]
    #[cfg(unix)]
    fn live_handle_dir_symlink_keeps_orphan() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let orphan = IdentityId::new_v4();
        let bound = IdentityId::new_v4();
        plant_identity_dir(dir.path(), orphan);
        write_profiles(dir.path(), &[("1", bound)], &[]);

        // Create a term-<our-own-pid> handle dir whose .credentials.json
        // symlink points into the orphan identity dir. Using our own PID makes
        // is_pid_alive() return true.
        let pid = std::process::id();
        let term = dir.path().join(format!("term-{pid}"));
        std::fs::create_dir_all(&term).unwrap();
        symlink(
            identity_path(dir.path(), orphan).join("credentials.json"),
            term.join(".credentials.json"),
        )
        .unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_orphan_identities(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 0, "live handle dir must block delete");
        assert_eq!(
            report
                .kept_reasons
                .get(&OrphanKeptReason::LiveHandleDir)
                .copied(),
            Some(1),
            "{report:?}"
        );
        assert!(identity_path(dir.path(), orphan).exists());
    }

    /// Redteam C1 regression: a live Codex handle dir symlinks `auth.json` (NOT
    /// `.credentials.json`) → `identities/<UUID>/credentials-codex.json`
    /// (`session::handle_dir::create_handle_dir_codex`). The live-handle scan
    /// MUST recognize the `auth.json` link name or it is blind to live Codex
    /// terminals. A future handle-dir link rename regresses this test.
    #[test]
    #[cfg(unix)]
    fn live_codex_auth_json_handle_dir_keeps_orphan() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let orphan = IdentityId::new_v4();
        let bound = IdentityId::new_v4();
        plant_identity_dir(dir.path(), orphan);
        std::fs::write(
            identity_path(dir.path(), orphan).join("credentials-codex.json"),
            br#"{"tokens":{"access_token":"x"}}"#,
        )
        .unwrap();
        write_profiles(dir.path(), &[("1", bound)], &[]);

        let pid = std::process::id();
        let term = dir.path().join(format!("term-{pid}"));
        std::fs::create_dir_all(&term).unwrap();
        // The REAL Codex handle-dir link name + target shape.
        symlink(
            identity_path(dir.path(), orphan).join("credentials-codex.json"),
            term.join("auth.json"),
        )
        .unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_orphan_identities(&lock, dir.path()).unwrap();

        assert_eq!(
            report.pruned_count, 0,
            "live Codex auth.json handle dir must block delete"
        );
        assert_eq!(
            report
                .kept_reasons
                .get(&OrphanKeptReason::LiveHandleDir)
                .copied(),
            Some(1),
            "{report:?}"
        );
        assert!(identity_path(dir.path(), orphan).exists());
    }

    /// Redteam MED-1 / FM1-CRITICAL: a Codex slot minted via the REAL
    /// `mint_for_codex_login` path lands in `by_slot` and MUST be KEPT — proves
    /// the predicate keeps what the mint actually writes, not just a hand-rolled
    /// `by_slot` fixture (per `feedback_test_fixtures_mirror_real_csq_state`).
    #[test]
    fn gc_keeps_live_codex_slot_minted_via_real_path() {
        use crate::daemon::identity_mint::mint_for_codex_login;

        let dir = TempDir::new().unwrap();
        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        // Real mint: writes by_slot[12] + by_email + identity.json.
        let uuid = mint_for_codex_login(&lock, dir.path(), 12, Some("acct-hint")).unwrap();
        std::fs::write(
            identity_path(dir.path(), uuid).join("credentials-codex.json"),
            br#"{"tokens":{"access_token":"x"}}"#,
        )
        .unwrap();

        let report = prune_orphan_identities(&lock, dir.path()).unwrap();

        assert_eq!(
            report.pruned_count, 0,
            "live Codex slot from the real mint path must be KEPT: {report:?}"
        );
        assert!(
            identity_path(dir.path(), uuid).exists(),
            "real-minted Codex identity dir must survive GC"
        );
    }

    #[test]
    #[cfg(unix)]
    fn dead_handle_dir_symlink_does_not_block_delete() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let orphan = IdentityId::new_v4();
        let bound = IdentityId::new_v4();
        plant_identity_dir(dir.path(), orphan);
        write_profiles(dir.path(), &[("1", bound)], &[]);

        // term-<dead-pid>: a PID that is not alive. The symlink points into the
        // orphan but the terminal is dead → must NOT block the delete.
        let dead_pid = 99_999_998u32;
        let term = dir.path().join(format!("term-{dead_pid}"));
        std::fs::create_dir_all(&term).unwrap();
        symlink(
            identity_path(dir.path(), orphan).join("credentials.json"),
            term.join(".credentials.json"),
        )
        .unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_orphan_identities(&lock, dir.path()).unwrap();

        assert_eq!(
            report.pruned_count, 1,
            "dead terminal must not block delete"
        );
        assert!(!identity_path(dir.path(), orphan).exists());
    }

    // ── AC-GC-13: mixed fixture — every keep-reason + a delete ─────────────

    #[test]
    fn report_taxonomy_across_mixed_fixture() {
        let dir = TempDir::new().unwrap();
        let by_slot_uuid = IdentityId::new_v4();
        let by_email_uuid = IdentityId::new_v4();
        let orphan = IdentityId::new_v4();
        plant_identity_dir(dir.path(), by_slot_uuid);
        plant_identity_dir(dir.path(), by_email_uuid);
        plant_identity_dir(dir.path(), orphan);
        write_profiles(
            dir.path(),
            &[("1", by_slot_uuid)],
            &[("reuse@me.com", by_email_uuid)],
        );

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_orphan_identities(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 1, "{report:?}");
        assert_eq!(report.kept_count, 2, "{report:?}");
        assert_eq!(
            report
                .kept_reasons
                .get(&OrphanKeptReason::ReferencedBySlot)
                .copied(),
            Some(1)
        );
        assert_eq!(
            report
                .kept_reasons
                .get(&OrphanKeptReason::ReferencedByEmail)
                .copied(),
            Some(1)
        );
        assert!(!identity_path(dir.path(), orphan).exists());
    }

    // ── Guard 1: profiles unreadable → KEEP everything ─────────────────────

    #[test]
    fn unreadable_profiles_keeps_everything() {
        let dir = TempDir::new().unwrap();
        let a = IdentityId::new_v4();
        plant_identity_dir(dir.path(), a);
        // Write garbage profiles.json that fails to parse.
        std::fs::write(profiles_path(dir.path()), b"{ not valid json").unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_orphan_identities(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 0, "parse failure must KEEP all");
        assert!(identity_path(dir.path(), a).exists());
    }
}
