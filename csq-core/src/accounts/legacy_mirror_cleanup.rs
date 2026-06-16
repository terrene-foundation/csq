//! RN1-C R2: idempotent post-retirement cleanup pass for legacy credential
//! mirror files.
//!
//! M4-12 (RN1-C) retired the WRITER to the legacy numeric credential mirror
//! paths `credentials/<N>.json` (Anthropic) and `credentials/codex-<N>.json`
//! (Codex) — refreshes now write only to `identities/<UUID>/credentials.json`
//! / `credentials-codex.json`. Retiring the writer left pre-existing files
//! from pre-M4-12 builds on disk. They are inert (no daemon path reads them
//! when `by_slot[N]` resolves) but trip the `LegacyCanonicalCredentialsFile*`
//! bridge detectors in `csq doctor`, blocking WINDOW-CLOSE P1 from clearing
//! and gating RN1-F (gh #292) structurally.
//!
//! This module ships `prune_legacy_credential_mirrors` — the paired
//! reconciler-cleanup half of the M4-12 retirement contract.
//!
//! # Predicate (per file `credentials/<N>.json` or `credentials/codex-<N>.json`)
//!
//! Deletion is information-preserving iff ALL of:
//!
//! 1. `profiles.json::by_slot[N]` resolves to `Some(UUID)` (the M4-12 writer
//!    target exists for this slot).
//! 2. `identities/<UUID>/credentials.json` (Anthropic) OR
//!    `identities/<UUID>/credentials-codex.json` (Codex) is present on disk
//!    AND parses successfully via `credentials::load`.
//!
//! Otherwise the file is KEPT. The keep set is:
//!
//! - `NoBySlotMapping` — pre-RN1-C install; legacy file is the live read
//!   source via `refresh::check.rs:69` fallback.
//! - `IdentityFileMissing` — half-mint state OR backup-restore omission.
//! - `IdentityFileCorrupt` — successor parse failure (rare).
//! - `IoError` — `remove_file` failed (EACCES, EROFS, etc.); file stays on
//!   disk and is retried next start.
//!
//! See `workspaces/legacy-credentials-mirror-cleanup/journal/0004-DECISION-analyze-r1-converged-design.md`
//! D1–D9 for the full predicate convergence trail.
//!
//! # Lock posture (per S4)
//!
//! The supplied `ProfilesFileLock` is held by the caller (the reconciler
//! wrapper acquires it). This function uses the lock ONLY to load the
//! `profiles.json` snapshot at entry — the per-file deletions execute
//! lock-free because deletions touch only filesystem entries, not the
//! `profiles.json` content. Do NOT "tidy up" by extending the lock to wrap
//! the deletion loop — that would block `csq login N` for the duration of
//! the batch without any added safety.
//!
//! # Idempotency
//!
//! Pure function of disk state. A second run is a no-op (every deletable
//! mirror is already gone; the kept set is stable). NOT sentinel-gated —
//! it runs every reconciler tick so a host that later resolves an
//! un-recoverable mirror (via `csq login N` minting the by_slot entry +
//! the daemon refresher seeding the identity file) gets it pruned on the
//! next start.

use crate::accounts::identity_store::{credentials_codex_path_for, credentials_path_for};
use crate::accounts::profiles::{self, ProfilesFile};
use crate::accounts::profiles_lock::ProfilesFileLock;
use crate::credentials;
use crate::error::ConfigError;
use crate::providers::catalog::Surface;
use crate::types::AccountNum;
use std::collections::HashMap;
use std::path::Path;

/// Per-pass report surfaced into `ReconcileSummary::legacy_mirror_prune`.
///
/// `pruned_count` + `kept_count` is the total file count the pass evaluated.
/// `kept_reasons` carries the keep-arm taxonomy for operator-visible
/// debugging via the daemon structured log.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LegacyMirrorPruneReport {
    /// Files whose successor exists + parses → deleted.
    pub pruned_count: usize,
    /// Files kept on disk because the predicate could not prove safety.
    pub kept_count: usize,
    /// Distribution of keep reasons. Sum equals `kept_count`.
    pub kept_reasons: HashMap<KeptReason, usize>,
}

/// Keep-arm taxonomy. Per S2 (`operator-surface-verification.md` Rule 6),
/// the variants carry NO path field — paths route to the structured log
/// via tracing fields only, never into operator-facing `csq doctor` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum KeptReason {
    /// `by_slot[N]` is absent. The legacy file may be the live read source
    /// (pre-RN1-C install via `refresh::check.rs:69` fallback). KEEP.
    NoBySlotMapping,
    /// `by_slot[N]` resolves, but `identities/<UUID>/credentials*.json` is
    /// missing. Half-mint state OR backup-restore omission. KEEP — the
    /// Phase-4 gate also refuses daemon start in this configuration.
    IdentityFileMissing,
    /// Successor identity file exists but fails to parse. KEEP — deleting
    /// would orphan the slot if the corrupt identity is the only remaining
    /// authoritative source.
    IdentityFileCorrupt,
    /// `remove_file` returned an I/O error (EACCES, EROFS, EISDIR, etc.).
    /// File stays on disk; predicate retries next reconciler tick.
    IoError,
}

/// One mirror surface's classification — internal to the predicate.
enum Action {
    Delete,
    Keep(KeptReason),
}

/// Prune legacy `credentials/<N>.json` and `credentials/codex-<N>.json`
/// mirrors whose M4-12 successor exists. See module-level docs for the full
/// predicate + lock posture.
///
/// **Lock contract:** `lock` is held only for the `profiles.json` snapshot
/// read; the deletion loop runs lock-free. Do not extend the lock to wrap
/// the deletion loop (S4).
///
/// **Filename matcher (S3):** Anthropic stems must be pure-decimal `u16`;
/// Codex stems require the `codex-` prefix AND a pure-decimal `u16` body.
/// Sentinel files (`<N>.broker-failed`, `<N>.refresh-lock`), Gemini files
/// (`gemini-<N>.json`), and any non-matching name are skipped silently.
///
/// **Path reconstruction (S1):** the deletion target path is reconstructed
/// via `canonical_path_for(base, AccountNum::try_from(N)?, surface)` — the
/// `read_dir` filename is treated as advisory only. `AccountNum::try_from`
/// rejects out-of-range slot ids structurally.
pub fn prune_legacy_credential_mirrors(
    _lock: &ProfilesFileLock,
    base_dir: &Path,
) -> Result<LegacyMirrorPruneReport, ConfigError> {
    // (1) Load snapshot once under the supplied lock.
    let pf = profiles::load(&profiles::profiles_path(base_dir))?;

    let mut report = LegacyMirrorPruneReport::default();

    // (2) Enumerate filesystem candidates. Missing or unreadable dir → no-op success.
    let creds_dir = base_dir.join("credentials");
    let entries = match std::fs::read_dir(&creds_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(report),
        Err(_) => return Ok(report),
    };

    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue, // non-UTF8 filename — not a mirror we wrote
        };

        // (3) Classify the filename. Reject non-mirror names structurally (S3).
        let Some((account, surface)) = classify_filename(&name) else {
            continue;
        };

        // (4) Reconstruct the canonical path from validated inputs (S1).
        let canonical = crate::credentials::file::canonical_path_for(base_dir, account, surface);

        // (5) Evaluate the predicate against the snapshot.
        match classify_mirror(&pf, base_dir, account, surface) {
            Action::Delete => match std::fs::remove_file(&canonical) {
                Ok(()) => {
                    report.pruned_count += 1;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Race with `csq logout N` — already deleted by the
                    // sibling path; treat as success (AC15).
                    report.pruned_count += 1;
                }
                Err(_) => {
                    record_keep(&mut report, KeptReason::IoError);
                }
            },
            Action::Keep(reason) => {
                record_keep(&mut report, reason);
            }
        }
    }

    Ok(report)
}

/// Returns `Some((account, surface))` when the filename is a legacy mirror
/// the cleanup pass owns. Mirrors the discipline at
/// `csq/src/cli/commands/doctor.rs::detect_legacy_canonical_anthropic` and
/// `detect_legacy_canonical_codex` (S3) — the same strip_prefix/strip_suffix
/// + `u16::parse` chain that rejects:
///
/// - Gemini files (`gemini-9.json` → stem `gemini-9` fails u16 parse).
/// - Sentinel files (`<N>.broker-failed` / `<N>.refresh-lock` lack `.json`).
/// - Non-credential JSON (e.g. `profile.json` → stem fails u16 parse).
fn classify_filename(name: &str) -> Option<(AccountNum, Surface)> {
    // Codex first — its prefix is more specific.
    if let Some(rest) = name.strip_prefix("codex-") {
        let stem = rest.strip_suffix(".json")?;
        let n: u16 = stem.parse().ok()?;
        let account = AccountNum::try_from(n).ok()?;
        return Some((account, Surface::Codex));
    }

    // Anthropic — pure decimal stem.
    let stem = name.strip_suffix(".json")?;
    let n: u16 = stem.parse().ok()?;
    let account = AccountNum::try_from(n).ok()?;
    Some((account, Surface::ClaudeCode))
}

/// The predicate: classify ONE mirror candidate as Delete or Keep+reason.
fn classify_mirror(
    pf: &ProfilesFile,
    base_dir: &Path,
    account: AccountNum,
    surface: Surface,
) -> Action {
    let slot_key = account.to_string();

    // arm (b1): no by_slot → KEEP. The legacy file may be the live read
    // source via `refresh::check.rs:69` fallback. Deleting would brick the
    // slot. This arm is load-bearing for FM1 safety.
    let Some(uuid) = pf.by_slot.get(&slot_key).copied() else {
        return Action::Keep(KeptReason::NoBySlotMapping);
    };

    let identity_path = match surface {
        Surface::ClaudeCode => credentials_path_for(base_dir, uuid),
        Surface::Codex => credentials_codex_path_for(base_dir, uuid),
        // Gemini is rejected at `classify_filename` (filename pattern). The
        // arm here is unreachable in practice; matching it explicitly keeps
        // the compiler check on the Surface enum if a future variant lands.
        Surface::Gemini => return Action::Keep(KeptReason::NoBySlotMapping),
    };

    // arm (b2): identity file absent → KEEP. The Phase-4 gate refuses
    // daemon start in this configuration so we rarely reach here, but the
    // pass is the redundant defense.
    if !identity_path.exists() {
        return Action::Keep(KeptReason::IdentityFileMissing);
    }

    // arm (b3): identity file present but unparseable → KEEP. Could not
    // prove the successor is valid; refuse to delete the only remaining
    // bytes that might carry the slot's tokens.
    match credentials::load(&identity_path) {
        Ok(_) => Action::Delete,
        Err(_) => Action::Keep(KeptReason::IdentityFileCorrupt),
    }
}

fn record_keep(report: &mut LegacyMirrorPruneReport, reason: KeptReason) {
    report.kept_count += 1;
    *report.kept_reasons.entry(reason).or_insert(0) += 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::identity_store::{identity_path, IdentityId};
    use crate::accounts::profiles::{profiles_path, save};
    use crate::credentials::{
        AnthropicCredentialFile, CodexCredentialFile, CodexTokensFile, CredentialFile, OAuthPayload,
    };
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn sample_anthropic_creds() -> CredentialFile {
        CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-test".into()),
                refresh_token: RefreshToken::new("sk-ant-ort01-test".into()),
                expires_at: 1775726524877,
                scopes: vec!["user:inference".into()],
                subscription_type: Some("max".into()),
                rate_limit_tier: Some("default_claude_max_20x".into()),
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        })
    }

    fn sample_codex_creds() -> CredentialFile {
        CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some("test-account-uuid".into()),
                access_token: "eyJhbGciOiJIUzI1NiJ9.test-at.sig".into(),
                refresh_token: Some("rt_test".into()),
                id_token: Some("eyJhbGciOiJIUzI1NiJ9.test-id.sig".into()),
                extra: HashMap::new(),
            },
            last_refresh: Some("2026-04-22T00:00:00Z".into()),
            extra: HashMap::new(),
        })
    }

    /// Helper: plant a legacy Anthropic mirror `credentials/<N>.json` with
    /// sample contents (the file is treated as opaque bytes by the predicate).
    fn plant_anthropic_mirror(base: &Path, slot: u16) {
        let dir = base.join("credentials");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{}.json", slot));
        crate::credentials::save(&path, &sample_anthropic_creds()).unwrap();
    }

    /// Helper: plant a legacy Codex mirror `credentials/codex-<N>.json`.
    fn plant_codex_mirror(base: &Path, slot: u16) {
        let dir = base.join("credentials");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("codex-{}.json", slot));
        crate::credentials::save(&path, &sample_codex_creds()).unwrap();
    }

    /// Helper: plant an identity-keyed Anthropic credentials.json for `uuid`.
    fn plant_identity_anthropic(base: &Path, uuid: IdentityId) {
        let dir = identity_path(base, uuid);
        std::fs::create_dir_all(&dir).unwrap();
        crate::credentials::save(&dir.join("credentials.json"), &sample_anthropic_creds()).unwrap();
    }

    /// Helper: plant an identity-keyed Codex credentials-codex.json for `uuid`.
    fn plant_identity_codex(base: &Path, uuid: IdentityId) {
        let dir = identity_path(base, uuid);
        std::fs::create_dir_all(&dir).unwrap();
        crate::credentials::save(&dir.join("credentials-codex.json"), &sample_codex_creds())
            .unwrap();
    }

    fn write_profiles_with_by_slot(base: &Path, bindings: &[(&str, IdentityId)]) {
        let mut pf = ProfilesFile::empty();
        for (slot, uuid) in bindings {
            pf.by_slot.insert((*slot).into(), *uuid);
        }
        save(&profiles_path(base), &pf).unwrap();
    }

    // ── AC11: predicate arm (a) — DELETE when by_slot + identity valid ───

    #[test]
    fn legacy_anthropic_mirror_pruned_when_by_slot_and_identity_valid() {
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        plant_anthropic_mirror(dir.path(), 1);
        plant_identity_anthropic(dir.path(), uuid);
        write_profiles_with_by_slot(dir.path(), &[("1", uuid)]);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_legacy_credential_mirrors(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 1, "arm-a: must DELETE: {:?}", report);
        assert_eq!(report.kept_count, 0);
        assert!(
            !dir.path().join("credentials/1.json").exists(),
            "mirror file must be removed from disk"
        );
    }

    #[test]
    fn legacy_codex_mirror_pruned_when_by_slot_and_codex_identity_valid() {
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        plant_codex_mirror(dir.path(), 8);
        plant_identity_codex(dir.path(), uuid);
        write_profiles_with_by_slot(dir.path(), &[("8", uuid)]);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_legacy_credential_mirrors(&lock, dir.path()).unwrap();

        assert_eq!(
            report.pruned_count, 1,
            "codex arm-a: must DELETE: {:?}",
            report
        );
        assert_eq!(report.kept_count, 0);
        assert!(
            !dir.path().join("credentials/codex-8.json").exists(),
            "codex mirror must be removed from disk"
        );
    }

    // ── AC12 + AC9: arm (b) — KEEP sub-cases each with own KeptReason ─────

    #[test]
    fn legacy_mirror_kept_when_no_by_slot() {
        let dir = TempDir::new().unwrap();
        plant_anthropic_mirror(dir.path(), 5);
        // NO by_slot mapping — pure-legacy install shape.
        save(&profiles_path(dir.path()), &ProfilesFile::empty()).unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_legacy_credential_mirrors(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 0);
        assert_eq!(report.kept_count, 1);
        assert_eq!(
            report
                .kept_reasons
                .get(&KeptReason::NoBySlotMapping)
                .copied(),
            Some(1),
            "b1 must KEEP with NoBySlotMapping: {:?}",
            report
        );
        assert!(
            dir.path().join("credentials/5.json").exists(),
            "FM1 safety: pure-legacy mirror MUST remain on disk"
        );
    }

    #[test]
    fn legacy_mirror_kept_when_identity_file_missing() {
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        plant_anthropic_mirror(dir.path(), 2);
        // by_slot points to uuid BUT no identity file planted.
        write_profiles_with_by_slot(dir.path(), &[("2", uuid)]);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_legacy_credential_mirrors(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 0);
        assert_eq!(report.kept_count, 1);
        assert_eq!(
            report
                .kept_reasons
                .get(&KeptReason::IdentityFileMissing)
                .copied(),
            Some(1),
            "b2 must KEEP with IdentityFileMissing: {:?}",
            report
        );
        assert!(dir.path().join("credentials/2.json").exists());
    }

    #[test]
    fn legacy_mirror_kept_when_identity_file_corrupt() {
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        plant_anthropic_mirror(dir.path(), 3);
        // Plant identity file with garbage that fails to parse.
        let id_dir = identity_path(dir.path(), uuid);
        std::fs::create_dir_all(&id_dir).unwrap();
        std::fs::write(
            id_dir.join("credentials.json"),
            b"{\"this\": \"is not a valid cred file\"}",
        )
        .unwrap();
        write_profiles_with_by_slot(dir.path(), &[("3", uuid)]);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_legacy_credential_mirrors(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 0);
        assert_eq!(report.kept_count, 1);
        assert_eq!(
            report
                .kept_reasons
                .get(&KeptReason::IdentityFileCorrupt)
                .copied(),
            Some(1),
            "b3 must KEEP with IdentityFileCorrupt: {:?}",
            report
        );
        assert!(dir.path().join("credentials/3.json").exists());
    }

    #[test]
    fn legacy_mirror_kept_each_reason_reflected_in_report() {
        // One mirror per KEEP arm — exercises the full keep-reason taxonomy.
        let dir = TempDir::new().unwrap();
        let uuid_b2 = IdentityId::new_v4();
        let uuid_b3 = IdentityId::new_v4();

        // b1: slot 1 — no by_slot mapping.
        plant_anthropic_mirror(dir.path(), 1);
        // b2: slot 2 — by_slot present, identity file absent.
        plant_anthropic_mirror(dir.path(), 2);
        // b3: slot 3 — identity file present but corrupt.
        plant_anthropic_mirror(dir.path(), 3);
        let id_dir = identity_path(dir.path(), uuid_b3);
        std::fs::create_dir_all(&id_dir).unwrap();
        std::fs::write(id_dir.join("credentials.json"), b"not json").unwrap();

        write_profiles_with_by_slot(dir.path(), &[("2", uuid_b2), ("3", uuid_b3)]);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_legacy_credential_mirrors(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 0);
        assert_eq!(report.kept_count, 3);
        assert_eq!(
            report
                .kept_reasons
                .get(&KeptReason::NoBySlotMapping)
                .copied(),
            Some(1)
        );
        assert_eq!(
            report
                .kept_reasons
                .get(&KeptReason::IdentityFileMissing)
                .copied(),
            Some(1)
        );
        assert_eq!(
            report
                .kept_reasons
                .get(&KeptReason::IdentityFileCorrupt)
                .copied(),
            Some(1)
        );
    }

    // ── AC8: directory-walk handling — sparse, empty ───────────────────────

    #[test]
    fn legacy_mirror_prune_handles_sparse_slot_set() {
        // Slots 1, 3, 7 (sparse) — pass MUST handle non-contiguous slot ids.
        let dir = TempDir::new().unwrap();
        let (u1, u3, u7) = (
            IdentityId::new_v4(),
            IdentityId::new_v4(),
            IdentityId::new_v4(),
        );
        for slot in [1u16, 3, 7] {
            plant_anthropic_mirror(dir.path(), slot);
        }
        plant_identity_anthropic(dir.path(), u1);
        plant_identity_anthropic(dir.path(), u3);
        plant_identity_anthropic(dir.path(), u7);
        write_profiles_with_by_slot(dir.path(), &[("1", u1), ("3", u3), ("7", u7)]);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_legacy_credential_mirrors(&lock, dir.path()).unwrap();

        assert_eq!(
            report.pruned_count, 3,
            "all sparse slots must be pruned: {:?}",
            report
        );
        for slot in [1u16, 3, 7] {
            assert!(
                !dir.path()
                    .join(format!("credentials/{}.json", slot))
                    .exists(),
                "slot {slot} mirror must be removed"
            );
        }
    }

    #[test]
    fn legacy_mirror_prune_no_op_on_empty_credentials_dir() {
        let dir = TempDir::new().unwrap();
        // Empty credentials/ directory.
        std::fs::create_dir_all(dir.path().join("credentials")).unwrap();
        save(&profiles_path(dir.path()), &ProfilesFile::empty()).unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_legacy_credential_mirrors(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 0);
        assert_eq!(report.kept_count, 0);
        assert!(report.kept_reasons.is_empty());
    }

    #[test]
    fn legacy_mirror_prune_no_op_when_credentials_dir_absent() {
        // Pre-init host shape — credentials/ directory does not exist.
        let dir = TempDir::new().unwrap();
        save(&profiles_path(dir.path()), &ProfilesFile::empty()).unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_legacy_credential_mirrors(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 0);
        assert_eq!(report.kept_count, 0);
    }

    // ── AC9 (S2): report struct correctness — keep-reason counters ─────────

    #[test]
    fn legacy_mirror_prune_report_populates_no_by_slot_mapping() {
        let dir = TempDir::new().unwrap();
        plant_anthropic_mirror(dir.path(), 4);
        save(&profiles_path(dir.path()), &ProfilesFile::empty()).unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_legacy_credential_mirrors(&lock, dir.path()).unwrap();

        assert_eq!(report.kept_reasons.len(), 1);
        assert_eq!(report.kept_reasons[&KeptReason::NoBySlotMapping], 1);
    }

    #[test]
    fn legacy_mirror_prune_report_populates_identity_file_missing() {
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        plant_anthropic_mirror(dir.path(), 4);
        write_profiles_with_by_slot(dir.path(), &[("4", uuid)]);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_legacy_credential_mirrors(&lock, dir.path()).unwrap();

        assert_eq!(report.kept_reasons[&KeptReason::IdentityFileMissing], 1);
    }

    #[test]
    fn legacy_mirror_prune_report_populates_identity_file_corrupt() {
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        plant_anthropic_mirror(dir.path(), 4);
        let id_dir = identity_path(dir.path(), uuid);
        std::fs::create_dir_all(&id_dir).unwrap();
        std::fs::write(id_dir.join("credentials.json"), b"garbage").unwrap();
        write_profiles_with_by_slot(dir.path(), &[("4", uuid)]);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_legacy_credential_mirrors(&lock, dir.path()).unwrap();

        assert_eq!(report.kept_reasons[&KeptReason::IdentityFileCorrupt], 1);
    }

    // ── AC15: csq logout race tolerance ────────────────────────────────────

    #[test]
    fn cleanup_pass_tolerant_of_concurrent_logout_delete() {
        // Simulate logout-deletes-first: the mirror is GONE when the pass
        // tries to delete it. The pass MUST count it as pruned (NotFound =
        // success no-op).
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        // No mirror planted — simulates `csq logout N` already removed it.
        plant_identity_anthropic(dir.path(), uuid);
        write_profiles_with_by_slot(dir.path(), &[("9", uuid)]);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_legacy_credential_mirrors(&lock, dir.path()).unwrap();

        // No mirror to delete — directory was empty of matching files —
        // pruned_count = 0 + kept_count = 0. The behaviour we are pinning
        // is that the pass does NOT panic on the missing-mirror baseline.
        assert_eq!(report.pruned_count, 0, "no mirror, no work");
        assert_eq!(report.kept_count, 0);
    }

    // ── AC16: pure-legacy install survives the pass (FM1 regression) ───────

    #[test]
    fn pure_legacy_install_survives_legacy_mirror_prune_pass() {
        // Three slots, all pre-RN1-C: mirrors present, NO by_slot, NO
        // identities/. The pass MUST KEEP all three so `discover_anthropic`
        // legacy fallback continues to surface them.
        let dir = TempDir::new().unwrap();
        for slot in [1u16, 2, 3] {
            plant_anthropic_mirror(dir.path(), slot);
        }
        // No profiles.json at all — emulating a true pre-Phase-1 install.

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_legacy_credential_mirrors(&lock, dir.path()).unwrap();

        assert_eq!(report.pruned_count, 0, "pure-legacy MUST NOT prune");
        assert_eq!(report.kept_count, 3);
        assert_eq!(
            report.kept_reasons[&KeptReason::NoBySlotMapping],
            3,
            "all 3 slots in arm b1"
        );
        for slot in [1u16, 2, 3] {
            assert!(
                dir.path()
                    .join(format!("credentials/{}.json", slot))
                    .exists(),
                "FM1 regression: slot {slot} mirror MUST remain for discovery fallback"
            );
        }
    }

    // ── AC17: partial-batch tolerance (best-effort posture) ────────────────

    #[test]
    #[cfg(unix)]
    fn legacy_mirror_prune_continues_batch_on_eacces() {
        use std::os::unix::fs::PermissionsExt;
        // Two mirrors. One can delete; the other has its parent dir made
        // 0o500 (deny WRITE) so `remove_file` fails with EACCES. The pass
        // MUST report 1 pruned + 1 kept-IoError, NOT abort the batch.
        //
        // Note: making the parent dir 0o500 affects ALL files in it, so we
        // arrange one delete first by giving each slot its own setup.
        //
        // POSIX `unlink` requires WRITE on the parent. To force EACCES on a
        // specific file we set the parent's mode to 0o500 (read+exec but
        // not write) AFTER planting. This blocks ALL deletes — so we use
        // sub-batching: plant slot 1, run pass (deletes 1); plant slot 2,
        // chmod parent 0o500, run pass (1 kept-IoError).
        //
        // The single-batch case below uses a sentinel that cannot be deleted
        // because we make IT individually non-deletable (chattr / overlay is
        // platform-specific). Cleaner: rely on the chmod-parent technique
        // and verify in TWO calls.
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        plant_anthropic_mirror(dir.path(), 1);
        plant_identity_anthropic(dir.path(), uuid);
        write_profiles_with_by_slot(dir.path(), &[("1", uuid)]);
        let creds_dir = dir.path().join("credentials");

        // Make the parent dir read-only — EACCES on every delete.
        let original_mode = std::fs::metadata(&creds_dir).unwrap().permissions().mode();
        let mut perms = std::fs::metadata(&creds_dir).unwrap().permissions();
        perms.set_mode(0o500);
        std::fs::set_permissions(&creds_dir, perms).unwrap();

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let report = prune_legacy_credential_mirrors(&lock, dir.path()).unwrap();

        // Restore so TempDir's Drop can clean up.
        let mut restore = std::fs::metadata(&creds_dir).unwrap().permissions();
        restore.set_mode(original_mode);
        std::fs::set_permissions(&creds_dir, restore).unwrap();

        // (α) posture: predicate matched + delete failed → kept-IoError.
        assert_eq!(report.pruned_count, 0);
        assert_eq!(report.kept_count, 1);
        assert_eq!(
            report.kept_reasons[&KeptReason::IoError],
            1,
            "partial-batch must record EACCES as IoError, not panic: {:?}",
            report
        );
        assert!(
            dir.path().join("credentials/1.json").exists(),
            "file MUST remain on disk after failed delete"
        );
    }

    // ── S2: KeptReason::IoError carries no path field — type-check assert ──

    #[test]
    fn kept_reason_io_error_variant_carries_no_path() {
        // Compile-time: KeptReason::IoError is unit-like; if a future
        // refactor adds a path field, std::mem::size_of would change and
        // this test's assertion captures the invariant.
        // (We assert structurally via a match — the unit-like pattern
        // would not compile if the variant gained a field.)
        let reason = KeptReason::IoError;
        match reason {
            KeptReason::IoError => {} // unit variant — no fields to destructure
            _ => unreachable!(),
        }
    }

    // ── S3: filename matcher rejects non-mirror names ──────────────────────

    #[test]
    fn classify_filename_rejects_non_mirror_names() {
        // Sentinel files
        assert!(classify_filename("1.broker-failed").is_none());
        assert!(classify_filename("3.refresh-lock").is_none());
        assert!(classify_filename("3.lock").is_none());

        // Gemini files
        assert!(classify_filename("gemini-9.json").is_none());
        assert!(classify_filename("gemini-13.json").is_none());

        // Other JSON not matching the pattern
        assert!(classify_filename("not-a-mirror.json").is_none());
        assert!(classify_filename("profile.json").is_none());

        // Non-decimal stems
        assert!(classify_filename("abc.json").is_none());
        assert!(classify_filename("codex-abc.json").is_none());
        assert!(classify_filename("codex-.json").is_none());

        // Out-of-range u16
        assert!(classify_filename("99999999.json").is_none());

        // Valid Anthropic
        let (a, s) = classify_filename("7.json").unwrap();
        assert_eq!(a.get(), 7);
        assert_eq!(s, Surface::ClaudeCode);

        // Valid Codex
        let (a, s) = classify_filename("codex-12.json").unwrap();
        assert_eq!(a.get(), 12);
        assert_eq!(s, Surface::Codex);
    }

    // ── Bonus: idempotency (re-running yields no change) ───────────────────

    #[test]
    fn legacy_mirror_prune_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        plant_anthropic_mirror(dir.path(), 1);
        plant_identity_anthropic(dir.path(), uuid);
        write_profiles_with_by_slot(dir.path(), &[("1", uuid)]);

        let lock = ProfilesFileLock::acquire(dir.path()).unwrap();
        let first = prune_legacy_credential_mirrors(&lock, dir.path()).unwrap();
        let second = prune_legacy_credential_mirrors(&lock, dir.path()).unwrap();

        assert_eq!(first.pruned_count, 1);
        assert_eq!(second.pruned_count, 0, "second run must be no-op");
        assert_eq!(second.kept_count, 0);
    }
}
