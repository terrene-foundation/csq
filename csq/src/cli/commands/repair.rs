//! `csq repair` (alias `repair-credentials`) — detect and optionally repair
//! credential + slot-attribution inconsistencies.
//!
//! Two independent passes run on every invocation:
//!
//! 1. **Credential contamination** — cross-slot refresh-token sharing
//!    (documented below).
//! 2. **Slot attribution** (workspace slot-attribution-consistency) — stale
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
    /// Phase 2 (M2-7) extension — see workspaces/account-slot-decoupling/
    /// 02-plans/03-phase2-readiness.md § M2-7.
    UuidLegacyDrift { uuid_prefix: String },
}

/// Public entry point. `apply = false` is a dry run.
pub fn handle(base_dir: &Path, apply: bool) -> Result<()> {
    // ── Pass 1: cross-slot credential contamination ──
    let findings = scan(base_dir).context("scan failed")?;
    // ── Pass 2: slot-attribution drift + orphaned mappings ──
    let attribution = scan_attribution(base_dir);

    if findings.is_empty() && attribution.is_empty() {
        println!("✓ No credential or slot-attribution issues detected.");
        return Ok(());
    }

    print_contamination(&findings);
    print_attribution(&attribution);

    if !apply {
        println!();
        println!("Dry run — no files modified. Re-run with `--apply` to repair");
        println!("(delete contaminated canonical credentials, rewrite stale");
        println!(".current-account caches).");
        return Ok(());
    }

    // ── Apply ──
    let mut total = 0usize;
    total += apply_contamination(base_dir, &findings);
    total += apply_attribution(base_dir, &attribution);
    println!();
    println!("Applied {total} repair(s).");
    if !findings.is_empty() {
        println!("Run the Add Account flow (or `csq login N`) to re-authenticate");
        println!("any slot whose contaminated credentials were removed.");
    }
    Ok(())
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
        // See workspaces/account-slot-decoupling/02-plans/03-phase2-readiness.md § M2-7.
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

    // Pass 0b RETIRED (slot-attribution-consistency, 2026-06-01): the
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
    use csq_core::testing::identity_fixtures::fixture_uuid_for_slot;
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
    /// See workspaces/account-slot-decoupling/02-plans/03-phase2-readiness.md § M2-7.
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

    /// Regression (slot-attribution-consistency, 2026-06-01): a HEALTHY
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

    // ── slot-attribution-consistency M5b: pass-2 (attribution) tests ──

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
