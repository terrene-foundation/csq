//! Durable desktop CLI-refresh outcomes and the shared managed-plist gate.
//!
//! Receipts describe the last attempt, not the current executable. Diagnostics
//! must probe the installed CLI again before reporting it as healthy.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const RECEIPT_FILENAME: &str = "cli-shim-refresh.json";
const RECEIPT_CAP: u64 = 16 * 1024;

/// Last desktop refresh attempt, atomically published with owner-only access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShimRefreshReceipt {
    /// Fixed outcome/rejection tag, never subprocess output or an error body.
    pub outcome: String,
    /// Local diagnostic state; absent only if no target could be resolved.
    /// Doctor redacts this path before placing it on its operator surface.
    pub target_path: Option<PathBuf>,
    /// The desktop's compiled-in identity, used to detect a stale terminal CLI.
    pub expected_version_line: String,
    /// Signature-verified version at the end of the attempt, or null.
    pub verified_version_line: Option<String>,
    /// Fixed tag describing install, repair, rejection, or unload of the plist.
    pub plist_decision: String,
    /// Stale-plist inspection/unload result, retained even after successful repair.
    pub stale_plist_decision: String,
    /// UTC Unix seconds when the attempt finished.
    pub timestamp: u64,
}

/// Desktop and doctor use exactly the same admissibility predicate.
pub fn managed_plist_allowed(
    target_exists: bool,
    refresh_failed: bool,
    target_verifies: bool,
) -> bool {
    target_exists && (!refresh_failed || target_verifies)
}

/// Admission uses a FINAL live verification, including after a nominally
/// successful refresh, and keeps community/enterprise installation coherent.
pub fn managed_plist_rejection(
    target_exists: bool,
    refresh_failed: bool,
    verified_line: Option<&str>,
    expected_line: &str,
) -> Option<&'static str> {
    if !managed_plist_allowed(
        target_exists,
        refresh_failed || verified_line.is_none(),
        verified_line.is_some(),
    ) {
        Some("skipped_unverifiable")
    } else if expected_line.contains("(community)")
        && verified_line.is_some_and(|l| l.contains("(enterprise)"))
    {
        Some("skipped_edition_mismatch")
    } else {
        None
    }
}

/// Paths/identity for one desktop attempt. The caller resolves the accounts
/// directory rather than deriving it from a terminal handle.
pub struct RefreshContext<'a> {
    pub base_dir: &'a Path,
    pub source: Option<&'a Path>,
    pub target: Option<&'a Path>,
    pub expected_version_line: &'a str,
}

/// One desktop refresh path, with filesystem/signature/launchd operations
/// injected. Final verification is performed once and shared by the plist
/// callback and receipt; a historical success is never used as a live probe.
pub fn refresh_cli_and_record_with(
    context: RefreshContext<'_>,
    refresh: impl FnOnce(&Path, &Path) -> Result<super::cli_shim::ShimOutcome>,
    verify: impl FnOnce(&Path) -> super::cli_shim::InstalledCliVerification,
    plist: impl FnOnce(
        Option<&Path>,
        &super::cli_shim::InstalledCliVerification,
        bool,
    ) -> (String, String),
) -> Result<ShimRefreshReceipt> {
    use super::cli_shim::{InstalledCliVerification, ShimOutcome};
    let (outcome, failed) = match (context.source, context.target) {
        (Some(source), Some(target)) => match refresh(source, target) {
            Ok(ShimOutcome::Installed) => ("installed", false),
            Ok(ShimOutcome::Updated) => ("updated", false),
            Ok(ShimOutcome::ReplacedNonRegular) => ("replaced_non_regular", false),
            Ok(ShimOutcome::NoOp) => ("no_op", false),
            Ok(ShimOutcome::SkippedAlreadyCurrent) => ("skipped_already_current", false),
            Ok(ShimOutcome::SkippedSameFile) => ("skipped_same_file", false),
            Ok(ShimOutcome::Rejected(reason)) => (reason, true),
            Err(_) => ("refresh_failed", true),
        },
        _ => ("source_or_target_unavailable", true),
    };
    let verified = context
        .target
        .map(verify)
        .unwrap_or(InstalledCliVerification::Invalid);
    let (plist_decision, stale_plist_decision) = plist(context.target, &verified, failed);
    let receipt = ShimRefreshReceipt {
        outcome: outcome.into(),
        target_path: context.target.map(Path::to_path_buf),
        expected_version_line: context.expected_version_line.into(),
        verified_version_line: verified.version_line().map(str::to_owned),
        plist_decision,
        stale_plist_decision,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    write_refresh_receipt(context.base_dir, &receipt)?;
    Ok(receipt)
}

/// A verified same-edition CLI at least as new as the desktop is current.
/// A rejected downgrade to an older bundle is not a stale CLI.
pub fn cli_shim_is_current(verified: Option<&str>, expected: &str) -> bool {
    use super::cli_shim::parse_version_triple;
    let Some(line) = verified else { return false };
    let edition = |s: &str| {
        if s.contains("(enterprise)") {
            2
        } else if s.contains("(community)") {
            1
        } else {
            0
        }
    };
    edition(line) != 0
        && edition(line) == edition(expected)
        && matches!((parse_version_triple(line), parse_version_triple(expected)),
            (Some(installed), Some(bundle)) if installed >= bundle)
}

/// Publish one complete receipt; a failure preserves the previous receipt and
/// removes only the temporary file created by this call.
pub fn write_refresh_receipt(base_dir: &Path, receipt: &ShimRefreshReceipt) -> Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(base_dir).context("create CLI-refresh receipt directory")?;
    let path = base_dir.join(RECEIPT_FILENAME);
    let bytes = serde_json::to_vec_pretty(receipt).context("serialize CLI-refresh receipt")?;
    anyhow::ensure!(
        bytes.len() as u64 <= RECEIPT_CAP,
        "CLI-refresh receipt too large"
    );
    let tmp = crate::platform::fs::unique_tmp_path(&path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // Exclusive open: an existing file/symlink is foreign and is never deleted.
    let mut file = options
        .open(&tmp)
        .context("create CLI-refresh receipt temp file")?;
    let result = (|| {
        #[cfg(not(unix))]
        crate::platform::fs::secure_file(&tmp)?;
        file.write_all(&bytes)
            .context("write CLI-refresh receipt")?;
        file.sync_all().context("sync CLI-refresh receipt")?;
        drop(file);
        crate::platform::fs::atomic_replace(&tmp, &path).context("replace CLI-refresh receipt")
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Read the last attempt. Absence is distinct from an unreadable/corrupt receipt.
pub fn read_refresh_receipt(base_dir: &Path) -> Result<Option<ShimRefreshReceipt>> {
    use std::io::Read;
    let file = match std::fs::File::open(base_dir.join(RECEIPT_FILENAME)) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("open CLI-refresh receipt"),
    };
    let mut bytes = Vec::new();
    file.take(RECEIPT_CAP + 1)
        .read_to_end(&mut bytes)
        .context("read CLI-refresh receipt")?;
    anyhow::ensure!(
        bytes.len() as u64 <= RECEIPT_CAP,
        "CLI-refresh receipt too large"
    );
    serde_json::from_slice(&bytes)
        .context("parse CLI-refresh receipt")
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_receipt_records_repair_and_replaces_previous_failure_privately() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_refresh_receipt(dir.path()).unwrap(), None);
        let mut receipt = ShimRefreshReceipt {
            outcome: "signature_invalid".into(),
            target_path: Some(dir.path().join("csq")),
            expected_version_line: "csq 2.21.0 (enterprise)".into(),
            verified_version_line: None,
            plist_decision: "skipped_unverifiable".into(),
            stale_plist_decision: "retained_unverifiable".into(),
            timestamp: 100,
        };
        write_refresh_receipt(dir.path(), &receipt).unwrap();
        assert_eq!(
            read_refresh_receipt(dir.path()).unwrap(),
            Some(receipt.clone())
        );
        receipt.outcome = "updated".into();
        receipt.verified_version_line = Some(receipt.expected_version_line.clone());
        receipt.plist_decision = "repaired".into();
        receipt.timestamp = 101;
        write_refresh_receipt(dir.path(), &receipt).unwrap();
        assert_eq!(read_refresh_receipt(dir.path()).unwrap(), Some(receipt));
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no temporary receipts remain"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(dir.path().join(RECEIPT_FILENAME))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn refresh_receipt_reports_corrupt_or_oversized_state_as_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(RECEIPT_FILENAME);
        std::fs::write(&path, b"not json").unwrap();
        assert!(read_refresh_receipt(dir.path()).is_err());
        std::fs::write(path, vec![b' '; RECEIPT_CAP as usize + 1]).unwrap();
        assert!(read_refresh_receipt(dir.path()).is_err());
    }

    #[test]
    fn desktop_refresh_records_successful_repair_after_a_rejected_attempt() {
        use super::super::cli_shim::{InstalledCliVerification, ShimOutcome};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("csq");
        let source = dir.path().join("source");
        let expected = "csq 2.21.0 (enterprise)";
        std::fs::write(&source, b"good").unwrap();
        std::fs::write(&target, b"bad").unwrap();
        let context = || RefreshContext {
            base_dir: dir.path(),
            source: Some(&source),
            target: Some(&target),
            expected_version_line: expected,
        };
        refresh_cli_and_record_with(
            context(),
            |_, _| Ok(ShimOutcome::Rejected("signature_invalid")),
            |_| InstalledCliVerification::Invalid,
            |t, v, failed| {
                assert!(failed);
                assert!(!managed_plist_allowed(
                    t.unwrap().exists(),
                    failed,
                    v.version_line().is_some()
                ));
                ("skipped_unverifiable".into(), "booted_out".into())
            },
        )
        .unwrap();
        assert_eq!(
            read_refresh_receipt(dir.path())
                .unwrap()
                .unwrap()
                .verified_version_line,
            None
        );
        let calls = std::cell::Cell::new(0);
        let receipt = refresh_cli_and_record_with(
            context(),
            |s, t| {
                std::fs::write(t, std::fs::read(s)?)?;
                Ok(ShimOutcome::Updated)
            },
            |_| {
                calls.set(calls.get() + 1);
                InstalledCliVerification::Verified(expected.into())
            },
            |t, v, failed| {
                assert!(!failed);
                assert!(managed_plist_allowed(
                    t.unwrap().exists(),
                    failed,
                    v.version_line().is_some()
                ));
                ("repaired".into(), "retained_verified".into())
            },
        )
        .unwrap();
        assert_eq!(
            calls.get(),
            1,
            "final verification must be shared, not repeated"
        );
        assert_eq!(receipt.outcome, "updated");
        assert_eq!(receipt.plist_decision, "repaired");
        assert_eq!(receipt.verified_version_line.as_deref(), Some(expected));
        assert_eq!(std::fs::read(&target).unwrap(), b"good");
        assert_eq!(read_refresh_receipt(dir.path()).unwrap(), Some(receipt));
    }

    #[test]
    fn managed_plist_gate_and_current_cli_distinguish_rejection_from_health() {
        assert!(!managed_plist_allowed(false, false, true));
        assert!(!managed_plist_allowed(true, true, false));
        assert!(managed_plist_allowed(true, true, true));
        assert!(managed_plist_allowed(true, false, false));
        let expected = "csq 2.21.0 (enterprise)";
        assert!(cli_shim_is_current(Some("2.21.0 (enterprise)"), expected));
        assert!(cli_shim_is_current(Some("2.22.0 (enterprise)"), expected));
        for line in [
            None,
            Some("2.20.0 (enterprise)"),
            Some("2.99.0 (community)"),
            Some("invalid"),
        ] {
            assert!(!cli_shim_is_current(line, expected));
        }
    }

    #[test]
    fn desktop_plist_admission_rejects_unverified_success_and_edition_mismatch() {
        use super::super::cli_shim::{InstalledCliVerification, ShimOutcome};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("csq");
        std::fs::write(&target, b"binary").unwrap();
        for (expected, verification, rejection) in [
            (
                "csq 2.21.0 (enterprise)",
                InstalledCliVerification::Invalid,
                "skipped_unverifiable",
            ),
            (
                "csq 2.21.0 (community)",
                InstalledCliVerification::Verified("csq 2.21.0 (enterprise)".into()),
                "skipped_edition_mismatch",
            ),
        ] {
            let install_calls = std::cell::Cell::new(0);
            let receipt = refresh_cli_and_record_with(
                RefreshContext {
                    base_dir: dir.path(),
                    source: Some(&target),
                    target: Some(&target),
                    expected_version_line: expected,
                },
                |_, _| Ok(ShimOutcome::SkippedSameFile),
                |_| verification,
                |t, v, failed| {
                    assert!(!failed, "nominal refresh succeeded");
                    let admission = managed_plist_rejection(
                        t.unwrap().exists(),
                        failed,
                        v.version_line(),
                        expected,
                    );
                    if admission.is_none() {
                        install_calls.set(install_calls.get() + 1);
                    }
                    assert_eq!(admission, Some(rejection));
                    (admission.unwrap().into(), "retained_unverifiable".into())
                },
            )
            .unwrap();
            assert_eq!(install_calls.get(), 0);
            assert_eq!(receipt.plist_decision, rejection);
        }
    }
}
