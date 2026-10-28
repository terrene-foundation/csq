//! Read-only gate diagnosis through the production private-pin verifier.
//!
//! Registry/row admission is a snapshot, not evidence of launcher activation.
//! Doctor and the gate CLI consume this same builder rather than recapturing a pin.

use super::legacy::{PackageError, VerifiedPackage};
use super::pin::{Pin, PinError, RowAdmissionError};
use super::registry::{Event, FailurePolicy, Form, RegistryError, Severity, Surface};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const STATUS_SCHEMA: &str = "csq.gate.status.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateHealth {
    Green,
    Red,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationStatus {
    /// No authenticated launcher observation is consumed by this reader.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PinAdmission {
    Verified,
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterPinAdmission {
    /// No immutable hook adapter manifest was supplied or installed.
    NotRequired,
    Verified,
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterCheckVerdict {
    Ok,
    Mismatch,
    Missing,
    NotChecked,
}

#[derive(Debug, Serialize)]
pub struct AdapterChecks {
    pub manifest_content_sha256: AdapterCheckVerdict,
    pub row_file_sha256: AdapterCheckVerdict,
    pub dependency_closure: AdapterCheckVerdict,
    pub runtimes_union: AdapterCheckVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_failing_path: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AdapterPinStatus {
    pub admission: AdapterPinAdmission,
    pub pin_source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_hash: Option<String>,
    pub checks: AdapterChecks,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_closure_files: Option<usize>,
    pub runtime_closure_gaps: usize,
    /// Lexical closure manifests cannot see dynamically assembled imports.
    pub dynamic_specifiers_review_required: bool,
    /// Runtime demotion is an execution observation and is not inferred here.
    pub demotion_observation: &'static str,
    pub runtimes_union_sha256: Option<String>,
    pub materialized_runtime_root: Option<String>,
    pub pool_template_rows: Option<usize>,
    pub pool_repo_rows: Option<usize>,
    pub repo_pool_admitted: Option<bool>,
    pub activation_state: &'static str,
    pub activation_reason: &'static str,
    pub last_verified_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<AdapterDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterDiagnostic {
    ManifestUnavailable,
    ManifestMalformed,
    ManifestLimit,
    ManifestInvalidPath,
    ManifestInvalidDigest,
    ManifestFileCount,
    ManifestDuplicatePath,
    ManifestRuntimeClosure,
    ManifestMissingFile,
    ManifestHashMismatch,
    ManifestUnsafeFile,
    ManifestUnsupportedPlatform,
    ManifestUnsafeRuntimeBase,
}

impl AdapterDiagnostic {
    pub(super) fn from_package(error: &PackageError) -> Self {
        match error {
            PackageError::Io => Self::ManifestUnavailable,
            PackageError::Malformed => Self::ManifestMalformed,
            PackageError::Limit => Self::ManifestLimit,
            PackageError::InvalidPath => Self::ManifestInvalidPath,
            PackageError::InvalidDigest => Self::ManifestInvalidDigest,
            PackageError::FileCount => Self::ManifestFileCount,
            PackageError::DuplicatePath => Self::ManifestDuplicatePath,
            PackageError::RuntimeClosure => Self::ManifestRuntimeClosure,
            PackageError::MissingFile => Self::ManifestMissingFile,
            PackageError::HashMismatch => Self::ManifestHashMismatch,
            PackageError::UnsafeFile => Self::ManifestUnsafeFile,
            PackageError::UnsupportedPlatform => Self::ManifestUnsupportedPlatform,
            PackageError::UnsafeRuntimeBase(_) => Self::ManifestUnsafeRuntimeBase,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCode {
    RegistryMalformed,
    RegistryUnsupportedVersion,
    RegistryContentMismatch,
    RegistryInvalidContract,
    RegistryLimit,
    PinInvalid,
    PinUnsafeNamespace,
    PinMismatch,
    PinUnavailable,
    PinIncomplete,
    RuntimeAdmission,
    PinDeadline,
    SignatureUnavailable,
    PlatformUnsupported,
    RowUnreadable,
    RowInvalidPath,
    RowHashMismatch,
    RowLimit,
    RowDeadline,
}

impl DiagnosticCode {
    fn from_pin(error: &PinError) -> Self {
        match error {
            PinError::Registry(error) => match error {
                RegistryError::Malformed => Self::RegistryMalformed,
                RegistryError::UnsupportedVersion => Self::RegistryUnsupportedVersion,
                RegistryError::ContentMismatch => Self::RegistryContentMismatch,
                RegistryError::InvalidContract => Self::RegistryInvalidContract,
                RegistryError::Limit => Self::RegistryLimit,
            },
            PinError::InvalidPin | PinError::TrustUnset => Self::PinInvalid,
            PinError::UnsafePath => Self::PinUnsafeNamespace,
            PinError::Mismatch => Self::PinMismatch,
            PinError::Io => Self::PinUnavailable,
            PinError::Incomplete => Self::PinIncomplete,
            PinError::RuntimeAdmission(_) => Self::RuntimeAdmission,
            PinError::Deadline => Self::PinDeadline,
            PinError::SignatureUnavailable => Self::SignatureUnavailable,
            PinError::UnsupportedPlatform => Self::PlatformUnsupported,
        }
    }

    fn from_row(error: &RowAdmissionError) -> Self {
        match error {
            RowAdmissionError::Unreadable => Self::RowUnreadable,
            RowAdmissionError::InvalidPath => Self::RowInvalidPath,
            RowAdmissionError::HashMismatch => Self::RowHashMismatch,
            RowAdmissionError::Limit => Self::RowLimit,
            RowAdmissionError::Deadline => Self::RowDeadline,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct VerifiedMetadata {
    pub source_sha: String,
    pub registry_version: String,
    pub manifest_sha256: String,
    pub content_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct RowStatus {
    /// Stable registry ID; source paths and arbitrary matcher text are not emitted.
    pub id: String,
    pub event: Event,
    pub surfaces: Vec<Surface>,
    pub declared_form: Form,
    pub severity: Severity,
    pub on_incomplete: FailurePolicy,
    pub admitted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<DiagnosticCode>,
}

#[derive(Debug, Serialize)]
pub struct GateStatusReport {
    pub schema: &'static str,
    /// Snapshot integrity only; green does not mean hooks are registered or active.
    pub health: GateHealth,
    pub pin_admission: PinAdmission,
    pub adapter_pin: AdapterPinStatus,
    pub activation: ActivationStatus,
    /// Verification method, not a success verdict. This remains hash-only when
    /// admission refuses; this reader does not establish publisher/signing authority.
    pub integrity_grade: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_metadata: Option<VerifiedMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<DiagnosticCode>,
    pub admitted_rows: usize,
    pub refused_rows: usize,
    /// Admitted rows declared legacy in the manifest; not observed runtime fallback.
    pub demoted_rows: Vec<String>,
    pub rows: Vec<RowStatus>,
}

impl GateStatusReport {
    fn refused(error: &PinError) -> Self {
        Self {
            schema: STATUS_SCHEMA,
            health: GateHealth::Red,
            pin_admission: PinAdmission::Refused,
            adapter_pin: AdapterPinStatus::not_required(),
            activation: ActivationStatus::Unknown,
            integrity_grade: "hash-only",
            verified_metadata: None,
            diagnostic: Some(DiagnosticCode::from_pin(error)),
            admitted_rows: 0,
            refused_rows: 0,
            demoted_rows: Vec::new(),
            rows: Vec::new(),
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self.health {
            GateHealth::Green => 0,
            GateHealth::Red => 1,
        }
    }

    fn with_adapter(mut self, adapter_pin: AdapterPinStatus) -> Self {
        self.adapter_pin = adapter_pin;
        self
    }
}

impl AdapterPinStatus {
    fn checks_not_checked() -> AdapterChecks {
        AdapterChecks {
            manifest_content_sha256: AdapterCheckVerdict::NotChecked,
            row_file_sha256: AdapterCheckVerdict::NotChecked,
            dependency_closure: AdapterCheckVerdict::NotChecked,
            runtimes_union: AdapterCheckVerdict::NotChecked,
            first_failing_path: None,
        }
    }

    fn now_ms() -> Option<u128> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_millis())
    }

    fn not_required() -> Self {
        Self {
            admission: AdapterPinAdmission::NotRequired,
            pin_source: "none",
            pin_hash: None,
            checks: Self::checks_not_checked(),
            package: None,
            version: None,
            manifest_sha256: None,
            file_count: None,
            runtime_closure_files: None,
            runtime_closure_gaps: 0,
            dynamic_specifiers_review_required: false,
            demotion_observation: "not_observed",
            runtimes_union_sha256: None,
            materialized_runtime_root: None,
            pool_template_rows: None,
            pool_repo_rows: None,
            repo_pool_admitted: None,
            activation_state: "held",
            activation_reason: "awaiting runtime clearance",
            last_verified_ms: None,
            diagnostic: None,
        }
    }

    fn from_manifest(path: &Path, repo: &Path) -> Self {
        Self::from_manifest_with(path, repo, &super::legacy::runtime_base_preflight)
    }

    /// `from_manifest` with the runtime-base probe supplied: a package that verifies but
    /// cannot be given a safe runtime base is refused with the typed reason, not shown as
    /// verified while every row would fail.
    fn from_manifest_with(
        path: &Path,
        repo: &Path,
        runtime_base: &dyn Fn() -> Result<(), PackageError>,
    ) -> Self {
        match VerifiedPackage::verify(path, repo) {
            Ok(package) => {
                let manifest = package.manifest();
                let mut union = String::new();
                for pin in manifest
                    .verification
                    .pins
                    .iter()
                    .filter(|pin| pin.source == "runtime_closure")
                {
                    union.push_str(&pin.path);
                    union.push(':');
                    union.push_str(&pin.sha256);
                    union.push('\n');
                }
                let materialized_root = (!manifest.proposed_path.contains("..")
                    && manifest.proposed_path.len() <= 256)
                    .then(|| manifest.proposed_path.clone());
                let base = runtime_base();
                Self {
                    admission: if base.is_ok() {
                        AdapterPinAdmission::Verified
                    } else {
                        AdapterPinAdmission::Refused
                    },
                    pin_source: "none",
                    pin_hash: None,
                    checks: AdapterChecks {
                        manifest_content_sha256: AdapterCheckVerdict::Ok,
                        row_file_sha256: AdapterCheckVerdict::NotChecked,
                        dependency_closure: AdapterCheckVerdict::Ok,
                        runtimes_union: AdapterCheckVerdict::Ok,
                        first_failing_path: None,
                    },
                    package: Some(manifest.package.clone()),
                    version: Some(manifest.version.clone()),
                    manifest_sha256: Some(package.manifest_sha256().to_owned()),
                    file_count: Some(manifest.file_count),
                    runtime_closure_files: Some(
                        manifest.verification.runtime_closure.reached_files,
                    ),
                    runtime_closure_gaps: manifest.verification.runtime_closure.gaps.len(),
                    dynamic_specifiers_review_required: manifest
                        .verification
                        .runtime_closure
                        .method
                        .to_ascii_lowercase()
                        .contains("lexical"),
                    demotion_observation: "not_observed",
                    runtimes_union_sha256: Some(hex::encode(Sha256::digest(union.as_bytes()))),
                    materialized_runtime_root: materialized_root,
                    pool_template_rows: None,
                    pool_repo_rows: None,
                    repo_pool_admitted: None,
                    activation_state: "held",
                    activation_reason: "awaiting runtime clearance",
                    last_verified_ms: Self::now_ms(),
                    diagnostic: base
                        .err()
                        .map(|error| AdapterDiagnostic::from_package(&error)),
                }
            }
            Err(error) => Self {
                admission: AdapterPinAdmission::Refused,
                pin_source: "none",
                pin_hash: None,
                checks: Self::checks_not_checked(),
                package: None,
                version: None,
                manifest_sha256: None,
                file_count: None,
                runtime_closure_files: None,
                runtime_closure_gaps: 0,
                dynamic_specifiers_review_required: false,
                demotion_observation: "not_observed",
                runtimes_union_sha256: None,
                materialized_runtime_root: None,
                pool_template_rows: None,
                pool_repo_rows: None,
                repo_pool_admitted: None,
                activation_state: "held",
                activation_reason: "awaiting runtime clearance",
                last_verified_ms: None,
                diagnostic: Some(AdapterDiagnostic::from_package(&error)),
            },
        }
    }

    fn refused(diagnostic: AdapterDiagnostic) -> Self {
        Self {
            admission: AdapterPinAdmission::Refused,
            pin_source: "none",
            pin_hash: None,
            checks: Self::checks_not_checked(),
            package: None,
            version: None,
            manifest_sha256: None,
            file_count: None,
            runtime_closure_files: None,
            runtime_closure_gaps: 0,
            dynamic_specifiers_review_required: false,
            demotion_observation: "not_observed",
            runtimes_union_sha256: None,
            materialized_runtime_root: None,
            pool_template_rows: None,
            pool_repo_rows: None,
            repo_pool_admitted: None,
            activation_state: "held",
            activation_reason: "awaiting runtime clearance",
            last_verified_ms: None,
            diagnostic: Some(diagnostic),
        }
    }
}

fn discover_adapter_manifest(repo: &Path) -> Result<Option<PathBuf>, AdapterDiagnostic> {
    let root = repo.join(".claude/hook-runtime");
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(AdapterDiagnostic::ManifestUnavailable),
    };
    let mut manifests = entries
        .map(|entry| entry.map(|entry| entry.path().join("PACKAGE-MANIFEST.json")))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AdapterDiagnostic::ManifestUnavailable)?
        .into_iter()
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    manifests.sort();
    match manifests.len() {
        0 => Err(AdapterDiagnostic::ManifestUnavailable),
        1 => Ok(manifests.pop()),
        _ => Err(AdapterDiagnostic::ManifestMalformed),
    }
}

/// Diagnose exactly the supplied repository and private pin, without capture,
/// repair, settings mutation, trust enrollment or hook execution. Adapter
/// discovery is limited to the sole versioned manifest under the repository.
pub fn build_report(repo: &Path, pin_path: &Path) -> GateStatusReport {
    build_report_with_adapter(repo, pin_path, None)
}

/// Build the same read-only report while optionally verifying the installed
/// immutable hook adapter package. A package refusal is exposed separately and
/// does not get folded into the legacy registry row counts.
pub fn build_report_with_adapter(
    repo: &Path,
    pin_path: &Path,
    adapter_manifest: Option<&Path>,
) -> GateStatusReport {
    let adapter_pin = match adapter_manifest {
        Some(path) => AdapterPinStatus::from_manifest(path, repo),
        None => match discover_adapter_manifest(repo) {
            Ok(Some(path)) => AdapterPinStatus::from_manifest(&path, repo),
            Ok(None) => AdapterPinStatus::not_required(),
            Err(error) => AdapterPinStatus::refused(error),
        },
    };
    let pin = match Pin::read_private(pin_path) {
        Ok(pin) => pin,
        Err(error) => return GateStatusReport::refused(&error).with_adapter(adapter_pin),
    };
    // Production verification binds the repository subject and compares
    // pinned manifest/registry metadata. Parsing a private pin alone is insufficient.
    let verified = match pin.verify(repo) {
        Ok(verified) => verified,
        Err(error) => return GateStatusReport::refused(&error).with_adapter(adapter_pin),
    };
    let metadata = VerifiedMetadata {
        source_sha: verified.registry.source_sha.clone(),
        registry_version: verified.registry.version.clone(),
        manifest_sha256: pin.manifest_sha256().to_owned(),
        content_sha256: verified.registry.content_sha256.clone(),
    };
    let rows: Vec<_> = verified
        .rows
        .into_iter()
        .map(|verified| RowStatus {
            id: verified.row.id,
            event: verified.row.event,
            surfaces: verified.row.surfaces,
            declared_form: verified.row.contract.form,
            severity: verified.row.contract.protocol.severity,
            on_incomplete: verified.row.on_incomplete,
            admitted: verified.admission.is_ok(),
            diagnostic: verified
                .admission
                .as_ref()
                .err()
                .map(DiagnosticCode::from_row),
        })
        .collect();
    let admitted_rows = rows.iter().filter(|row| row.admitted).count();
    let refused_rows = rows.len() - admitted_rows;
    let demoted_rows = rows
        .iter()
        .filter(|row| row.admitted && row.declared_form == Form::Legacy)
        .map(|row| row.id.clone())
        .collect();
    GateStatusReport {
        schema: STATUS_SCHEMA,
        health: if refused_rows == 0 && adapter_pin.admission != AdapterPinAdmission::Refused {
            GateHealth::Green
        } else {
            GateHealth::Red
        },
        pin_admission: PinAdmission::Verified,
        adapter_pin,
        activation: ActivationStatus::Unknown,
        integrity_grade: "hash-only",
        verified_metadata: Some(metadata),
        diagnostic: None,
        admitted_rows,
        refused_rows,
        demoted_rows,
        rows,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::gate::pin::MANIFEST_FILE;
    use crate::gate::registry::tests::{fixture as registry_fixture, sealed};
    use serde_json::Value;
    use sha2::Digest;
    use std::fs;
    use std::path::PathBuf;

    const RUNTIME_BYTES: &[u8] = b"trusted runtime fixture";
    fn fixture(bytes: &[u8]) -> Value {
        let mut value = registry_fixture(bytes);
        value["runtimes"] = serde_json::json!([{"entry":".claude/hooks/runtime.js",
            "entry_sha256": crate::gate::registry::sha256(RUNTIME_BYTES), "deps":[]}]);
        value
    }
    struct Fixture {
        _temp: tempfile::TempDir,
        repo: PathBuf,
        pin: PathBuf,
    }
    impl Fixture {
        fn new(continue_class: bool) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let repo = temp.path().join("private-home-canary-repo");
            let handle = temp.path().join("private-home-canary-handle");
            fs::create_dir_all(repo.join(".claude/hooks")).unwrap();
            fs::create_dir(&handle).unwrap();
            let source = b"fixture bytes; never executed";
            fs::write(repo.join(".claude/hooks/guard.js"), source).unwrap();
            fs::write(repo.join(".claude/hooks/runtime.js"), RUNTIME_BYTES).unwrap();
            let mut manifest = fixture(source);
            if continue_class {
                manifest["hooks"][0]["on_incomplete"] = "continue".into();
                manifest["hooks"][0]["contract"]["protocol"]["severity"] = "advise".into();
            }
            fs::write(repo.join(MANIFEST_FILE), sealed(manifest)).unwrap();
            let pin = handle.join("pin.json");
            Pin::capture_operator(&repo)
                .unwrap()
                .write_private(&pin)
                .unwrap();
            Self {
                _temp: temp,
                repo,
                pin,
            }
        }

        fn mutate_pin(&self, field: &str, value: Value) {
            let mut pin: Value = serde_json::from_slice(&fs::read(&self.pin).unwrap()).unwrap();
            pin[field] = value;
            // Replacing bytes in the already-private production file retains mode.
            fs::write(&self.pin, serde_json::to_vec(&pin).unwrap()).unwrap();
        }
    }

    #[test]
    fn healthy_pin_has_verified_metadata_but_activation_stays_unknown() {
        let f = Fixture::new(false);
        let before_pin = fs::read(&f.pin).unwrap();
        let before_manifest = fs::read(f.repo.join(MANIFEST_FILE)).unwrap();
        let before_hook = fs::read(f.repo.join(".claude/hooks/guard.js")).unwrap();
        let report = build_report(&f.repo, &f.pin);
        assert_eq!(report.health, GateHealth::Green);
        assert_eq!(report.pin_admission, PinAdmission::Verified);
        assert_eq!(report.activation, ActivationStatus::Unknown);
        assert_eq!(
            report.adapter_pin.admission,
            AdapterPinAdmission::NotRequired
        );
        assert_eq!(report.adapter_pin.demotion_observation, "not_observed");
        assert_eq!(report.admitted_rows, 1);
        assert_eq!(report.demoted_rows, vec![report.rows[0].id.clone()]);
        assert_eq!(
            report.verified_metadata.as_ref().unwrap().registry_version,
            "1.0.0"
        );
        assert_eq!(fs::read(&f.pin).unwrap(), before_pin);
        assert_eq!(
            fs::read(f.repo.join(MANIFEST_FILE)).unwrap(),
            before_manifest
        );
        assert_eq!(
            fs::read(f.repo.join(".claude/hooks/guard.js")).unwrap(),
            before_hook
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("private-home-canary"));
    }

    #[test]
    fn adapter_status_verifies_manifest_and_refuses_tampering() {
        let f = Fixture::new(false);
        let runtime_dir = f.repo.join(".claude/hook-runtime/1.0.0");
        fs::create_dir_all(&runtime_dir).unwrap();
        let runtime = runtime_dir.join("runtime.js");
        let runtime_bytes = b"trusted adapter runtime";
        fs::write(&runtime, runtime_bytes).unwrap();
        let sha = hex::encode(sha2::Sha256::digest(runtime_bytes));
        let manifest = serde_json::json!({
            "package": "hook-runtime",
            "version": "1.0.0",
            "proposed_path": ".claude/hook-runtime/1.0.0/",
            "invocation": "node runtime.js",
            "commit_sha": "a".repeat(40),
            "commit_sha_convention": "pinned",
            "head_at_generation": "b".repeat(40),
            "runtime_clean_at_generation": true,
            "file_count": 1,
            "files": [{"path":".claude/hook-runtime/1.0.0/runtime.js","sha256":sha,"bytes":runtime_bytes.len()}],
            "verification": {
                "pins": [{"path":".claude/hook-runtime/1.0.0/runtime.js","sha256":sha,"source":"runtime_closure"}],
                "runtime_closure": {"entry_points":[".claude/hook-runtime/1.0.0/runtime.js"],"reached_files":1,"gaps":[],"method":"lexical walk"}
            }
        });
        let manifest_path = runtime_dir.join("PACKAGE-MANIFEST.json");
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let report = build_report_with_adapter(&f.repo, &f.pin, Some(&manifest_path));
        assert_eq!(report.adapter_pin.admission, AdapterPinAdmission::Verified);
        assert_eq!(report.adapter_pin.package.as_deref(), Some("hook-runtime"));
        assert!(report.adapter_pin.dynamic_specifiers_review_required);
        fs::write(&runtime, b"tampered").unwrap();
        let refused = build_report_with_adapter(&f.repo, &f.pin, Some(&manifest_path));
        assert_eq!(refused.adapter_pin.admission, AdapterPinAdmission::Refused);
        assert_eq!(
            refused.adapter_pin.diagnostic,
            Some(AdapterDiagnostic::ManifestHashMismatch)
        );
        assert_eq!(refused.health, GateHealth::Red);
        assert_eq!(refused.exit_code(), 1);
    }

    // MED-C: a package that verifies but has no safe runtime base is reported as refused
    // with the typed reason (caller level: the status the operator reads), not Verified.
    #[test]
    fn adapter_status_reports_an_unsafe_runtime_base() {
        let f = Fixture::new(false);
        let runtime_dir = f.repo.join(".claude/hook-runtime/1.0.0");
        fs::create_dir_all(&runtime_dir).unwrap();
        let runtime_bytes = b"console.log(1)";
        let sha = hex::encode(Sha256::digest(runtime_bytes));
        fs::write(runtime_dir.join("runtime.js"), runtime_bytes).unwrap();
        let manifest = serde_json::json!({
            "package": "hook-runtime",
            "version": "1.0.0",
            "proposed_path": ".claude/hook-runtime/1.0.0/",
            "invocation": "node runtime.js",
            "commit_sha": "a".repeat(40),
            "commit_sha_convention": "pinned",
            "head_at_generation": "b".repeat(40),
            "runtime_clean_at_generation": true,
            "file_count": 1,
            "files": [{"path":".claude/hook-runtime/1.0.0/runtime.js","sha256":sha,"bytes":runtime_bytes.len()}],
            "verification": {
                "pins": [{"path":".claude/hook-runtime/1.0.0/runtime.js","sha256":sha,"source":"runtime_closure"}],
                "runtime_closure": {"entry_points":[".claude/hook-runtime/1.0.0/runtime.js"],"reached_files":1,"gaps":[],"method":"lexical walk"}
            }
        });
        let manifest_path = runtime_dir.join("PACKAGE-MANIFEST.json");
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let ok = AdapterPinStatus::from_manifest_with(&manifest_path, &f.repo, &|| Ok(()));
        assert_eq!(ok.admission, AdapterPinAdmission::Verified);
        assert_eq!(ok.diagnostic, None);
        let unsafe_base = AdapterPinStatus::from_manifest_with(&manifest_path, &f.repo, &|| {
            Err(PackageError::UnsafeRuntimeBase("/tmp refused".into()))
        });
        assert_eq!(unsafe_base.admission, AdapterPinAdmission::Refused);
        assert_eq!(
            unsafe_base.diagnostic,
            Some(AdapterDiagnostic::ManifestUnsafeRuntimeBase)
        );
        assert_eq!(unsafe_base.package.as_deref(), Some("hook-runtime"));
    }

    #[test]
    fn missing_and_malformed_pins_are_red_without_capture_or_repair() {
        let f = Fixture::new(false);
        fs::remove_file(&f.pin).unwrap();
        let missing = build_report(&f.repo, &f.pin);
        assert_eq!(missing.health, GateHealth::Red);
        assert_eq!(missing.pin_admission, PinAdmission::Refused);
        assert!(!f.pin.exists());
        fs::write(&f.pin, b"malformed").unwrap();
        crate::platform::fs::secure_file(&f.pin).unwrap();
        assert_eq!(build_report(&f.repo, &f.pin).health, GateHealth::Red);
        assert_eq!(fs::read(&f.pin).unwrap(), b"malformed");
    }

    #[test]
    fn syntactically_valid_pin_metadata_tampering_requires_production_compare() {
        for (field, value) in [
            ("manifest_sha256", Value::from("0".repeat(64))),
            ("content_sha256", Value::from("0".repeat(64))),
            ("source_sha", Value::from("0".repeat(40))),
            ("version", Value::from("1.9.0")),
        ] {
            let f = Fixture::new(false);
            f.mutate_pin(field, value);
            assert!(Pin::read_private(&f.pin).is_ok());
            let report = build_report(&f.repo, &f.pin);
            assert_eq!(report.health, GateHealth::Red, "{field}");
            assert_eq!(report.diagnostic, Some(DiagnosticCode::PinMismatch));
            assert!(report.verified_metadata.is_none());
        }
    }

    #[test]
    fn tampered_fallback_policy_cannot_report_verified_integrity() {
        let f = Fixture::new(false);
        let mut policies: Value = serde_json::from_slice(&fs::read(&f.pin).unwrap()).unwrap();
        policies["event_policies"]["PreToolUse"] = "continue".into();
        f.mutate_pin("event_policies", policies["event_policies"].clone());
        assert!(Pin::read_private(&f.pin).is_ok());
        let report = build_report(&f.repo, &f.pin);
        assert_eq!(report.health, GateHealth::Red);
        assert_eq!(report.diagnostic, Some(DiagnosticCode::PinInvalid));
    }

    #[test]
    fn other_repository_subject_cannot_borrow_a_valid_pin() {
        let f = Fixture::new(false);
        let other = f.repo.parent().unwrap().join("other-repo");
        fs::create_dir(&other).unwrap();
        let report = build_report(&other, &f.pin);
        assert_eq!(report.health, GateHealth::Red);
        assert_eq!(report.diagnostic, Some(DiagnosticCode::PinMismatch));
    }

    #[test]
    fn changed_manifest_is_red_even_if_registry_resealed() {
        let f = Fixture::new(false);
        let path = f.repo.join(MANIFEST_FILE);
        let mut manifest: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        manifest["source_sha"] = "0".repeat(40).into();
        fs::write(path, sealed(manifest)).unwrap();
        assert_eq!(build_report(&f.repo, &f.pin).health, GateHealth::Red);
    }

    #[test]
    fn all_row_admissions_are_checked_including_continue_class() {
        for continue_class in [false, true] {
            let f = Fixture::new(continue_class);
            fs::write(f.repo.join(".claude/hooks/guard.js"), b"changed").unwrap();
            let report = build_report(&f.repo, &f.pin);
            assert_eq!(report.pin_admission, PinAdmission::Verified);
            assert_eq!(report.health, GateHealth::Red);
            assert_eq!(report.admitted_rows, 0);
            assert_eq!(report.refused_rows, 1);
            assert_eq!(
                report.rows[0].diagnostic,
                Some(DiagnosticCode::RowHashMismatch)
            );
            assert!(report.demoted_rows.is_empty());
            assert_eq!(report.exit_code(), 1);
        }
    }

    #[test]
    fn diagnosis_checks_other_events_and_does_not_stop_at_first_admitted_row() {
        let f = Fixture::new(false);
        let bytes = b"fixture bytes; never executed";
        let mut manifest = fixture(bytes);
        let mut second = manifest["hooks"][0].clone();
        second["file"] = ".claude/hooks/other.js".into();
        second["event"] = "PostToolUse".into();
        second["order"] = 11.into();
        second["on_incomplete"] = "continue".into();
        second["contract"]["protocol"]["kind"] = "context-injection".into();
        manifest["hooks"].as_array_mut().unwrap().push(second);
        fs::write(f.repo.join(".claude/hooks/other.js"), bytes).unwrap();
        fs::write(f.repo.join(MANIFEST_FILE), sealed(manifest)).unwrap();
        Pin::capture_operator(&f.repo)
            .unwrap()
            .write_private(&f.pin)
            .unwrap();
        assert_eq!(build_report(&f.repo, &f.pin).admitted_rows, 2);
        fs::write(f.repo.join(".claude/hooks/other.js"), b"changed").unwrap();
        let report = build_report(&f.repo, &f.pin);
        assert_eq!(report.health, GateHealth::Red);
        assert_eq!(report.admitted_rows, 1);
        assert_eq!(report.refused_rows, 1);
        assert_eq!(report.rows[1].event, Event::PostToolUse);
        assert_eq!(
            report.rows[1].diagnostic,
            Some(DiagnosticCode::RowHashMismatch)
        );
    }
}
