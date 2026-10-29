//! Internal updater error classification; no renderer command or alternate owner.
#[cfg(test)]
use serde::Serialize;

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
// The shared prefix is the point: these variants mirror the production
// `failure_tag` values asserted below ("update_signature_invalid" is also the
// literal returned by the `#[cfg(windows)]` tag function), so renaming them
// would decouple the test-only classification from the shipped tag vocabulary.
#[allow(clippy::enum_variant_names)]
enum UpdateError {
    UpdateCheckFailed,
    UpdateDownloadFailed,
    UpdateSignatureInvalid,
    UpdateInstallFailed,
}

// Match the pinned tauri-plugin-updater 2.12.0 Error enum. Never format its
// Display/Debug: payloads can contain URLs, signatures and private paths.
#[cfg(any(windows, test))]
fn updater_error_kind(error: &tauri_plugin_updater::Error) -> (&'static str, bool) {
    use tauri_plugin_updater::Error;
    match error {
        Error::EmptyEndpoints => ("empty_endpoints", false),
        Error::Io(_) => ("io", false),
        Error::Semver(_) => ("semver", false),
        Error::Serialization(_) => ("serialization", false),
        Error::ReleaseNotFound => ("release_not_found", false),
        Error::UnsupportedArch => ("unsupported_arch", false),
        Error::UnsupportedOs => ("unsupported_os", false),
        Error::FailedToDetermineExtractPath => ("extract_path", false),
        Error::UrlParse(_) => ("url_parse", false),
        Error::Reqwest(_) => ("reqwest", false),
        Error::TargetNotFound(_) => ("target_not_found", false),
        Error::TargetsNotFound(_) => ("targets_not_found", false),
        Error::Network(_) => ("network", false),
        Error::Minisign(_) => ("minisign", true),
        Error::Base64(_) => ("signature_base64", true),
        Error::SignatureUtf8(_) => ("signature_utf8", true),
        Error::TempDirNotOnSameMountPoint => ("temp_mount", false),
        Error::BinaryNotFoundInArchive => ("binary_not_found", false),
        Error::TempDirNotFound => ("temp_dir_not_found", false),
        Error::AuthenticationFailed => ("authentication_failed", false),
        Error::DebInstallFailed => ("deb_install_failed", false),
        Error::PackageInstallFailed => ("package_install_failed", false),
        Error::InvalidUpdaterFormat => ("invalid_updater_format", false),
        Error::Http(_) => ("http", false),
        Error::InvalidHeaderValue(_) => ("invalid_header_value", false),
        Error::InvalidHeaderName(_) => ("invalid_header_name", false),
        Error::FormatDate => ("format_date", false),
        Error::InsecureTransportProtocol => ("insecure_transport", false),
        Error::SignedVersionMismatch { .. } => ("signed_version_mismatch", true),
        Error::MissingSignedVersion => ("missing_signed_version", true),
        Error::Tauri(_) => ("tauri", false),
        // The upstream enum is non_exhaustive; future variants remain sanitized.
        _ => ("unknown_updater_error", false),
    }
}

#[cfg(test)]
fn updater_failure(
    stage: &'static str,
    error: &tauri_plugin_updater::Error,
    fallback: UpdateError,
) -> UpdateError {
    let (error_kind, signature_invalid) = updater_error_kind(error);
    tracing::warn!(stage, error_kind, "Windows update failed");
    if signature_invalid {
        UpdateError::UpdateSignatureInvalid
    } else {
        fallback
    }
}

#[cfg(any(windows, test))]
pub(super) fn install_returned(result: tauri_plugin_updater::Result<()>) -> Result<(), ()> {
    match result {
        Err(error) => {
            let (error_kind, _) = updater_error_kind(&error);
            tracing::warn!(stage = "install", error_kind, "Windows update failed");
        }
        // A successful Windows handoff exits. Returning Ok cannot certify it.
        Ok(()) => tracing::warn!(
            stage = "install",
            error_kind = "unexpected_return",
            "Windows update installer returned without exiting"
        ),
    }
    Err(())
}

#[cfg(windows)]
pub(super) fn failure_tag(
    stage: &'static str,
    error: &tauri_plugin_updater::Error,
    fallback: &'static str,
) -> &'static str {
    let (error_kind, signature_invalid) = updater_error_kind(error);
    tracing::warn!(stage, error_kind, "Windows update failed");
    if signature_invalid {
        "update_signature_invalid"
    } else {
        fallback
    }
}

#[cfg(test)]
mod updater_failure_tests {
    use super::*;
    use tauri_plugin_updater::Error;

    #[test]
    fn signature_variants_have_distinct_fixed_kinds_and_signature_code() {
        let cases = [
            (
                Error::Minisign(std::io::Error::other("private-path").into()),
                "minisign",
            ),
            (
                Error::Base64(base64::DecodeError::InvalidLength(1)),
                "signature_base64",
            ),
            (
                Error::SignatureUtf8("private-signature".into()),
                "signature_utf8",
            ),
            (
                Error::SignedVersionMismatch {
                    signed: "private-signed".into(),
                    announced: "private-announced".into(),
                },
                "signed_version_mismatch",
            ),
            (Error::MissingSignedVersion, "missing_signed_version"),
        ];
        for (error, kind) in cases {
            assert_eq!(updater_error_kind(&error), (kind, true));
            assert_eq!(
                updater_failure("download", &error, UpdateError::UpdateDownloadFailed),
                UpdateError::UpdateSignatureInvalid
            );
            assert_eq!(
                serde_json::to_string(&updater_failure(
                    "download",
                    &error,
                    UpdateError::UpdateDownloadFailed
                ))
                .unwrap(),
                "\"update_signature_invalid\""
            );
        }
    }

    #[test]
    fn network_and_io_keep_stage_codes_and_never_reuse_payload_as_kind() {
        for (error, kind) in [
            (
                Error::Network("https://private-token/path".into()),
                "network",
            ),
            (
                Error::Io(std::io::Error::other("C:/private-token/path")),
                "io",
            ),
        ] {
            assert_eq!(updater_error_kind(&error), (kind, false));
            for (stage, expected) in [
                ("builder", UpdateError::UpdateCheckFailed),
                ("check", UpdateError::UpdateCheckFailed),
                ("download", UpdateError::UpdateDownloadFailed),
                ("install", UpdateError::UpdateInstallFailed),
            ] {
                assert_eq!(updater_failure(stage, &error, expected), expected);
            }
        }
    }

    #[test]
    fn installer_errors_and_unexpected_success_both_require_recovery() {
        assert_eq!(
            install_returned(Err(Error::Network("private-token".into()))),
            Err(())
        );
        assert_eq!(install_returned(Ok(())), Err(()));
    }

    #[test]
    fn failure_logs_record_fixed_stage_and_kind_without_error_payloads() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        #[derive(Clone)]
        struct Log(Arc<Mutex<Vec<u8>>>);
        impl Write for Log {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = Log(bytes.clone());
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || writer.clone())
            .finish();
        let _capture = csq_core::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            for stage in ["builder", "check", "download"] {
                updater_failure(
                    stage,
                    &Error::Network("private-token".into()),
                    UpdateError::UpdateDownloadFailed,
                );
            }
            assert_eq!(
                install_returned(Err(Error::Io(std::io::Error::other("private-path")))),
                Err(())
            );
            updater_failure(
                "download",
                &Error::SignatureUtf8("private-signature".into()),
                UpdateError::UpdateDownloadFailed,
            );
        });
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        for stage in ["builder", "check", "download", "install"] {
            assert!(
                output.contains(&format!("stage=\"{stage}\"")),
                "missing stage: {stage}"
            );
        }
        for kind in ["network", "io", "signature_utf8"] {
            assert!(
                output.contains(&format!("error_kind=\"{kind}\"")),
                "missing kind: {kind}"
            );
        }
        assert!(!output.contains("private-"), "updater error payload leaked");
    }
}
