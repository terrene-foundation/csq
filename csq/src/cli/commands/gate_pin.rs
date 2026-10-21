//! Explicit operator pin creation. The expected raw digest is reviewed outside
//! the subject; no implicit capture or signature-to-hash downgrade is permitted.
use anyhow::{anyhow, Result};
use clap::Args;
use csq_core::gate::pin::{IntegrityPolicy, Pin, PinError};
use serde::Serialize;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct GatePinArgs {
    /// Exact repository whose registry and declared files were reviewed.
    #[arg(long)]
    pub repo: PathBuf,
    /// Private pin destination outside the repository; its parent must exist.
    #[arg(long)]
    pub pin: PathBuf,
    /// Independently reviewed SHA-256 of the raw hook-registry.json bytes.
    #[arg(long)]
    pub expected_manifest_sha256: String,
    /// Require signed attestation. Refuses until Loom's verifier is configured.
    #[arg(long)]
    pub require_signature: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum PinResult {
    Created,
    Refused,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Diagnostic {
    OperatorHash,
    SignatureNotConfigured,
    AnchorNotConfigured,
    AdmissionRefused,
}

#[derive(Debug, Serialize)]
struct Receipt {
    pin: PinResult,
    diagnostic: Diagnostic,
}

fn create(args: &GatePinArgs) -> Result<Pin, PinError> {
    let integrity = if args.require_signature {
        IntegrityPolicy::RequireSignature
    } else {
        IntegrityPolicy::Hash
    };
    let pin = Pin::capture_operator_bound(&args.repo, &args.expected_manifest_sha256, integrity)?;
    // Reuse the private 0600 no-follow writer; it refuses repository-local
    // destinations and unsupported platforms, and never creates the parent.
    pin.write_private(&args.pin)?;
    Ok(pin)
}

pub fn handle(args: &GatePinArgs, json: bool) -> Result<i32> {
    let (receipt, code) = match create(args) {
        Ok(_) => (
            Receipt {
                pin: PinResult::Created,
                diagnostic: Diagnostic::OperatorHash,
            },
            0,
        ),
        Err(error) => (
            Receipt {
                pin: PinResult::Refused,
                diagnostic: match error {
                    PinError::SignatureUnavailable => Diagnostic::SignatureNotConfigured,
                    PinError::TrustUnset => Diagnostic::AnchorNotConfigured,
                    _ => Diagnostic::AdmissionRefused,
                },
            },
            2,
        ),
    };
    let stdout = io::stdout();
    write_receipt(&receipt, json, &mut stdout.lock())?;
    Ok(code)
}

fn write_receipt(receipt: &Receipt, json: bool, out: &mut impl Write) -> Result<()> {
    if json {
        serde_json::to_writer(&mut *out, receipt)
            .map_err(|_| anyhow!("gate pin receipt could not be encoded"))?;
        writeln!(out).map_err(|_| anyhow!("gate pin receipt could not be written"))?;
    } else {
        writeln!(out, "Gate pin: {:?}; {:?}", receipt.pin, receipt.diagnostic)
            .map_err(|_| anyhow!("gate pin receipt could not be written"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        args: GatePinArgs,
    }

    #[test]
    fn pin_requires_all_three_operator_inputs() {
        for args in [
            vec!["pin"],
            vec!["pin", "--repo", "repo", "--pin", "pin"],
            vec![
                "pin",
                "--repo",
                "repo",
                "--expected-manifest-sha256",
                "digest",
            ],
            vec![
                "pin",
                "--pin",
                "pin",
                "--expected-manifest-sha256",
                "digest",
            ],
        ] {
            assert!(Command::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn required_signature_refuses_before_any_artifact_write() {
        let temp = tempfile::tempdir().unwrap();
        let args = GatePinArgs {
            repo: temp.path().join("untrusted-subject"),
            pin: temp.path().join("pin"),
            expected_manifest_sha256: "a".repeat(64),
            require_signature: true,
        };
        assert!(matches!(create(&args), Err(PinError::SignatureUnavailable)));
        assert!(!args.pin.exists());
        assert!(!args.repo.exists());
    }

    #[test]
    fn fixed_receipts_do_not_echo_untrusted_paths_or_errors() {
        for diagnostic in [
            Diagnostic::OperatorHash,
            Diagnostic::SignatureNotConfigured,
            Diagnostic::AnchorNotConfigured,
            Diagnostic::AdmissionRefused,
        ] {
            let receipt = Receipt {
                pin: PinResult::Refused,
                diagnostic,
            };
            for json in [false, true] {
                let mut bytes = Vec::new();
                write_receipt(&receipt, json, &mut bytes).unwrap();
                let text = String::from_utf8(bytes).unwrap();
                assert!(!text.contains('/'));
                if json {
                    assert_eq!(
                        serde_json::from_str::<serde_json::Value>(&text).unwrap()["pin"],
                        "refused"
                    );
                }
            }
        }
    }
}
