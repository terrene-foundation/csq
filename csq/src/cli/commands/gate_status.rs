//! Read-only `csq gate status --repo <repo> --pin <private-pin> [--json]`.
//! Explicit paths are inputs; neither paths nor raw filesystem errors are output.

use anyhow::{anyhow, Result};
use clap::Args;
use csq_core::gate::status::{self, GateStatusReport};
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct GateStatusArgs {
    /// Exact repository to compare against the private session pin.
    #[arg(long)]
    pub repo: PathBuf,
    /// Existing private session pin; diagnosis never creates or replaces it.
    #[arg(long)]
    pub pin: PathBuf,
    /// Optional immutable hook adapter manifest. When omitted, the sole
    /// installed versioned manifest under the repository is inspected.
    #[arg(long)]
    pub adapter_manifest: Option<PathBuf>,
}

/// Return integrity exit status; unknown activation is disclosed independently.
pub fn handle(args: &GateStatusArgs, json: bool) -> Result<i32> {
    let report =
        status::build_report_with_adapter(&args.repo, &args.pin, args.adapter_manifest.as_deref());
    let stdout = io::stdout();
    write_report(&report, json, &mut stdout.lock())?;
    Ok(report.exit_code())
}

pub fn write_report(report: &GateStatusReport, json: bool, out: &mut impl Write) -> Result<()> {
    if json {
        serde_json::to_writer(&mut *out, report)
            .map_err(|_| anyhow!("gate status output could not be encoded"))?;
        writeln!(out).map_err(|_| anyhow!("gate status output could not be written"))?;
    } else {
        // Render only the typed, bounded diagnostic projection; no source paths,
        // matcher strings, configuration values or arbitrary upstream messages.
        writeln!(out, "Gate integrity: {:?}", report.health)
            .and_then(|_| writeln!(out, "Pin admission: {:?}", report.pin_admission))
            .and_then(|_| {
                writeln!(
                    out,
                    "Adapter pin admission: {:?}",
                    report.adapter_pin.admission
                )
            })
            .and_then(|_| {
                writeln!(
                    out,
                    "Activation: UNKNOWN (no authenticated launcher observation)"
                )
            })
            .and_then(|_| writeln!(out, "Integrity grade: {}", report.integrity_grade))
            .map_err(|_| anyhow!("gate status output could not be written"))?;
        if let Some(metadata) = &report.verified_metadata {
            writeln!(out, "Pinned source: {}", metadata.source_sha)
                .and_then(|_| writeln!(out, "Registry version: {}", metadata.registry_version))
                .and_then(|_| writeln!(out, "Manifest SHA-256: {}", metadata.manifest_sha256))
                .and_then(|_| writeln!(out, "Content SHA-256: {}", metadata.content_sha256))
                .map_err(|_| anyhow!("gate status output could not be written"))?;
        }
        writeln!(
            out,
            "Adapter package: {:?} {:?}",
            report.adapter_pin.package, report.adapter_pin.version
        )
        .and_then(|_| {
            writeln!(
                out,
                "Adapter closure files: {:?}",
                report.adapter_pin.runtime_closure_files
            )
        })
        .and_then(|_| {
            writeln!(
                out,
                "Adapter dynamic-specifier review: {}",
                report.adapter_pin.dynamic_specifiers_review_required
            )
        })
        .map_err(|_| anyhow!("gate status output could not be written"))?;
        if let Some(code) = report.adapter_pin.diagnostic {
            writeln!(out, "Adapter diagnostic: {code:?}")
                .map_err(|_| anyhow!("gate status output could not be written"))?;
        }
        writeln!(
            out,
            "Rows: {} admitted, {} refused",
            report.admitted_rows, report.refused_rows
        )
        .and_then(|_| {
            writeln!(
                out,
                "Declared legacy rows (not observed fallback): {}",
                report.demoted_rows.len()
            )
        })
        .map_err(|_| anyhow!("gate status output could not be written"))?;
        if let Some(code) = report.diagnostic {
            writeln!(out, "Diagnostic: {code:?}")
                .map_err(|_| anyhow!("gate status output could not be written"))?;
        }
        for row in &report.rows {
            writeln!(
                out,
                "{} {:?}: admitted={} form={:?} diagnostic={:?}",
                row.id, row.event, row.admitted, row.declared_form, row.diagnostic
            )
            .map_err(|_| anyhow!("gate status output could not be written"))?;
        }
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
        args: GateStatusArgs,
        #[arg(long, global = true)]
        json: bool,
    }

    #[test]
    fn explicit_repo_and_pin_are_both_required_without_discovery() {
        assert!(Command::try_parse_from(["status"]).is_err());
        assert!(Command::try_parse_from(["status", "--repo", "repo"]).is_err());
        assert!(Command::try_parse_from(["status", "--pin", "pin"]).is_err());
        let parsed =
            Command::try_parse_from(["status", "--repo", "repo", "--pin", "pin", "--json"])
                .unwrap();
        assert_eq!(parsed.args.repo, PathBuf::from("repo"));
        assert_eq!(parsed.args.pin, PathBuf::from("pin"));
        assert!(parsed.json);
    }

    #[test]
    fn missing_pin_reports_red_unknown_without_echoing_input_paths() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("private-home-canary-repo");
        let pin = temp.path().join("private-home-canary-pin");
        let report = status::build_report(&repo, &pin);
        for json in [false, true] {
            let mut output = Vec::new();
            write_report(&report, json, &mut output).unwrap();
            let text = String::from_utf8(output).unwrap();
            assert!(!text.contains("private-home-canary"));
            assert!(!text.contains(temp.path().to_str().unwrap()));
            if json {
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                assert_eq!(value["health"], "red");
                assert_eq!(value["activation"], "unknown");
            } else {
                assert!(text.contains("Gate integrity: Red"));
                assert!(text.contains("Activation: UNKNOWN"));
            }
        }
        assert!(!pin.exists());
    }
}
