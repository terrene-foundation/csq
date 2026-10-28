//! `csq sessions disk-report [--json]`: inspect lifecycle evidence without mutation.
use anyhow::Result;
use csq_core::sdk::{self, session_disk::*, Envelope, SCHEMA_SESSION_DISK_V1};
use csq_core::sessions::lifecycle_report::{self, LifecycleReport};
use std::io::Write;
use std::path::Path;

const EXIT_CODE_SESSION_DISK_UNDETERMINED: i32 = 5;

fn payload(report: LifecycleReport) -> SessionDiskPayload {
    SessionDiskPayload {
        complete: report.complete,
        reasons: report.reasons,
        rows: report
            .rows
            .into_iter()
            .map(|row| SessionDiskRow {
                generation: row.generation,
                pid: row.pid,
                session_id: row.session_id,
                scratch_dir: row.scratch_dir.map(|p| p.to_string_lossy().into_owned()),
                state: row.state,
                decision: row.decision,
                reasons: row.reasons,
            })
            .collect(),
    }
}

pub fn handle(base: &Path, json: bool) -> Result<i32> {
    let report = payload(lifecycle_report::report(base));
    let exit_code = if report.complete {
        0
    } else {
        EXIT_CODE_SESSION_DISK_UNDETERMINED
    };
    if json {
        sdk::emit(&Envelope::verdict(
            SCHEMA_SESSION_DISK_V1,
            None,
            report.complete,
            report,
        ))?;
        return Ok(exit_code);
    }
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    writeln!(
        output,
        "Lifecycle evidence: {} records; complete={}",
        report.rows.len(),
        report.complete
    )?;
    for row in &report.rows {
        writeln!(
            output,
            "{} pid={} {} {}",
            row.generation, row.pid, row.state, row.decision
        )?;
    }
    writeln!(
        output,
        "Scratch retirement: KEEP; open handles, session union and keep policy remain unknown."
    )?;
    output.flush()?;
    Ok(exit_code)
}

#[cfg(test)]
#[path = "sessions_disk_tests.rs"]
mod tests;
