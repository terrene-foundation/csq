//! Pure lifecycle evidence report. Open-holder and complete-resume oracles remain Unknown.
#[cfg(unix)]
use super::lifecycle::{probe_process, scratch_path, ProcessProbe};
#[cfg(unix)]
use super::lifecycle_records::{self as private, *};
use serde::Serialize;
#[cfg(unix)]
use std::io;
use std::path::{Path, PathBuf};
#[derive(Debug, Serialize)]
pub struct LifecycleRow {
    pub generation: String,
    pub pid: u32,
    pub session_id: Option<String>,
    pub scratch_dir: Option<PathBuf>,
    pub state: String,
    pub decision: &'static str,
    pub reasons: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct LifecycleReport {
    pub schema: &'static str,
    pub complete: bool,
    pub rows: Vec<LifecycleRow>,
    pub reasons: Vec<&'static str>,
}

pub fn report(base: &Path) -> LifecycleReport {
    let mut report = LifecycleReport {
        schema: "csq.session-disk.v1",
        complete: false,
        rows: vec![],
        reasons: vec![
            "open_handles_unknown",
            "current_session_union_unknown",
            "keep_protocol_unknown",
        ],
    };
    #[cfg(unix)]
    {
        let outcome = (|| -> io::Result<()> {
            let store = private::store(base, false)?;
            // `lock_shared` marks the Dir, so its drop unlocks explicitly.
            if let Err(error) = private::lock_shared(&store) {
                // Classify at the lock syscall: unrelated IO refusal is not contention.
                report.reasons.push("store_lock_refused");
                return Err(error);
            }
            for name in store.names()? {
                let d = store.child(&name, false)?;
                let l: Launch = d.read("launch")?.ok_or_else(invalid)?;
                validate_launch(&l, &name)?;
                let binding: Option<Binding> = d.read("binding")?;
                let end: Option<End> = d.read("ended")?;
                let cancelled = d.read::<End>("cancelled")?;
                let invalidated = d.read::<End>("invalidated")?;
                validate_event(
                    end.as_ref(),
                    &l,
                    &["direct_wait", "raw_esrch", "incarnation_replaced"],
                )?;
                validate_event(cancelled.as_ref(), &l, &["exec_failed"])?;
                validate_event(invalidated.as_ref(), &l, &["binding_changed"])?;
                let cancelled = cancelled.is_some();
                let invalidated = invalidated.is_some();
                let mut reasons = vec![
                    "open_handles_unknown",
                    "current_session_union_unknown",
                    "keep_protocol_unknown",
                ];
                if binding.is_none() {
                    reasons.push("scratch_binding_unproved");
                }
                if end.is_none() {
                    reasons.push("positive_end_unproved");
                }
                if invalidated {
                    reasons.push("binding_changed");
                }
                if cancelled {
                    reasons.push("launch_cancelled");
                }
                if probe_process(l.pid) == ProcessProbe::Unknown {
                    reasons.push("process_probe_unknown");
                }
                if let Some(b) = &binding {
                    if !valid_uuid(&b.uuid)
                        || b.observed < l.created
                        || b.observed > now().ok_or_else(invalid)?
                        || b.scratch != scratch_path(&l, &b.uuid, &scratch_tmp())
                        || private::identity(&b.scratch).ok() != Some((b.dev, b.ino))
                    {
                        reasons.push("scratch_identity_unproved");
                    }
                }
                report.rows.push(LifecycleRow {
                    generation: name,
                    pid: l.pid,
                    session_id: binding.as_ref().map(|b| b.uuid.clone()),
                    scratch_dir: binding.map(|b| b.scratch),
                    state: if cancelled {
                        "cancelled"
                    } else if end.is_some() {
                        "ended"
                    } else {
                        "launched"
                    }
                    .into(),
                    decision: "KEEP",
                    reasons,
                });
            }
            Ok(())
        })();
        if outcome.is_ok() {
            report.complete = true;
        } else {
            report.reasons.push("lifecycle_store_unknown");
            tracing::warn!(
                error_kind = "lifecycle_report_failed",
                "lifecycle evidence report incomplete"
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = base;
        report.reasons.push("platform_unsupported");
    }
    report
}
#[cfg(test)]
#[path = "lifecycle_report_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "lifecycle_report_diagnostics_tests.rs"]
mod diagnostics_tests;
