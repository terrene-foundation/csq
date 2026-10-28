//! Observations of the existing admitted per-row execution path.
//! A returned row result is not an independent process-count measurement.

use super::gate_row_audit::AuditWriter;
use csq_core::gate::dispatch::{RowFailure, RowOutput, RowRequest, RowRunner};
use csq_core::gate::registry::{self, Event};
use serde_json::json;
use std::io;

pub(crate) struct RowObserver<R> {
    inner: R,
    audit: Option<AuditWriter>,
    event: Event,
    payload_sha256: String,
    failed: bool,
}

impl<R> RowObserver<R> {
    pub(crate) fn new(
        inner: R,
        audit: Option<AuditWriter>,
        event: Event,
        payload_sha256: String,
    ) -> Self {
        Self {
            inner,
            audit,
            event,
            payload_sha256,
            failed: false,
        }
    }

    pub(crate) fn finish(self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "row audit incomplete",
            ));
        }
        if let Some(audit) = self.audit {
            audit.complete()?;
        }
        Ok(())
    }
}

impl<R: RowRunner> RowRunner for RowObserver<R> {
    fn run(&mut self, request: RowRequest<'_>) -> Result<RowOutput, RowFailure> {
        // Once evidence custody fails, do not run later rows or emit completion.
        if self.failed {
            return Err(RowFailure::DemotionLedger);
        }
        if self.audit.is_none() {
            return self.inner.run(request);
        }
        let row_id = request.row.id.clone();
        let source_sha256 = registry::sha256(request.source.as_bytes());
        let cwd_sha256 = registry::sha256(request.cwd.as_os_str().as_encoded_bytes());
        let pool = match request.row.pool {
            csq_core::gate::registry::Pool::Template => "template",
            csq_core::gate::registry::Pool::Repo => "repo",
        };
        let result = self.inner.run(request);
        let mut record = json!({
            "type": "row",
            "event": self.event.as_str(),
            "pool": pool,
            "row_id": row_id,
            "source_sha256": source_sha256,
            "payload_sha256": self.payload_sha256,
            "cwd_sha256": cwd_sha256,
        });
        match &result {
            Ok(output) => {
                record["status"] = "executed".into();
                record["exit_code"] = output.exit_code.into();
                record["stdout_bytes"] = output.stdout.len().into();
                record["stdout_sha256"] = registry::sha256(&output.stdout).into();
                record["stderr_bytes"] = output.stderr.len().into();
                record["stderr_sha256"] = registry::sha256(&output.stderr).into();
            }
            Err(failure) => {
                record["status"] = match failure {
                    RowFailure::Crash => "crash",
                    RowFailure::Timeout => "timeout",
                    RowFailure::Incomplete => "incomplete",
                    RowFailure::DemotionLedger => "refused",
                }
                .into();
            }
        }
        if self
            .audit
            .as_mut()
            .expect("audit present")
            .record(&record)
            .is_err()
        {
            self.failed = true;
            // This failure must not pass through a Continue-on-incomplete rule.
            return Err(RowFailure::DemotionLedger);
        }
        result
    }
}
