//! Single-use durable audit tickets. Persistence runs off the PTY pump; these
//! values never carry a descriptor or payload bytes across that boundary.

use super::control::{OwnerAdmission, RequestLease};
use super::owner::AuthorizedOwnerCommand;
use super::state::{EntryKind, RelayState, SlashCmd, Transaction, TxMetadata};
use super::types::InjectOutcome;
use super::writer::{BeforeWriteRefusal, WriterTerminalProof};
use crate::audit::{op_emit, persist::AuditV2Error, types::*};
use crate::sdk::SdkErrorCode;
use std::path::PathBuf;

pub(super) struct IntentInput {
    metadata: TxMetadata,
    owner: AuthorizedOwnerCommand,
    lease: RequestLease,
}

impl IntentInput {
    /// Consume a live immediate transaction's frame-bound owner admission.
    /// Raw owner provenance and an independent lease cannot enter this path.
    pub(super) fn capture(
        tx: &Transaction,
        gate: &RelayState,
        admission: OwnerAdmission,
    ) -> Result<Self, SdkErrorCode> {
        let (owner, lease) = admission.into_parts();
        let metadata = tx.audit_metadata(gate)?;
        if !metadata.immediate
            || metadata.kind != EntryKind::Slash(owner.command())
            || metadata.caller != owner.relay()
            || metadata.target != owner.target()
        {
            return Err(SdkErrorCode::NotAuthorized);
        }
        let lease = lease.clamp(owner.deadline());
        if lease.is_expired() {
            return Err(SdkErrorCode::RequestExpired);
        }
        Ok(Self {
            metadata,
            owner,
            lease,
        })
    }

    /// Blocking worker operation. Failure produces no writer capability.
    pub(super) fn persist(self, base: PathBuf) -> Result<PreparedIntent, SdkErrorCode> {
        let metadata = self.metadata;
        let EntryKind::Slash(slash) = metadata.kind else {
            return Err(SdkErrorCode::NotAuthorized);
        };
        let payload = SessionInjectPayload {
            inject_id: metadata.id,
            caller_pid: metadata.caller.pid,
            caller_started_at: metadata.caller.started_at,
            target_pid: metadata.target.pid,
            target_started_at: metadata.target.started_at,
            incarnation_unit: incarnation_unit()?,
            role: SessionInjectRole::Operator,
            primitive: SessionInjectPrimitive::Slash,
            slash: match slash {
                SlashCmd::Clear => SessionInjectSlash::Clear,
                SlashCmd::Compact => SessionInjectSlash::Compact,
            },
            byte_len: metadata.byte_len as u64,
            when: SessionInjectWhen::Immediate,
            outcome: SessionInjectOutcome::Intent,
            error_code: None,
        };
        let correlation =
            op_emit::gen_correlation_id().map_err(|_| SdkErrorCode::AuditUnavailable)?;
        op_emit::emit_session_inject(&base, payload.clone(), correlation.clone(), None)
            .map_err(|_| SdkErrorCode::AuditUnavailable)?;
        Ok(PreparedIntent {
            owner: self.owner,
            pending: PendingAudit {
                metadata,
                lease: self.lease,
                data: Some(AuditData {
                    base,
                    payload,
                    correlation,
                    #[cfg(test)]
                    settled: None,
                }),
            },
        })
    }
}

fn incarnation_unit() -> Result<SessionInjectIncarnationUnit, SdkErrorCode> {
    #[cfg(target_os = "linux")]
    {
        Ok(SessionInjectIncarnationUnit::LinuxTicks)
    }
    #[cfg(target_os = "macos")]
    {
        Ok(SessionInjectIncarnationUnit::MacosSeconds)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(SdkErrorCode::UnsupportedPlatform)
    }
}

/// Private fields, no Clone/Deserialize: only a successful durable append makes
/// a prepared intent, and the writer factory consumes it exactly once.
#[must_use = "consume the durable intent or let it settle as undetermined"]
pub(super) struct PreparedIntent {
    owner: AuthorizedOwnerCommand,
    pending: PendingAudit,
}

impl PreparedIntent {
    pub(super) fn into_parts(self) -> (AuthorizedOwnerCommand, PendingAudit) {
        (self.owner, self.pending)
    }
}

#[must_use = "an admitted intent needs a terminal audit result"]
pub(super) struct PendingAudit {
    metadata: TxMetadata,
    lease: RequestLease,
    data: Option<AuditData>,
}

struct AuditData {
    base: PathBuf,
    payload: SessionInjectPayload,
    correlation: RecordId,
    #[cfg(test)]
    settled: Option<std::sync::mpsc::Sender<bool>>,
}

impl PendingAudit {
    pub(super) const fn metadata(&self) -> TxMetadata {
        self.metadata
    }
    pub(super) fn lease(&self) -> RequestLease {
        self.lease.clone()
    }
    pub(super) fn result(mut self, proof: WriterTerminalProof) -> CapturedResult {
        let (metadata, mut outcome) = proof.into_parts();
        if metadata != self.metadata {
            outcome = InjectOutcome::Undetermined;
        }
        CapturedResult {
            data: self.data.take(),
            outcome,
        }
    }
    pub(super) fn reject(mut self, proof: BeforeWriteRefusal) -> CapturedResult {
        let (metadata, code) = proof.into_parts();
        let matches_intent = metadata == self.metadata;
        CapturedResult {
            data: self.data.take(),
            outcome: if !matches_intent || code == SdkErrorCode::Undetermined {
                InjectOutcome::Undetermined
            } else {
                InjectOutcome::Refused(code)
            },
        }
    }

    #[cfg(test)]
    pub(super) fn observe_settlement_for_test(&mut self) -> std::sync::mpsc::Receiver<bool> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.data
            .as_mut()
            .expect("unconsumed pending audit")
            .settled = Some(tx);
        rx
    }
}

impl Drop for PendingAudit {
    fn drop(&mut self) {
        // Revoke only this intent's child write lease, never the reply lease.
        self.lease.revoke();
        if let Some(data) = self.data.take() {
            settle_abandoned(data);
        }
    }
}

/// Owns only metadata: release the writer lock before persistence on a worker.
#[must_use = "persist the captured terminal result before returning a receipt"]
pub(super) struct CapturedResult {
    data: Option<AuditData>,
    outcome: InjectOutcome,
}

impl std::fmt::Debug for CapturedResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CapturedResult(<pending-audit>)")
    }
}

impl CapturedResult {
    /// No success receipt escapes before the durable terminal append. Failed
    /// persistence leaves an orphan intent, never an authorization to retry.
    pub(super) fn persist(mut self) -> InjectOutcome {
        match self.data.take() {
            Some(data) => persist_terminal(data, self.outcome),
            None => InjectOutcome::Undetermined,
        }
    }
}

impl Drop for CapturedResult {
    fn drop(&mut self) {
        if let Some(data) = self.data.take() {
            settle_abandoned(data);
        }
    }
}

fn settle_abandoned(data: AuditData) {
    // Drop can run on the byte pump: no signing, filesystem I/O, retry of input,
    // or join here. A process crash or failed spawn can leave an orphan intent.
    let dispatcher = tracing::dispatcher::get_default(Clone::clone);
    if std::thread::Builder::new()
        .name("relay-audit-abandoned".into())
        .spawn(move || {
            tracing::dispatcher::with_default(&dispatcher, || {
                let _ = persist_terminal(data, InjectOutcome::Undetermined);
            });
        })
        .is_err()
    {
        tracing::warn!("relay_audit_abandoned_worker_unavailable");
    }
}

fn persist_terminal(mut data: AuditData, mut terminal: InjectOutcome) -> InjectOutcome {
    let (outcome, code) = match terminal {
        InjectOutcome::DeliveredToPty => (SessionInjectOutcome::DeliveredToPty, None),
        InjectOutcome::Refused(code) => {
            let code = serde_json::to_value(code)
                .ok()
                .and_then(|v| serde_json::from_value(v).ok());
            if code.is_some() {
                (SessionInjectOutcome::Refused, code)
            } else {
                terminal = InjectOutcome::Undetermined;
                (SessionInjectOutcome::Undetermined, None)
            }
        }
        _ => {
            terminal = InjectOutcome::Undetermined;
            (SessionInjectOutcome::Undetermined, None)
        }
    };
    data.payload.outcome = outcome;
    data.payload.error_code = code;
    let result = if outcome == SessionInjectOutcome::DeliveredToPty {
        OpOutcome::Ok
    } else {
        OpOutcome::Failed {
            reason: op_emit::redact_reason("relay_terminal_failure"),
        }
    };
    let persisted = match op_emit::emit_session_inject(
        &data.base,
        data.payload,
        data.correlation,
        Some(result),
    ) {
        Ok(()) => true,
        Err(error) => {
            warn_terminal_persist_failed(&error);
            false
        }
    };
    #[cfg(test)]
    if let Some(settled) = data.settled {
        let _ = settled.send(persisted);
    }
    if persisted {
        terminal
    } else {
        InjectOutcome::Undetermined
    }
}

/// Trace only the closed variant name: error bodies may contain sensitive data.
fn warn_terminal_persist_failed(error: &AuditV2Error) {
    let variant = match error {
        AuditV2Error::Io(_) => "Io",
        AuditV2Error::Serialize(_) => "Serialize",
        AuditV2Error::ChainCorrupt { .. } => "ChainCorrupt",
        AuditV2Error::Signing { .. } => "Signing",
        AuditV2Error::ChainLockTimeout { .. } => "ChainLockTimeout",
        AuditV2Error::ChainBrokenRefuseAppend { .. } => "ChainBrokenRefuseAppend",
        AuditV2Error::Internal { .. } => "Internal",
        AuditV2Error::GenesisAlreadyExists => "GenesisAlreadyExists",
        AuditV2Error::PrecheckRefused => "PrecheckRefused",
    };
    tracing::warn!(
        error_kind = "relay_audit_terminal_persist_failed",
        audit_error_variant = variant,
        "relay audit terminal persistence failed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Duration;
    use tempfile::TempDir;

    const SENSITIVE: &str = "private-audit-fixture-body-path-key-nonce-do-not-log";

    #[derive(Default)]
    struct Fields(BTreeMap<String, String>);
    impl tracing::field::Visit for Fields {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().into(), value.into());
        }
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().into(), format!("{value:?}"));
        }
    }
    struct Capture(Arc<Mutex<Vec<Fields>>>);
    impl tracing::Subscriber for Capture {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            *metadata.level() == tracing::Level::WARN
        }
        fn register_callsite(
            &self,
            _: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            // Always consult the calling thread's dispatcher; do not depend on
            // a global subscriber, interest-cache rebuild or shared capture state.
            tracing::subscriber::Interest::sometimes()
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut fields = Fields::default();
            event.record(&mut fields);
            self.0.lock().unwrap().push(fields);
        }
    }
    fn captured() -> (tracing::Dispatch, Arc<Mutex<Vec<Fields>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        (tracing::Dispatch::new(Capture(events.clone())), events)
    }
    fn assert_closed(event: &Fields, variant: &str) {
        assert_eq!(
            event.0.keys().map(String::as_str).collect::<Vec<_>>(),
            ["audit_error_variant", "error_kind", "message"],
            "terminal_warning_fields_must_be_closed"
        );
        assert_eq!(event.0["error_kind"], "relay_audit_terminal_persist_failed");
        assert_eq!(
            event.0["audit_error_variant"], variant,
            "terminal_warning_variant_must_match_typed_error"
        );
        assert_eq!(
            event.0["message"],
            "relay audit terminal persistence failed"
        );
        assert!(
            event.0.values().all(|value| !value.contains(SENSITIVE)),
            "terminal_warning_must_not_log_error_body"
        );
    }
    struct FailedTerminal {
        _base: TempDir,
        result: CapturedResult,
        settled: mpsc::Receiver<bool>,
        path: PathBuf,
        intent: Vec<u8>,
    }
    fn failed_terminal() -> FailedTerminal {
        let base = TempDir::new().unwrap();
        let payload = SessionInjectPayload {
            inject_id: 1,
            caller_pid: 2,
            caller_started_at: 3,
            target_pid: 4,
            target_started_at: 5,
            incarnation_unit: if cfg!(target_os = "linux") {
                SessionInjectIncarnationUnit::LinuxTicks
            } else {
                SessionInjectIncarnationUnit::MacosSeconds
            },
            role: SessionInjectRole::Operator,
            primitive: SessionInjectPrimitive::Slash,
            slash: SessionInjectSlash::Clear,
            byte_len: 6,
            when: SessionInjectWhen::Immediate,
            outcome: SessionInjectOutcome::Intent,
            error_code: None,
        };
        let correlation = op_emit::gen_correlation_id().unwrap();
        op_emit::emit_session_inject(base.path(), payload.clone(), correlation.clone(), None)
            .unwrap();
        let path = base
            .path()
            .join("csq-runs")
            .join(format!("{}.jsonl", op_emit::load_chain_id(base.path())));
        let intent = std::fs::read(&path).unwrap();
        // Real terminal append refusal carrying a body that must never reach logs.
        std::fs::write(base.path().join("csq-runs/.chain-broken"), SENSITIVE).unwrap();
        let (tx, rx) = mpsc::channel();
        let result = CapturedResult {
            data: Some(AuditData {
                base: base.path().to_path_buf(),
                payload,
                correlation,
                settled: Some(tx),
            }),
            outcome: InjectOutcome::DeliveredToPty,
        };
        FailedTerminal {
            _base: base,
            result,
            settled: rx,
            path,
            intent,
        }
    }

    #[test]
    fn terminal_append_failure_warns_closed_variant_on_normal_persist() {
        let _env = crate::platform::test_env::lock();
        let FailedTerminal {
            _base,
            result,
            settled,
            path,
            intent,
        } = failed_terminal();
        let (dispatch, events) = captured();
        assert_eq!(
            tracing::dispatcher::with_default(&dispatch, || result.persist()),
            InjectOutcome::Undetermined
        );
        assert!(!settled.recv_timeout(Duration::from_secs(5)).unwrap());
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1, "terminal_persist_failure_must_warn_normal");
        assert_closed(&events[0], "ChainBrokenRefuseAppend");
        assert_eq!(
            std::fs::read(path).unwrap(),
            intent,
            "failed_terminal_must_retain_orphan_intent"
        );
    }

    #[test]
    fn terminal_append_failure_warns_closed_variant_on_abandoned_drop_worker() {
        let _env = crate::platform::test_env::lock();
        let FailedTerminal {
            _base,
            result,
            settled,
            path,
            intent,
        } = failed_terminal();
        let (dispatch, events) = captured();
        tracing::dispatcher::with_default(&dispatch, || drop(result));
        // The worker must carry this per-test dispatcher after the parent's
        // scoped default has ended; Drop itself never waits for persistence.
        assert!(!settled.recv_timeout(Duration::from_secs(5)).unwrap());
        let events = events.lock().unwrap();
        assert_eq!(
            events.len(),
            1,
            "terminal_persist_failure_must_warn_abandoned_worker"
        );
        assert_closed(&events[0], "ChainBrokenRefuseAppend");
        assert_eq!(
            std::fs::read(path).unwrap(),
            intent,
            "abandoned_failure_must_retain_orphan_intent"
        );
    }

    #[test]
    fn terminal_warning_uses_only_each_audit_error_variant_name() {
        let (dispatch, events) = captured();
        let errors = [
            (AuditV2Error::Io(std::io::Error::other(SENSITIVE)), "Io"),
            (
                AuditV2Error::Serialize(<serde_json::Error as serde::de::Error>::custom(SENSITIVE)),
                "Serialize",
            ),
            (
                AuditV2Error::ChainCorrupt {
                    reason: SENSITIVE.into(),
                },
                "ChainCorrupt",
            ),
            (
                AuditV2Error::Signing {
                    reason: SENSITIVE.into(),
                },
                "Signing",
            ),
            (
                AuditV2Error::ChainLockTimeout { deadline_secs: 5 },
                "ChainLockTimeout",
            ),
            (
                AuditV2Error::ChainBrokenRefuseAppend {
                    error_kind: SENSITIVE.into(),
                },
                "ChainBrokenRefuseAppend",
            ),
            (
                AuditV2Error::Internal {
                    reason: SENSITIVE.into(),
                },
                "Internal",
            ),
            (AuditV2Error::GenesisAlreadyExists, "GenesisAlreadyExists"),
            (AuditV2Error::PrecheckRefused, "PrecheckRefused"),
        ];
        tracing::dispatcher::with_default(&dispatch, || {
            for (error, _) in &errors {
                warn_terminal_persist_failed(error);
            }
        });
        let events = events.lock().unwrap();
        assert_eq!(
            events.len(),
            errors.len(),
            "every_terminal_error_variant_must_warn"
        );
        for (event, (_, expected)) in events.iter().zip(&errors) {
            assert_closed(event, expected);
        }
    }
}
