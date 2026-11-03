//! Control-plane adapter for the PTY observer (spec 34, shard 1).
//!
//! This adapter has no master descriptor, writer or transaction constructor.
//! It authenticates owner command envelopes and returns a fixed refusal while
//! the production slash cells and input-loop integration remain unavailable.
//! It does not register a launch arm or convert a peer message into input.

use super::control::{ControlRequest, ControlServer};
use super::owner::{OwnerAuthError, OwnerVerifier, WireOwnerCommand};
use super::pty::{RelayChildIdentity, RelayExit, RelayObserver};
use super::state::SlashTable;
use super::types::{CliKind, InjectOutcome, SessionIdentity};
use crate::sdk::SdkErrorCode;
use std::io;
use std::path::PathBuf;
use std::sync::mpsc::TryRecvError;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

type WallClock = fn() -> Option<u64>;

/// Public binding data for trusted daemon integration. The generation binds
/// envelopes to this verifier; it is not a signing key or an authorization.
#[derive(Clone, Copy)]
pub struct ControlBinding {
    pub target: SessionIdentity,
    pub relay: SessionIdentity,
    pub generation: [u8; 32],
}

fn wall_clock_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis()
        .try_into()
        .ok()
}

/// Library-side control adapter. Only trusted local launch code supplies the
/// key and private handle directory. Neither can be chosen over the socket.
/// Launch arms do not yet construct this adapter; slash cells remain closed.
pub struct ControlLoop {
    handle_dir: PathBuf,
    cli: CliKind,
    key: Option<Zeroizing<[u8; 32]>>,
    verifier: Option<OwnerVerifier>,
    server: Option<ControlServer>,
    now: WallClock,
}

impl ControlLoop {
    /// Prepare an adapter without binding or starting a thread. Binding occurs
    /// after the shim has forked the actual CLI, in `child_started`.
    /// Key ownership stays inside its zeroizing wrapper across this handoff.
    pub fn new(handle_dir: PathBuf, cli: CliKind, key: Zeroizing<[u8; 32]>) -> Self {
        Self {
            handle_dir,
            cli,
            key: Some(key),
            verifier: None,
            server: None,
            now: wall_clock_ms,
        }
    }

    /// Disabling revokes this verifier's tokens. There is no socket operation
    /// for enabling the adapter or changing its generation.
    pub fn disable(&mut self) {
        if let Some(verifier) = self.verifier.as_mut() {
            verifier.disable();
        }
    }

    /// Available only after the actual CLI incarnation has been observed.
    /// Discovery/publication of this data is separate launch integration work.
    pub fn binding(&self) -> Option<ControlBinding> {
        let verifier = self.verifier.as_ref()?;
        Some(ControlBinding {
            target: verifier.target(),
            relay: verifier.relay(),
            generation: verifier.generation(),
        })
    }

    fn stop(&mut self) {
        self.disable();
        self.server.take();
        self.verifier.take();
        self.key.take();
    }
}

impl RelayObserver for ControlLoop {
    fn child_started(&mut self, child: RelayChildIdentity) -> io::Result<()> {
        if self.server.is_some() || self.verifier.is_some() {
            return Err(io::Error::other("relay_control_already_started"));
        }
        let relay_pid = std::process::id();
        let relay_start = super::pty::process_identity_start(relay_pid)
            .ok_or_else(|| io::Error::other("relay_control_identity_unavailable"))?;
        let key = self
            .key
            .take()
            .ok_or_else(|| io::Error::other("relay_control_key_unavailable"))?;
        let verifier = OwnerVerifier::new(
            key,
            child.cli(),
            SessionIdentity {
                pid: relay_pid,
                started_at: relay_start,
            },
        )
        .map_err(|_| io::Error::other("relay_control_authority_unavailable"))?;
        // This runs after CLI fork/identity validation. No transport thread is
        // present during the shim's fork boundary.
        let server = ControlServer::bind(&self.handle_dir)?;
        self.verifier = Some(verifier);
        self.server = Some(server);
        Ok(())
    }

    fn poll_tick(&mut self) -> io::Result<()> {
        let (Some(server), Some(verifier)) = (&self.server, self.verifier.as_mut()) else {
            return Err(io::Error::other("relay_control_not_started"));
        };
        // A finite drain per pump edge. Client reads and writes remain on the
        // transport workers; reply only posts a bounded response to a channel.
        for _ in 0..4 {
            let request = match server.try_recv() {
                Ok(request) => request,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    return Err(io::Error::other("relay_control_disconnected"));
                }
            };
            let outcome = request_outcome(verifier, self.cli, &request, (self.now)());
            // A disconnected client cannot turn a completed refusal into a
            // relay failure. There were no master writes or queued commands.
            let _ = request.reply(response(outcome));
        }
        Ok(())
    }

    fn child_exited(&mut self, _exit: RelayExit) {
        self.stop();
    }
}

impl Drop for ControlLoop {
    fn drop(&mut self) {
        // Also covers observer/PTY errors, where no exit status was observed.
        self.stop();
    }
}

fn request_outcome(
    verifier: &mut OwnerVerifier,
    cli: CliKind,
    request: &ControlRequest,
    now_ms: Option<u64>,
) -> InjectOutcome {
    // Queueing cannot renew the transport's original absolute deadline. Check
    // before entering the verifier: even a refusal there can consume replay or
    // clock high-water state while the waiting client already observed failure.
    if request.is_expired() {
        return InjectOutcome::Refused(SdkErrorCode::RequestExpired);
    }
    if !request.peer_is_live() {
        return InjectOutcome::Undetermined;
    }
    if request.is_expired() {
        return InjectOutcome::Refused(SdkErrorCode::RequestExpired);
    }
    let outcome = owner_request(verifier, cli, request.line(), now_ms);
    if request.peer_is_live() {
        outcome
    } else {
        InjectOutcome::Undetermined
    }
}

fn owner_request(
    verifier: &mut OwnerVerifier,
    cli: CliKind,
    line: &[u8],
    now_ms: Option<u64>,
) -> InjectOutcome {
    // CLI kind is supplied by trusted launch code until the launch seam is
    // wired. Independently refuse Codex here, before consuming any authority.
    if cli == CliKind::Codex {
        return InjectOutcome::Refused(SdkErrorCode::InputRejected);
    }
    let wire = match serde_json::from_slice::<WireOwnerCommand>(line) {
        Ok(wire) => wire,
        Err(_) => return InjectOutcome::Refused(SdkErrorCode::NotAuthorized),
    };
    let token = match verifier.verify(wire, now_ms) {
        Ok(token) => token,
        Err(error) => return auth_refusal(error),
    };
    let command = match verifier.authorize_delivery(token, now_ms) {
        Ok(command) => command,
        Err(error) => return auth_refusal(error),
    };
    match SlashTable::availability(cli, command) {
        Err(code) => InjectOutcome::Refused(code),
        // Even a future measured cell does not open a path around the
        // classifier, permission latch, foreground and transaction gates.
        Ok(()) => InjectOutcome::Refused(SdkErrorCode::IdleSignalUnavailable),
    }
}

fn auth_refusal(error: OwnerAuthError) -> InjectOutcome {
    match error {
        OwnerAuthError::Disabled => InjectOutcome::Refused(SdkErrorCode::DisabledByOperator),
        OwnerAuthError::Expired => InjectOutcome::Refused(SdkErrorCode::RequestExpired),
        OwnerAuthError::ClockUnavailable | OwnerAuthError::GenerationUnavailable => {
            InjectOutcome::Undetermined
        }
        OwnerAuthError::Invalid | OwnerAuthError::Replay => {
            InjectOutcome::Refused(SdkErrorCode::NotAuthorized)
        }
    }
}

fn response(outcome: InjectOutcome) -> &'static [u8] {
    match outcome {
        InjectOutcome::Refused(SdkErrorCode::CliUnmeasured) => {
            b"{\"outcome\":\"refused\",\"error\":{\"code\":\"cli_unmeasured\"}}"
        }
        InjectOutcome::Refused(SdkErrorCode::DisabledByOperator) => {
            b"{\"outcome\":\"refused\",\"error\":{\"code\":\"disabled_by_operator\"}}"
        }
        InjectOutcome::Refused(SdkErrorCode::RequestExpired) => {
            b"{\"outcome\":\"refused\",\"error\":{\"code\":\"request_expired\"}}"
        }
        InjectOutcome::Refused(SdkErrorCode::IdleSignalUnavailable) => {
            b"{\"outcome\":\"refused\",\"error\":{\"code\":\"idle_signal_unavailable\"}}"
        }
        InjectOutcome::Refused(SdkErrorCode::ChainUnsupported) => {
            b"{\"outcome\":\"refused\",\"error\":{\"code\":\"chain_unsupported\"}}"
        }
        InjectOutcome::Refused(SdkErrorCode::InputRejected) => {
            b"{\"outcome\":\"refused\",\"error\":{\"code\":\"input_rejected\"}}"
        }
        InjectOutcome::Undetermined => b"{\"outcome\":\"undetermined\"}",
        // Fixed deny even if a future internal outcome reaches this adapter;
        // never serialize a success that this no-writer shard cannot establish.
        _ => b"{\"outcome\":\"refused\",\"error\":{\"code\":\"not_authorized\"}}",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::owner::{mint, OwnerCommand, OwnerCommandFields};

    const KEY: [u8; 32] = [0x39; 32];
    const NOW: u64 = 100_000;

    fn verifier() -> OwnerVerifier {
        OwnerVerifier::new(
            Zeroizing::new(KEY),
            SessionIdentity {
                pid: 11,
                started_at: 22,
            },
            SessionIdentity {
                pid: 33,
                started_at: 44,
            },
        )
        .unwrap()
    }

    fn wire(verifier: &OwnerVerifier, command: OwnerCommand) -> serde_json::Value {
        serde_json::to_value(
            mint(
                OwnerCommandFields {
                    version: 1,
                    target_pid: verifier.target().pid,
                    target_started_at: verifier.target().started_at,
                    relay_pid: verifier.relay().pid,
                    relay_started_at: verifier.relay().started_at,
                    generation: verifier.generation(),
                    update_id: 7,
                    issued_at_ms: NOW - 1,
                    expires_at_ms: NOW + 1000,
                    command,
                },
                &KEY,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn verified_owner_slashes_remain_closed_for_every_production_cli() {
        for cli in [CliKind::Claude, CliKind::Unknown] {
            for command in [OwnerCommand::Clear, OwnerCommand::Compact] {
                let mut verifier = verifier();
                let line = serde_json::to_vec(&wire(&verifier, command)).unwrap();
                assert_eq!(
                    owner_request(&mut verifier, cli, &line, Some(NOW)),
                    InjectOutcome::Refused(SdkErrorCode::CliUnmeasured),
                    "owner provenance cannot open an unmeasured cell"
                );
                assert_eq!(
                    owner_request(&mut verifier, cli, &line, Some(NOW)),
                    InjectOutcome::Refused(SdkErrorCode::NotAuthorized),
                    "even a refused authenticated command consumes its replay identity"
                );
            }
        }
    }

    #[test]
    fn expired_dequeued_request_preserves_replay_and_clock_high_water() {
        let mut verifier = verifier();
        let line = serde_json::to_vec(&wire(&verifier, OwnerCommand::Clear)).unwrap();
        let pid = std::process::id();
        let peer = SessionIdentity {
            pid,
            started_at: super::super::pty::process_identity_start(pid).unwrap(),
        };
        let deadline = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_millis(1))
            .unwrap();
        let request = ControlRequest::for_test(peer, line.clone(), deadline);
        let (send, incoming) = std::sync::mpsc::sync_channel(1);
        assert!(send.try_send(request).is_ok());
        let request = incoming.try_recv().unwrap();
        assert!(request.is_expired());
        assert_eq!(
            request_outcome(&mut verifier, CliKind::Claude, &request, Some(NOW + 50)),
            InjectOutcome::Refused(SdkErrorCode::RequestExpired),
            "expired dequeued transport request must be refused before verification"
        );
        assert_eq!(
            owner_request(&mut verifier, CliKind::Claude, &line, Some(NOW)),
            InjectOutcome::Refused(SdkErrorCode::CliUnmeasured),
            "expired dequeue must preserve both replay identity and clock high-water"
        );
    }

    #[test]
    fn codex_owner_request_refuses_without_consuming_authority() {
        let mut verifier = verifier();
        let line = serde_json::to_vec(&wire(&verifier, OwnerCommand::Clear)).unwrap();
        assert_eq!(
            owner_request(&mut verifier, CliKind::Codex, &line, Some(NOW + 50)),
            InjectOutcome::Refused(SdkErrorCode::InputRejected),
            "caller-supplied Codex kind must be refused before owner verification"
        );
        assert_eq!(
            owner_request(&mut verifier, CliKind::Codex, b"invalid-wire", None),
            InjectOutcome::Refused(SdkErrorCode::InputRejected)
        );
        assert_eq!(
            owner_request(&mut verifier, CliKind::Claude, &line, Some(NOW)),
            InjectOutcome::Refused(SdkErrorCode::CliUnmeasured),
            "Codex refusal must preserve replay identity and clock high-water"
        );
    }

    #[test]
    fn adapter_preserves_chain_and_input_refusal_wire_codes() {
        for (code, expected) in [
            (SdkErrorCode::ChainUnsupported, "chain_unsupported"),
            (SdkErrorCode::InputRejected, "input_rejected"),
        ] {
            let value: serde_json::Value =
                serde_json::from_slice(response(InjectOutcome::Refused(code))).unwrap();
            assert_eq!(value["outcome"], "refused");
            assert_eq!(
                value["error"]["code"], expected,
                "closed response must preserve the explicit refusal code"
            );
        }
    }

    #[test]
    fn forged_origin_and_command_arguments_do_not_become_authority() {
        let mut verifier = verifier();
        for line in [
            br#"{"origin":"OwnerTelegram","command":"clear"}"#.as_slice(),
            br#"{"role":"operator","slash":"compact","text":"anything"}"#,
        ] {
            assert_eq!(
                owner_request(&mut verifier, CliKind::Claude, line, Some(NOW)),
                InjectOutcome::Refused(SdkErrorCode::NotAuthorized)
            );
        }
        let valid = wire(&verifier, OwnerCommand::Clear);
        for (field, value) in [
            ("command", serde_json::json!("clear anything")),
            ("target_pid", serde_json::json!(99)),
            ("relay_started_at", serde_json::json!(999)),
            ("enable", serde_json::json!(true)),
        ] {
            let mut hostile = valid.clone();
            hostile["fields"][field] = value;
            assert_eq!(
                owner_request(
                    &mut verifier,
                    CliKind::Claude,
                    &serde_json::to_vec(&hostile).unwrap(),
                    Some(NOW)
                ),
                InjectOutcome::Refused(SdkErrorCode::NotAuthorized)
            );
        }
        assert_eq!(
            owner_request(
                &mut verifier,
                CliKind::Claude,
                &serde_json::to_vec(&valid).unwrap(),
                Some(NOW)
            ),
            InjectOutcome::Refused(SdkErrorCode::CliUnmeasured)
        );
    }

    #[test]
    fn adapter_preserves_disable_expiry_and_unknown_clock_refusals() {
        let mut disabled = verifier();
        let line = serde_json::to_vec(&wire(&disabled, OwnerCommand::Clear)).unwrap();
        disabled.disable();
        assert_eq!(
            owner_request(&mut disabled, CliKind::Claude, &line, Some(NOW)),
            InjectOutcome::Refused(SdkErrorCode::DisabledByOperator)
        );

        let mut expired = verifier();
        let line = serde_json::to_vec(&wire(&expired, OwnerCommand::Clear)).unwrap();
        assert_eq!(
            owner_request(&mut expired, CliKind::Claude, &line, Some(NOW + 1000)),
            InjectOutcome::Refused(SdkErrorCode::RequestExpired)
        );

        let mut unknown = verifier();
        let line = serde_json::to_vec(&wire(&unknown, OwnerCommand::Clear)).unwrap();
        assert_eq!(
            owner_request(&mut unknown, CliKind::Claude, &line, None),
            InjectOutcome::Undetermined
        );
    }

    #[test]
    fn adapter_cannot_report_delivery_or_queue_acceptance() {
        for outcome in [
            InjectOutcome::DeliveredToPty,
            InjectOutcome::QueuedDeferred,
            InjectOutcome::RequestPending,
            InjectOutcome::NotUnderRelay,
        ] {
            let value: serde_json::Value = serde_json::from_slice(response(outcome)).unwrap();
            assert_eq!(value["outcome"], "refused");
            assert_eq!(value["error"]["code"], "not_authorized");
        }
    }
}
