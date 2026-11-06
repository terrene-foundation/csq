//! `csq sessions service add|remove|list` and `csq sessions send --service` — the CLI half of
//! the registered service sender (an internal ticket, spec 32h §11).
//!
//! A service is an identity a NON-session process (a scheduled job, a watcher) may send csq
//! messages as. Registration is NOT exclusivity: any same-UID process can register a name,
//! including one the owner did not create. The protection this surface provides is exactly
//! three things — the `service:<name>` framing (a service is never rendered as a session and
//! never as an approval), the audit trail of every admission and refusal, and revocability.
//!
//! `add`, `remove` and `list` read and write `<base>/services/` directly: no daemon and no
//! session. `send --service` NEVER resolves a caller session — it validates the name,
//! resolves the target to `<pid>:<started_at>`, POSTs
//! [`SEND_SERVICE_ROUTE`](csq_core::messaging::service::SEND_SERVICE_ROUTE) over the
//! daemon's Unix socket and renders the ordinary `csq.message_receipt.v1` envelope. A
//! missing daemon is `service_daemon_unavailable`; there is no fallback that writes the
//! store directly, because a refused ask must write nothing (design an internal ticket §4).

use std::path::Path;

use anyhow::Result;
#[cfg(test)]
use csq_core::messaging::model::VerifiedSession;
use csq_core::messaging::service::{
    self, validate_service_name, SendServiceError, SendServiceRequest, SendServiceResponse,
    SEND_SERVICE_ROUTE,
};
use csq_core::messaging::wake::Delivery;
use csq_core::messaging::SenderSurface;
use csq_core::sdk::{SdkErrorCode, SCHEMA_MESSAGE_RECEIPT_V1};
use csq_core::sessions::directives::{DirectiveError, UndeterminedCause as Cause};

#[cfg(test)]
use super::sessions_messages::resolve_verified;
use super::sessions_messages::{
    err, finish, now_secs, parse_target, read_stdin_bounded, real_candidates, receipt_dto,
    NameListing,
};

// ── fixed tags ──────────────────────────────────────────────────────

/// The fixed vocabulary this surface renders. Every value is csq-authored; a tag the daemon
/// sends that is NOT in this set is reported as `service_daemon_response_invalid` rather
/// than echoed, so no daemon response text can reach a log, an envelope or a terminal
/// (`security.md` MUST-2).
fn tag_code(tag: &str) -> Option<SdkErrorCode> {
    Some(match tag {
        "service_name_invalid"
        | "service_name_reserved"
        | "service_exists"
        | "service_no_inbox"
        | "invalid_input" => SdkErrorCode::InvalidInput,
        "service_unknown" | "not_found" => SdkErrorCode::NotFound,
        "service_uid_mismatch" | "not_authorized" => SdkErrorCode::NotAuthorized,
        "service_registry_unreadable"
        | "service_audit_unavailable"
        | "service_daemon_unavailable"
        | "service_daemon_response_invalid"
        | "undetermined" => SdkErrorCode::Undetermined,
        "service_send_surface_unsupported" | "unsupported" => SdkErrorCode::Unsupported,
        "target_mismatch" => SdkErrorCode::TargetMismatch,
        "rate_limited" => SdkErrorCode::RateLimited,
        "invalid_idempotency_key" => SdkErrorCode::InvalidIdempotencyKey,
        "internal" => SdkErrorCode::Internal,
        _ => return None,
    })
}

/// The envelope error for a fixed refusal tag: the tag IS the whole message.
fn tag_error(tag: &str) -> DirectiveError {
    match tag_code(tag) {
        Some(code) => err(code, tag),
        None => err(
            SdkErrorCode::Undetermined,
            "service_daemon_response_invalid",
        ),
    }
}

// ── registry commands (no daemon, no session) ───────────────────────

/// A registration time a person can read, plus nothing caller-controlled: `created_at` is a
/// `u64` and `registration_id` was validated as a canonical UUIDv4 on the read path.
fn human_time(epoch: u64) -> String {
    let Ok(secs) = i64::try_from(epoch) else {
        return "unrepresentable".to_string();
    };
    match chrono::DateTime::from_timestamp(secs, 0) {
        Some(at) => at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        None => "unrepresentable".to_string(),
    }
}

/// Register `name` for the current effective uid; returns the line to print. Refusals are
/// the fixed tags `add` can emit (`service_name_invalid`, `service_name_reserved`,
/// `service_exists`, `service_registry_unreadable`, `undetermined`).
pub(crate) fn add_result(
    base: &Path,
    name: &str,
    force: bool,
    clock: &dyn Fn() -> Result<u64, DirectiveError>,
) -> Result<String, &'static str> {
    validate_service_name(name)?;
    let now = clock().map_err(|_| "undetermined")?;
    let record = service::register(base, name, now, force)?;
    Ok(format!(
        "service registered: {} (registration_id {})",
        record.name, record.registration_id
    ))
}

/// Revoke `name`; the daemon reads the registry per send, so the NEXT send refuses.
pub(crate) fn remove_result(base: &Path, name: &str) -> Result<String, &'static str> {
    validate_service_name(name)?;
    service::revoke(base, name)?;
    Ok(format!("service removed: {name}"))
}

/// Every readable record with `created_at` (readable AND raw epoch) and `registration_id`,
/// plus the count of unreadable entries when there are any — an entry that cannot be read is
/// reported, never silently dropped.
pub(crate) fn list_result(base: &Path) -> Result<String, &'static str> {
    let (records, unreadable) = service::list(base)?;
    let mut lines: Vec<String> = records
        .iter()
        .map(|record| {
            format!(
                "{}  created {} (epoch {})  registration {}",
                record.name,
                human_time(record.created_at),
                record.created_at,
                record.registration_id
            )
        })
        .collect();
    if records.is_empty() {
        lines.push("no registered services".to_string());
    }
    if unreadable > 0 {
        lines.push(format!("unreadable entries: {unreadable}"));
    }
    Ok(lines.join("\n"))
}

/// ROOT amendment A (design an internal ticket §2/§7), stated on EVERY `add` refusal — the moment an
/// operator hits `service_exists` on a name they did not create is the moment the disclosure
/// is for. Fixed, csq-authored text: no tag, path or caller input.
pub(crate) const REGISTRATION_IS_NOT_EXCLUSIVITY: &str =
    "registration is not exclusivity: any same-uid process can register a name, including \
     one you did not create. The protection is the `service:<name>` framing (a service is \
     never rendered as a session and never as an approval), the audit trail of every \
     admission and refusal, and revocability. `csq sessions service list` prints each \
     registration's created_at and registration_id so you can spot one you did not create.";

/// The text a registry-command refusal prints: the fixed tag, then the fixed note when the
/// command carries one (`add` always does).
fn refusal_text(tag: &str, note: Option<&'static str>) -> String {
    match note {
        Some(note) => format!("error: {tag}\n{note}"),
        None => format!("error: {tag}"),
    }
}

/// The success/refusal outcome before printing: `Ok` is stdout, `Err` is stderr.
fn report_lines(
    result: Result<String, &'static str>,
    note: Option<&'static str>,
) -> Result<String, String> {
    result.map_err(|tag| refusal_text(tag, note))
}

/// Print a registry command's outcome: one line on success, the fixed tag (and note) on
/// stderr and a non-zero exit on refusal (never a silent fallback).
fn report(result: Result<String, &'static str>, note: Option<&'static str>) -> Result<()> {
    match report_lines(result, note) {
        Ok(text) => {
            println!("{text}");
            Ok(())
        }
        Err(text) => {
            eprintln!("{text}");
            std::process::exit(1);
        }
    }
}

/// `csq sessions service add <name> [--force]`. Every refusal states amendment A.
pub fn add(base: &Path, name: &str, force: bool) -> Result<()> {
    report(
        add_result(base, name, force, &now_secs),
        Some(REGISTRATION_IS_NOT_EXCLUSIVITY),
    )
}

/// `csq sessions service remove <name>`.
pub fn remove(base: &Path, name: &str) -> Result<()> {
    report(remove_result(base, name), None)
}

/// `csq sessions service list`.
pub fn list(base: &Path) -> Result<()> {
    report(list_result(base), None)
}

// ── send --service ──────────────────────────────────────────────────

/// The daemon's answer to one service-send POST: status plus body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceHttpResponse {
    /// Numeric HTTP status.
    pub status: u16,
    /// Response body.
    pub body: String,
}

/// Why a service-send POST produced no usable HTTP answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceTransportError {
    /// No listener at the socket: the daemon is not running, and nothing was sent.
    /// Only the Unix transport constructs this (non-Unix refuses `Unsupported` first).
    #[cfg_attr(not(unix), allow(dead_code))]
    Unavailable,
    /// The exchange did not complete into a usable answer, so the message's fate is
    /// UNKNOWN. Never reported as "not sent". Unix transport only, like `Unavailable`.
    #[cfg_attr(not(unix), allow(dead_code))]
    Invalid,
    /// This platform has no service-send surface (spec 32h §11.3). Constructed by the
    /// non-Unix `post`; on Unix only the mapping test builds it, which is the point.
    #[cfg_attr(unix, allow(dead_code))]
    Unsupported,
}

/// The seams of one `send --service`.
///
/// The two session seams are deliberate falsification points: `caller` MUST never be
/// reached from this path (spec 32h §11.7 — a `--service` send works outside every session),
/// and [`Self::candidates`] is consulted ONLY for a session-NAME target. Tests implement both
/// as panics where they must not run, so a regression reds instead of silently resolving a
/// caller.
pub(crate) trait ServiceSendPorts {
    /// Resolve the CALLING session. A service send never does.
    ///
    /// Test builds only: the production transport has no caller-resolution seam at all, so a
    /// `--service` send cannot reach one. It exists so [`tests`] can arm a panic here and
    /// prove every send path completes without tripping it.
    #[cfg(test)]
    fn caller(&self) -> Result<VerifiedSession, DirectiveError>;
    /// The live sessions with their names, and whether the listing was whole.
    fn candidates(&self) -> NameListing;
    /// The body for `--message -`.
    fn stdin(&self) -> Result<String, DirectiveError>;
    /// POST `body` to `route` on `socket`.
    fn post(
        &self,
        socket: &Path,
        route: &str,
        body: &str,
    ) -> Result<ServiceHttpResponse, ServiceTransportError>;
}

/// The daemon route addresses a live session by `<pid>:<started_at>`. A session NAME is a
/// client-side convenience resolved here against the live listing (with NO caller exclusion —
/// a service is not a session); the daemon re-verifies the pair against its own table, so a
/// name is never trusted.
fn service_target(target: &str, ports: &dyn ServiceSendPorts) -> Result<String, DirectiveError> {
    if target.contains(':') {
        parse_target(target).map_err(|_| tag_error("invalid_input"))?;
        return Ok(target.to_string());
    }
    let (live, complete) = ports
        .candidates()
        .map_err(|e| e.with_cause(Cause::RegistryRead))?;
    let chosen =
        csq_core::messaging::registry::resolve_recipient_by_name(&live, complete, target, None)
            .map_err(|e| e.with_cause(Cause::RegistryRead))?;
    Ok(format!("{}:{}", chosen.pid, chosen.started_at))
}

/// POST the request and render the receipt payload. `Err` is always a fixed tag; nothing
/// request-shaped reaches it.
fn transport_error(error: ServiceTransportError) -> DirectiveError {
    match error {
        ServiceTransportError::Unavailable => tag_error("service_daemon_unavailable"),
        ServiceTransportError::Invalid => tag_error("service_daemon_response_invalid"),
        ServiceTransportError::Unsupported => tag_error("service_send_surface_unsupported"),
    }
}

/// A non-2xx answer: the route's error shape is exactly `{"error":"<tag>"}`. A tag outside
/// the fixed vocabulary, or any other body, is `service_daemon_response_invalid` — daemon
/// text is never echoed into the envelope.
fn refusal(body: &str) -> DirectiveError {
    match serde_json::from_str::<SendServiceError>(body) {
        Ok(answer) if tag_code(&answer.error).is_some() => tag_error(&answer.error),
        _ => tag_error("service_daemon_response_invalid"),
    }
}

/// Render a 2xx answer as the ordinary receipt payload, with the service sender shape
/// explicit (`guard-reader-writer-parity`: a service is never rendered as a session).
fn render(
    response: ServiceHttpResponse,
    service_name: &str,
    wake: bool,
) -> Result<serde_json::Value, DirectiveError> {
    if !(200..300).contains(&response.status) {
        return Err(refusal(&response.body));
    }
    let answer: SendServiceResponse = serde_json::from_str(&response.body)
        .map_err(|_| tag_error("service_daemon_response_invalid"))?;
    // The re-verified recipient's surface is a fixed vocabulary; an unknown spelling is an
    // unusable response, never rendered as a session.
    let codex = match answer.to.surface.as_str() {
        "claude-code" => false,
        "codex" => true,
        _ => return Err(tag_error("service_daemon_response_invalid")),
    };
    let mut receipt = receipt_dto(&answer.receipt)
        .with_to(answer.to.pid, answer.to.started_at)
        .with_to_surface(Some(answer.to.surface));
    if !wake {
        if codex {
            // Codex has no per-turn hook, so the daemon wakes it regardless of `--no-wake`;
            // report the same override the session send does.
            receipt = receipt.with_wake_override(Some(
                csq_core::messaging::mcp::WAKE_OVERRIDE_CODEX.to_string(),
            ));
        } else {
            // Provable from the request and the re-verified surface: the daemon attempted
            // no wake. A wake that WAS attempted is not reported, because the route does not
            // return its outcome.
            receipt = receipt.with_delivery(Some(Delivery::StoredNoWake.as_str().to_string()));
        }
    }
    let mut payload = serde_json::to_value(receipt)
        .map_err(|_| err(SdkErrorCode::Undetermined, "receipt serialization failed"))?;
    // The SENDER shape, rendered explicitly. The route does not return the registration id,
    // so only the name is rendered.
    payload["from_surface"] = serde_json::json!(SenderSurface::Service.as_str());
    payload["from_name"] = serde_json::json!(service_name);
    Ok(payload)
}

/// `csq sessions send --service <name> <target> --message <…>`.
///
/// Validates the name, resolves the target, builds the exact [`SendServiceRequest`] the
/// route's `deny_unknown_fields` body expects, POSTs it and renders the receipt. The caller
/// session is NEVER resolved.
#[allow(clippy::too_many_arguments)]
pub(crate) fn send_with(
    base_dir: &Path,
    service_name: &str,
    target: &str,
    message: &str,
    reply_to: Option<&str>,
    key: Option<&str>,
    wake: bool,
    ports: &dyn ServiceSendPorts,
) -> Result<serde_json::Value, DirectiveError> {
    // The grammar is re-checked by the daemon at every send; refusing it here means a
    // malformed name needs no daemon and writes nothing.
    validate_service_name(service_name).map_err(tag_error)?;
    let target = service_target(target, ports)?;
    // `--message -` reads the body from stdin (bounded), after the cheap refusals.
    let body = if message == "-" {
        ports.stdin()?
    } else {
        message.to_string()
    };
    let request = SendServiceRequest {
        service: service_name.to_string(),
        target,
        message: body,
        reply_to: reply_to.map(str::to_string),
        idempotency_key: key.map(str::to_string),
        wake,
    };
    let json = serde_json::to_string(&request).map_err(|_| {
        err(
            SdkErrorCode::Undetermined,
            "service request serialization failed",
        )
    })?;
    let socket = csq_core::daemon::socket_path(base_dir);
    let response = ports
        .post(&socket, SEND_SERVICE_ROUTE, &json)
        .map_err(transport_error)?;
    render(response, service_name, wake)
}

/// The production seams. `ServiceSendPorts::caller` is implemented but never called from
/// this path; it exists so the trait is honest about what a service send may NOT use.
struct RealPorts<'a> {
    base_dir: &'a Path,
}

impl ServiceSendPorts for RealPorts<'_> {
    #[cfg(test)]
    fn caller(&self) -> Result<VerifiedSession, DirectiveError> {
        // Armed here so the tripwire has a real implementation to hit; no production path
        // calls it (the method is absent without `cfg(test)`).
        resolve_verified()
    }
    fn candidates(&self) -> NameListing {
        real_candidates(self.base_dir)
    }
    fn stdin(&self) -> Result<String, DirectiveError> {
        read_stdin_bounded(std::io::stdin().lock())
    }
    #[cfg(unix)]
    fn post(
        &self,
        socket: &Path,
        route: &str,
        body: &str,
    ) -> Result<ServiceHttpResponse, ServiceTransportError> {
        use csq_core::daemon::DaemonClientError;
        match csq_core::daemon::http_post_unix_json(socket, route, body) {
            Ok(response) => Ok(ServiceHttpResponse {
                status: response.status,
                body: response.body,
            }),
            // No listener: nothing was sent.
            Err(DaemonClientError::Connect(_)) => Err(ServiceTransportError::Unavailable),
            // A read/write failure or an unparseable answer: the outcome is UNKNOWN, never
            // reported as "not sent".
            Err(_) => Err(ServiceTransportError::Invalid),
        }
    }
    #[cfg(not(unix))]
    fn post(
        &self,
        _socket: &Path,
        _route: &str,
        _body: &str,
    ) -> Result<ServiceHttpResponse, ServiceTransportError> {
        // No peer-credentialed Unix listener on this platform, so the route does not exist
        // (spec 32h §11.3). A compile-time platform gate, not a runtime fallback.
        Err(ServiceTransportError::Unsupported)
    }
}

/// `csq sessions send --service <name> …`. Always emits `csq.message_receipt.v1`; exits
/// non-zero on any refusal. With `--service` this command does NOT resolve a caller session:
/// it works outside every session, and a service is not a session and never an approval.
pub fn send(
    base_dir: &Path,
    service_name: &str,
    target: &str,
    message: &str,
    reply_to: Option<&str>,
    key: Option<&str>,
    wake: bool,
) -> Result<()> {
    let ports = RealPorts { base_dir };
    finish(
        SCHEMA_MESSAGE_RECEIPT_V1,
        send_with(
            base_dir,
            service_name,
            target,
            message,
            reply_to,
            key,
            wake,
            &ports,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use csq_core::messaging::registry::{Candidate, NameSource};
    use csq_core::messaging::Surface;
    use std::cell::RefCell;

    const T0: u64 = 1_700_000_000;
    const REG: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

    /// `(socket, route, body)` exactly as the transport received them.
    type Captured = (String, String, String);

    /// The injected ports of the send path. `caller` panics on EVERY test: a `--service`
    /// send that resolves a caller session must red, not pass silently.
    struct Rig {
        captured: RefCell<Option<Captured>>,
        answer: Result<ServiceHttpResponse, ServiceTransportError>,
        names: Option<NameListing>,
        stdin: Option<String>,
    }

    impl Rig {
        fn answering(answer: Result<ServiceHttpResponse, ServiceTransportError>) -> Self {
            Self {
                captured: RefCell::new(None),
                answer,
                names: None,
                stdin: None,
            }
        }

        fn captured(&self) -> Captured {
            self.captured
                .borrow_mut()
                .take()
                .expect("the transport received no request")
        }
    }

    impl ServiceSendPorts for Rig {
        fn caller(&self) -> Result<VerifiedSession, DirectiveError> {
            panic!("a --service send must never resolve a caller session")
        }
        fn candidates(&self) -> NameListing {
            match &self.names {
                Some(listing) => listing.clone(),
                None => panic!("a <pid>:<started_at> target must not consult the name listing"),
            }
        }
        fn stdin(&self) -> Result<String, DirectiveError> {
            match &self.stdin {
                Some(body) => Ok(body.clone()),
                None => panic!("stdin must not be read for a literal message"),
            }
        }
        fn post(
            &self,
            socket: &Path,
            route: &str,
            body: &str,
        ) -> Result<ServiceHttpResponse, ServiceTransportError> {
            *self.captured.borrow_mut() = Some((
                socket.to_string_lossy().into_owned(),
                route.to_string(),
                body.to_string(),
            ));
            self.answer.clone()
        }
    }

    fn receipt_response(status: &str, surface: &str) -> ServiceHttpResponse {
        ServiceHttpResponse {
            status: 200,
            body: serde_json::json!({
                "receipt": {
                    "id": "11111111-1111-4111-8111-111111111111",
                    "thread": "22222222-2222-4222-8222-222222222222",
                    "status": status,
                    "created_at": 1_700_000_123u64
                },
                "to": { "pid": 4242, "started_at": 1_699_999_000u64, "surface": surface }
            })
            .to_string(),
        }
    }

    fn error_response(status: u16, tag: &str) -> ServiceHttpResponse {
        ServiceHttpResponse {
            status,
            body: serde_json::json!({ "error": tag }).to_string(),
        }
    }

    fn candidate(pid: u32, started_at: u64, name: &str) -> Candidate {
        Candidate {
            pid,
            started_at,
            surface: Surface::ClaudeCode,
            name: name.to_string(),
            name_source: NameSource::SelfSet,
            repo: Some("csq".to_string()),
            branch: Some("dev".to_string()),
            label_fallback: false,
        }
    }

    // ── add / remove / list ─────────────────────────────────────────

    #[test]
    fn an_add_refusal_states_amendment_a_verbatim() {
        // Byte equality against the ratified amendment-A wording (design an internal ticket §2): a
        // reworded disclosure reds here instead of shipping silently.
        assert_eq!(
            REGISTRATION_IS_NOT_EXCLUSIVITY,
            "registration is not exclusivity: any same-uid process can register a name, \
             including one you did not create. The protection is the `service:<name>` \
             framing (a service is never rendered as a session and never as an approval), \
             the audit trail of every admission and refusal, and revocability. \
             `csq sessions service list` prints each registration's created_at and \
             registration_id so you can spot one you did not create."
        );
        assert_eq!(
            report_lines(Err("service_exists"), Some(REGISTRATION_IS_NOT_EXCLUSIVITY)),
            Err(format!(
                "error: service_exists\n{REGISTRATION_IS_NOT_EXCLUSIVITY}"
            )),
            "every add refusal prints the tag AND amendment A"
        );
        assert_eq!(
            report_lines(Err("service_unknown"), None),
            Err("error: service_unknown".to_string()),
            "remove/list refusals stay tag-only"
        );
    }

    #[test]
    fn a_registration_at_the_epoch_is_refused_and_writes_nothing() {
        let base = tempfile::tempdir().unwrap();
        assert_eq!(
            add_result(base.path(), "nightly", false, &|| Ok(0)).unwrap_err(),
            "undetermined",
            "created_at == 0 is the load path's unreadable marker; never mint it"
        );
        assert!(
            !service::service_dir(base.path()).exists(),
            "a refused registration writes nothing"
        );
    }

    #[test]
    fn add_registers_and_refuses_existing_unless_forced() {
        let base = tempfile::tempdir().unwrap();
        let line = add_result(base.path(), "nightly-backup-1", false, &|| Ok(T0)).unwrap();
        assert!(
            line.starts_with("service registered: nightly-backup-1"),
            "{line}"
        );
        let first = service::load(base.path(), "nightly-backup-1", service::current_uid()).unwrap();
        assert_eq!(first.created_at, T0);
        assert_eq!(first.uid, service::current_uid());
        assert!(line.contains(&first.registration_id), "{line}");

        assert_eq!(
            add_result(base.path(), "nightly-backup-1", false, &|| Ok(T0)).unwrap_err(),
            "service_exists"
        );
        let forced = add_result(base.path(), "nightly-backup-1", true, &|| Ok(T0 + 30)).unwrap();
        let second =
            service::load(base.path(), "nightly-backup-1", service::current_uid()).unwrap();
        assert_ne!(second.registration_id, first.registration_id);
        assert_eq!(second.created_at, T0 + 30);
        assert!(forced.contains(&second.registration_id), "{forced}");
    }

    #[test]
    fn add_refuses_a_name_that_mimics_a_session_label_or_target() {
        let base = tempfile::tempdir().unwrap();
        for reserved in [
            "term-34743",
            "term-0",
            REG,
            "claude-code",
            "codex",
            "service",
        ] {
            assert_eq!(
                add_result(base.path(), reserved, false, &|| Ok(T0)).unwrap_err(),
                "service_name_reserved",
                "{reserved}"
            );
        }
        for invalid in ["", "-leading", "Upper", "has space", "has.dot", "has/slash"] {
            assert_eq!(
                add_result(base.path(), invalid, false, &|| Ok(T0)).unwrap_err(),
                "service_name_invalid",
                "{invalid:?}"
            );
        }
        assert!(
            !service::service_dir(base.path()).exists(),
            "a refused name writes nothing"
        );
    }

    #[test]
    fn a_clock_refusal_is_a_fixed_tag_and_writes_nothing() {
        let base = tempfile::tempdir().unwrap();
        let boom = || Err(err(SdkErrorCode::Undetermined, "system clock is broken"));
        assert_eq!(
            add_result(base.path(), "nightly", false, &boom).unwrap_err(),
            "undetermined"
        );
        assert!(!service::service_dir(base.path()).exists());
    }

    #[test]
    fn remove_refuses_an_unknown_record_and_revokes_a_known_one() {
        let base = tempfile::tempdir().unwrap();
        assert_eq!(
            remove_result(base.path(), "never-registered").unwrap_err(),
            "service_unknown"
        );
        add_result(base.path(), "nightly", false, &|| Ok(T0)).unwrap();
        assert_eq!(
            remove_result(base.path(), "nightly").unwrap(),
            "service removed: nightly"
        );
        assert_eq!(
            service::load(base.path(), "nightly", service::current_uid()).unwrap_err(),
            "service_unknown"
        );
        assert_eq!(
            remove_result(base.path(), "nightly").unwrap_err(),
            "service_unknown"
        );
    }

    #[test]
    fn list_prints_created_at_registration_id_and_the_unreadable_count() {
        let base = tempfile::tempdir().unwrap();
        assert_eq!(list_result(base.path()).unwrap(), "no registered services");

        add_result(base.path(), "alpha", false, &|| Ok(1_000)).unwrap();
        add_result(base.path(), "beta", false, &|| Ok(T0)).unwrap();
        let alpha = service::load(base.path(), "alpha", service::current_uid()).unwrap();
        let beta = service::load(base.path(), "beta", service::current_uid()).unwrap();
        let out = list_result(base.path()).unwrap();
        assert!(out.contains("alpha"), "{out}");
        assert!(
            out.contains("created 1970-01-01T00:16:40Z (epoch 1000)"),
            "{out}"
        );
        assert!(out.contains(&format!("registration {}", alpha.registration_id)));
        assert!(out.contains(&format!("registration {}", beta.registration_id)));
        assert!(out.contains(&format!("epoch {T0}")), "{out}");
        assert!(!out.contains("unreadable entries"), "{out}");

        // An entry the read path refuses is COUNTED, never silently dropped.
        std::fs::write(service::service_dir(base.path()).join("junk.json"), b"nope").unwrap();
        let out = list_result(base.path()).unwrap();
        assert!(out.contains("unreadable entries: 1"), "{out}");
    }

    #[test]
    fn no_registry_record_carries_a_secret_into_the_listing() {
        let base = tempfile::tempdir().unwrap();
        add_result(base.path(), "nightly", false, &|| Ok(T0)).unwrap();
        let out = list_result(base.path()).unwrap();
        // Exactly the four record fields are rendered; no uid, no path, no key material.
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(!out.contains("uid"), "{out}");
        assert!(!out.contains("services/"), "{out}");
    }

    // ── send --service: the request ─────────────────────────────────

    #[test]
    fn a_service_send_builds_the_exact_request_and_returns_the_receipt() {
        let base = tempfile::tempdir().unwrap();
        let rig = Rig::answering(Ok(receipt_response("queued", "claude-code")));
        let payload = send_with(
            base.path(),
            "nightly",
            "4242:1699999000",
            "disk 91% on /System/Volumes/Data",
            None,
            None,
            true,
            &rig,
        )
        .unwrap();

        let (socket, route, body) = rig.captured();
        assert_eq!(route, "/api/message/send-service");
        assert_eq!(route, SEND_SERVICE_ROUTE);
        assert_eq!(
            socket,
            csq_core::daemon::socket_path(base.path())
                .to_string_lossy()
                .into_owned()
        );
        // EXACT body: `deny_unknown_fields` on the route means an extra key is a refusal, and
        // equality here catches both an extra and a missing field.
        let sent: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            sent,
            serde_json::json!({
                "service": "nightly",
                "target": "4242:1699999000",
                "message": "disk 91% on /System/Volumes/Data",
                "wake": true
            })
        );

        assert_eq!(payload["id"], "11111111-1111-4111-8111-111111111111");
        assert_eq!(payload["status"], "queued");
        assert_eq!(payload["created_at"], 1_700_000_123u64);
        assert_eq!(payload["to_pid"], 4242);
        assert_eq!(payload["to_started_at"], 1_699_999_000u64);
        assert_eq!(payload["to_surface"], "claude-code");
        // The sender shape is explicit and can never be a session.
        assert_eq!(payload["from_surface"], "service");
        assert_eq!(payload["from_name"], "nightly");
        // A service is always pinned by its registration id: no unpinned warning.
        assert!(payload.get("warning").is_none(), "{payload}");
    }

    #[test]
    fn optional_reply_and_key_are_carried_and_no_wake_is_boolean() {
        let base = tempfile::tempdir().unwrap();
        let rig = Rig::answering(Ok(receipt_response("queued", "claude-code")));
        send_with(
            base.path(),
            "nightly",
            "4242:1699999000",
            "answer",
            Some("33333333-3333-4333-8333-333333333333"),
            Some("1700000000.0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"),
            false,
            &rig,
        )
        .unwrap();
        let (_, _, body) = rig.captured();
        let sent: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            sent,
            serde_json::json!({
                "service": "nightly",
                "target": "4242:1699999000",
                "message": "answer",
                "reply_to": "33333333-3333-4333-8333-333333333333",
                "idempotency_key": "1700000000.0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
                "wake": false
            })
        );
    }

    #[test]
    fn a_message_dash_reads_the_injected_stdin() {
        let base = tempfile::tempdir().unwrap();
        let mut rig = Rig::answering(Ok(receipt_response("queued", "claude-code")));
        rig.stdin = Some("body from stdin".to_string());
        send_with(
            base.path(),
            "nightly",
            "4242:1699999000",
            "-",
            None,
            None,
            true,
            &rig,
        )
        .unwrap();
        let (_, _, body) = rig.captured();
        let sent: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(sent["message"], "body from stdin");
    }

    #[test]
    fn a_session_name_target_is_resolved_without_a_caller() {
        let base = tempfile::tempdir().unwrap();
        let mut rig = Rig::answering(Ok(receipt_response("queued", "claude-code")));
        rig.names = Some(Ok((
            vec![candidate(4242, 1_699_999_000, "nightly-target")],
            true,
        )));
        send_with(
            base.path(),
            "svc",
            "nightly-target",
            "hi",
            None,
            None,
            true,
            &rig,
        )
        .unwrap();
        let (_, _, body) = rig.captured();
        let sent: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(sent["target"], "4242:1699999000");
    }

    #[test]
    fn a_bad_name_or_target_is_refused_before_the_daemon_is_contacted() {
        let base = tempfile::tempdir().unwrap();
        let rig = Rig::answering(Ok(receipt_response("queued", "claude-code")));
        assert_eq!(
            send_with(
                base.path(),
                "term-34743",
                "4242:1",
                "hi",
                None,
                None,
                true,
                &rig
            )
            .unwrap_err()
            .message,
            "service_name_reserved"
        );
        // A target that contains `:` is a PAIR and is parsed strictly; anything else is a
        // session name and is resolved by the listing (see the name test).
        for malformed in ["4242:", ":1699999000", "4242:x", "x:1699999000"] {
            assert_eq!(
                send_with(
                    base.path(),
                    "nightly",
                    malformed,
                    "hi",
                    None,
                    None,
                    true,
                    &rig
                )
                .unwrap_err()
                .message,
                "invalid_input",
                "{malformed}"
            );
        }
        assert!(
            rig.captured.borrow().is_none(),
            "no request may reach the transport"
        );
    }

    // ── send --service: the daemon's answer ─────────────────────────

    #[test]
    fn every_daemon_error_tag_maps_to_its_fixed_cli_tag() {
        let tags = [
            "service_name_invalid",
            "service_name_reserved",
            "service_exists",
            "service_unknown",
            "service_registry_unreadable",
            "service_uid_mismatch",
            "service_audit_unavailable",
            "service_no_inbox",
            "service_send_surface_unsupported",
            "invalid_input",
            "invalid_idempotency_key",
            "target_mismatch",
            "rate_limited",
            "not_found",
            "not_authorized",
            "undetermined",
            "internal",
        ];
        let base = tempfile::tempdir().unwrap();
        for tag in tags {
            let rig = Rig::answering(Ok(error_response(400, tag)));
            let error = send_with(
                base.path(),
                "nightly",
                "4242:1",
                "hi",
                None,
                None,
                true,
                &rig,
            )
            .unwrap_err();
            assert_eq!(error.message, tag, "{tag}");
            assert_eq!(
                error.code,
                tag_code(tag).expect("tag is in the fixed vocabulary"),
                "{tag}"
            );
        }
    }

    #[test]
    fn an_unknown_tag_or_body_is_never_echoed() {
        let base = tempfile::tempdir().unwrap();
        for body in [
            r#"{"error":"service_attacker_controlled_text"}"#.to_string(),
            "<html>proxy error with a token sk-ant-secret</html>".to_string(),
            String::new(),
            r#"{"error":"service_unknown","detail":"extra field"}"#.to_string(),
        ] {
            let rig = Rig::answering(Ok(ServiceHttpResponse { status: 400, body }));
            let error = send_with(
                base.path(),
                "nightly",
                "4242:1",
                "hi",
                None,
                None,
                true,
                &rig,
            )
            .unwrap_err();
            assert_eq!(error.message, "service_daemon_response_invalid");
            assert!(!error.message.contains("sk-ant"), "{}", error.message);
            assert!(!error.message.contains("attacker"), "{}", error.message);
        }
    }

    #[test]
    fn a_2xx_that_is_not_a_receipt_is_never_read_as_success() {
        let base = tempfile::tempdir().unwrap();
        let mut bodies = vec![
            // An error body on a 2xx is not a success.
            serde_json::json!({ "error": "service_unknown" }).to_string(),
            // A malformed receipt.
            r#"{"receipt":{},"to":{"pid":1,"started_at":2,"surface":"claude-code"}}"#.to_string(),
            // A recipient surface outside the fixed vocabulary.
            receipt_response_with_surface("claude-code-v2"),
        ];
        bodies.push("not json".to_string());
        for body in bodies {
            let rig = Rig::answering(Ok(ServiceHttpResponse { status: 200, body }));
            let error = send_with(
                base.path(),
                "nightly",
                "4242:1",
                "hi",
                None,
                None,
                true,
                &rig,
            )
            .unwrap_err();
            assert_eq!(error.message, "service_daemon_response_invalid");
        }
    }

    fn receipt_response_with_surface(surface: &str) -> String {
        receipt_response("queued", surface).body
    }

    #[test]
    fn transport_failures_map_to_their_fixed_tags() {
        let base = tempfile::tempdir().unwrap();
        for (failure, tag) in [
            (
                ServiceTransportError::Unavailable,
                "service_daemon_unavailable",
            ),
            (
                ServiceTransportError::Invalid,
                "service_daemon_response_invalid",
            ),
            (
                ServiceTransportError::Unsupported,
                "service_send_surface_unsupported",
            ),
        ] {
            let rig = Rig::answering(Err(failure));
            let error = send_with(
                base.path(),
                "nightly",
                "4242:1",
                "hi",
                None,
                None,
                true,
                &rig,
            )
            .unwrap_err();
            assert_eq!(error.message, tag, "{failure:?}");
        }
    }

    #[test]
    fn a_missing_daemon_is_unavailable_and_stores_nothing() {
        let base = tempfile::tempdir().unwrap();
        let rig = Rig::answering(Err(ServiceTransportError::Unavailable));
        assert_eq!(
            send_with(
                base.path(),
                "nightly",
                "4242:1",
                "hi",
                None,
                None,
                true,
                &rig
            )
            .unwrap_err()
            .message,
            "service_daemon_unavailable"
        );
        // The injected transport wrote nothing; the CLI has no direct-store fallback.
        assert!(!base.path().join("messages").exists());
    }

    #[test]
    fn no_wake_renders_exactly_what_the_daemon_can_prove() {
        let base = tempfile::tempdir().unwrap();
        // --no-wake to a Claude Code recipient: the daemon attempts no wake.
        let rig = Rig::answering(Ok(receipt_response("queued", "claude-code")));
        let payload = send_with(
            base.path(),
            "nightly",
            "4242:1",
            "hi",
            None,
            None,
            false,
            &rig,
        )
        .unwrap();
        assert_eq!(payload["delivery"], "stored_no_wake");
        assert!(payload.get("wake_override").is_none());

        // --no-wake to a Codex recipient: the daemon wakes it anyway.
        let rig = Rig::answering(Ok(receipt_response("queued", "codex")));
        let payload = send_with(
            base.path(),
            "nightly",
            "4242:1",
            "hi",
            None,
            None,
            false,
            &rig,
        )
        .unwrap();
        assert_eq!(payload["wake_override"], "codex_no_turn_hook");
        assert!(payload.get("delivery").is_none());

        // A requested wake has an outcome the route does not return: neither field is
        // claimed.
        let rig = Rig::answering(Ok(receipt_response("queued", "codex")));
        let payload = send_with(
            base.path(),
            "nightly",
            "4242:1",
            "hi",
            None,
            None,
            true,
            &rig,
        )
        .unwrap();
        assert!(payload.get("delivery").is_none());
        assert!(payload.get("wake_override").is_none());
    }

    // ── send --service: never a session ─────────────────────────────

    /// The property spec 32h §11.7 states: `--service` never resolves a caller session. The
    /// rig's `caller` panics, so every success AND every refusal below proves the path
    /// never touched it.
    #[test]
    fn a_service_send_never_resolves_a_caller_session() {
        let base = tempfile::tempdir().unwrap();
        let ok = Rig::answering(Ok(receipt_response("queued", "claude-code")));
        assert!(send_with(
            base.path(),
            "nightly",
            "4242:1",
            "hi",
            None,
            None,
            true,
            &ok
        )
        .is_ok());
        let refused = Rig::answering(Ok(error_response(400, "service_unknown")));
        assert_eq!(
            send_with(
                base.path(),
                "nightly",
                "4242:1",
                "hi",
                None,
                None,
                true,
                &refused
            )
            .unwrap_err()
            .message,
            "service_unknown"
        );
        let down = Rig::answering(Err(ServiceTransportError::Unavailable));
        assert!(send_with(
            base.path(),
            "nightly",
            "4242:1",
            "hi",
            None,
            None,
            true,
            &down
        )
        .is_err());
    }

    /// The tripwire the test above relies on is ARMED: [`Rig::caller`] panics by
    /// construction, so "the send completed" is evidence the path never resolved a caller
    /// (`instrument-discipline.md` MUST-2 — a test that cannot red is no evidence).
    #[test]
    #[should_panic(expected = "a --service send must never resolve a caller session")]
    fn the_caller_tripwire_is_armed() {
        let rig = Rig::answering(Ok(receipt_response("queued", "claude-code")));
        let _ = rig.caller();
    }

    #[test]
    fn registration_commands_need_no_session_and_no_daemon() {
        // A temp base and a temp uid: the three registry commands never take the daemon
        // transport, so none of them can depend on a running daemon or a session env.
        let base = tempfile::tempdir().unwrap();
        add_result(base.path(), "scheduled-job", false, &|| Ok(T0)).unwrap();
        assert!(list_result(base.path()).unwrap().contains("scheduled-job"));
        remove_result(base.path(), "scheduled-job").unwrap();
        assert_eq!(list_result(base.path()).unwrap(), "no registered services");
    }
}
