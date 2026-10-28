//! `csq sessions deliver | receipts | ack | inbox` — session-directive delivery
//! (contract `internal-design-docs` §3-§5).
//!
//! The store, validation and lifecycle live in `csq_core::sessions::directives`; this
//! module is the envelope-emitting CLI surface. Every command emits ONE spec 30 envelope
//! line. A refusal is `ok:false` with its `error.code`; `rate_limited` additionally
//! carries `next_allowed_at` in the payload. Exit status is 0 iff `ok`; a consumer
//! distinguishes a refusal from could-not-determine by `error.code`, never by status.

use std::io::Read;
use std::path::Path;

use anyhow::Result;
use csq_core::sdk::directives::{
    DirectiveInboxPayload, DirectiveReceiptsPayload, DirectiveRefusalPayload,
};
use csq_core::sdk::{
    self, Envelope, SdkError, SdkErrorCode, SCHEMA_DIRECTIVE_INBOX_V1,
    SCHEMA_DIRECTIVE_RECEIPTS_V1, SCHEMA_DIRECTIVE_RECEIPT_V1,
};
use csq_core::sessions::directives::{self, DirectiveError};
use csq_core::sessions::{CallerError, CliKind, SessionInfo, Visibility};
use serde::Serialize;

/// Upper bound on a directive document: ~13 text fields of 500 characters of up to four
/// bytes each is ~26 KiB, so 256 KiB is generous and still bounds a hostile stdin.
const MAX_STDIN_BYTES: u64 = 256 * 1024;

/// Build the envelope for one operation result. `Ok` payloads and refusal payloads are
/// both rendered through `serde_json::Value` so one envelope type covers every outcome.
fn build<T: Serialize>(
    schema: &'static str,
    result: Result<T, DirectiveError>,
) -> Envelope<serde_json::Value> {
    match result {
        Ok(payload) => match serde_json::to_value(payload) {
            Ok(v) => Envelope::success(schema, None, v),
            Err(_) => Envelope::failure(
                schema,
                None,
                SdkError::trusted(SdkErrorCode::Undetermined, "result could not be serialized"),
            ),
        },
        Err(e) => {
            let err = SdkError::trusted(e.code, e.message);
            match e.next_allowed_at {
                Some(next) => {
                    let payload = serde_json::to_value(DirectiveRefusalPayload::new(next))
                        .unwrap_or(serde_json::Value::Null);
                    let mut env = Envelope::verdict(schema, None, false, payload);
                    env.error = Some(err);
                    env
                }
                None => Envelope::failure(schema, None, err),
            }
        }
    }
}

fn finish<T: Serialize>(schema: &'static str, result: Result<T, DirectiveError>) -> Result<()> {
    let code = sdk::emit(&build(schema, result))?;
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

fn read_stdin_bounded(mut input: impl Read) -> Result<String, DirectiveError> {
    let mut buf = Vec::new();
    input
        .by_ref()
        .take(MAX_STDIN_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|_| DirectiveError {
            code: SdkErrorCode::Undetermined,
            message: "stdin could not be read".to_string(),
            cause: None,
            attempts: None,
            next_allowed_at: None,
        })?;
    if buf.len() as u64 > MAX_STDIN_BYTES {
        return Err(DirectiveError {
            code: SdkErrorCode::InvalidInput,
            message: "directive document is too large".to_string(),
            cause: None,
            attempts: None,
            next_allowed_at: None,
        });
    }
    String::from_utf8(buf).map_err(|_| DirectiveError {
        code: SdkErrorCode::InvalidInput,
        message: "directive document is not valid UTF-8".to_string(),
        cause: None,
        attempts: None,
        next_allowed_at: None,
    })
}

/// The envelope schema a `csq sessions …` invocation promises, when its arguments do not
/// parse. Every directive verb always answers with one envelope, and `list` does when
/// `--json` is present, so an argument error on those must also be an envelope rather than
/// clap's usage text and exit 2. The global flags are all value-less, so the first token
/// that does not start with `-` is the command. A literal `--` ends the options: nothing
/// after it can name the verb, so it yields `None` (a misattributed schema would be a lie
/// about which command failed). `None` means "not an envelope surface": the caller keeps
/// clap's own error.
pub fn parse_error_schema(args: &[String]) -> Option<&'static str> {
    let head: Vec<&String> = args
        .iter()
        .skip(1)
        .take_while(|a| a.as_str() != "--")
        .collect();
    let mut positional = head.iter().filter(|a| !a.starts_with('-'));
    if positional.next()?.as_str() != "sessions" {
        return None;
    }
    match positional.next()?.as_str() {
        "deliver" | "ack" => Some(SCHEMA_DIRECTIVE_RECEIPT_V1),
        "receipts" => Some(SCHEMA_DIRECTIVE_RECEIPTS_V1),
        "inbox" => Some(SCHEMA_DIRECTIVE_INBOX_V1),
        "list" if head.iter().any(|a| a.as_str() == "--json") => {
            Some(csq_core::sdk::SCHEMA_SESSIONS_V1)
        }
        _ => None,
    }
}

/// Emit the `invalid_input` envelope for an argument error on an envelope surface and
/// return the exit status (1). The clap message is not echoed: it can quote the offending
/// argument verbatim, and argument text is caller-controlled.
pub fn emit_parse_error(schema: &'static str) -> Result<i32> {
    Ok(sdk::emit(&Envelope::<serde_json::Value>::failure(
        schema,
        None,
        SdkError::trusted(
            SdkErrorCode::InvalidInput,
            "arguments could not be parsed; see `csq sessions --help`",
        ),
    ))?)
}

/// `csq sessions deliver --json`: read one `csq.directive.v1` from stdin.
pub fn deliver(base_dir: &Path) -> Result<()> {
    let result = read_stdin_bounded(std::io::stdin().lock())
        .and_then(|raw| directives::deliver(base_dir, &raw));
    finish(SCHEMA_DIRECTIVE_RECEIPT_V1, result)
}

/// Receipts for `since`/`id`; a `since` that is not unix seconds is `invalid_input`.
fn receipts_result(
    base_dir: &Path,
    since: Option<&str>,
    id: Option<&str>,
) -> Result<DirectiveReceiptsPayload, DirectiveError> {
    let since = since
        .map(|s| {
            s.trim().parse::<u64>().map_err(|_| DirectiveError {
                code: SdkErrorCode::InvalidInput,
                message: "since must be unix seconds".to_string(),
                cause: None,
                attempts: None,
                next_allowed_at: None,
            })
        })
        .transpose()?;
    directives::receipts(base_dir, since, id).map(DirectiveReceiptsPayload::new)
}

/// `csq sessions receipts --json [--since <unix>] [--id <uuid>]`.
pub fn receipts(base_dir: &Path, since: Option<&str>, id: Option<&str>) -> Result<()> {
    finish(
        SCHEMA_DIRECTIVE_RECEIPTS_V1,
        receipts_result(base_dir, since, id),
    )
}

/// The acknowledgement of directive `id` by the session `caller` resolves to. A missing
/// id is `invalid_input` and is checked before the caller is resolved.
fn ack_result(
    base_dir: &Path,
    id: Option<&str>,
    outcome: &str,
    note: Option<&str>,
    caller: directives::CallerFn<'_>,
) -> Result<csq_core::sdk::directives::DirectiveReceipt, DirectiveError> {
    let Some(id) = id else {
        return Err(DirectiveError {
            code: SdkErrorCode::InvalidInput,
            message: "ack requires a directive id".to_string(),
            cause: None,
            attempts: None,
            next_allowed_at: None,
        });
    };
    directives::ack(base_dir, id, outcome, note, caller)
}

/// `csq sessions ack <id> --outcome done|declined|deferred [--note "..."] --json`. Only
/// the session the directive is addressed to (resolved from `CLAUDE_CONFIG_DIR`, as
/// `inbox` does) may acknowledge it.
pub fn ack(base_dir: &Path, id: Option<&str>, outcome: &str, note: Option<&str>) -> Result<()> {
    finish(
        SCHEMA_DIRECTIVE_RECEIPT_V1,
        ack_result(base_dir, id, outcome, note, &calling_session),
    )
}

/// Identify the CALLING session: the live `claude` process whose `CLAUDE_CONFIG_DIR` is
/// the caller's own handle dir. Zero matches or more than one is undetermined — the
/// caller must not be guessed. Every owner is counted BEFORE any is dropped for lacking a
/// start time: two owners are ambiguous even if only one has a start time.
///
/// `CLAUDE_CONFIG_DIR` alone is spoofable by any same-user process, so the resolved
/// process must ALSO be the NEAREST session ancestor of this one (`ancestry`; `Some(None)`
/// is `target_mismatch`, `None` is `undetermined`; a session between is `target_mismatch`), and its start time re-read through
/// `start_of` must still match the listed one within `START_TOLERANCE_SECS` — the pid
/// may have been recycled between the listing and the walk (INV-31-01).
fn resolve_calling_session(
    sessions: &[SessionInfo],
    unreadable: &[u32],
    view: Visibility,
    config_dir: Option<&str>,
    ancestry: &dyn Fn(u32) -> Option<Option<csq_core::sessions::AncestorHops>>,
    start_of: &dyn Fn(u32) -> Option<u64>,
) -> Result<(u32, u64), DirectiveError> {
    // The resolution is `csq_core::sessions::resolve_caller` (the §2.2 resolver, shared with
    // messaging); directives address Claude Code sessions only, so the kind is fixed.
    csq_core::sessions::resolve_caller(
        CliKind::Claude,
        sessions,
        unreadable,
        view,
        config_dir,
        ancestry,
        // a session between the caller and the owner makes the owner the wrong session
        &csq_core::sessions::is_session_hop,
        start_of,
    )
    .map(|r| (r.pid(), r.started_at()))
    .map_err(|e| match e {
        CallerError::Undetermined(message) => DirectiveError {
            code: SdkErrorCode::Undetermined,
            message,
            cause: None,
            attempts: None,
            next_allowed_at: None,
        },
        CallerError::TargetMismatch => DirectiveError {
            code: SdkErrorCode::TargetMismatch,
            message: "caller is not running inside that session".to_string(),
            cause: None,
            attempts: None,
            next_allowed_at: None,
        },
    })
}

/// The calling session, from `CLAUDE_CONFIG_DIR` and the live process table. The table
/// is read natively (no per-session process spawn). The listing omits a `claude` it
/// cannot read, so uniqueness is NOT whole by itself: `try_list_detailed` also reports how
/// many same-uid `claude`-named processes were unreadable, and whether the process table
/// is `incomplete`; a non-zero count or a true `incomplete` makes the resolution
/// `undetermined` (see [`resolve_calling_session`]).
fn calling_session() -> Result<(u32, u64), DirectiveError> {
    let config_dir = std::env::var("CLAUDE_CONFIG_DIR").ok();
    let listing = csq_core::sessions::try_list_detailed().ok_or_else(|| DirectiveError {
        code: SdkErrorCode::Undetermined,
        message: "live sessions could not be enumerated".to_string(),
        cause: None,
        attempts: None,
        next_allowed_at: None,
    })?;
    resolve_calling_session(
        &listing.sessions,
        &listing.unreadable_pids,
        listing.visibility(),
        config_dir.as_deref(),
        &csq_core::sessions::ancestor_path_of_current,
        &csq_core::sessions::process_start_time,
    )
}

/// `csq sessions inbox --json [--pending] [--mark-surfaced]`.
pub fn inbox(base_dir: &Path, pending: bool, mark_surfaced: bool) -> Result<()> {
    let result = calling_session()
        .and_then(|(pid, started_at)| {
            directives::inbox_for(base_dir, pid, started_at, pending, mark_surfaced)
        })
        .map(DirectiveInboxPayload::new);
    finish(SCHEMA_DIRECTIVE_INBOX_V1, result)
}

#[cfg(test)]
mod tests {
    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_errors_on_envelope_surfaces_map_to_their_schema() {
        use super::parse_error_schema as f;
        assert_eq!(
            f(&argv(&["csq", "sessions", "inbox", "--bogus"])),
            Some(super::SCHEMA_DIRECTIVE_INBOX_V1)
        );
        assert_eq!(
            f(&argv(&["csq", "--json", "sessions", "ack", "--note"])),
            Some(super::SCHEMA_DIRECTIVE_RECEIPT_V1)
        );
        assert_eq!(
            f(&argv(&["csq", "sessions", "deliver", "x"])),
            Some(super::SCHEMA_DIRECTIVE_RECEIPT_V1)
        );
        assert_eq!(
            f(&argv(&["csq", "sessions", "receipts", "--zz"])),
            Some(super::SCHEMA_DIRECTIVE_RECEIPTS_V1)
        );
        assert_eq!(
            f(&argv(&["csq", "sessions", "list", "--json", "--zz"])),
            Some(csq_core::sdk::SCHEMA_SESSIONS_V1)
        );
        // not envelope surfaces: clap keeps its own error
        assert_eq!(f(&argv(&["csq", "sessions", "list", "--zz"])), None);
        assert_eq!(f(&argv(&["csq", "sessions", "share", "--zz"])), None);
        assert_eq!(f(&argv(&["csq", "swap", "sessions"])), None);
        assert_eq!(f(&argv(&["csq", "sessions"])), None);
        assert_eq!(f(&argv(&["csq"])), None);
    }

    #[test]
    fn a_literal_double_dash_before_the_verb_is_not_an_envelope_surface() {
        use super::parse_error_schema as f;
        assert_eq!(f(&argv(&["csq", "sessions", "--", "inbox"])), None);
        assert_eq!(f(&argv(&["csq", "--", "sessions", "inbox"])), None);
        // `--json` after `--` is not the list flag either
        assert_eq!(f(&argv(&["csq", "sessions", "list", "--", "--json"])), None);
        // a `--` AFTER the verb leaves the verb's schema intact
        assert_eq!(
            f(&argv(&["csq", "sessions", "inbox", "--", "x"])),
            Some(super::SCHEMA_DIRECTIVE_INBOX_V1)
        );
    }

    use super::*;
    use csq_core::sessions::IncompleteCause;
    use std::path::PathBuf;

    fn yes(_: u32) -> Option<Option<csq_core::sessions::AncestorHops>> {
        Some(Some(Vec::new()))
    }

    /// Re-read start times matching `session()`'s listed ones: pid 1 -> 10, 2 -> 20, ...
    fn start_matching(pid: u32) -> Option<u64> {
        Some(u64::from(pid) * 10)
    }

    fn session(pid: u32, dir: &str, started_at: Option<u64>) -> SessionInfo {
        SessionInfo {
            pid,
            cwd: PathBuf::from("/"),
            config_dir: PathBuf::from(dir),
            account_id: None,
            started_at,
            tty: None,
            term_window: None,
            term_tab: None,
            term_pane: None,
            iterm_profile: None,
            terminal_title: None,
        }
    }

    fn err(code: SdkErrorCode, next: Option<u64>) -> DirectiveError {
        DirectiveError {
            code,
            message: "m".to_string(),
            cause: None,
            attempts: None,
            next_allowed_at: next,
        }
    }

    #[test]
    fn resolves_the_unique_session_for_the_handle_dir() {
        let s = [
            session(1, "/nope/term-1", Some(10)),
            session(2, "/nope/term-2", Some(20)),
        ];
        assert_eq!(
            resolve_calling_session(
                &s,
                &[],
                Visibility::WHOLE,
                Some("/nope/term-2"),
                &yes,
                &start_matching
            )
            .unwrap(),
            (2, 20)
        );
    }

    fn code_of(
        s: &[SessionInfo],
        anc: &dyn Fn(u32) -> Option<Option<csq_core::sessions::AncestorHops>>,
        start: &dyn Fn(u32) -> Option<u64>,
    ) -> SdkErrorCode {
        resolve_calling_session(s, &[], Visibility::WHOLE, Some("/nope/term-2"), anc, start)
            .unwrap_err()
            .code
    }

    #[test]
    fn a_caller_that_is_not_inside_the_session_is_a_target_mismatch() {
        // CLAUDE_CONFIG_DIR names session 2's handle dir, but this process is not
        // one of its descendants: a spoofed env var must not pass as that session.
        let s = [session(2, "/nope/term-2", Some(20))];
        assert_eq!(
            code_of(&s, &|_| Some(None), &start_matching),
            SdkErrorCode::TargetMismatch
        );
    }

    #[test]
    fn an_unreadable_ancestry_is_undetermined_never_success() {
        let s = [session(2, "/nope/term-2", Some(20))];
        assert_eq!(
            code_of(&s, &|_| None, &start_matching),
            SdkErrorCode::Undetermined
        );
    }

    #[test]
    fn a_recycled_pid_is_refused_and_an_unreadable_start_is_undetermined() {
        let s = [session(2, "/nope/term-2", Some(20))];
        // listed 20, now reads 500: a different process holds the pid
        assert_eq!(
            code_of(&s, &yes, &|_| Some(500)),
            SdkErrorCode::TargetMismatch
        );
        assert_eq!(code_of(&s, &yes, &|_| None), SdkErrorCode::Undetermined);
        // one second of Linux btime jitter is the same process
        assert_eq!(
            resolve_calling_session(
                &s,
                &[],
                Visibility::WHOLE,
                Some("/nope/term-2"),
                &yes,
                &|_| Some(21)
            )
            .unwrap(),
            (2, 20)
        );
        assert_eq!(
            resolve_calling_session(
                &s,
                &[],
                Visibility::WHOLE,
                Some("/nope/term-2"),
                &yes,
                &|_| Some(19)
            )
            .unwrap(),
            (2, 20)
        );
    }

    #[test]
    fn unresolvable_caller_is_undetermined() {
        let s = [
            session(1, "/nope/term-1", Some(10)),
            session(2, "/nope/term-1", Some(11)),
        ];
        for (sessions, dir) in [
            (&s[..], None),
            (&s[..], Some("")),
            (&s[..], Some("/nope/other")),
            (&s[..], Some("/nope/term-1")), // two owners: refuse to guess
            (
                &[session(3, "/nope/term-3", None)][..],
                Some("/nope/term-3"),
            ), // no start time
            (
                &[
                    session(4, "/nope/term-4", None),
                    session(5, "/nope/term-4", Some(50)),
                ][..],
                Some("/nope/term-4"),
            ), // two owners, one lacks a start time: still two owners
        ] {
            let e = resolve_calling_session(
                sessions,
                &[],
                Visibility::WHOLE,
                dir,
                &yes,
                &start_matching,
            )
            .unwrap_err();
            assert_eq!(e.code, SdkErrorCode::Undetermined, "{dir:?}");
        }
    }

    /// An unreadable `claude`-named process makes resolution undetermined even when exactly
    /// one readable owner exists; control: the same input with none unreadable resolves.
    #[test]
    fn an_unreadable_claude_makes_the_caller_undetermined() {
        let s = [session(2, "/nope/term-2", Some(20))];
        let at = |unreadable: &[u32]| {
            resolve_calling_session(
                &s,
                unreadable,
                Visibility::WHOLE,
                Some("/nope/term-2"),
                &yes,
                &start_matching,
            )
        };
        assert_eq!(at(&[]).unwrap(), (2, 20), "control: nothing unreadable");
        let one = at(&[41]).unwrap_err();
        assert_eq!(one.code, SdkErrorCode::Undetermined);
        assert!(
            one.message
                .contains("1 process(es) that may be a claude session")
                && one.message.contains("pid 41"),
            "{}",
            one.message
        );
        assert!(one.message.contains("retry"), "{}", one.message);
        let many = at(&[1, 2, 3, 4, 5, 6, 7]).unwrap_err();
        assert!(
            many.message.contains("7 process(es) that may be a claude")
                && many.message.contains("pid 1, 2, 3, 4, 5, …"),
            "{}",
            many.message
        );
        assert!(
            !many.message.contains('6'),
            "only five pids are named: {}",
            many.message
        );
    }

    /// An incomplete process listing makes resolution undetermined with its own reason,
    /// distinct from the unreadable-claude one, and names the cause's next step; control: the
    /// same input complete resolves.
    #[test]
    fn an_incomplete_listing_makes_the_caller_undetermined() {
        let s = [session(2, "/nope/term-2", Some(20))];
        let at = |view: Visibility| {
            resolve_calling_session(&s, &[], view, Some("/nope/term-2"), &yes, &start_matching)
        };
        assert_eq!(at(Visibility::WHOLE).unwrap(), (2, 20), "control: complete");
        let generic = at(Visibility {
            incomplete: true,
            ..Visibility::WHOLE
        })
        .unwrap_err();
        assert_eq!(generic.code, SdkErrorCode::Undetermined);
        assert!(
            generic.message.contains("hides processes"),
            "{}",
            generic.message
        );
        let ns = at(Visibility {
            incomplete: true,
            cause: Some(IncompleteCause::PidNamespaceMismatch),
            ..Visibility::WHOLE
        })
        .unwrap_err();
        assert!(
            ns.message
                .contains("run csq on the host, outside the container"),
            "{}",
            ns.message
        );
    }

    /// A restricted caller gets the sandbox message and NOT a list of pids, even with
    /// hundreds unreadable; control: the same unreadable pids unrestricted name the pids.
    #[test]
    fn a_restricted_caller_is_told_about_the_sandbox_not_the_pids() {
        let s = [session(2, "/nope/term-2", Some(20))];
        let pids: Vec<u32> = (100..600).collect();
        let at = |restricted: bool| {
            resolve_calling_session(
                &s,
                &pids,
                Visibility {
                    restricted,
                    ..Visibility::WHOLE
                },
                Some("/nope/term-2"),
                &yes,
                &start_matching,
            )
            .unwrap_err()
        };
        let e = at(true);
        assert!(
            e.message.contains("restricted for this caller")
                && e.message.contains("outside the sandbox"),
            "{}",
            e.message
        );
        assert!(!e.message.contains("pid 100"), "{}", e.message);
        assert!(
            at(false).message.contains("pid 100"),
            "control names the pids"
        );
    }

    #[test]
    fn rate_limited_envelope_carries_next_allowed_at_and_error_code() {
        let env = build::<()>(
            SCHEMA_DIRECTIVE_RECEIPT_V1,
            Err(err(SdkErrorCode::RateLimited, Some(77))),
        );
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], "rate_limited");
        assert_eq!(v["next_allowed_at"], 77);
        assert_eq!(v["schema"], "csq.directive_receipt.v1");
    }

    #[test]
    fn other_refusals_carry_only_the_error() {
        let env = build::<()>(
            SCHEMA_DIRECTIVE_RECEIPT_V1,
            Err(err(SdkErrorCode::TargetMismatch, None)),
        );
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], "target_mismatch");
        assert!(v.get("next_allowed_at").is_none());
    }

    #[test]
    fn success_envelope_inlines_the_payload() {
        let payload = DirectiveReceiptsPayload::new(vec![]);
        let env = build(SCHEMA_DIRECTIVE_RECEIPTS_V1, Ok(payload));
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["receipts"], serde_json::json!([]));
        assert!(v.get("error").is_none());
    }

    #[test]
    fn stdin_over_the_cap_is_invalid_input() {
        let big = vec![b'x'; (MAX_STDIN_BYTES + 1) as usize];
        assert_eq!(
            read_stdin_bounded(&big[..]).unwrap_err().code,
            SdkErrorCode::InvalidInput
        );
        assert_eq!(read_stdin_bounded(&b"{}"[..]).unwrap(), "{}");
        assert_eq!(
            read_stdin_bounded(&[0xff, 0xfe][..]).unwrap_err().code,
            SdkErrorCode::InvalidInput
        );
    }

    fn line(env: &Envelope<serde_json::Value>) -> serde_json::Value {
        serde_json::from_str(&env.to_line().unwrap()).unwrap()
    }

    fn no_caller() -> Result<(u32, u64), DirectiveError> {
        panic!("the caller must not be resolved for a malformed request")
    }

    #[test]
    fn bad_since_is_an_invalid_input_receipts_envelope() {
        let t = tempfile::tempdir().unwrap();
        for bad in ["abc", "-1", "", "1.5"] {
            let v = line(&build(
                SCHEMA_DIRECTIVE_RECEIPTS_V1,
                receipts_result(t.path(), Some(bad), None),
            ));
            assert_eq!(v["schema"], "csq.directive_receipts.v1", "{bad:?}");
            assert_eq!(v["ok"], false);
            assert_eq!(v["error"]["code"], "invalid_input", "{bad:?}");
        }
        let v = line(&build(
            SCHEMA_DIRECTIVE_RECEIPTS_V1,
            receipts_result(t.path(), Some("100"), None),
        ));
        assert_eq!(v["ok"], true);
    }

    #[test]
    fn missing_ack_id_and_bad_outcome_are_invalid_input_receipt_envelopes() {
        let t = tempfile::tempdir().unwrap();
        let v = line(&build(
            SCHEMA_DIRECTIVE_RECEIPT_V1,
            ack_result(t.path(), None, "done", None, &no_caller),
        ));
        assert_eq!(v["schema"], "csq.directive_receipt.v1");
        assert_eq!(v["error"]["code"], "invalid_input");
        for outcome in ["", "maybe"] {
            let v = line(&build(
                SCHEMA_DIRECTIVE_RECEIPT_V1,
                ack_result(
                    t.path(),
                    Some("0b6c3c1e-7d0e-4b0a-9d3e-2f8f1a2b3c4d"),
                    outcome,
                    None,
                    &no_caller,
                ),
            ));
            assert_eq!(v["error"]["code"], "invalid_input", "{outcome:?}");
        }
    }

    #[test]
    fn directive_verbs_parse_without_clap_usage_errors_on_bad_values() {
        use clap::Parser;
        for args in [
            &["csq", "sessions", "ack"][..],
            &["csq", "sessions", "ack", "--outcome", "maybe"],
            &["csq", "sessions", "ack", "x", "--outcome", "done"],
            &["csq", "sessions", "receipts", "--since", "abc"],
            &["csq", "sessions", "receipts", "--id", "nope"],
        ] {
            assert!(
                crate::cli::Cli::try_parse_from(args).is_ok(),
                "{args:?} must reach the handler, not clap's exit 2"
            );
        }
    }

    #[test]
    fn a_flag_shaped_value_is_a_parse_error_not_a_swallowed_flag() {
        use clap::Parser;
        // Without `allow_hyphen_values`, `--note --json` can no longer store "--json"
        // as the note, and `--since -5` is refused instead of reaching the handler.
        for (args, schema) in [
            (
                &["csq", "sessions", "ack", "x", "--note", "--json"][..],
                super::SCHEMA_DIRECTIVE_RECEIPT_V1,
            ),
            (
                &["csq", "sessions", "receipts", "--since", "-5"][..],
                super::SCHEMA_DIRECTIVE_RECEIPTS_V1,
            ),
            (
                &["csq", "sessions", "receipts", "--id", "--json"][..],
                super::SCHEMA_DIRECTIVE_RECEIPTS_V1,
            ),
        ] {
            assert!(
                crate::cli::Cli::try_parse_from(args).is_err(),
                "{args:?} must be a parse error"
            );
            assert_eq!(super::parse_error_schema(&argv(args)), Some(schema));
        }
        // the `=` form still carries a hyphen-leading value
        assert!(
            crate::cli::Cli::try_parse_from(["csq", "sessions", "ack", "x", "--note=-hello"])
                .is_ok()
        );
    }
}
