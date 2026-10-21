//! The csq-owned messaging row. Repository row IDs cannot select this builtin.
//! It reuses the existing store claim and exact output renderer, without stdin
//! reparsing or spawning a second csq process.

use crate::messaging::hook::{self, HookEvent};
use crate::messaging::limits::Liveness;
use crate::messaging::{Recipient, VerifiedSession};
use crate::sessions::directives::{DirectiveError, FsOps};
use serde_json::Value;
use std::path::Path;
use std::time::Instant;

/// Preserve the existing standalone hook's payload admission bound.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// Execute only a proved main-session event. Failure is messaging's existing
/// continue policy, never a denial of the user's action. The returned bytes are
/// exactly the existing hook output; the dispatcher owns merging and emission.
pub fn run(
    base_dir: &Path,
    event: &str,
    payload: &Value,
    payload_bytes: usize,
    deadline: Instant,
    context: MessagingContext<'_>,
) -> Option<String> {
    let event = HookEvent::parse(event)?;
    if payload_bytes > MAX_PAYLOAD_BYTES || Instant::now() >= deadline {
        return None;
    }
    let object = payload.as_object()?;
    // A nonempty native agent_id identifies a subagent. Invalid/malformed IDs
    // are unresolved, never a main-session proof. agent_type alone is not proof.
    if object.contains_key("agent_id") {
        return None;
    }
    if event == HookEvent::Stop
        && object
            .get("stop_hook_active")
            .is_some_and(|flag| flag.as_bool() != Some(false))
    {
        return None;
    }
    let who = (context.caller)().ok()?;
    let now = (context.now)().ok()?;
    let unknown = |_: &Recipient| Liveness::Unknown;
    hook::surface_until(base_dir, now, context.fs, &unknown, &who, event, deadline)
        .ok()
        .flatten()
}

/// Identity and store dependencies are supplied by the proved session caller,
/// never by the hook payload or a repository-declared row.
pub struct MessagingContext<'a> {
    pub caller: &'a dyn Fn() -> Result<VerifiedSession, DirectiveError>,
    pub now: &'a dyn Fn() -> Result<u64, DirectiveError>,
    pub fs: &'a FsOps<'a>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::limits::Limits;
    use crate::messaging::model::{Sender, Surface};
    use crate::messaging::store;
    use crate::sessions::directives::real_fs;
    use serde_json::json;
    use std::time::Duration;

    const NOW: u64 = 1_000_000;

    fn session(pid: u32) -> VerifiedSession {
        VerifiedSession::from_resolved(Sender {
            pid,
            started_at: NOW - 10,
            started_exact: Some(NOW - 10),
            surface: Surface::ClaudeCode,
            handle_dir_hash: format!("handle{pid}"),
            handle_dir: format!("/private/term-{pid}"),
            name: None,
        })
    }

    #[test]
    fn native_messaging_bytes_match_standalone_renderer_and_claim_semantics() {
        for event in ["UserPromptSubmit", "PostToolUse", "Stop"] {
            let dir = tempfile::tempdir().unwrap();
            let who = session(9);
            store::send(
                dir.path(),
                NOW,
                &real_fs(),
                &Limits::DEFAULT,
                &|_| Liveness::Live,
                &session(7),
                who.as_recipient(),
                "review the exact change",
                None,
            )
            .unwrap();
            let views = store::inbox(
                dir.path(),
                NOW,
                &real_fs(),
                &|_| Liveness::Live,
                &who,
                true,
                None,
            )
            .unwrap();
            let expected = hook::render(HookEvent::parse(event).unwrap(), &views);
            let fs = real_fs();
            let actual = run(
                dir.path(),
                event,
                &json!({}),
                2,
                Instant::now() + Duration::from_secs(2),
                MessagingContext {
                    caller: &|| Ok(who.clone()),
                    now: &|| Ok(NOW),
                    fs: &fs,
                },
            );
            assert_eq!(actual, expected, "builtin output must be byte-identical");
            let pending = store::pending_count(dir.path(), NOW, &who.as_recipient()).unwrap();
            assert_eq!(
                pending.queued,
                usize::from(event == "Stop"),
                "Stop preserves the unread pointer; full frames use the existing surfacing claim"
            );
        }
    }

    #[test]
    fn native_messaging_origin_and_expiry_refuse_before_identity_or_store() {
        for (event, payload, len, expired) in [
            ("PostToolUse", json!({"agent_id":"child"}), 20, false),
            ("PostToolUse", json!({"agent_id":null}), 20, false),
            ("Stop", json!({"stop_hook_active":true}), 20, false),
            ("Stop", json!({"stop_hook_active":null}), 20, false),
            ("PostToolUse", json!([]), 2, false),
            ("PostToolUse", json!({}), MAX_PAYLOAD_BYTES + 1, false),
            ("PreToolUse", json!({}), 2, false),
            ("PostToolUse", json!({}), 2, true),
        ] {
            let fs = real_fs();
            let deadline = if expired {
                Instant::now()
            } else {
                Instant::now() + Duration::from_secs(1)
            };
            assert!(run(
                Path::new("/not-a-message-store"),
                event,
                &payload,
                len,
                deadline,
                MessagingContext {
                    caller: &|| panic!("unadmitted event cannot resolve identity"),
                    now: &|| panic!("unadmitted event cannot read clock"),
                    fs: &fs,
                },
            )
            .is_none());
        }
    }

    #[test]
    fn native_messaging_agent_type_alone_and_false_stop_flag_still_surface() {
        let dir = tempfile::tempdir().unwrap();
        let who = session(9);
        let fs = real_fs();
        store::send(
            dir.path(),
            NOW,
            &fs,
            &Limits::DEFAULT,
            &|_| Liveness::Live,
            &session(7),
            who.as_recipient(),
            "main session message",
            None,
        )
        .unwrap();
        assert!(run(
            dir.path(),
            "Stop",
            &json!({"agent_type":"custom", "stop_hook_active":false}),
            48,
            Instant::now() + Duration::from_secs(1),
            MessagingContext {
                caller: &|| Ok(who.clone()),
                now: &|| Ok(NOW),
                fs: &fs
            },
        )
        .is_some());
    }

    #[test]
    fn shared_dispatch_deadline_never_marks_a_queued_record_after_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let who = session(9);
        let fs = real_fs();
        store::send(
            dir.path(),
            NOW,
            &fs,
            &Limits::DEFAULT,
            &|_| Liveness::Live,
            &session(7),
            who.as_recipient(),
            "still pending",
            None,
        )
        .unwrap();
        assert!(
            hook::surface_until(
                dir.path(),
                NOW,
                &fs,
                &|_| Liveness::Unknown,
                &who,
                HookEvent::PostToolUse,
                Instant::now(),
            )
            .is_err(),
            "an expired dispatch must not acquire a new marking budget"
        );
        assert_eq!(
            store::pending_count(dir.path(), NOW, &who.as_recipient())
                .unwrap()
                .queued,
            1,
            "expiry leaves the message available for the next event",
        );
    }

    #[test]
    fn child_event_preserves_main_cohort_without_emitting_its_body() {
        let dir = tempfile::tempdir().unwrap();
        let who = session(9);
        let fs = real_fs();
        store::send(
            dir.path(),
            NOW,
            &fs,
            &Limits::DEFAULT,
            &|_| Liveness::Live,
            &session(7),
            who.as_recipient(),
            "main-only body",
            None,
        )
        .unwrap();
        let output = run(
            dir.path(),
            "PostToolUse",
            &json!({"agent_id":"child"}),
            20,
            Instant::now() + Duration::from_secs(1),
            MessagingContext {
                caller: &|| Ok(who.clone()),
                now: &|| Ok(NOW),
                fs: &fs,
            },
        );
        assert!(
            output.is_none(),
            "a child event must not emit the MAIN framed body"
        );
        assert_eq!(
            store::pending_count(dir.path(), NOW, &who.as_recipient())
                .unwrap()
                .queued,
            1
        );
    }
}
