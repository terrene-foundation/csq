//! Private store fixtures at the dispatch/claim seam, not live Claude execution.
use super::*;
use crate::gate::messaging::{self, MessagingContext};
use crate::messaging::limits::{Limits, Liveness};
use crate::messaging::model::{Sender, Surface as MessageSurface};
use crate::messaging::{store, VerifiedSession};
use crate::sessions::directives::real_fs;

const NOW: u64 = 1_000_000;

#[cfg(test)]
fn session(pid: u32) -> VerifiedSession {
    VerifiedSession::from_resolved(Sender {
        pid,
        started_at: NOW - 10,
        started_exact: Some(NOW - 10),
        surface: MessageSurface::ClaudeCode,
        handle_dir_hash: format!("handle{pid}"),
        handle_dir: format!("/private/term-{pid}"),
        name: None,
    })
}

struct InboxNative<'a> {
    base: &'a Path,
    who: VerifiedSession,
    clock: &'a Cell<Instant>,
    cross_after_claim: bool,
    committed: Option<Vec<u8>>,
}
impl NativeHook for InboxNative<'_> {
    fn output_bound(&self) -> usize {
        crate::messaging::hook::MAX_HOOK_CHARS * 4
    }
    fn run(&mut self, input: &ParsedPayload, deadline: Instant) -> Result<RowOutput, RowFailure> {
        let fs = real_fs();
        let text = messaging::run(
            self.base,
            input.event.as_str(),
            &input.value,
            input.original_bytes.len(),
            deadline,
            MessagingContext {
                caller: &|| Ok(self.who.clone()),
                now: &|| Ok(NOW),
                fs: &fs,
            },
        )
        .unwrap();
        let bytes = text.into_bytes();
        assert!(bytes.len() <= self.output_bound());
        self.committed = Some(bytes.clone());
        if self.cross_after_claim {
            self.clock.set(deadline);
        }
        Ok(RowOutput {
            stdout: bytes,
            ..RowOutput::default()
        })
    }
}

fn send(base: &Path, who: &VerifiedSession) {
    store::send(
        base,
        NOW,
        &real_fs(),
        &Limits::DEFAULT,
        &|_| Liveness::Live,
        &session(7),
        who.as_recipient(),
        "committed native body",
        None,
    )
    .unwrap();
}

#[test]
fn gate_post_claim_expiry_keeps_committed_native_bytes() {
    let (dir, verified, input) = world(Event::PostToolUse, vec![]);
    let base = dir.path().join("message-store");
    let who = session(9);
    send(&base, &who);
    let clock = Cell::new(Instant::now());
    let deadline = clock.get() + Duration::from_secs(2);
    let mut native = InboxNative {
        base: &base,
        who: who.clone(),
        clock: &clock,
        cross_after_claim: true,
        committed: None,
    };
    let result = dispatch_with_clock(
        &input,
        &verified,
        &mut Runner::new(vec![]),
        &mut NativeMatcher,
        Some(&mut native),
        (deadline, || clock.get()),
    );
    assert_eq!(
        result.stdout,
        native.committed.unwrap(),
        "committed claim must be delivered after cooperative expiry"
    );
    assert_eq!(
        store::pending_count(&base, NOW, &who.as_recipient())
            .unwrap()
            .queued,
        0
    );
    assert!(String::from_utf8(result.stdout)
        .unwrap()
        .contains("committed native body"));
}

#[test]
fn gate_native_capacity_is_reserved_before_repository_output() {
    let mut r = row("large", 10, Event::PostToolUse);
    r["on_incomplete"] = "deny".into();
    r["on_crash"] = "deny".into();
    r["on_timeout"] = "deny".into();
    let (dir, verified, input) = world(Event::PostToolUse, vec![r]);
    let base = dir.path().join("message-store");
    let who = session(9);
    send(&base, &who);
    let clock = Cell::new(Instant::now());
    let deadline = clock.get() + Duration::from_secs(2);
    let mut native = InboxNative {
        base: &base,
        who: who.clone(),
        clock: &clock,
        cross_after_claim: false,
        committed: None,
    };
    let large = context(input.event, &"x".repeat(MAX_ROW_OUTPUT_BYTES - 100));
    assert!(large.stdout.len() < MAX_ROW_OUTPUT_BYTES);
    let result = dispatch_with_clock(
        &input,
        &verified,
        &mut Runner::new(vec![Ok(large)]),
        &mut NativeMatcher,
        Some(&mut native),
        (deadline, || clock.get()),
    );
    assert!(
        result.denied,
        "repository output exceeding its reserved share follows its policy"
    );
    assert!(
        String::from_utf8(result.stdout)
            .unwrap()
            .contains("committed native body"),
        "earlier output cannot consume the native claim's capacity"
    );
    assert_eq!(
        store::pending_count(&base, NOW, &who.as_recipient())
            .unwrap()
            .queued,
        0
    );
}
