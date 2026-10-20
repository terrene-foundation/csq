//! Production JSON locked maintenance, with per-pass conservative liveness reuse.
#![cfg(test)]
use super::super::model::Surface;
use super::*;
use crate::sessions::directives::real_fs;
use std::cell::Cell;

const NOW: u64 = 1_000_000;
const N: u32 = 32;
struct Fixture {
    root: tempfile::TempDir,
    ids: Vec<String>,
}
fn recipient() -> Recipient {
    Recipient {
        pid: 101,
        started_at: NOW - 100,
        surface: Surface::Codex,
        started_exact: Some(50001),
    }
}
fn sender(to: Recipient) -> Sender {
    Sender {
        pid: to.pid,
        started_at: to.started_at,
        surface: to.surface,
        handle_dir_hash: "fixture101".to_owned(),
        handle_dir: "/fixture/101".to_owned(),
        name: None,
        started_exact: to.started_exact,
    }
}
impl Fixture {
    fn new(recipients: &[Recipient]) -> Self {
        let root = tempfile::tempdir().unwrap();
        let dir = store_dir(root.path());
        ensure_dir_as(LABEL, &dir).unwrap();
        let mut ids = Vec::new();
        for (n, &to) in recipients.iter().enumerate() {
            let id = format!("00000000-0000-4000-8000-{n:012x}");
            let message = Message {
                schema: SCHEMA.to_owned(),
                id: id.clone(),
                thread: id.clone(),
                from: sender(Recipient {
                    pid: 100,
                    ..recipient()
                }),
                to,
                in_reply_to: None,
                body: format!("fixture {n}"),
                created_at: NOW - 100,
                noticed_at: None,
                surfaced_at: None,
                read_at: None,
                acked_at: None,
                undeliverable_at: None,
                ack_note: None,
                ack_nonce: None,
            };
            save(&dir, &message, &real_fs()).unwrap();
            ids.push(id);
        }
        Self { root, ids }
    }
    fn maintenance(&self, now: u64, live: &dyn Fn(&Recipient) -> Liveness) -> usize {
        locked(
            self.root.path(),
            now,
            &real_fs(),
            &Limits::DEFAULT,
            live,
            |_, records| Ok(records.iter().filter(|message| message.pending()).count()),
        )
        .unwrap()
    }
    fn rows(&self) -> Vec<Message> {
        self.ids
            .iter()
            .map(|id| {
                load_one(&store_dir(self.root.path()), id)
                    .unwrap_or_else(|_| panic!("fixture record must pass production validation"))
                    .unwrap()
            })
            .collect()
    }
}

#[test]
fn live_recipient_is_sampled_once_in_actual_locked_maintenance() {
    let f = Fixture::new(&[recipient(); N as usize]);
    let calls = Cell::new(0);
    let live = |_: &Recipient| {
        calls.set(calls.get() + 1);
        Liveness::Live
    };
    assert_eq!(f.maintenance(NOW, &live), N as usize);
    assert_eq!(
        calls.get(),
        1,
        "same full recipient must not repeat conservative native liveness lookup"
    );
    assert!(f.rows().iter().all(|row| row.undeliverable_at.is_none()));
    assert_eq!(f.maintenance(NOW + 1, &live), N as usize);
    assert_eq!(
        calls.get(),
        2,
        "a second maintenance pass must sample afresh"
    );
}

#[test]
fn unknown_preserves_rows_and_the_next_pass_rechecks_every_ended_record() {
    let f = Fixture::new(&[recipient(); N as usize]);
    let calls = Cell::new(0);
    assert_eq!(
        f.maintenance(NOW, &|_: &Recipient| {
            calls.set(calls.get() + 1);
            Liveness::Unknown
        }),
        N as usize
    );
    assert_eq!(calls.get(), 1);
    assert!(f.rows().iter().all(|row| row.undeliverable_at.is_none()));
    calls.set(0);
    assert_eq!(
        f.maintenance(NOW + 1, &|_: &Recipient| {
            calls.set(calls.get() + 1);
            Liveness::Ended
        }),
        0
    );
    assert_eq!(
        calls.get(),
        N,
        "Ended requires a fresh proof for each pending record"
    );
    assert!(f
        .rows()
        .iter()
        .all(|row| row.undeliverable_at == Some(NOW + 1)));
}

#[test]
fn ended_is_not_reused_and_a_following_live_record_is_preserved() {
    let f = Fixture::new(&[recipient(); 3]);
    let calls = Cell::new(0);
    let live = |_: &Recipient| {
        calls.set(calls.get() + 1);
        if calls.get() == 1 {
            Liveness::Ended
        } else {
            Liveness::Live
        }
    };
    assert_eq!(f.maintenance(NOW, &live), 2);
    assert_eq!(
        calls.get(),
        2,
        "a first Ended result cannot retire subsequent records without resampling"
    );
    assert_eq!(
        f.rows()
            .iter()
            .filter(|row| row.undeliverable_at == Some(NOW))
            .count(),
        1
    );
}

#[test]
fn all_four_recipient_fields_and_optional_exact_start_separate_reuse_keys() {
    let original = recipient();
    let addresses = [
        original,
        Recipient {
            pid: original.pid + 1,
            ..original
        },
        Recipient {
            started_at: original.started_at + 1,
            ..original
        },
        Recipient {
            started_exact: Some(50002),
            ..original
        },
        Recipient {
            started_exact: None,
            ..original
        },
        Recipient {
            surface: Surface::ClaudeCode,
            ..original
        },
    ];
    let recipients: Vec<_> = addresses
        .iter()
        .flat_map(|recipient| [*recipient, *recipient])
        .collect();
    let f = Fixture::new(&recipients);
    let calls = Cell::new(0);
    assert_eq!(
        f.maintenance(NOW, &|_: &Recipient| {
            calls.set(calls.get() + 1);
            Liveness::Live
        }),
        recipients.len()
    );
    assert_eq!(
        calls.get(),
        addresses.len(),
        "pid, coarse start, exact start and surface each bind a distinct conservative result"
    );
    assert!(f.rows().iter().all(|row| row.undeliverable_at.is_none()));
}

#[test]
fn a_live_or_unknown_result_is_only_conservative_for_the_current_pass() {
    for first in [Liveness::Live, Liveness::Unknown] {
        let f = Fixture::new(&[recipient(); 3]);
        let calls = Cell::new(0);
        let changing = |_: &Recipient| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                first
            } else {
                Liveness::Ended
            }
        };
        assert_eq!(f.maintenance(NOW, &changing), 3);
        assert_eq!(calls.get(), 1);
        assert!(f.rows().iter().all(|row| row.undeliverable_at.is_none()));
        assert_eq!(f.maintenance(NOW + 1, &changing), 0);
        assert_eq!(
            calls.get(),
            4,
            "a new pass must reconsider all three now-Ended records"
        );
    }
}

#[cfg(test)]
fn caller() -> VerifiedSession {
    VerifiedSession::from_resolved(sender(Recipient {
        pid: 100,
        ..recipient()
    }))
}
#[test]
fn send_admission_resamples_after_conservative_maintenance_and_refuses_without_new_id() {
    for keyed in [false, true] {
        for refusal in [Liveness::Ended, Liveness::Unknown] {
            let f = Fixture::new(&[recipient(); N as usize]);
            let calls = Cell::new(0);
            let changing = |_: &Recipient| {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    Liveness::Live
                } else {
                    refusal
                }
            };
            let from = caller();
            // Isolate the liveness gate: the seeded cohort must leave one admissible rate slot.
            let limits = Limits {
                max_send_per_pair: N as usize + 1,
                ..Limits::DEFAULT
            };
            let code = if keyed {
                let key = super::super::request::mint(NOW);
                let error = super::super::request::send(
                    f.root.path(),
                    NOW,
                    &real_fs(),
                    &limits,
                    &changing,
                    &from,
                    recipient(),
                    "peer",
                    "new message",
                    None,
                    &key,
                )
                .unwrap_err();
                assert_eq!(
                    super::super::request::lookup(f.root.path(), NOW, &real_fs(), &from, &key)
                        .unwrap(),
                    super::super::request::Lookup::NotStored,
                    "fresh admission refusal must not create Prepared authority",
                );
                error.code
            } else {
                send(
                    f.root.path(),
                    NOW,
                    &real_fs(),
                    &limits,
                    &changing,
                    &from,
                    recipient(),
                    "new message",
                    None,
                )
                .unwrap_err()
                .code
            };
            assert_eq!(
                code,
                if refusal == Liveness::Ended {
                    SdkErrorCode::TargetMismatch
                } else {
                    SdkErrorCode::Undetermined
                }
            );
            assert_eq!(
                calls.get(),
                2,
                "admission must not consume the maintenance Live result"
            );
            assert_eq!(
                load_all(
                    &store_dir(f.root.path()),
                    Limits::DEFAULT.max_records,
                    NOW,
                    false
                )
                .unwrap()
                .len(),
                N as usize
            );
            assert!(f.rows().iter().all(|row| row.undeliverable_at.is_none()));
        }
        let f = Fixture::new(&[recipient(); N as usize]);
        let calls = Cell::new(0);
        let live = |_: &Recipient| {
            calls.set(calls.get() + 1);
            Liveness::Live
        };
        let from = caller();
        let limits = Limits {
            max_send_per_pair: N as usize + 1,
            ..Limits::DEFAULT
        };
        let receipt = if keyed {
            let key = super::super::request::mint(NOW);
            super::super::request::send(
                f.root.path(),
                NOW,
                &real_fs(),
                &limits,
                &live,
                &from,
                recipient(),
                "peer",
                "new message",
                None,
                &key,
            )
            .unwrap()
            .0
        } else {
            send(
                f.root.path(),
                NOW,
                &real_fs(),
                &limits,
                &live,
                &from,
                recipient(),
                "new message",
                None,
            )
            .unwrap()
        };
        assert_eq!(
            calls.get(),
            2,
            "positive admission control also requires its fresh sample"
        );
        assert!(!f.ids.contains(&receipt.id));
        assert_eq!(
            load_all(&store_dir(f.root.path()), limits.max_records, NOW, false)
                .unwrap()
                .len(),
            N as usize + 1
        );
    }
}
