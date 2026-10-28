//! Process-lifetime admission and drain for desktop credential writers.
//!
//! The gate itself lives in [`super::login_custody`]: sign-in custody and every
//! other credential writer MUST share one admission count, or a Quit drain
//! could miss a login running on the other module's singleton. This module
//! keeps S1's names so its call sites stay readable; no state lives here.
//!
//! A permit belongs to the actual writer, including a blocking closure whose
//! join handle was dropped. Closing admission never cancels an admitted writer.
//! The Windows Quit coordinator owns the single dependency-derived deadline;
//! this module only observes completion and does not invent a transport bound.

#[cfg(windows)]
pub(super) use super::login_custody::{close_for_quit_tag, Drain};
pub(super) use super::login_custody::{global, CredentialWrites, SigninProvider};

#[cfg(test)]
mod tests {
    use super::*;
    use csq_core::types::AccountNum;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::{future::Future, pin::Pin, task::Poll};

    struct ReleaseOnDrop<F: FnOnce()>(Option<F>);

    impl<F: FnOnce()> Drop for ReleaseOnDrop<F> {
        fn drop(&mut self) {
            if let Some(release) = self.0.take() {
                release();
            }
        }
    }

    async fn assert_pending<F: Future>(mut future: Pin<&mut F>) {
        std::future::poll_fn(|cx| {
            assert!(
                future.as_mut().poll(cx).is_pending(),
                "drain finished with a live writer"
            );
            Poll::Ready(())
        })
        .await;
    }

    #[test]
    fn shim_and_login_custody_share_the_process_singleton() {
        assert!(std::ptr::eq(
            global(),
            crate::desktop::login_custody::global()
        ));
    }

    #[test]
    fn signin_metadata_tracks_exact_worker_registration_lifetime() {
        let writes = CredentialWrites::default();
        let account = AccountNum::try_from(7u16).unwrap();
        let worker = writes
            .register_signin(SigninProvider::Claude, account)
            .unwrap();
        let signins = writes.active_signins().unwrap();
        assert_eq!(signins.len(), 1);
        assert_eq!(signins[0].provider, "Claude");
        assert_eq!(signins[0].account, 7);
        drop(worker);
        assert!(writes.active_signins().unwrap().is_empty());
    }

    #[test]
    fn signin_drop_notifies_with_post_drop_metadata_and_without_registry_lock() {
        let writes = CredentialWrites::default();
        let callbacks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&callbacks);
        let registry = writes.clone();
        writes
            .set_signin_listener(Arc::new(move || {
                assert!(registry.active_signins().unwrap().is_empty());
                observed.fetch_add(1, Ordering::SeqCst);
            }))
            .unwrap();
        let registration = writes
            .register_signin(SigninProvider::Claude, AccountNum::try_from(7u16).unwrap())
            .unwrap();
        assert_eq!(callbacks.load(Ordering::SeqCst), 0);
        drop(registration);
        assert_eq!(callbacks.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn quit_cancels_pending_interaction_and_joins_its_cleanup() {
        let writes = CredentialWrites::default();
        let interaction = writes.register_interactive().unwrap();
        let cancelled = interaction.cancellation_flag();
        let drain = writes.close();
        assert!(cancelled.load(Ordering::Acquire));
        let wait = drain.wait();
        tokio::pin!(wait);
        assert_pending(wait.as_mut()).await;
        assert!(
            interaction.admit().is_err(),
            "closed browser flow minted a token"
        );
        drop(interaction);
        wait.await.unwrap();
    }

    #[tokio::test]
    async fn quit_never_cancels_interaction_after_mint_admission() {
        let writes = CredentialWrites::default();
        let interaction = writes.register_interactive().unwrap();
        let cancelled = interaction.cancellation_flag();
        let permit = interaction.admit().unwrap();
        let drain = writes.close();
        assert!(
            !cancelled.load(Ordering::Acquire),
            "Quit cancelled an admitted mint"
        );
        let wait = drain.wait();
        tokio::pin!(wait);
        assert_pending(wait.as_mut()).await;
        drop(permit);
        assert_pending(wait.as_mut()).await;
        drop(interaction);
        wait.await.unwrap();
    }

    #[tokio::test]
    async fn refused_quit_never_revives_cancelled_browser_interaction() {
        let writes = CredentialWrites::default();
        let interaction = writes.register_interactive().unwrap();
        writes.close().reopen().unwrap();
        assert!(interaction.admit().is_err());
        drop(writes.register_interactive().unwrap().admit().unwrap());
    }

    #[tokio::test]
    async fn close_refuses_new_writes_and_empty_drain_finishes() {
        let writes = CredentialWrites::default();
        let drain = writes.close();
        assert!(matches!(writes.admit(), Err(tag) if tag == "credential_write_admission_closed"));
        drain.wait().await.unwrap();
    }

    #[tokio::test]
    async fn drain_waits_for_every_admitted_writer() {
        let writes = CredentialWrites::default();
        let first = writes.admit().unwrap();
        let second = writes.admit().unwrap();
        let drain = writes.close();
        let wait = drain.wait();
        tokio::pin!(wait);
        assert_pending(wait.as_mut()).await;
        drop(first);
        assert_pending(wait.as_mut()).await;
        drop(second);
        wait.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_drain_observer_never_cancels_writer_or_reopens_admission() {
        let writes = CredentialWrites::default();
        let permit = writes.admit().unwrap();
        let drain = writes.close();
        {
            let wait = drain.wait();
            tokio::pin!(wait);
            assert_pending(wait.as_mut()).await;
        }
        assert!(writes.admit().is_err());
        drop(permit);
        drain.wait().await.unwrap();
        drop(drain);
        assert!(
            writes.admit().is_err(),
            "dropping a drain is not an explicit refusal"
        );
    }

    #[tokio::test]
    async fn refusal_reopens_without_forgetting_existing_writer() {
        let writes = CredentialWrites::default();
        let first = writes.admit().unwrap();
        writes.close().reopen().unwrap();
        let second = writes.admit();
        assert!(
            second.is_ok(),
            "explicit refusal must reopen writer admission"
        );
        let second = second.unwrap();
        let drain = writes.close();
        let wait = drain.wait();
        tokio::pin!(wait);
        drop(second);
        assert_pending(wait.as_mut()).await;
        drop(first);
        wait.await.unwrap();
    }

    #[tokio::test]
    async fn stale_refusal_cannot_reopen_newer_quit_attempt() {
        let writes = CredentialWrites::default();
        let stale = writes.close();
        let current = writes.close();
        assert_eq!(
            stale.reopen().unwrap_err(),
            "credential_write_drain_superseded"
        );
        assert!(writes.admit().is_err());
        current.wait().await.unwrap();
        current.reopen().unwrap();
        drop(writes.admit().unwrap());
    }

    #[tokio::test]
    async fn blocking_writer_keeps_permit_when_command_future_is_cancelled() {
        let writes = CredentialWrites::default();
        let writer_gate = writes.clone();
        let fixture = Arc::new(tempfile::tempdir().unwrap());
        let worker_fixture = Arc::clone(&fixture);
        let path = fixture.path().join("fixture-commit.json");
        let writer_path = path.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let command = tokio::spawn(async move {
            writer_gate
                .spawn_blocking(move || {
                    let _fixture = worker_fixture;
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    // Inert fixture: no HOME, network, provider, process or credential access.
                    std::fs::write(writer_path, b"fixture committed").unwrap();
                })
                .unwrap()
                .await
                .unwrap();
        });
        let release = ReleaseOnDrop(Some(move || {
            let _ = release_tx.send(());
        }));
        started_rx.await.unwrap();
        command.abort();
        assert!(command.await.unwrap_err().is_cancelled());
        let drain = writes.close();
        let wait = drain.wait();
        tokio::pin!(wait);
        assert_pending(wait.as_mut()).await;
        assert!(!path.exists());
        drop(release);
        wait.await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"fixture committed");
    }

    #[tokio::test]
    async fn completed_write_is_seen_even_before_drain_is_first_polled() {
        let writes = CredentialWrites::default();
        let permit = writes.admit().unwrap();
        let drain = writes.close();
        drop(permit);
        drain.wait().await.unwrap();
    }

    #[tokio::test]
    async fn owned_async_writer_keeps_permit_when_command_future_is_cancelled() {
        let writes = CredentialWrites::default();
        let writer_gate = writes.clone();
        let fixture = Arc::new(tempfile::tempdir().unwrap());
        let worker_fixture = Arc::clone(&fixture);
        let path = fixture.path().join("async-fixture-commit.json");
        let writer_path = path.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let command = tokio::spawn(async move {
            writer_gate
                .spawn(async move {
                    let _fixture = worker_fixture;
                    started_tx.send(()).unwrap();
                    release_rx.await.unwrap();
                    std::fs::write(writer_path, b"async fixture committed").unwrap();
                })
                .unwrap()
                .await
                .unwrap();
        });
        let release = ReleaseOnDrop(Some(move || {
            let _ = release_tx.send(());
        }));
        started_rx.await.unwrap();
        command.abort();
        assert!(command.await.unwrap_err().is_cancelled());
        let drain = writes.close();
        let wait = drain.wait();
        tokio::pin!(wait);
        assert_pending(wait.as_mut()).await;
        assert!(!path.exists());
        drop(release);
        wait.await.unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"async fixture committed");
    }
}
