//! All renderer update/restart effects cross the canonical sign-in custody gate.
//! Raw updater install/process restart permissions are deliberately removed.
use crate::desktop::login_custody::{self, UpdateLease, UpdateProbe};
use std::future::Future;
use tauri::{ipc::Channel, AppHandle, WebviewWindow};
use tauri_plugin_updater::UpdaterExt;

#[derive(Clone, serde::Serialize)]
#[serde(tag = "event", content = "data")]
pub enum UpdateProgress {
    WaitingForSignIn,
    #[serde(rename_all = "camelCase")]
    Started {
        content_length: Option<u64>,
    },
    #[serde(rename_all = "camelCase")]
    Progress {
        chunk_length: usize,
    },
    Finished,
}

#[cfg_attr(all(windows, not(test)), allow(dead_code))] // Release is used by the non-Windows installer.
enum UpdateFailure {
    Release(&'static str),
    KeepClosed(&'static str),
}

/// A probe refusal keeps the sticky UNVERIFIED tag when that is the cause;
/// every other lost-quiescence cause is the generic tag.
fn keep_closed_tag(reason: &str) -> &'static str {
    match reason {
        "desktop_update_unverified" => "desktop_update_unverified",
        _ => "update_quiescence_lost",
    }
}
/// Layer 2 probe gate shared by the install and restart bodies: an error or a
/// not-drained answer ABORTS the action (never installs/restarts).
#[cfg(any(not(windows), test))]
fn probe_guard(probe: &UpdateProbe) -> Result<(), UpdateFailure> {
    match probe.ready() {
        Ok(true) => Ok(()),
        Ok(false) => Err(UpdateFailure::KeepClosed("update_quiescence_lost")),
        Err(reason) => Err(UpdateFailure::KeepClosed(keep_closed_tag(&reason))),
    }
}

async fn wait_for_update(
    lease: &UpdateLease,
    progress: &mut impl FnMut(UpdateProgress),
) -> Result<(), String> {
    if !lease.ready()? {
        progress(UpdateProgress::WaitingForSignIn);
        // UPDATE_CUSTODY_DRAIN: baseline carrier skips only this actual wait.
        lease.wait().await?;
    }
    Ok(())
}

#[cfg(windows)]
async fn install_windows(
    lease: UpdateLease,
    app: AppHandle,
    on_event: Channel<UpdateProgress>,
) -> Result<bool, String> {
    let mut progress = |event| {
        let _ = on_event.send(event);
    };
    wait_for_update(&lease, &mut progress).await?;
    // Suppress only the plugin's destructive pre-exit UI cleanup. The actual
    // handoff is authorized later, after exact supervisor/listener joins.
    let prepared = async {
        let updater = app
            .updater_builder()
            .on_before_exit(|| {})
            .build()
            .map_err(|error| {
                super::windows_update::failure_tag(
                    "builder",
                    &error,
                    "update_configuration_refused",
                )
            })?;
        let Some(update) = updater.check().await.map_err(|error| {
            super::windows_update::failure_tag("check", &error, "update_check_failed")
        })?
        else {
            return Ok(None);
        };
        let chunks = on_event.clone();
        let mut started = false;
        let bytes = update
            .download(
                move |chunk_length, content_length| {
                    if !started {
                        let _ = chunks.send(UpdateProgress::Started { content_length });
                        started = true;
                    }
                    let _ = chunks.send(UpdateProgress::Progress { chunk_length });
                },
                || {},
            )
            .await
            .map_err(|error| {
                super::windows_update::failure_tag(
                    "download",
                    &error,
                    "update_download_or_signature_failed",
                )
            })?;
        // Download completion precedes signature verification in the plugin.
        let _ = on_event.send(UpdateProgress::Finished);
        Ok::<_, &'static str>(Some((update, bytes)))
    }
    .await;
    let (update, bytes) = match prepared {
        Ok(Some(prepared)) => prepared,
        Ok(None) => {
            lease.release()?;
            return Ok(false);
        }
        Err(tag) => {
            lease
                .release()
                .map_err(|_| "update_custody_release_refused")?;
            return Err(tag.into());
        }
    };
    let completion =
        crate::desktop::windows_upgrade::request_install(&app, lease, move |_approved| {
            super::windows_update::install_returned(update.install(&bytes))
        })
        .map_err(|_| "update_install_failed")?;
    match completion.await {
        Ok(Err("desktop_install_refused")) => Err("update_install_failed".into()),
        // Successful Windows install exits; a return cannot report success.
        _ => Err("update_installer_completion_unverified".into()),
    }
}

// This is the actual production sequencing body, also used by inert tests.
async fn after_update_drain<F, Fut>(
    lease: UpdateLease,
    mut progress: impl FnMut(UpdateProgress),
    action: F,
) -> Result<bool, String>
where
    F: FnOnce(UpdateProbe) -> Fut,
    Fut: Future<Output = Result<bool, UpdateFailure>>,
{
    wait_for_update(&lease, &mut progress).await?;
    // The probe re-checks quiescence under the gate lock before each side
    // effect below; the lease itself stays with this drainer (and its Drop).
    let probe = lease.probe();
    match action(probe).await {
        Ok(true) => {
            // A restart was requested: a VERIFIED outcome. The handoff clears
            // the quiescence flag and keeps admission closed through process
            // replacement; it never reopens.
            lease.hand_off_restart();
            Ok(true)
        }
        Ok(false) => {
            lease.release()?;
            Ok(false)
        }
        Err(UpdateFailure::Release(tag)) => {
            lease
                .release()
                .map_err(|_| "update_custody_release_refused")?;
            Err(tag.into())
        }
        Err(UpdateFailure::KeepClosed(tag)) => Err(tag.into()),
    }
}

/// Not idempotent: a concurrent update/Exit is refused by the canonical lease.
/// The owned task retains the lease if its renderer observer disappears.
#[tauri::command]
pub async fn install_update_with_custody(
    app: AppHandle,
    window: WebviewWindow,
    on_event: Channel<UpdateProgress>,
) -> Result<bool, String> {
    super::authorize_cancel_window(&window).map_err(|_| "update_permission_denied")?;
    // Preserve the existing enterprise/community updater trust boundary.
    if crate::BUILD_EDITION == "enterprise" {
        return Err("update_community_channel_disabled".into());
    }
    tauri::async_runtime::spawn(async move {
        let lease = login_custody::begin_update()?;
        #[cfg(windows)]
        {
            install_windows(lease, app, on_event).await
        }
        #[cfg(not(windows))]
        {
            let progress = on_event.clone();
            after_update_drain(
                lease,
                move |event| {
                    let _ = progress.send(event);
                },
                move |probe| async move {
                    let updater = app
                        .updater()
                        .map_err(|_| UpdateFailure::Release("update_configuration_refused"))?;
                    let Some(update) = updater
                        .check()
                        .await
                        .map_err(|_| UpdateFailure::Release("update_check_failed"))?
                    else {
                        return Ok(false);
                    };
                    let chunks = on_event.clone();
                    let finished = on_event.clone();
                    let mut started = false;
                    let bytes = update
                        .download(
                            move |chunk_length, content_length| {
                                if !started {
                                    let _ = chunks.send(UpdateProgress::Started { content_length });
                                    started = true;
                                }
                                let _ = chunks.send(UpdateProgress::Progress { chunk_length });
                            },
                            move || {
                                let _ = finished.send(UpdateProgress::Finished);
                            },
                        )
                        .await
                        .map_err(|_| {
                            UpdateFailure::Release("update_download_or_signature_failed")
                        })?;
                    // Layer 2: quiescence must still be OURS under the gate lock
                    // immediately before the install side effect.
                    probe_guard(&probe)?;
                    // Windows install can process::exit, so verified drain MUST precede
                    // this blocking owner; a UI relaunch interception is insufficient.
                    tauri::async_runtime::spawn_blocking(move || update.install(bytes))
                        .await
                        .map_err(|_| {
                            UpdateFailure::KeepClosed("update_installer_completion_unverified")
                        })?
                        .map_err(|_| UpdateFailure::Release("update_install_failed"))?;
                    // Layer 2 again, ONE lock: verify the drain AND convert the
                    // lease into an approved exit intent BEFORE request_restart, so
                    // an ExitRequested arriving first is not deferred.
                    probe
                        .authorize_restart()
                        .map_err(|reason| UpdateFailure::KeepClosed(keep_closed_tag(&reason)))?;
                    app.request_restart();
                    Ok(true)
                },
            )
            .await
        }
    })
    .await
    .map_err(|_| "update_owner_completion_unverified".to_string())?
}

/// Manual restarts share the same actual gate; no raw process-plugin bypass.
#[tauri::command]
pub async fn restart_with_custody(
    app: AppHandle,
    window: WebviewWindow,
    on_event: Channel<UpdateProgress>,
) -> Result<bool, String> {
    super::authorize_cancel_window(&window).map_err(|_| "update_permission_denied")?;
    tauri::async_runtime::spawn(async move {
        let lease = login_custody::begin_update()?;
        after_update_drain(
            lease,
            move |event| {
                let _ = on_event.send(event);
            },
            move |probe| async move {
                // ONE lock: verify the drain AND record the approved exit
                // intent before request_restart, so an ExitRequested arriving
                // first rides the intent instead of deferring.
                probe
                    .authorize_restart()
                    .map_err(|reason| UpdateFailure::KeepClosed(keep_closed_tag(&reason)))?;
                app.request_restart();
                Ok(true)
            },
        )
        .await
    })
    .await
    .map_err(|_| "update_owner_completion_unverified".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desktop::login_custody::CredentialWrites;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[test]
    fn raw_plugin_custody_bypass_grants_are_revoked() {
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../../../capabilities/default.json"))
                .expect("actual application capability JSON");
        let permissions = capability["permissions"]
            .as_array()
            .expect("actual permission list");
        for grant in [
            "updater:allow-check",
            "updater:allow-download-and-install",
            "process:allow-restart",
            "process:allow-exit",
        ] {
            assert!(
                !permissions
                    .iter()
                    .any(|value| value.as_str() == Some(grant)),
                "UPDATE_RAW_PLUGIN_BYPASS_GRANT: {grant}"
            );
        }
    }

    async fn deferred_action_assertion(marker: &'static str) {
        let gate = CredentialWrites::default();
        let writer = gate.admit().expect("actual admitted writer");
        let lease = gate.begin_update().expect("actual canonical update lease");
        let actions = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&actions);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut tx = Some(tx);
        let task = tokio::spawn(after_update_drain(
            lease,
            move |event| {
                if matches!(event, UpdateProgress::WaitingForSignIn) {
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(());
                    }
                }
            },
            move |_probe| async move {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(true)
            },
        ));
        rx.await.expect("actual wrapper reached pending drain");
        assert_eq!(actions.load(Ordering::SeqCst), 0, "{marker}");
        assert!(gate.admit().is_err(), "update lease must close admission");
        drop(writer);
        assert!(task
            .await
            .expect("actual wrapper joined")
            .expect("verified drain"));
        assert_eq!(actions.load(Ordering::SeqCst), 1);
        assert!(gate.admit().is_err(), "UPDATE_SUCCESS_REOPENED_ADMISSION");
    }

    #[tokio::test]
    async fn update_install_waits_for_actual_signin_drain() {
        deferred_action_assertion("UPDATE_INSTALL_BEFORE_SIGNIN_DRAIN").await;
    }
    #[tokio::test]
    async fn update_restart_waits_for_actual_signin_drain() {
        deferred_action_assertion("UPDATE_RESTART_BEFORE_SIGNIN_DRAIN").await;
    }
    #[tokio::test]
    async fn failed_update_reopens_same_lease_without_running_restart() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("update lease");
        let result = after_update_drain(
            lease,
            |_| {},
            |_probe| async { Err(UpdateFailure::Release("inert_update_failure")) },
        )
        .await;
        assert_eq!(
            result.as_ref().map_err(String::as_str),
            Err("inert_update_failure")
        );
        assert!(gate.admit().is_ok(), "UPDATE_FAILURE_DID_NOT_RELEASE_LEASE");
    }
    #[tokio::test]
    async fn no_update_bundle_releases_lease() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("update lease");
        assert!(
            !after_update_drain(lease, |_| {}, |_probe| async { Ok(false) })
                .await
                .expect("no bundle")
        );
        assert!(
            gate.admit().is_ok(),
            "NO_UPDATE_BUNDLE_DID_NOT_RELEASE_LEASE"
        );
    }
    #[tokio::test]
    async fn unverified_installer_keeps_admission_closed() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("update lease");
        let result = after_update_drain(
            lease,
            |_| {},
            |_probe| async { Err(UpdateFailure::KeepClosed("inert_join_unknown")) },
        )
        .await;
        assert_eq!(
            result.as_ref().map_err(String::as_str),
            Err("inert_join_unknown")
        );
        assert!(
            gate.admit().is_err(),
            "UNKNOWN_INSTALLER_REOPENED_ADMISSION"
        );
        assert!(
            gate.update_unverified_for_test(),
            "UNKNOWN_INSTALLER_MUST_GO_STICKY"
        );
    }

    /// The corr probe from the paired R1, answered by a test: the Ok(true)
    /// restart path used to leave `update_pending` recorded, so a later
    /// request_exit early-returned and the post-install restart never
    /// completed. The verified handoff must release the flag on this path.
    #[tokio::test]
    async fn restart_outcome_releases_the_quiescence_flag() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("update lease");
        let restarted = after_update_drain(
            lease,
            |_| {},
            |probe| async move {
                assert!(probe.ready().expect("live lease probe"));
                probe.authorize_restart().expect("drained restart intent");
                Ok(true)
            },
        )
        .await
        .expect("restart requested");
        assert!(restarted);
        assert!(
            !gate.update_pending_for_test(),
            "UPDATE_RESTART_STRANDED_QUIESCENCE"
        );
        assert!(gate.admit().is_err(), "UPDATE_RESTART_REOPENED_ADMISSION");
        assert!(
            !gate.update_unverified_for_test(),
            "a verified restart handoff must not go sticky"
        );
    }

    /// An unwind inside the update body must not strand the flag either.
    #[tokio::test]
    async fn panicking_update_body_still_releases_the_quiescence_flag() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("update lease");
        let task = tokio::spawn(after_update_drain(
            lease,
            |_| {},
            |_probe| async move {
                panic!("inert update panic");
                #[allow(unreachable_code)]
                Ok(true)
            },
        ));
        assert!(task.await.is_err(), "the inert panic must abort the task");
        assert!(
            !gate.update_pending_for_test(),
            "UPDATE_PANIC_STRANDED_QUIESCENCE"
        );
        assert!(
            gate.update_unverified_for_test(),
            "UPDATE_PANIC_MUST_GO_STICKY"
        );
        assert!(gate.admit().is_err(), "UPDATE_PANIC_REOPENED_ADMISSION");
    }

    /// R2 item 1(b): a Windows Quit close during an update is REFUSED and the
    /// lease is intact.
    #[test]
    fn quit_close_refused_while_an_update_lease_is_live() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("update lease");
        let refused_reason = match gate.close_for_quit() {
            Ok(_) => panic!("a Quit close during a live update must be refused"),
            Err(reason) => reason,
        };
        assert_eq!(refused_reason, "desktop_update_quiescence_held");
        assert!(gate.admit().is_err(), "a refused Quit reopened admission");
        assert!(lease.ready().expect("intact lease"));
        assert!(gate.update_pending_for_test(), "the lease must stay intact");
        lease.release().expect("explicit non-restart release");
        assert!(
            gate.admit().is_ok(),
            "lease release did not reopen admission"
        );
    }

    /// R2 item 1(a): a plain close during a live lease never supersedes it, and
    /// its drain can never reopen admission under the lease.
    #[test]
    fn close_never_supersedes_a_live_update_lease() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("update lease");
        let drain = gate.close();
        assert!(gate.admit().is_err());
        assert_eq!(
            drain.reopen().unwrap_err(),
            "desktop_update_quiescence_held"
        );
        assert!(gate.admit().is_err(), "Quit drain reopened a live lease");
        assert!(lease.ready().expect("lease intact"));
        drop(lease);
        assert!(!gate.update_pending_for_test());
        assert!(
            gate.admit().is_err(),
            "lease Drop must not reopen admission"
        );
        // R2 item 4: the drain built over the lease's identity can NEVER
        // reopen it, not even after the lease drops.
        assert_eq!(drain.reopen().unwrap_err(), "desktop_update_unverified");
        assert!(
            gate.admit().is_err(),
            "a non-lease reopen cleared a retained lease identity"
        );
    }

    /// ROOT M1 correction (liveness): a KeepClosed outcome is STICKY for
    /// admission, yet a later Windows Quit is ADMITTED and drains, because a
    /// user must never be unable to quit after an unverified update.
    #[tokio::test]
    async fn keep_closed_then_a_windows_quit_is_admitted_with_admission_closed() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("update lease");
        assert!(after_update_drain(
            lease,
            |_| {},
            |_probe| async {
                Err(UpdateFailure::KeepClosed(
                    "desktop_update_installer_completion_unverified",
                ))
            },
        )
        .await
        .is_err());
        let admission = gate
            .close_for_quit()
            .expect("an unverified update must still admit the Quit");
        admission
            .wait()
            .await
            .expect("the closed gate drains empty");
        assert_eq!(admission.reopen().unwrap_err(), "desktop_update_unverified");
        assert!(gate.admit().is_err(), "the Quit drain reopened admission");
    }

    /// R2 item 1: a refused supervisor stop after a KeepClosed outcome must
    /// NOT reopen admission through its own drain.
    #[tokio::test]
    async fn keep_closed_then_a_refused_supervisor_stop_cannot_reopen_admission() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("update lease");
        assert!(after_update_drain(
            lease,
            |_| {},
            |_probe| async {
                Err(UpdateFailure::KeepClosed(
                    "desktop_update_installer_completion_unverified",
                ))
            },
        )
        .await
        .is_err());
        let admission = gate.close();
        assert_eq!(admission.reopen().unwrap_err(), "desktop_update_unverified");
        assert!(gate.admit().is_err(), "a refused stop reopened admission");
    }

    /// R2 item 6: the shared install/restart probe gate ABORTS — not installs,
    /// not restarts — once the outcome is unverified.
    #[test]
    fn probe_guard_aborts_once_the_outcome_is_unverified() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("update lease");
        let probe = lease.probe();
        assert!(probe_guard(&probe).is_ok());
        drop(lease);
        assert!(matches!(
            probe_guard(&probe),
            Err(UpdateFailure::KeepClosed("desktop_update_unverified"))
        ));
    }

    /// R2 item 1 layer 2: the probe refuses once the lease's identity is no
    /// longer the gate's, which is what aborts install/restart.
    #[test]
    fn update_probe_reports_lost_quiescence() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("lease");
        let probe = lease.probe();
        assert!(probe.ready().expect("live probe"));
        drop(lease);
        // A fresh close (flag now clear) supersedes the lease identity.
        let drain = gate.close();
        assert_eq!(
            probe.ready().unwrap_err(),
            "desktop_update_lease_superseded"
        );
        drop(drain);
    }
}

#[cfg(test)]
#[path = "update_custody_acl_tests.rs"]
mod acl_tests;
