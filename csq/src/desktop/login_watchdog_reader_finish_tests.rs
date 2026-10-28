// Included by the existing private desktop test module; source preparation only.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub(super) const READER_FINISH: &str = "actual exited child must not seal vendor completion while owned reader is blocked";

#[derive(Default)]
struct ReaderBarrier {
    entered: AtomicBool,
    returned: AtomicBool,
    expired: AtomicBool,
    released: Mutex<bool>,
    changed: std::sync::Condvar,
}
impl ReaderBarrier {
    fn after_eof(&self, tag: &'static str) {
        if tag != "stdout" { return; }
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut released = self.released.lock().unwrap_or_else(|e| e.into_inner());
        self.entered.store(true, Ordering::SeqCst);
        while !*released {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                self.expired.store(true, Ordering::SeqCst);break;
            };
            let waited = self.changed.wait_timeout(released, remaining)
                .unwrap_or_else(|e| e.into_inner());
            released = waited.0;
        }
        self.returned.store(true, Ordering::SeqCst);
    }
    fn release(&self) {
        *self.released.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.changed.notify_all();
    }
}
struct ReleaseReader(Arc<ReaderBarrier>);
impl Drop for ReleaseReader { fn drop(&mut self) { self.0.release(); } }

pub(super) async fn case_reader_finish() -> Result<(), String> {
    let app = tauri::test::mock_app();
    let handle = app.handle().clone();
    let mut fixture = DesktopFixture::new().map_err(|e| e.to_string())?;
    let command = fixture.command("stdout-held").map_err(|e| e.to_string())?;
    let barrier = Arc::new(ReaderBarrier::default());
    let _release_on_unwind = ReleaseReader(Arc::clone(&barrier));
    let hook_barrier = Arc::clone(&barrier);
    let hook: Arc<dyn Fn(&'static str) + Send + Sync> = Arc::new(move |tag| hook_barrier.after_eof(tag));
    let lock = private_lock(fixture.root(), 5)?;
    let key = ChildKey::new(LoginProvider::Codex, account(5));
    let watchdog = crate::login_child_custody::LoginWatchdog::new(Duration::from_secs(8), crate::login_child_custody::DeliveryPhase::Unknown);
    let deadline = watchdog.deadline().ok_or("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: finite actual deadline absent")?;
    let worker_watchdog = watchdog.clone();
    let observer_watchdog = watchdog.clone();
    let post = Arc::new(AtomicUsize::new(0));
    let worker_post = Arc::clone(&post);
    let mut observer = login_custody::global().spawn_with_ticket(move |ticket| async move {
        let worker = tokio::task::spawn_blocking(move || {
            let slot = Arc::new(Mutex::new(None));
            let mut on_code = |_| {};
            let status = super::super::commands::codex_vendor_with_command_and_reader_completion(
                command, &mut on_code, &handle, &slot, worker_watchdog, (ticket, lock), key, hook,
            ).map_err(|e| format!("{e:#}"))?;
            if status.success() { worker_post.fetch_add(1, Ordering::SeqCst); }
            Ok(())
        });
        super::super::commands::observe_desktop_login(worker, observer_watchdog).await
    })?;
    bind(&mut fixture, key).await?;
    fixture.release(0).map_err(|e| e.to_string())?;
    // Observe the same original without consuming the production owner's wait
    // lease while its actual reader is blocked. An early-seal mutant may have
    // already reaped; only that same owner's recorded receipt is an alternative.
    if !until(Duration::from_secs(5), || {
        barrier.entered.load(Ordering::SeqCst) && (watchdog.reaped_status().is_some()
            || fixture.original.as_ref().and_then(|child| child.try_lock().ok())
                .filter(|child| fixture.pid == Some(child.id()))
                .is_some_and(|child| matches!(crate::login_child_custody::group::observe_owned_unreaped_for_test(&child), Ok(true))))
    }).await {
        return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: terminal child and actual EOF hook not both observed".into());
    }
    if barrier.expired.load(Ordering::SeqCst) {
        return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: private child/hook failed".into());
    }
    if deadline.checked_duration_since(Instant::now()).is_none_or(|remaining| remaining < Duration::from_secs(2)) {
        return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: insufficient pre-deadline mutation reach window".into());
    }
    let drain = login_custody::global().close();
    pending(&drain).await?;
    if !until(Duration::from_secs(9), || Instant::now() >= deadline).await {
        return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: real watchdog deadline not observed".into());
    }
    watchdog.observe_deadline();
    let refused = watchdog.refusal().is_some_and(|receipt| receipt.reason == crate::login_child_custody::RefusalReason::Timeout);
    let policy_failed = !refused || post.load(Ordering::SeqCst) != 0
        || barrier.returned.load(Ordering::SeqCst) || !lock_held(fixture.root(), 5);
    pending(&drain).await?;
    // The mutant may have sealed success but still be blocked in real reader
    // RAII cleanup. Release and join before reporting its policy assertion.
    barrier.release();
    let outcome = result(&mut observer).await?;
    let status = drain_complete(&drain, &mut fixture).await?;
    if barrier.expired.load(Ordering::SeqCst) || !barrier.returned.load(Ordering::SeqCst) || status.code() != Some(0) {
        return Err("DESKTOP_FIXTURE_CUSTODY_UNKNOWN: actual reader/child drain not proven".into());
    }
    drain.reopen()?;
    if policy_failed { return Err(READER_FINISH.into()); }
    let error = outcome.err().ok_or(READER_FINISH)?;
    if !error.contains("login_timeout_refused") || post.load(Ordering::SeqCst) != 0 {
        return Err(READER_FINISH.into());
    }
    Ok(())
}

#[test]
fn actual_child_exit_waits_for_actual_reader_finish_before_seal() {
    case_process("case-reader-finish");
}
