//! Process-wide panic hook for the daemon (`keychain-fix-r11.md` S-LOW-3).
//!
//! The Rust DEFAULT panic hook prints the panic payload VERBATIM to
//! stderr — including whatever string the panicking code formatted into
//! its message, which is not itself redacted by anything upstream. A
//! `.expect("failed to parse credential: {e}")`-shaped panic (or any panic
//! whose message embeds a `Debug`/`Display` of upstream data) can therefore
//! leak a token fragment straight to the daemon's stderr, which is captured
//! into a log file most operators do not think of as secret-bearing.
//!
//! This hook REPLACES the default: it logs the panic's LOCATION
//! (`file:line:col`) and its payload passed through
//! [`crate::error::redact_tokens`] via the structured `tracing` log, and
//! never writes the raw payload to stderr at all.

use std::panic::PanicHookInfo;

/// Formats a panic for the daemon's structured log — pure, so it is
/// directly unit-testable without ever triggering a real panic (there is no
/// way to synthesize a real `&PanicHookInfo` outside `std::panic::set_hook`'s
/// own callback, so this function's tests exercise it only through
/// `std::panic::catch_unwind` + a hook that captures the formatted string —
/// see the tests below).
///
/// Handles BOTH payload shapes `panic!`/`.unwrap()`/`.expect()` actually
/// produce: `&'static str` (a string literal) and `String` (anything
/// built with `format!`, which is where a token fragment would appear).
/// Any other payload type (rare — `panic_any` with a non-string value) is
/// reported by its type name only, never guessed at or displayed.
pub fn format_panic_message(label: &str, info: &PanicHookInfo<'_>) -> String {
    let location = info
        .location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
        .unwrap_or_else(|| "<unknown location>".to_string());
    let thread = std::thread::current()
        .name()
        .unwrap_or("<unnamed>")
        .to_string();
    let payload = info
        .payload()
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| info.payload().downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "<non-string panic payload>".to_string());
    format!(
        "{label} at {location} [thread {}]: {}",
        crate::error::redact_tokens(&thread),
        crate::error::redact_tokens(&payload)
    )
}

/// Set once [`install`] has run in this process. Never reset: the hook is
/// installed through a `OnceLock` and cannot be un-installed, so this reports
/// the install EVENT, not whether the custom hook is currently the active
/// one (a test may restore a prior hook for isolation).
static INSTALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether [`install`] has run in this process.
pub fn is_installed() -> bool {
    INSTALLED.load(std::sync::atomic::Ordering::Acquire)
}

/// The label the installed hook reports (`daemon_panic` / `desktop_panic`).
/// Set exactly once, by the call that installs the hook; `None` before any
/// install. Lets a caller ASSERT which process label won, instead of
/// inferring it from an install flag.
static LABEL: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

/// The active hook's process label, or `None` before any install.
pub fn active_label() -> Option<&'static str> {
    LABEL.get().copied()
}

/// Installs this hook process-wide, replacing the default. Idempotent via
/// `std::sync::OnceLock`: the first call stores its label in `LABEL`,
/// installs the hook with it, and every later call reports `false` without
/// touching the process hook — safe to call on every daemon-session start
/// (the supervised loop restarts sessions in-process on a transient
/// failure) without stacking hooks or re-wrapping an already-installed one.
///
/// `label` names the PROCESS on every event and message (`daemon_panic` for
/// the CLI daemon, `desktop_panic` for the desktop app), so a desktop UI or
/// Tauri panic is never mislabelled as a daemon panic. Returns `true` when
/// THIS call installed the hook, `false` when an earlier call already had —
/// callers use that for order-independent tests rather than a process-global
/// read.
pub fn install(label: &'static str) -> bool {
    let mut installed_now = false;
    let active: &'static str = LABEL.get_or_init(|| {
        installed_now = true;
        label
    });
    if installed_now {
        std::panic::set_hook(Box::new(move |info| {
            tracing::error!(
                error_kind = active,
                "{}",
                format_panic_message(active, info)
            );
        }));
        INSTALLED.store(true, std::sync::atomic::Ordering::Release);
    }
    installed_now
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Drives `format_panic_message` against a REAL `&PanicHookInfo` by
    /// installing a temporary hook (via `catch_unwind`, so the process
    /// itself never aborts), capturing the formatted string, then restoring
    /// the prior hook — never touching the process-wide `install()` path
    /// this test exists to validate independently of.
    ///
    /// `std::panic::set_hook`/`take_hook` mutate PROCESS-GLOBAL state, and
    /// `cargo test` runs this module's tests on separate threads by
    /// default, so two tests swapping the hook concurrently interleave:
    /// one thread's `catch_unwind` trigger can fire while a SIBLING
    /// thread's hook is the one currently installed, capturing into the
    /// sibling's `captured` cell instead of this call's — which then
    /// panics on the `.expect(...)` below with nothing captured. This is
    /// not hypothetical: it is the exact race that made this suite flake
    /// under the default (parallel) test runner. `test_env::lock()` is
    /// the crate's existing shared mutex for exactly this class of
    /// process-global mutation (see `audit::verify`'s own panic-hook
    /// swap, which already serializes on it) — reusing it here closes the
    /// race against both this module's OTHER hook-mutating tests and that
    /// sibling one. Ordinary tests may still panic without taking that mutex,
    /// so the temporary hook captures only this calling thread and forwards
    /// other threads to the prior hook.
    fn capture_formatted_panic(trigger: impl FnOnce() + std::panic::UnwindSafe) -> String {
        capture_formatted_panic_after(trigger, || {})
    }

    fn capture_formatted_panic_after(
        trigger: impl FnOnce() + std::panic::UnwindSafe,
        after: impl FnOnce(),
    ) -> String {
        let _guard = crate::platform::test_env::lock();
        let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_in_hook = Arc::clone(&captured);
        let owner = std::thread::current().id();
        let prior_hook = Arc::new(std::panic::take_hook());
        let prior_in_hook = Arc::clone(&prior_hook);
        std::panic::set_hook(Box::new(move |info| {
            if std::thread::current().id() == owner {
                *captured_in_hook.lock().unwrap() =
                    Some(format_panic_message("daemon_panic", info));
            } else {
                prior_in_hook(info);
            }
        }));
        let result = std::panic::catch_unwind(trigger);
        // Restore even if the after-trigger regression fixture fails. set_hook
        // itself cannot run from an unwinding thread, so catch before restoring.
        let after_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(after));
        std::panic::set_hook(Box::new(move |info| prior_hook(info)));
        if let Err(error) = after_result {
            std::panic::resume_unwind(error);
        }
        assert!(result.is_err(), "the trigger closure must actually panic");
        let message = captured
            .lock()
            .unwrap()
            .take()
            .expect("the temporary hook must have run and captured a formatted message");
        message
    }

    /// RED under a mutation that formats the RAW payload instead of the
    /// `redact_tokens`-passed one: this would then contain the literal
    /// token substring `sk-ant-api03-`, which `redact_tokens` strips.
    #[test]
    fn format_panic_message_redacts_a_token_shaped_string_payload() {
        let formatted = capture_formatted_panic(|| {
            panic!("credential parse failed: sk-ant-api03-FAKETESTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        });
        assert!(
            !formatted.contains("sk-ant-api03-FAKETESTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            "the raw token must never reach the formatted message: {formatted}"
        );
    }

    /// A `&'static str` payload (a bare string-literal panic, no `format!`)
    /// must also be captured and included (redaction is a no-op on
    /// non-token text, but the message itself must not be dropped).
    #[test]
    fn format_panic_message_includes_a_str_literal_payload() {
        let formatted = capture_formatted_panic(|| {
            panic!("plain literal panic, no interpolation");
        });
        assert!(
            formatted.contains("plain literal panic, no interpolation"),
            "a bare &str payload must be included verbatim (nothing to redact): {formatted}"
        );
    }

    /// The location (file:line:col) must be present — that is the whole
    /// point of a structured panic log over the default hook's dump.
    #[test]
    fn format_panic_message_includes_the_source_location() {
        let formatted = capture_formatted_panic(|| {
            panic!("locate me");
        });
        assert!(
            formatted.contains("panic_hook.rs"),
            "the panic's own source location must be included: {formatted}"
        );
    }

    /// A joined foreign panic occurs after ours while the capture hook is still
    /// installed. It must neither overwrite our payload nor our source location.
    #[test]
    fn foreign_thread_panic_cannot_replace_the_captured_panic() {
        let formatted = capture_formatted_panic_after(
            || panic!("owned panic capture"),
            || {
                std::thread::spawn(|| {
                    let result = std::panic::catch_unwind(|| {
                        panic!("foreign panic capture");
                    });
                    assert!(result.is_err());
                })
                .join()
                .unwrap();
            },
        );
        assert!(
            formatted.ends_with(": owned panic capture"),
            "a foreign panic overwrote our captured record: {formatted}"
        );
        assert!(formatted.contains("panic_hook.rs"));
        assert!(!formatted.contains("foreign panic capture"));
    }

    /// `install()` MUST be idempotent — calling it twice must not panic,
    /// error, or stack a second hook (the supervised loop calls this on
    /// every session restart). Restores the PRIOR process-wide hook
    /// afterward — `cargo test` runs every test in one process, and
    /// `install()`'s whole purpose is to replace the global hook, so
    /// leaving it installed would affect every other test's panic output
    /// for the rest of this process's lifetime.
    #[test]
    fn install_is_idempotent() {
        // Same shared mutex as `capture_formatted_panic` — this test also
        // mutates the process-global hook and must not race the others.
        let _guard = crate::platform::test_env::lock();
        let _first = install("daemon_panic");
        let second = install("daemon_panic");
        assert!(
            !second,
            "the second install() must report that it did NOT install (Once already fired)"
        );
        // Restore the default hook so this test does not leave the
        // process-wide hook installed for every later test in this binary.
        let _ = std::panic::take_hook();
    }
}
