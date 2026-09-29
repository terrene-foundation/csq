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
pub fn format_panic_message(info: &PanicHookInfo<'_>) -> String {
    let location = info
        .location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
        .unwrap_or_else(|| "<unknown location>".to_string());
    let payload = info
        .payload()
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| info.payload().downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "<non-string panic payload>".to_string());
    format!(
        "daemon panicked at {location}: {}",
        crate::error::redact_tokens(&payload)
    )
}

/// Installs this hook process-wide, replacing the default. Idempotent via
/// `std::sync::Once` — safe to call on every daemon-session start (the
/// supervised loop restarts sessions in-process on a transient failure)
/// without stacking hooks or re-wrapping an already-installed one.
pub fn install() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            tracing::error!(
                error_kind = "daemon_panic",
                "{}",
                format_panic_message(info)
            );
        }));
    });
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
    /// sibling one.
    fn capture_formatted_panic(trigger: impl FnOnce() + std::panic::UnwindSafe) -> String {
        let _guard = crate::platform::test_env::lock();
        let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_in_hook = Arc::clone(&captured);
        let prior_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            *captured_in_hook.lock().unwrap() = Some(format_panic_message(info));
        }));
        let result = std::panic::catch_unwind(trigger);
        std::panic::set_hook(prior_hook);
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
            panic!("credential parse failed: sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        });
        assert!(
            !formatted.contains("sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
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
        install();
        install();
        // Restore the default hook so this test does not leave the
        // process-wide hook installed for every later test in this binary.
        let _ = std::panic::take_hook();
    }
}
