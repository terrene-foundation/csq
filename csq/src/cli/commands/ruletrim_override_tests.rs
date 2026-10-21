// Child of cli::commands::run::tests; exact-value policy only, no native/model process.
mod ruletrim_override_tests {
    use super::*;
    const PARITY: &str = "CSQ_COC_PARITY_TEST";
    struct RestoreParity(Option<std::ffi::OsString>);
    impl Drop for RestoreParity {
        fn drop(&mut self) {
            // SAFETY: the caller retains the shared environment lock until this guard drops.
            unsafe {
                match self.0.take() {
                    Some(value) => std::env::set_var(PARITY, value),
                    None => std::env::remove_var(PARITY),
                }
            }
        }
    }
    fn assert_policy(owned: &Path, codex_force: bool, other_force: bool) {
        assert_eq!(
            should_inject_scaffold(Surface::Codex, owned, Some(owned)),
            codex_force,
            "Codex parity override must accept only literal1"
        );
        for surface in [
            Surface::ClaudeCode,
            Surface::Gemini,
            Surface::Kimi,
            Surface::Grok,
        ] {
            assert_eq!(
                should_inject_scaffold(surface, owned, Some(owned)),
                other_force,
                "literal Codex repair must preserve other surface presence override"
            );
        }
    }
    #[test]
    fn codex_override_requires_literal_one_and_preserves_other_surfaces() {
        let _env = csq_core::platform::test_env::lock();
        let _restore = RestoreParity(std::env::var_os(PARITY));
        let owned = TempDir::new().unwrap();
        for marker in [".codex", ".claude", ".gemini", ".kimi-code", ".grok"] {
            std::fs::create_dir(owned.path().join(marker)).unwrap();
        }
        // Native markers bound at this owned root isolate FORCE behavior, not complete delivery.
        for (value, force) in [
            (None, false),
            (Some(""), false),
            (Some("0"), false),
            (Some("true"), false),
            (Some("01"), false),
            (Some(" 1"), false),
            (Some("1 "), false),
            (Some("1"), true),
        ] {
            // SAFETY: shared environment lock is first guard; RAII restores on any assertion unwind.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(PARITY, value),
                    None => std::env::remove_var(PARITY),
                }
            }
            assert_policy(owned.path(), force, value.is_some());
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            // A valid non-UTF8 environment value must not accidentally enable a literal string policy.
            unsafe {
                std::env::set_var(PARITY, std::ffi::OsString::from_vec(vec![0xff]));
            }
            assert_policy(owned.path(), false, true);
        }
        let empty = TempDir::new().unwrap();
        unsafe {
            std::env::set_var(PARITY, "0");
        }
        assert!(
            should_inject_scaffold(Surface::Codex, empty.path(), Some(empty.path())),
            "literal force repair must preserve ordinary no-native scaffold transition"
        );
    }
}
