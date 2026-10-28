//! End-to-end smoke test for `create_handle_dir` settings materialization.
//!
//! Drives the library against the *real* `~/.claude/settings.json` on the
//! current machine (when present) to confirm the alpha.9 fix preserves
//! user-global customization (`statusLine`, `permissions.defaultMode`,
//! `enabledPlugins`, env flags) when a `csq run N` handle dir is created.
//!
//! This test is skipped automatically in CI because `~/.claude/settings.json`
//! does not exist there. On a developer machine with an existing
//! installation it proves the materialization path against the concrete
//! content shape that end users actually have on disk.

use csq_core::session::handle_dir::create_handle_dir;
use csq_core::types::AccountNum;
use serde_json::Value;
use tempfile::TempDir;

fn real_claude_home() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    let path = std::path::PathBuf::from(home).join(".claude");
    if path.join("settings.json").exists() {
        Some(path)
    } else {
        None
    }
}

#[test]
fn materializes_against_real_user_settings_when_present() {
    let Some(claude_home) = real_claude_home() else {
        eprintln!("skipping: ~/.claude/settings.json not present");
        return;
    };

    // Parse the real user settings first so we know what to assert
    // against. If the parse fails, the handle-dir materialization will
    // treat it as empty (logged WARN) — still a valid outcome, but a
    // noisy one we want to flag.
    let user_content = std::fs::read_to_string(claude_home.join("settings.json")).unwrap();
    let user: Value = serde_json::from_str(&user_content)
        .expect("real ~/.claude/settings.json failed to parse — fix or remove it");

    // Create a scratch base_dir with a single fake OAuth slot.
    let tmp = TempDir::new().unwrap();
    let base = tmp.path();
    let slot = base.join("config-1");
    std::fs::create_dir_all(&slot).unwrap();
    std::fs::write(slot.join(".csq-account"), "1").unwrap();
    std::fs::write(slot.join(".credentials.json"), "{}").unwrap();
    // NOTE: deliberately NO config-1/settings.json — OAuth slots don't
    // have one. This is the exact case that broke alpha.8.

    // PID choice: std::process::id() to satisfy the invariant documented
    // on create_handle_dir.
    let pid = std::process::id();
    let handle = create_handle_dir(base, &claude_home, AccountNum::try_from(1u16).unwrap(), pid)
        .expect("create_handle_dir failed against real ~/.claude");

    // Read what CC would actually see.
    let materialized_path = handle.join("settings.json");
    assert!(
        materialized_path.exists(),
        "materialized settings.json missing"
    );
    #[cfg(unix)]
    {
        let meta = materialized_path.symlink_metadata().unwrap();
        assert!(
            !meta.file_type().is_symlink(),
            "settings.json must be a real file, not a symlink"
        );
    }

    let materialized_content = std::fs::read_to_string(&materialized_path).unwrap();
    let materialized: Value = serde_json::from_str(&materialized_content)
        .expect("materialized settings.json is not valid JSON");

    // Assert every top-level key the user had is still present in the
    // materialized file. For OAuth slots there is no overlay, so this
    // should be a strict subset equality on top-level keys.
    if let Some(user_obj) = user.as_object() {
        let materialized_obj = materialized
            .as_object()
            .expect("materialized root is not an object");

        for (key, user_val) in user_obj {
            let mat_val = materialized_obj.get(key).unwrap_or_else(|| {
                panic!(
                    "materialized settings.json is missing user key '{key}' — \
                     this is the exact alpha.8 regression. \
                     user content: {user_val:?}"
                )
            });
            assert_eq!(
                mat_val, user_val,
                "materialized value for '{key}' does not match user's original"
            );
        }
    }

    // Best-effort cleanup — remove the scratch handle dir we created
    // inside the OS tempdir. TempDir drops the parent anyway.
    let _ = std::fs::remove_dir_all(&handle);
}
