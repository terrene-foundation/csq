//! Persisted desktop-only user preferences.
//!
//! These preferences govern UI behaviour of the Tauri desktop shell.
//! They are NOT read by the CLI (`csq run`, `csq daemon`) and never
//! influence credential or quota logic — purely cosmetic state for
//! the windowed app. Today's fields: `hide_dock_icon` (macOS-only
//! effect, no-op on Windows / Linux) and `dashboard_at_launch`
//! (cross-platform; controls whether the main window is shown at
//! app start or whether the app launches into the tray only).
//!
//! # File location and shape
//!
//! Stored at `<base_dir>/desktop-prefs.json` as plain JSON. No
//! secrets in this file — all fields are booleans — but writes still
//! go through [`csq_core::platform::fs::atomic_replace`] +
//! [`csq_core::platform::fs::secure_file`] for shape-consistency
//! with every other on-disk csq state file. A torn write would not
//! leak credentials but would corrupt user intent. The
//! cleanup-on-failure pattern from `rules/security.md` §5a is
//! applied so a future field that adds a non-boolean secret-bearing
//! value (e.g. an OAuth token override) does not introduce a new
//! tmp-file leak path.
//!
//! ```json
//! {
//!   "hide_dock_icon": false,
//!   "dashboard_at_launch": true
//! }
//! ```
//!
//! Default semantics: a missing file or missing `hide_dock_icon` reads
//! as `false` (Dock icon visible — the historical default). A missing
//! `dashboard_at_launch` reads as `true` (dashboard shown at launch —
//! the classic desktop-app behavior), with one migration carve-out:
//! a legacy file with `hide_dock_icon: true` and no `dashboard_at_launch`
//! field migrates the field to `false`, preserving the conflated
//! pre-refactor behavior of the user who set dock-hide on. See
//! [`load_desktop_prefs`] for the migration logic.
//!
//! # Wrong-type field defense
//!
//! `save_desktop_prefs` always emits JSON booleans for both fields, but a
//! hand-edited `desktop-prefs.json` (operator debugging, accidental
//! corruption, downgrade-and-reupgrade across a schema change) may carry
//! a non-boolean value for either `hide_dock_icon` or
//! `dashboard_at_launch`. A bare typed deserialize would fail the whole
//! struct and silently discard the OTHER field via the outer error
//! fallback. [`load_desktop_prefs`] pre-strips any non-boolean value at
//! each known boolean key so the per-field serde default applies and the
//! sibling field survives the round-trip.
//!
//! # Why a new file, not `capability_layer.json`
//!
//! `capability_layer.json` carries CLI-side technique opt-outs read
//! by `csq run` at every spawn. Co-locating desktop-only cosmetic
//! state in that file would (a) force the CLI to deserialize a field
//! it cannot use, and (b) prevent the desktop pref from evolving its
//! shape independently. Desktop prefs get their own file with their
//! own load/save.

use csq_core::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;

/// Outcome of a [`load_desktop_prefs`] call. Used by the renderer's
/// corruption-disclosure surface to detect when the user's prefs were
/// silently reset to defaults due to file corruption, hand-edit, or
/// truncation.
///
/// `Fresh` means the file loaded cleanly (or did not exist — a fresh
/// install is structurally identical to a no-op load).
///
/// `RecoveredFromCorrupt` means the loader fell back to defaults because
/// the file was unparseable, non-object at top-level, or had a per-field
/// type that did not survive the strip-and-defaults path. The `reason`
/// tag matches one of the existing WARN log tag prefixes
/// (`desktop_prefs_read`, `desktop_prefs_parse_value`,
/// `desktop_prefs_parse_typed`, `desktop_prefs_field_stripped`,
/// `desktop_prefs_top_level`, `desktop_prefs_empty`) for observability
/// parity with the existing log surface.
///
/// # Why NOT `#[derive(serde::Serialize)]`
///
/// This enum is internal API. Only the `reason: &'static str` inner
/// field ever crosses the IPC boundary (via `PrefsRecoveryPayload` in
/// `consume_prefs_recovery`). If a future refactor switched to
/// `serde_json::to_value(&outcome)`, the payload shape would change
/// silently and the frontend type would stop matching. Keeping
/// `LoadOutcome` non-Serialize forces all IPC serialization through the
/// explicit `PrefsRecoveryPayload` conversion, making the wire shape
/// explicit and auditable. (MED-2 / LOW-1: removed dead serde derive.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadOutcome {
    /// File loaded cleanly, or did not exist (fresh install).
    Fresh,
    /// File existed but was corrupt; defaults were used. `reason` is the
    /// log-tag prefix identifying the failure class.
    RecoveredFromCorrupt(&'static str),
}

/// Persisted desktop-shell preferences. Reads via [`load_desktop_prefs`],
/// writes via [`save_desktop_prefs`]. The struct intentionally does NOT
/// `#[derive(Default)]`: `dashboard_at_launch` defaults to `true` (show the
/// dashboard on launch), which is the inverse of `bool::default()`. See
/// [`DesktopPrefs::default`] below.
///
/// **Adding a new `bool` field?** Append its serde name to [`BOOL_FIELDS`]
/// so [`load_desktop_prefs`] strips a hand-edited junk value at that
/// key. The `bool_fields_enumeration_matches_serialized_struct`
/// regression test enforces this at CI time and emits a directed
/// failure message when the wiring drifts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopPrefs {
    /// When `true`, the desktop shell calls
    /// `set_activation_policy(Accessory)` at startup and on toggle,
    /// removing the Dock icon, the Cmd-Tab entry, and the menubar
    /// application menu on macOS. No-op on Windows / Linux. Default
    /// `false` preserves the historical foreground-app behaviour.
    ///
    /// **Decoupled from window visibility** as of the settings-popover
    /// refactor: this pref no longer affects whether the main dashboard
    /// window is shown at launch. That is owned by `dashboard_at_launch`.
    ///
    /// **Platform contract.** The wrong-type strip defense in
    /// [`load_desktop_prefs`] resets a hand-edited non-boolean value
    /// to `false` on every platform. On macOS this is observable
    /// (Dock icon stays visible). On Windows / Linux it is invisible
    /// because `apply_dock_hidden_policy` is a no-op there. If a
    /// future change ever wires this field to non-macOS behaviour
    /// (e.g. a taskbar-icon toggle), add a dedicated platform-pinning
    /// regression test for that surface — the existing
    /// `non_boolean_hide_dock_icon_preserves_dashboard_at_launch`
    /// test pins the prefs-layer invariant but not the
    /// platform-side effect chain.
    #[serde(default)]
    pub hide_dock_icon: bool,

    /// When `true` (default), the main dashboard window is shown at app
    /// startup. When `false`, the app launches into the menu-bar/tray
    /// only — the user clicks the tray icon (or Dock icon, if still
    /// shown) to open the dashboard. Independent of `hide_dock_icon`:
    /// any combination is valid.
    ///
    /// **Migration:** a pre-existing `desktop-prefs.json` with
    /// `hide_dock_icon: true` and no `dashboard_at_launch` field was
    /// written by the pre-refactor build where dock-hide implied
    /// window-hide. [`load_desktop_prefs`] detects that shape and
    /// materializes `dashboard_at_launch = false` to preserve the
    /// user's observed behavior across the upgrade. Otherwise missing
    /// = `true` (the default).
    #[serde(default = "default_dashboard_at_launch")]
    pub dashboard_at_launch: bool,
}

/// Serde default for [`DesktopPrefs::dashboard_at_launch`]. The window-shown
/// case is the classic desktop-app behavior; users explicitly opt into the
/// launch-hidden tray-only mode.
fn default_dashboard_at_launch() -> bool {
    true
}

/// Every boolean field on [`DesktopPrefs`] that [`load_desktop_prefs`]
/// pre-strips from a hand-edited JSON file when its value is not a
/// boolean. This list is the structural enforcement primitive for the
/// wrong-type field defense: if a new `bool` field lands on
/// [`DesktopPrefs`] without its serde name being added here, the
/// regression test `bool_fields_enumeration_matches_serialized_struct`
/// fails at CI time — surfacing the wiring gap before a hand-edited
/// junk value reaches a real user.
///
/// **Adding a new field?** If it is a `bool`, append its serde name
/// here. If it is a non-`bool`, this list and [`strip_non_boolean`]
/// no longer cover the full strip surface — refactor the helper into
/// a per-field-type strip primitive before merging. The
/// `bool_fields_enumeration_matches_serialized_struct` regression
/// test fails CI on either drift class — the structural defense, not
/// just operator discipline.
const BOOL_FIELDS: &[&str] = &["hide_dock_icon", "dashboard_at_launch"];

/// Strips `key` from `obj` if its value is anything other than a JSON
/// boolean. Returns `true` if a value was stripped. Used to pre-filter
/// the two-stage deserialize in [`load_desktop_prefs`] so a hand-edited
/// non-boolean value for a `bool`-typed field falls back to the
/// per-field serde default rather than failing the whole-struct
/// deserialize (which would silently discard every other field via the
/// outer error fallback).
fn strip_non_boolean(obj: &mut serde_json::Map<String, serde_json::Value>, key: &str) -> bool {
    if matches!(obj.get(key), Some(v) if !v.is_boolean()) {
        obj.remove(key);
        true
    } else {
        false
    }
}

impl Default for DesktopPrefs {
    fn default() -> Self {
        Self {
            hide_dock_icon: false,
            dashboard_at_launch: true,
        }
    }
}

/// Filename for the persisted preferences, relative to `base_dir`.
pub const DESKTOP_PREFS_FILE: &str = "desktop-prefs.json";

/// Typed newtype around the desktop-prefs serialization mutex.
///
/// Acts as a type-witness for "the caller holds the prefs lock." Every
/// function that mutates `desktop-prefs.json` content requires a
/// `&PrefsLock` as a witness parameter, making lock acquisition
/// compile-time-enforced rather than reviewer-enforced.
///
/// Combined with the `pub(in crate::desktop)` visibility on
/// [`load_desktop_prefs`] and [`save_desktop_prefs`], the only
/// read-mutate-write path that can cross the module boundary is
/// [`mutate_prefs`]. Any caller outside `csq/src/desktop/` that
/// tries to call `load_desktop_prefs` + `save_desktop_prefs` directly
/// will see a compile error — the structural defense is in the type
/// system, not the reviewer's memory.
pub struct PrefsLock(Mutex<()>);

impl PrefsLock {
    /// Constructs a new, unlocked `PrefsLock`.
    pub fn new() -> Self {
        Self(Mutex::new(()))
    }

    /// Acquires the underlying mutex guard, recovering from poison.
    ///
    /// Poison recovery is intentional: a thread that panicked while
    /// holding the prefs lock does not leave the preferences in a
    /// corrupt state (it may have mutated an in-memory `DesktopPrefs`
    /// but not yet written it). The next caller inherits a recovered
    /// guard and can proceed with a fresh load from disk.
    pub(in crate::desktop) fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for PrefsLock {
    fn default() -> Self {
        Self::new()
    }
}

/// Read-mutate-write helper for `desktop-prefs.json`. Acquires the
/// prefs lock, loads the current file (or default on corrupt/missing),
/// invokes the closure to mutate the in-memory representation, then
/// persists.
///
/// The `&PrefsLock` parameter is the type-witness for lock acquisition.
/// Callers cannot invoke `mutate_prefs` without owning a reference to
/// the `PrefsLock` instance, and [`load_desktop_prefs`] /
/// [`save_desktop_prefs`] are `pub(in crate::desktop)` so they cannot
/// be called from outside `csq/src/desktop/`. Combined, every
/// read-mutate-write of `desktop-prefs.json` MUST funnel through this
/// helper.
///
/// The closure receives `&mut DesktopPrefs` BEFORE the mutation is
/// persisted — it can capture the pre-mutation state if the caller
/// needs it for rollback logic (see `apply_and_persist_dock_hidden`
/// in `mod.rs`, which captures `previous` inside the closure for
/// post-save rollback).
pub fn mutate_prefs(
    lock: &PrefsLock,
    base: &Path,
    f: impl FnOnce(&mut DesktopPrefs),
) -> Result<(), String> {
    let _guard = lock.lock();
    let (mut prefs, _outcome) = load_desktop_prefs(base);
    f(&mut prefs);
    save_desktop_prefs(base, &prefs)
}

/// Loads persisted desktop preferences. Returns `(DesktopPrefs, LoadOutcome)`.
/// When the file does not exist the outcome is `Fresh` (fresh install — not
/// a corruption case). When the file exists but is corrupt, unparseable, or
/// has wrong-type fields the outcome is `RecoveredFromCorrupt(<tag>)` where
/// `<tag>` matches the WARN log tag prefix for observability parity.
///
/// None of the fallback cases are fatal for the desktop hot path (startup must
/// not block on a corrupt prefs file). Read failures are logged at WARN with
/// `error_kind` tags per `rules/security.md` Rule 2.
pub(in crate::desktop) fn load_desktop_prefs(base_dir: &Path) -> (DesktopPrefs, LoadOutcome) {
    let path = base_dir.join(DESKTOP_PREFS_FILE);
    match std::fs::read_to_string(&path) {
        Ok(content) if !content.trim().is_empty() => {
            // Two-step parse so we can detect the legacy pre-refactor shape
            // (file written before `dashboard_at_launch` existed) and apply
            // the dock-hide-implied-window-hide migration. A plain
            // `from_str::<DesktopPrefs>` would silently fill missing fields
            // with the serde defaults, losing the legacy signal.
            match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(mut value) => {
                    // Probe for the field's *meaningful* presence. Any
                    // non-boolean value (JSON `null`, number, string,
                    // array, object) is treated as missing for two
                    // reasons: (1) `bool` cannot deserialize from a
                    // non-bool JSON value, so any non-bool here would
                    // fail the whole-struct deserialize at `from_value`
                    // below and silently discard the user's
                    // `hide_dock_icon` setting via the outer error
                    // branch's `DesktopPrefs::default()`; (2) user intent
                    // for `null` / junk-typed values is indistinguishable
                    // from "field-absent" — none of them signal an
                    // explicit boolean.
                    let dashboard_field_explicit = matches!(
                        value.get("dashboard_at_launch"),
                        Some(v) if v.is_boolean()
                    );
                    // Top-level non-object guard. A file containing a
                    // bare scalar / array / null at the top level would
                    // skip the strip block (since `as_object_mut`
                    // returns `None`) and rely on `from_value` to fail
                    // and trigger the outer error fallback. That works
                    // by accident today, but a future maintainer who
                    // adds a forgiving newtype could reintroduce the
                    // silent-discard class. Short-circuit explicitly.
                    if !value.is_object() {
                        log::warn!(
                            target: "csq::desktop::preferences",
                            "desktop_prefs_top_level: desktop-prefs.json is not a JSON object, using defaults"
                        );
                        return (
                            DesktopPrefs::default(),
                            LoadOutcome::RecoveredFromCorrupt("desktop_prefs_top_level"),
                        );
                    }
                    // Strip any non-boolean value at every known
                    // boolean key so `from_value` falls back to the
                    // per-field serde default (rather than failing the
                    // whole-struct deserialize, which would discard
                    // EVERY field via the outer error branch). Applies
                    // symmetrically across all `BOOL_FIELDS` — same
                    // bug-class, same defense, per
                    // `rules/zero-tolerance.md` Rule 1.
                    //
                    // NOTE: every new `bool` field on `DesktopPrefs`
                    // MUST be appended to `BOOL_FIELDS` above. The
                    // `bool_fields_enumeration_matches_serialized_struct`
                    // regression test enforces this at CI time.
                    //
                    // Track whether any field was stripped; if so the
                    // outcome is RecoveredFromCorrupt even though the
                    // remaining fields survive.
                    let mut any_field_stripped = false;
                    if let Some(obj) = value.as_object_mut() {
                        for field in BOOL_FIELDS {
                            if strip_non_boolean(obj, field) {
                                any_field_stripped = true;
                            }
                        }
                    }
                    match serde_json::from_value::<DesktopPrefs>(value) {
                        Ok(mut p) => {
                            // Migration: legacy file had only `hide_dock_icon`.
                            // Pre-refactor, `hide_dock_icon=true` ALSO hid the
                            // window at launch (the two behaviors were
                            // conflated in `apply_dock_hidden_policy`). On
                            // upgrade we preserve the user's observed startup
                            // behavior: dock hidden → keep dashboard hidden.
                            // Users who explicitly want the dashboard back can
                            // flip the new `dashboard_at_launch` toggle.
                            if !dashboard_field_explicit && p.hide_dock_icon {
                                p.dashboard_at_launch = false;
                            }
                            let outcome = if any_field_stripped {
                                // LOW-2: use a distinct tag for the strip-success
                                // path so operators can distinguish it from the
                                // typed-deserialize-fail path at the same log
                                // target. Previously both paths logged and tagged
                                // as `desktop_prefs_parse_typed`, making it
                                // impossible to tell from `csq.log` whether the
                                // struct survived (fields preserved via strip +
                                // serde default) or fell back to all-defaults.
                                log::warn!(
                                    target: "csq::desktop::preferences",
                                    "desktop_prefs_field_stripped: one or more \
                                     non-boolean field values were stripped and \
                                     reset to per-field serde defaults; remaining \
                                     fields were preserved"
                                );
                                LoadOutcome::RecoveredFromCorrupt("desktop_prefs_field_stripped")
                            } else {
                                LoadOutcome::Fresh
                            };
                            (p, outcome)
                        }
                        Err(_e) => {
                            // R2 security-reviewer MED: `serde_json::Error::Display`
                            // echoes a substring of the offending JSON near the
                            // parse-error position (per an internal journal entry). Today
                            // desktop-prefs.json holds no secrets, but the module
                            // docstring at lines 19-22 explicitly anticipates a
                            // future secret-bearing field; pre-hardening the log
                            // format now per `rules/security.md` Rule 2 prevents
                            // the rule-violation from landing in the same commit
                            // that adds such a field. The fixed-vocabulary tag
                            // prefix `desktop_prefs_parse_typed:` conveys the
                            // error class; the unbounded `{e}` body is dropped.
                            log::warn!(
                                target: "csq::desktop::preferences",
                                "desktop_prefs_parse_typed: desktop-prefs.json typed deserialize failed, using defaults"
                            );
                            (
                                DesktopPrefs::default(),
                                LoadOutcome::RecoveredFromCorrupt("desktop_prefs_parse_typed"),
                            )
                        }
                    }
                }
                Err(_e) => {
                    // R2 security-reviewer MED: same defense as above. The
                    // `from_str::<Value>` arm is structurally the more dangerous
                    // of the two — `serde_json::Error::Display` includes a
                    // substring of the input near the parse-error position.
                    log::warn!(
                        target: "csq::desktop::preferences",
                        "desktop_prefs_parse_value: desktop-prefs.json JSON syntax invalid, using defaults"
                    );
                    (
                        DesktopPrefs::default(),
                        LoadOutcome::RecoveredFromCorrupt("desktop_prefs_parse_value"),
                    )
                }
            }
        }
        // File existed but was empty / whitespace-only. Not a missing-file
        // (fresh install) case — the file was written and later truncated or
        // zeroed. Treat as corruption so the renderer can disclose it.
        // LOW-3: emit the same WARN that every other recovery branch emits
        // so operators grepping `csq.log` for `desktop_prefs_empty` see a
        // hit (previously this path was silent).
        Ok(_) => {
            log::warn!(
                target: "csq::desktop::preferences",
                "desktop_prefs_empty: desktop-prefs.json is empty or \
                 whitespace-only, using defaults"
            );
            (
                DesktopPrefs::default(),
                LoadOutcome::RecoveredFromCorrupt("desktop_prefs_empty"),
            )
        }
        // File not found → fresh install, not a corruption case.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            (DesktopPrefs::default(), LoadOutcome::Fresh)
        }
        Err(_e) => {
            // R2 security-reviewer MED: `std::io::Error::Display` typically
            // includes the file path. The path is non-secret today (a known
            // structural location under `<base>/desktop-prefs.json`), but
            // uniformity across the three log call sites in this function
            // matters for future-maintainer auditability — if a future field
            // adds secrets and a maintainer audits only ONE of these arms,
            // missing the others reintroduces the leak class.
            log::warn!(
                target: "csq::desktop::preferences",
                "desktop_prefs_read: desktop-prefs.json read failed, using defaults"
            );
            (
                DesktopPrefs::default(),
                LoadOutcome::RecoveredFromCorrupt("desktop_prefs_read"),
            )
        }
    }
}

/// Persists desktop preferences using the same atomic-write +
/// chmod-0o600 contract as [`csq_core::providers::settings::save_settings`]
/// and `capability_layer.json`. Returns a flat `String` error so the
/// caller (a Tauri command handler) can map directly to the IPC
/// boundary per `rules/tauri-commands.md` MUST Rule 1.
pub(in crate::desktop) fn save_desktop_prefs(
    base_dir: &Path,
    prefs: &DesktopPrefs,
) -> Result<(), String> {
    save_desktop_prefs_inner(
        base_dir,
        prefs,
        |p, b| std::fs::write(p, b),
        secure_file_err_to_io,
        atomic_replace_err_to_io,
    )
}

/// Closure-injected core of [`save_desktop_prefs`]. Each platform
/// fs operation is a separate function pointer so tests can inject
/// failing stubs that exercise the §5a cleanup-on-failure path
/// (R1 redteam Finding S-H4 — the original test only triggered
/// the `write` branch, leaving `secure_file` and `atomic_replace`
/// failure-cleanup uncovered).
///
/// The closure shape mirrors the precedent at
/// `csq-core/src/daemon/identity_mint.rs::write_identity_json_inner`
/// (closure-injected `write` / `secure` / `replace` for §5a
/// failure-branch coverage).
fn save_desktop_prefs_inner<W, S, R>(
    base_dir: &Path,
    prefs: &DesktopPrefs,
    write: W,
    secure: S,
    replace: R,
) -> Result<(), String>
where
    W: FnOnce(&Path, &[u8]) -> std::io::Result<()>,
    S: FnOnce(&Path) -> std::io::Result<()>,
    R: FnOnce(&Path, &Path) -> std::io::Result<()>,
{
    let path = base_dir.join(DESKTOP_PREFS_FILE);

    let json =
        serde_json::to_string_pretty(prefs).map_err(|e| format!("desktop_prefs_serialize: {e}"))?;

    if let Some(parent) = path.parent() {
        // Best-effort: parent should already exist (it's the csq
        // base dir, created by the daemon / first login). If it
        // doesn't, the write below will fail with a clearer error
        // than mkdir's would.
        std::fs::create_dir_all(parent).ok();
    }

    let tmp = unique_tmp_path(&path);
    if let Err(e) = write(&tmp, json.as_bytes()) {
        // §5a cleanup-on-failure: remove the umask-default-permission
        // tmp file before returning. The payload is not secret today
        // but the discipline is uniform across every save_* in the
        // codebase per the audit primitive.
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("desktop_prefs_write: {e}"));
    }
    if let Err(e) = secure(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("desktop_prefs_chmod: {e}"));
    }
    if let Err(e) = replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("desktop_prefs_replace: {e}"));
    }

    Ok(())
}

/// Adapter for `secure_file` whose error type is
/// `crate::platform::PlatformError`. Maps to `std::io::Error` so
/// the closure-injected save shape uses a single error type.
fn secure_file_err_to_io(path: &Path) -> std::io::Result<()> {
    secure_file(path).map_err(|e| std::io::Error::other(format!("{e}")))
}

/// Adapter for `atomic_replace`. Same shape as `secure_file_err_to_io`.
fn atomic_replace_err_to_io(tmp: &Path, target: &Path) -> std::io::Result<()> {
    atomic_replace(tmp, target).map_err(|e| std::io::Error::other(format!("{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn defaults_have_dock_icon_visible() {
        let p = DesktopPrefs::default();
        assert!(!p.hide_dock_icon);
    }

    #[test]
    fn missing_file_returns_default() {
        let dir = TempDir::new().unwrap();
        let (p, outcome) = load_desktop_prefs(dir.path());
        assert_eq!(p, DesktopPrefs::default());
        assert_eq!(outcome, LoadOutcome::Fresh);
    }

    #[test]
    fn corrupt_file_returns_default() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(DESKTOP_PREFS_FILE), "{ not valid json,").unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert_eq!(p, DesktopPrefs::default());
    }

    #[test]
    fn empty_file_returns_default() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(DESKTOP_PREFS_FILE), "").unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert_eq!(p, DesktopPrefs::default());
    }

    #[test]
    fn whitespace_only_file_returns_default() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(DESKTOP_PREFS_FILE), "   \n\t  ").unwrap();
        let (p, outcome) = load_desktop_prefs(dir.path());
        assert_eq!(p, DesktopPrefs::default());
        // Per /redteam R2 testing-specialist LOW-1: whitespace-only must
        // route through the same `RecoveredFromCorrupt("desktop_prefs_empty")`
        // path as the empty-file case (see `load_returns_recovered_outcome_on_empty_file`).
        // Without this assertion, a future refactor that changes the
        // `trim().is_empty()` guard to route whitespace through
        // `LoadOutcome::Fresh` would silently regress while this test still passes.
        assert_eq!(
            outcome,
            LoadOutcome::RecoveredFromCorrupt("desktop_prefs_empty"),
            "whitespace-only file must be RecoveredFromCorrupt(desktop_prefs_empty), not Fresh"
        );
    }

    #[test]
    fn round_trip_preserves_field() {
        let dir = TempDir::new().unwrap();
        let original = DesktopPrefs {
            hide_dock_icon: true,
            ..Default::default()
        };
        save_desktop_prefs(dir.path(), &original).unwrap();
        let (loaded, _) = load_desktop_prefs(dir.path());
        assert_eq!(loaded, original);
    }

    #[test]
    fn round_trip_false_is_persisted_explicitly() {
        // After the user has flipped hide → on then back to off, the
        // file should record the explicit `false` (not be deleted) so
        // a future field addition does not inherit the default-on
        // shape from a missing file.
        let dir = TempDir::new().unwrap();
        save_desktop_prefs(
            dir.path(),
            &DesktopPrefs {
                hide_dock_icon: false,
                ..Default::default()
            },
        )
        .unwrap();
        let content = std::fs::read_to_string(dir.path().join(DESKTOP_PREFS_FILE)).unwrap();
        assert!(content.contains("\"hide_dock_icon\""));
        assert!(content.contains("false"));
    }

    #[test]
    fn missing_field_reads_as_false() {
        // Forward-compat shape: a future version may add a field
        // older csq does not understand. Older csq must not refuse
        // to parse it.
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(DESKTOP_PREFS_FILE), r#"{}"#).unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert!(!p.hide_dock_icon);
    }

    #[test]
    fn unknown_field_in_json_is_ignored() {
        // Forward-compat: when a future version writes a field
        // older csq doesn't know about, older csq must still parse
        // the known fields successfully.
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(DESKTOP_PREFS_FILE),
            r#"{"hide_dock_icon": true, "future_field": "ignored"}"#,
        )
        .unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert!(p.hide_dock_icon);
    }

    #[test]
    fn save_creates_file_with_secure_permissions_on_unix() {
        // The file must be 0o600 after save per security.md Rule 5.
        // Only assert on Unix — secure_file is a no-op on Windows.
        let dir = TempDir::new().unwrap();
        save_desktop_prefs(
            dir.path(),
            &DesktopPrefs {
                hide_dock_icon: true,
                ..Default::default()
            },
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(dir.path().join(DESKTOP_PREFS_FILE)).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "expected 0o600, got {mode:o}");
        }
    }

    // ── §5a closure-injected failure-branch tests ─────────────────
    //
    // R1 redteam Finding S-H4: the original `save_to_nonexistent_dir_…`
    // test only exercised the `std::fs::write` failure path AND the
    // cleanup itself failed (the r-x parent denies remove_file too),
    // so it provided weak coverage of the cleanup-on-failure pattern
    // §5a actually defends. The three tests below inject failing
    // closures at each branch — write, secure, replace — and verify
    // (a) the call returns Err, (b) no tmp file is left on disk.

    /// Counts the number of entries in `dir`. Used to assert that the
    /// §5a cleanup-on-failure path leaves zero residue after each
    /// failure-branch test. R2 testing-specialist LOW-1: previously
    /// named `make_dir_and_count_remaining` — the name implied this
    /// helper created state, but it only counts what is already on
    /// disk. The renamed form matches the actual behavior.
    fn count_dir_entries(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .count()
    }

    #[test]
    fn save_cleans_tmp_on_write_error() {
        // R1 rust-specialist LOW: the prior shape of this test used a
        // failing write closure that NEVER created the tmp file, which
        // made the `count == 0` assertion vacuous — deleting the
        // cleanup line at `save_desktop_prefs_inner` would not have
        // caused the test to fail. The closure below simulates the
        // load-bearing scenario: the write partially succeeds (a real
        // disk-full / ENOSPC mid-write leaves the tmp on disk), then
        // returns `Err`. The cleanup line MUST delete the residue.
        let dir = TempDir::new().unwrap();
        let result = save_desktop_prefs_inner(
            dir.path(),
            &DesktopPrefs {
                hide_dock_icon: true,
                ..Default::default()
            },
            // Failing write that DOES create the tmp file (simulates
            // mid-write failure). Cleanup-on-failure MUST remove it.
            |p, b| {
                std::fs::write(p, b).expect("test setup: write must succeed");
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "injected post-write failure",
                ))
            },
            |_p| panic!("secure_file should not run after write failure"),
            |_t, _p| panic!("atomic_replace should not run after write failure"),
        );
        assert!(result.is_err(), "expected write failure to propagate");
        assert!(
            result.unwrap_err().contains("desktop_prefs_write"),
            "expected error to identify the write branch"
        );
        assert_eq!(
            count_dir_entries(dir.path()),
            0,
            "tmp file MUST be cleaned up on write-branch failure (§5a) — \
             this assertion is non-vacuous because the closure created \
             the tmp before returning Err"
        );
    }

    #[test]
    fn save_cleans_tmp_on_secure_file_error() {
        let dir = TempDir::new().unwrap();
        let result = save_desktop_prefs_inner(
            dir.path(),
            &DesktopPrefs {
                hide_dock_icon: true,
                ..Default::default()
            },
            // Successful write — creates the tmp file with the
            // payload. Cleanup-on-failure MUST delete it.
            |p, b| std::fs::write(p, b),
            // Failing secure_file step.
            |_p| Err(std::io::Error::other("injected secure_file failure")),
            |_t, _p| panic!("atomic_replace should not run after secure_file failure"),
        );
        assert!(result.is_err(), "expected secure_file failure to propagate");
        assert!(
            result.unwrap_err().contains("desktop_prefs_chmod"),
            "expected error to identify the secure_file branch"
        );
        assert_eq!(
            count_dir_entries(dir.path()),
            0,
            "tmp file MUST be cleaned up on secure_file failure (§5a)"
        );
    }

    #[test]
    fn save_cleans_tmp_on_atomic_replace_error() {
        let dir = TempDir::new().unwrap();
        let result = save_desktop_prefs_inner(
            dir.path(),
            &DesktopPrefs {
                hide_dock_icon: true,
                ..Default::default()
            },
            // Successful write — creates the tmp file with the payload.
            |p, b| std::fs::write(p, b),
            // Successful chmod no-op.
            |_p| Ok(()),
            // Failing atomic_replace. The tmp file still exists at
            // this point; cleanup-on-failure MUST delete it.
            |_t, _p| Err(std::io::Error::other("injected atomic_replace failure")),
        );
        assert!(
            result.is_err(),
            "expected atomic_replace failure to propagate"
        );
        assert!(
            result.unwrap_err().contains("desktop_prefs_replace"),
            "expected error to identify the atomic_replace branch"
        );
        assert_eq!(
            count_dir_entries(dir.path()),
            0,
            "tmp file MUST be cleaned up on atomic_replace failure (§5a)"
        );
    }

    #[test]
    fn save_bootstraps_nonexistent_base_dir_via_create_dir_all() {
        // R2 redteam Finding R2-HIGH-1: the fresh-install case
        // where `<base>` does not yet exist must succeed —
        // `save_desktop_prefs` calls `create_dir_all(parent)`
        // best-effort, and the closure-injected pipeline then
        // writes the file inside the newly created directory.
        //
        // This test pairs with the `resolve_csq_base_dir`
        // relaxation in `csq/src/desktop/commands/mod.rs` which
        // allows the not-yet-existent base_dir through to here.
        let dir = TempDir::new().unwrap();
        let nonexistent = dir.path().join("fresh-install").join("accounts");
        assert!(!nonexistent.exists(), "precondition");
        save_desktop_prefs(
            &nonexistent,
            &DesktopPrefs {
                hide_dock_icon: true,
                ..Default::default()
            },
        )
        .expect("save should bootstrap the dir and write the file");
        assert!(
            nonexistent.join(DESKTOP_PREFS_FILE).is_file(),
            "expected the prefs file to be present after bootstrap"
        );
        let (loaded, _) = load_desktop_prefs(&nonexistent);
        assert!(loaded.hide_dock_icon);
    }

    #[test]
    fn save_success_consumes_tmp_and_writes_target() {
        // Sanity: the closure-injected path's happy case still
        // leaves exactly the target file (tmp consumed by
        // atomic_replace) — same observable behaviour as the
        // production `save_desktop_prefs`.
        let dir = TempDir::new().unwrap();
        let result = save_desktop_prefs_inner(
            dir.path(),
            &DesktopPrefs {
                hide_dock_icon: true,
                ..Default::default()
            },
            |p, b| std::fs::write(p, b),
            |_p| Ok(()),
            |t, p| std::fs::rename(t, p),
        );
        assert!(result.is_ok());
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        assert_eq!(entries.len(), 1, "exactly the target file should remain");
        assert_eq!(entries[0], DESKTOP_PREFS_FILE);
    }

    // ── dashboard_at_launch field + migration ────────────────────────

    #[test]
    fn default_has_dashboard_visible_at_launch() {
        let p = DesktopPrefs::default();
        assert!(
            p.dashboard_at_launch,
            "default must show the dashboard at launch — the classic desktop-app behavior"
        );
    }

    #[test]
    fn missing_file_yields_dashboard_at_launch_true() {
        // Fresh install: no desktop-prefs.json. Must default to showing the
        // dashboard (not the migration branch — the migration only fires for
        // legacy files with hide_dock_icon=true).
        let dir = TempDir::new().unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert!(p.dashboard_at_launch);
        assert!(!p.hide_dock_icon);
    }

    #[test]
    fn legacy_file_with_dock_hidden_migrates_to_dashboard_at_launch_false() {
        // Pre-refactor build wrote `{"hide_dock_icon": true}` — the dock-hide
        // ALSO hid the window at launch (the two behaviors were conflated in
        // apply_dock_hidden_policy). Migration preserves the user's observed
        // behavior across upgrade: dashboard_at_launch = false.
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(DESKTOP_PREFS_FILE),
            r#"{"hide_dock_icon": true}"#,
        )
        .unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert!(p.hide_dock_icon, "hide_dock_icon=true should be preserved");
        assert!(
            !p.dashboard_at_launch,
            "legacy hide_dock_icon=true with no dashboard_at_launch field must migrate to false"
        );
    }

    #[test]
    fn legacy_file_with_dock_visible_does_not_migrate() {
        // Pre-refactor user with hide_dock_icon=false saw a visible dashboard
        // at launch. Migration must NOT downgrade them — leave the default
        // (dashboard_at_launch=true) intact.
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(DESKTOP_PREFS_FILE),
            r#"{"hide_dock_icon": false}"#,
        )
        .unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert!(!p.hide_dock_icon);
        assert!(
            p.dashboard_at_launch,
            "legacy hide_dock_icon=false must keep the default dashboard_at_launch=true"
        );
    }

    #[test]
    fn explicit_dashboard_field_overrides_migration() {
        // A post-refactor file with BOTH fields present must be honored
        // verbatim — the migration only fires when dashboard_at_launch is
        // absent. A user who explicitly opted IN to dashboard_at_launch=true
        // while keeping hide_dock_icon=true must not get downgraded to false.
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(DESKTOP_PREFS_FILE),
            r#"{"hide_dock_icon": true, "dashboard_at_launch": true}"#,
        )
        .unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert!(p.hide_dock_icon);
        assert!(
            p.dashboard_at_launch,
            "explicit dashboard_at_launch=true must override the migration"
        );
    }

    #[test]
    fn round_trip_preserves_both_fields() {
        let dir = TempDir::new().unwrap();
        let original = DesktopPrefs {
            hide_dock_icon: true,
            dashboard_at_launch: false,
        };
        save_desktop_prefs(dir.path(), &original).unwrap();
        let (loaded, _) = load_desktop_prefs(dir.path());
        assert_eq!(loaded, original);
    }

    #[test]
    fn explicit_null_dashboard_field_treated_as_missing_with_migration() {
        // R1 deep-analyst MED-1: `serde_json::Value::get` returns
        // `Some(Value::Null)` for an explicit JSON `null`. Pre-fix the
        // probe treated that as "field present" (skipping migration) AND
        // `from_value::<bool>(Null)` failed the whole-struct deserialize,
        // silently discarding `hide_dock_icon` via the outer error fallback.
        // Both pathologies must be closed: null = missing-equivalent, and
        // the rest of the file is preserved.
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(DESKTOP_PREFS_FILE),
            r#"{"hide_dock_icon": true, "dashboard_at_launch": null}"#,
        )
        .unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert!(
            p.hide_dock_icon,
            "hide_dock_icon must be preserved when dashboard_at_launch is JSON null"
        );
        assert!(
            !p.dashboard_at_launch,
            "explicit null is migration-eligible — legacy hide_dock_icon=true should set false"
        );
    }

    #[test]
    fn round_trip_writes_dashboard_at_launch_field_explicitly() {
        // The serializer must emit the field so future loads see it as
        // "explicit" and skip the migration branch.
        let dir = TempDir::new().unwrap();
        save_desktop_prefs(dir.path(), &DesktopPrefs::default()).unwrap();
        let content = std::fs::read_to_string(dir.path().join(DESKTOP_PREFS_FILE)).unwrap();
        assert!(
            content.contains("\"dashboard_at_launch\""),
            "serialized file must contain the dashboard_at_launch key; got: {content}"
        );
    }

    // ── wrong-type field defense ─────────────────────────────────────
    //
    // `save_desktop_prefs` always emits booleans, but a hand-edited file
    // (operator debug, accidental corruption, schema-skew downgrade) may
    // carry a non-boolean at either bool-typed key. The whole-struct
    // typed deserialize would fail on such a value and silently discard
    // EVERY field via the outer error fallback. The `strip_non_boolean`
    // pre-filter is the structural defense — each known boolean key is
    // stripped if its value is non-boolean so the per-field serde
    // default applies and sibling fields survive the load.

    #[test]
    fn non_boolean_dashboard_field_preserves_hide_dock_icon_and_triggers_migration() {
        // A string at `dashboard_at_launch` was treating the field as
        // "present-but-junk" → typed deserialize failed → whole struct
        // defaulted → `hide_dock_icon: true` was silently lost AND the
        // legacy-dock-hidden migration never fired. After the fix, the
        // non-boolean is field-absent-equivalent: `hide_dock_icon`
        // survives, and the migration sets `dashboard_at_launch: false`.
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(DESKTOP_PREFS_FILE),
            r#"{"hide_dock_icon": true, "dashboard_at_launch": "yes"}"#,
        )
        .unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert!(
            p.hide_dock_icon,
            "hide_dock_icon=true must survive a junk-typed dashboard_at_launch value"
        );
        assert!(
            !p.dashboard_at_launch,
            "non-boolean dashboard_at_launch is field-absent-equivalent; legacy migration must fire"
        );
    }

    #[test]
    fn non_boolean_dashboard_field_without_dock_hidden_uses_default_no_migration() {
        // Number at `dashboard_at_launch`, dock visible. The non-boolean
        // is stripped → serde default applies (`true`) → migration does
        // NOT fire because the trigger requires `hide_dock_icon=true`.
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(DESKTOP_PREFS_FILE),
            r#"{"hide_dock_icon": false, "dashboard_at_launch": 42}"#,
        )
        .unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert!(!p.hide_dock_icon);
        assert!(
            p.dashboard_at_launch,
            "non-boolean dashboard_at_launch with dock visible must use serde default true"
        );
    }

    #[test]
    fn non_boolean_hide_dock_icon_preserves_dashboard_at_launch() {
        // Sibling defense: a non-boolean at `hide_dock_icon` would
        // previously fail the whole-struct deserialize and silently
        // discard the user's explicit `dashboard_at_launch` selection.
        // After the fix, `hide_dock_icon` falls back to its serde
        // default (`false`) and `dashboard_at_launch` survives.
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(DESKTOP_PREFS_FILE),
            r#"{"hide_dock_icon": 5, "dashboard_at_launch": false}"#,
        )
        .unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert!(
            !p.hide_dock_icon,
            "non-boolean hide_dock_icon must fall back to the serde default false"
        );
        assert!(
            !p.dashboard_at_launch,
            "explicit dashboard_at_launch=false must survive a junk-typed hide_dock_icon"
        );
    }

    #[test]
    fn both_fields_non_boolean_returns_default_struct_via_per_field_strip() {
        // R2 testing-specialist MED-1: an earlier version of this
        // comment claimed the assertion distinguishes the per-field-strip
        // happy path from the outer-error-fallback path. The assertion
        // cannot — both paths produce the identical default-struct
        // shape, so a refactor that accidentally routed through the
        // outer fallback would still pass this test. The comment was
        // rewritten to describe only what the assertion observably
        // verifies: both non-boolean fields land at the per-field
        // serde defaults, same shape as `DesktopPrefs::default()`.
        // Distinguishing the two code paths from a unit test is not
        // possible with the current single-struct shape; if it ever
        // matters, add a third non-stripped field whose presence in
        // the post-load value would prove the strip path ran.
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(DESKTOP_PREFS_FILE),
            r#"{"hide_dock_icon": [], "dashboard_at_launch": {}}"#,
        )
        .unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert_eq!(
            p,
            DesktopPrefs::default(),
            "both fields non-boolean must land at the per-field serde defaults"
        );
    }

    // ── structural-enforcement: BOOL_FIELDS parity ───────────────────
    //
    // R1 deep-analyst F2 (MED): without a structural check, a future
    // maintainer who adds `pub minimize_to_tray: bool` to
    // `DesktopPrefs` would silently reintroduce the bug class this PR
    // closes — a hand-edited junk value at the new key fails the
    // whole-struct deserialize and discards siblings. The test below
    // serializes the default struct, walks every emitted key, and
    // asserts (a) the value is a JSON boolean (catches non-bool field
    // additions that need a refactored strip helper), and (b) the key
    // appears in `BOOL_FIELDS` (catches bool field additions that
    // forgot to wire the strip).

    #[test]
    fn bool_fields_enumeration_matches_serialized_struct() {
        let v = serde_json::to_value(DesktopPrefs::default()).expect("DesktopPrefs must serialize");
        let obj = v
            .as_object()
            .expect("DesktopPrefs serializes to a JSON object");
        for (key, value) in obj {
            assert!(
                value.is_boolean(),
                "field `{key}` serializes to non-boolean {value:?}; \
                 `strip_non_boolean` is bool-only — refactor the helper \
                 to be type-aware before adding non-bool fields to DesktopPrefs"
            );
            assert!(
                BOOL_FIELDS.contains(&key.as_str()),
                "field `{key}` is not enumerated in `BOOL_FIELDS`; \
                 add it so `load_desktop_prefs` strips hand-edited junk values \
                 at that key (otherwise sibling fields are silently discarded)"
            );
        }
        // And every entry in BOOL_FIELDS must correspond to a field
        // that actually serializes — otherwise the list is stale and
        // the strip is a no-op (cheaper failure, but still drift).
        for field in BOOL_FIELDS {
            assert!(
                obj.contains_key(*field),
                "`BOOL_FIELDS` contains `{field}` but `DesktopPrefs` does not serialize it; \
                 the entry is stale — remove it"
            );
        }
    }

    // ── top-level shape coverage (F1 + F3) ───────────────────────────
    //
    // R1 deep-analyst F1/F3: a file containing a bare scalar / array /
    // null at the top level falls through `as_object_mut()` returning
    // `None`, skips the strip block, and relies on `from_value` to
    // fail. The fix adds an explicit `!value.is_object()` short-circuit
    // returning `DesktopPrefs::default()`. These tests pin that
    // behavior so a future refactor cannot drop the guard silently.

    #[test]
    fn top_level_null_returns_default() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(DESKTOP_PREFS_FILE), "null").unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert_eq!(p, DesktopPrefs::default());
    }

    #[test]
    fn top_level_array_returns_default() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(DESKTOP_PREFS_FILE), "[]").unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert_eq!(p, DesktopPrefs::default());
    }

    #[test]
    fn top_level_number_returns_default() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(DESKTOP_PREFS_FILE), "42").unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert_eq!(p, DesktopPrefs::default());
    }

    #[test]
    fn top_level_string_returns_default() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(DESKTOP_PREFS_FILE), r#""yes""#).unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert_eq!(p, DesktopPrefs::default());
    }

    #[test]
    fn top_level_bare_bool_returns_default() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(DESKTOP_PREFS_FILE), "true").unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert_eq!(p, DesktopPrefs::default());
    }

    // ── trailing-junk + case-variant invariants (F4 + F5) ─────────────
    //
    // R1 deep-analyst F4: `serde_json::from_str::<Value>` is strict
    // about trailing content. Input `{"hide_dock_icon":true} garbage`
    // returns `Err`, the file is treated as corrupt, defaults are
    // returned, sibling state is lost. This is correct behavior but
    // unpinned — a tolerant-refactor (e.g. `Deserializer::into_iter`)
    // would silently change semantics. Pin it here.
    //
    // R1 deep-analyst F5: `Value::get` and the serde-derived deserialize
    // are both case-sensitive (no `#[serde(rename_all)]` / `alias`). A
    // case-variant of either key is treated as field-absent by both
    // the probe and the typed deserialize — combined with a legacy
    // `hide_dock_icon: true` shape, migration fires.

    #[test]
    fn trailing_garbage_after_valid_object_returns_default() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(DESKTOP_PREFS_FILE),
            r#"{"hide_dock_icon": true} garbage"#,
        )
        .unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert_eq!(
            p,
            DesktopPrefs::default(),
            "trailing junk must fail the strict JSON parse and yield default"
        );
    }

    #[test]
    fn case_variant_dashboard_key_treated_as_absent_field() {
        // The case-variant `Dashboard_At_Launch` is unknown to both the
        // probe and the serde deserialize. With legacy
        // `hide_dock_icon: true` present, migration fires and sets
        // `dashboard_at_launch = false` — NOT the misspelled key's
        // value. Documents the case-sensitivity invariant.
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(DESKTOP_PREFS_FILE),
            r#"{"hide_dock_icon": true, "Dashboard_At_Launch": true}"#,
        )
        .unwrap();
        let (p, _) = load_desktop_prefs(dir.path());
        assert!(p.hide_dock_icon);
        assert!(
            !p.dashboard_at_launch,
            "case-variant key is unknown — migration must fire from hide_dock_icon=true"
        );
    }

    // ── PrefsLock + mutate_prefs tests ───────────────────────────────

    #[test]
    fn mutate_prefs_persists_after_closure_returns() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let lock = PrefsLock::new();

        // Act
        mutate_prefs(&lock, dir.path(), |p| {
            p.hide_dock_icon = true;
        })
        .unwrap();

        // Assert — reload from disk and verify the mutation is durable.
        let (loaded, _) = load_desktop_prefs(dir.path());
        assert!(
            loaded.hide_dock_icon,
            "mutate_prefs must persist the closure mutation to disk"
        );
    }

    #[test]
    fn mutate_prefs_closure_sees_loaded_state_before_mutation() {
        // Arrange — pre-populate the file with a known value.
        let dir = TempDir::new().unwrap();
        save_desktop_prefs(
            dir.path(),
            &DesktopPrefs {
                hide_dock_icon: true,
                dashboard_at_launch: false,
            },
        )
        .unwrap();
        let lock = PrefsLock::new();
        let mut saw_hide = false;
        let mut saw_dashboard = true; // wrong sentinel — will be overwritten

        // Act — closure observes the PRE-mutation state from disk.
        mutate_prefs(&lock, dir.path(), |p| {
            saw_hide = p.hide_dock_icon;
            saw_dashboard = p.dashboard_at_launch;
            // Do not mutate — the observation is the point.
        })
        .unwrap();

        // Assert — the closure received the on-disk state, not the default.
        assert!(
            saw_hide,
            "closure must see hide_dock_icon=true from the pre-populated file"
        );
        assert!(
            !saw_dashboard,
            "closure must see dashboard_at_launch=false from the pre-populated file"
        );
    }

    #[test]
    fn mutate_prefs_acquires_lock_serializes_concurrent_writers() {
        // Arrange — shared lock and a base dir both writers use.
        use std::sync::Arc;
        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        let lock = Arc::new(PrefsLock::new());

        // Start with a known on-disk state.
        save_desktop_prefs(
            &base,
            &DesktopPrefs {
                hide_dock_icon: false,
                dashboard_at_launch: true,
            },
        )
        .unwrap();

        // Use a Barrier to force both threads into the lock acquisition at
        // the same wall-clock instant — without this, thread A often completes
        // before thread B even spawns, and the lock is never actually contested.
        // Per /redteam R2 intermediate-reviewer NIT-1: the assertion still
        // holds without the barrier, but the test does not exercise the
        // serialization scenario it claims to.
        let barrier = Arc::new(std::sync::Barrier::new(2));

        let lock_a = Arc::clone(&lock);
        let base_a = base.clone();
        let barrier_a = Arc::clone(&barrier);
        // Writer A: sets hide_dock_icon = true.
        let handle_a = std::thread::spawn(move || {
            barrier_a.wait();
            mutate_prefs(&lock_a, &base_a, |p| {
                p.hide_dock_icon = true;
            })
            .unwrap();
        });

        let lock_b = Arc::clone(&lock);
        let base_b = base.clone();
        let barrier_b = Arc::clone(&barrier);
        // Writer B: sets dashboard_at_launch = false.
        let handle_b = std::thread::spawn(move || {
            barrier_b.wait();
            mutate_prefs(&lock_b, &base_b, |p| {
                p.dashboard_at_launch = false;
            })
            .unwrap();
        });

        handle_a.join().unwrap();
        handle_b.join().unwrap();

        // Assert — the final file is one of two valid single-write final
        // states: whichever writer ran second sees the other's mutation
        // in the loaded prefs and overwrites only its own field.
        let (final_prefs, _) = load_desktop_prefs(&base);

        // Regardless of ordering: both fields must be at the state left
        // by whichever writer ran LAST — the lock prevents any torn write.
        // The only valid final states are:
        //   - A ran last: hide=true, dashboard=false (A saw B's dashboard=false, flipped hide)
        //   - B ran last: hide=true, dashboard=false (B saw A's hide=true, flipped dashboard)
        // Both orderings converge to the same final state in this test!
        assert!(
            final_prefs.hide_dock_icon,
            "hide_dock_icon must be true regardless of A/B ordering"
        );
        assert!(
            !final_prefs.dashboard_at_launch,
            "dashboard_at_launch must be false regardless of A/B ordering"
        );
    }

    #[test]
    #[cfg(unix)]
    fn mutate_prefs_returns_save_failure_on_unwriteable_dir() {
        // Arrange — create a base dir and then remove write permission.
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        // Make the dir read-execute only (no write).
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let lock = PrefsLock::new();

        // Act
        let result = mutate_prefs(&lock, dir.path(), |p| {
            p.hide_dock_icon = true;
        });

        // Restore permissions so TempDir cleanup can delete it.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).ok();

        // Assert
        assert!(
            result.is_err(),
            "mutate_prefs must propagate save failure when the base dir is unwriteable"
        );
    }

    #[test]
    fn prefs_lock_recovers_from_poison() {
        // Arrange — spawn a thread that panics while holding the guard.
        use std::sync::Arc;
        let lock = Arc::new(PrefsLock::new());
        let lock_clone = Arc::clone(&lock);

        let handle = std::thread::spawn(move || {
            let _guard = lock_clone.lock();
            panic!("intentional panic to poison the mutex");
        });
        // The thread panics — join returns Err but that's expected.
        let _ = handle.join();

        // Act — acquire the lock on the now-poisoned mutex.
        // PrefsLock::lock() must recover via unwrap_or_else(into_inner).
        let _guard = lock.lock(); // must not panic

        // Assert — if we reach here, poison recovery worked.
        // The recovered guard can be used normally.
        drop(_guard);
    }

    // ── LoadOutcome tests (an internal ticket) ───────────────────────────────
    //
    // These six tests assert the tagged outcome returned by
    // `load_desktop_prefs`, covering each distinct code-path so the
    // renderer's corruption-disclosure banner has a tested invariant
    // for every case it may fire on.

    #[test]
    fn load_returns_fresh_outcome_on_missing_file() {
        // Arrange
        let dir = TempDir::new().unwrap();
        // no desktop-prefs.json written

        // Act
        let (prefs, outcome) = load_desktop_prefs(dir.path());

        // Assert
        assert_eq!(prefs, DesktopPrefs::default());
        assert_eq!(
            outcome,
            LoadOutcome::Fresh,
            "missing file (fresh install) must return Fresh, not RecoveredFromCorrupt"
        );
    }

    #[test]
    fn load_returns_fresh_outcome_on_clean_file() {
        // Arrange
        let dir = TempDir::new().unwrap();
        save_desktop_prefs(
            dir.path(),
            &DesktopPrefs {
                hide_dock_icon: true,
                dashboard_at_launch: false,
            },
        )
        .unwrap();

        // Act
        let (prefs, outcome) = load_desktop_prefs(dir.path());

        // Assert
        assert_eq!(
            prefs,
            DesktopPrefs {
                hide_dock_icon: true,
                dashboard_at_launch: false,
            }
        );
        assert_eq!(outcome, LoadOutcome::Fresh, "clean file must return Fresh");
    }

    #[test]
    fn load_returns_recovered_outcome_on_invalid_json() {
        // Arrange
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(DESKTOP_PREFS_FILE), "{ not valid json,").unwrap();

        // Act
        let (prefs, outcome) = load_desktop_prefs(dir.path());

        // Assert
        assert_eq!(prefs, DesktopPrefs::default());
        assert_eq!(
            outcome,
            LoadOutcome::RecoveredFromCorrupt("desktop_prefs_parse_value"),
            "invalid JSON must return RecoveredFromCorrupt(desktop_prefs_parse_value)"
        );
    }

    #[test]
    fn load_returns_recovered_outcome_on_non_object_top_level() {
        // Arrange
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(DESKTOP_PREFS_FILE), "[1,2,3]").unwrap();

        // Act
        let (prefs, outcome) = load_desktop_prefs(dir.path());

        // Assert
        assert_eq!(prefs, DesktopPrefs::default());
        assert_eq!(
            outcome,
            LoadOutcome::RecoveredFromCorrupt("desktop_prefs_top_level"),
            "non-object top-level must return RecoveredFromCorrupt(desktop_prefs_top_level)"
        );
    }

    #[test]
    fn load_returns_recovered_outcome_on_empty_file() {
        // Arrange
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(DESKTOP_PREFS_FILE), "").unwrap();

        // Act
        let (prefs, outcome) = load_desktop_prefs(dir.path());

        // Assert
        assert_eq!(prefs, DesktopPrefs::default());
        assert_eq!(
            outcome,
            LoadOutcome::RecoveredFromCorrupt("desktop_prefs_empty"),
            "empty file must return RecoveredFromCorrupt(desktop_prefs_empty), \
             not Fresh (file existed but was truncated)"
        );
    }

    #[test]
    fn load_returns_recovered_outcome_on_wrong_type_field() {
        // Arrange
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(DESKTOP_PREFS_FILE),
            r#"{"hide_dock_icon": "yes"}"#,
        )
        .unwrap();

        // Act
        let (prefs, outcome) = load_desktop_prefs(dir.path());

        // Assert — hide_dock_icon stripped (non-boolean) → falls back to serde
        // default false. dashboard_at_launch missing + hide_dock_icon was true
        // in the original file, but since "yes" was stripped hide_dock_icon is
        // false → no migration fires → dashboard_at_launch stays at default true.
        // LOW-2: the strip-success path now returns the distinct tag
        // `desktop_prefs_field_stripped` (not `desktop_prefs_parse_typed`, which
        // is reserved for the typed-deserialize-fail path where from_value fails).
        assert!(!prefs.hide_dock_icon);
        assert_eq!(
            outcome,
            LoadOutcome::RecoveredFromCorrupt("desktop_prefs_field_stripped"),
            "wrong-type field (strip-success) must return RecoveredFromCorrupt(\
             desktop_prefs_field_stripped), distinct from the typed-deserialize-fail tag"
        );
    }

    /// The `desktop_prefs_parse_typed` tag is returned when `from_value`
    /// fails AFTER stripping. With the current two-field struct (both
    /// fields are `bool` with serde defaults — see `BOOL_FIELDS`), this
    /// path is structurally unreachable: stripping removes non-boolean
    /// values, the per-field `#[serde(default)]` fills any missing key,
    /// and `from_value` always succeeds. The path exists for
    /// future-proofing — a future non-bool field WITHOUT a serde default
    /// would land here.
    ///
    /// This is marked `#[ignore]` per `rules/testing.md` and /redteam R2
    /// testing-specialist MED-1: an `#[ignore]`-d test with a directed
    /// message is visible in `cargo test --ignored` output, where a
    /// passing-but-vacuous test silently inflates coverage counts and
    /// reads as system-behavior coverage that it does not provide. If
    /// the struct shape changes to add a non-bool field without a
    /// serde default, remove the `#[ignore]` AND write a real fixture
    /// that exercises the from_value-fail path.
    #[test]
    #[ignore = "typed_deserialize_fail path is unreachable while all DesktopPrefs fields have serde defaults — re-enable when a non-bool no-default field lands"]
    fn typed_deserialize_fail_path_is_currently_unreachable_by_construction() {
        // Intentionally no assertion. The compile-time reachability of
        // `LoadOutcome::RecoveredFromCorrupt("desktop_prefs_parse_typed")`
        // is the structural invariant; the runtime fixture cannot
        // exercise it with the current struct shape.
    }
}
