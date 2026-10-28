//! One-shot migration of Kimi settings off the retired csq default model.
//!
//! csq's Kimi default moved from `kimi-k3[1m]` to `k3.1-pro[1m]` (K3.1 Pro).
//! A slot or the global `settings-kimi.json` profile whose model fields ALL
//! still hold the old csq default is moved to the new one; a file carrying
//! any other model value is a user choice and is left untouched.
//!
//! # Scope
//!
//! Both slot write paths (`write_slot_model_with_uuid_routing` writes one or
//! the other, so either can be the live copy) plus the global profile:
//!
//! - `<base>/identities/<UUID>/settings.json` (Phase 2 canonical),
//! - `<base>/config-<N>/settings.json` (legacy),
//! - `<base>/settings-kimi.json`.
//!
//! A slot file is Kimi only when its `env.ANTHROPIC_BASE_URL` is the Kimi
//! provider's base URL; the global profile is Kimi by name.
//!
//! # Invariants
//!
//! - Key order and formatting are preserved: the edit is made in place on
//!   the file's text (`edit_in_place`) and kept only when re-parsing it
//!   yields exactly the intended value; otherwise the value is re-serialised
//!   (values still exact, order then follows `serde_json`'s map). The binary
//!   graph does not reliably enable `serde_json/preserve_order` (a plain
//!   `-p csq-core` build has it off), and enabling it workspace-wide would
//!   change every other crate's JSON output order.
//! - Only the model keys ([`MODEL_KEYS`] + `CLAUDE_CODE_SUBAGENT_MODEL`) and
//!   an absent `CLAUDE_CODE_MAX_CONTEXT_TOKENS` are written; every other key
//!   is carried through the parsed value unchanged.
//! - Writes go through the shared §5a writer
//!   (`write_settings_json_private`), which removes its tmp file on every
//!   failure branch.
//! - One-shot: after the first pass that held the profiles lock (and met no
//!   residency refusal), the [`MARKER_FILENAME`] marker is written and the migration
//!   never runs again, so a later deliberate switch back to `kimi-k3[1m]`
//!   is kept. Before the marker exists a re-run is a no-op for every file
//!   already migrated (it now holds the new default).
//! - Fail-closed: each file is read and rewritten under its `<file>.lock`
//!   (the lock `csq setkey` holds); an unavailable lock, or an unreadable,
//!   oversized, malformed, symlinked or FIFO file, is left as it is and
//!   logged; the migration never aborts the caller.
//! - Logs carry fixed event tags and a location class only — never a model
//!   value, a path, or any other settings content.
//!
//! Callers: `csq run` launch and daemon start. Never the statusline path.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use tracing::{info, warn};

use super::merge::MODEL_KEYS;
use super::settings::{write_settings_bytes_private, write_settings_json_private};

/// The retired csq Kimi default.
pub const OLD_KIMI_DEFAULT: &str = "kimi-k3[1m]";
/// The current csq Kimi default (K3.1 Pro, 1M context).
pub const NEW_KIMI_DEFAULT: &str = "k3.1-pro[1m]";
const SUBAGENT_KEY: &str = "CLAUDE_CODE_SUBAGENT_MODEL";
const MAX_CONTEXT_KEY: &str = "CLAUDE_CODE_MAX_CONTEXT_TOKENS";
const MAX_CONTEXT_1M: &str = "1048576";
const KIMI_SETTINGS_FILENAME: &str = "settings-kimi.json";

/// What happened to one settings file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Model fields moved to [`NEW_KIMI_DEFAULT`].
    Migrated,
    /// Already on the new default (or no model keys): nothing written.
    Current,
    /// A model field holds a user choice: nothing written.
    SkippedCustom,
    /// Not a Kimi slot: nothing written.
    NotKimi,
    /// Read but not valid UTF-8 JSON: permanently skipped, left as is.
    LeftUntouched,
    /// The file's settings lock was held by another writer: left as is, a
    /// permanent skip that does not hold the marker back (that writer is
    /// rewriting the file; the user can still switch it explicitly).
    Locked,
    /// The rewrite failed: left as is; a permanent skip (no marker hold).
    WriteFailed,
    /// Any read error, or a lock that cannot be used at all (not
    /// contention): permanently skipped; does not hold the marker back.
    ReadSkipped,
}

/// Per-run counts, for callers and tests. Carries no settings content.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub migrated: usize,
    pub skipped_custom: usize,
    pub left_untouched: usize,
    pub locked: usize,
    /// The profiles lock was contended: nothing was touched and no marker
    /// was written, so the next launch runs the pass.
    pub profiles_locked: bool,
    pub write_failed: usize,
    /// Files permanently skipped because they could not be read (or their
    /// lock could not be used at all). Does not hold the marker back.
    pub read_skipped: usize,
    /// The enterprise residency policy refused Kimi settings writes.
    pub residency_refused: bool,
}

#[derive(Clone, Copy)]
enum Location {
    Identity,
    Legacy,
    Global,
}

impl Location {
    fn tag(self) -> &'static str {
        match self {
            Location::Identity => "identity",
            Location::Legacy => "legacy",
            Location::Global => "global",
        }
    }
}

/// Runs the migration over every Kimi settings file under `base_dir`.
/// One-shot marker, `<base>/.kimi-k31-migration-done`. Written (privately,
/// atomically; content not secret) after the first pass that met no lock
/// contention and no residency refusal; while it exists the migration never runs
/// again. Without it a slot the user deliberately switched back to
/// `kimi-k3[1m]` (`csq models switch kimi kimi-k3`) would be indistinguishable
/// from an unmigrated one and re-migrated on every launch.
pub const MARKER_FILENAME: &str = ".kimi-k31-migration-done";

pub fn migrate_kimi_default_model(base_dir: &Path) -> Summary {
    migrate_with_reader(
        base_dir,
        &crate::platform::fs::read_regular_nofollow_bounded,
    )
}

/// [`migrate_kimi_default_model`] with the file reader injected — the test
/// seam that produces EACCES / EIO deterministically (a mode-000 file is
/// readable to a privileged runner, so it cannot prove the error path).
fn migrate_with_reader<R>(base_dir: &Path, read: &R) -> Summary
where
    R: Fn(&Path, u64) -> std::io::Result<Option<Vec<u8>>>,
{
    let mut summary = Summary::default();
    if !base_dir.is_dir() {
        return summary;
    }
    let marker = base_dir.join(MARKER_FILENAME);
    if std::fs::symlink_metadata(&marker).is_ok() {
        return summary;
    }
    // C-M2: the enterprise residency-policy gate
    // that the global-profile writers (`save_settings` / `update_settings`,
    // via `prepare_global_write`) and the per-slot bind
    // (`accounts::third_party::bind_provider_to_slot`) apply. NOT every Kimi
    // settings writer passes it: the slot model switch
    // (`write_slot_model_with_uuid_routing`), the pass-0 identity catch-up and
    // the legacy apiKeyHelper strip rewrite an already-bound slot and do not
    // gate. This pass gates both its slot and global writes. Refused ->
    // nothing is written and no marker, so a later policy change still lets
    // the pass run. Community builds carry no gate.
    #[cfg(feature = "enterprise")]
    if crate::edition_ext::residency::enforce_provider_write(base_dir, "kimi").is_err() {
        warn!(
            event = "kimi_model_migration_residency_refused",
            "kimi model migration: residency policy refuses Kimi settings writes; nothing touched"
        );
        summary.residency_refused = true;
        return summary;
    }
    // Lock order is setkey's (accounts::third_party PD-3): ProfilesFileLock
    // FIRST, then each file's `<file>.lock`. Held for the whole pass, so the
    // slot -> UUID routing and every file read below are a consistent view.
    let _profiles = match crate::accounts::profiles_lock::ProfilesFileLock::acquire(base_dir) {
        Ok(guard) => guard,
        Err(_) => {
            warn!(
                event = "kimi_model_migration_locked",
                location = "profiles",
                "kimi model migration: profiles lock unavailable; nothing touched"
            );
            summary.locked += 1;
            summary.profiles_locked = true;
            return summary;
        }
    };
    for (location, path) in candidate_files(base_dir) {
        match migrate_file(&path, location, read) {
            Outcome::Migrated => summary.migrated += 1,
            Outcome::SkippedCustom => summary.skipped_custom += 1,
            Outcome::LeftUntouched => summary.left_untouched += 1,
            Outcome::Locked => summary.locked += 1,
            Outcome::WriteFailed => summary.write_failed += 1,
            Outcome::ReadSkipped => summary.read_skipped += 1,
            Outcome::Current | Outcome::NotKimi => {}
        }
    }
    // Only a contended profiles lock or a residency refusal (both returned
    // above, before any file was touched) hold the marker back. Every
    // per-file outcome, including per-file lock contention, is final: a
    // retry would re-migrate every OTHER file on the next launch and undo a
    // deliberate switch made in between (C-H1).
    write_marker(&marker);
    summary
}

fn write_marker(marker: &Path) {
    let tmp = crate::platform::fs::unique_tmp_path(marker);
    let written = crate::platform::fs::write_new_private(&tmp, b"1\n")
        .map_err(|_| ())
        .and_then(|()| crate::platform::fs::atomic_replace(&tmp, marker).map_err(|_| ()));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
        warn!(
            event = "kimi_model_migration_marker_write_failed",
            "kimi model migration: one-shot marker not written; the next launch re-runs it"
        );
    }
}

fn candidate_files(base_dir: &Path) -> Vec<(Location, PathBuf)> {
    let mut out = Vec::new();
    let identities = crate::accounts::identity_store::identities_dir(base_dir);
    for name in dir_names(&identities) {
        if name
            .parse::<crate::accounts::identity_store::IdentityId>()
            .is_ok()
        {
            out.push((
                Location::Identity,
                identities.join(name).join("settings.json"),
            ));
        }
    }
    for name in dir_names(base_dir) {
        let is_slot = name
            .strip_prefix("config-")
            .and_then(|n| n.parse::<u16>().ok())
            .is_some_and(|n| crate::types::AccountNum::try_from(n).is_ok());
        if is_slot {
            out.push((Location::Legacy, base_dir.join(name).join("settings.json")));
        }
    }
    out.push((Location::Global, base_dir.join(KIMI_SETTINGS_FILENAME)));
    out
}

/// Directory entry names under `dir`; an absent or unreadable directory
/// yields none (a missing `identities/` is the normal pre-Phase-2 state).
fn dir_names(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .collect()
}

/// Upper bound on a settings file the migration will read (a real slot
/// `settings.json` is a few KiB).
const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;

fn migrate_file<R>(path: &Path, location: Location, read: &R) -> Outcome
where
    R: Fn(&Path, u64) -> std::io::Result<Option<Vec<u8>>>,
{
    let loc = location.tag();
    // Cheap absence short-circuit so an absent file never gains a lock file.
    // NOT a type check: the regular-file / no-symlink check runs on the
    // opened handle below, inside the lock.
    if matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        return Outcome::NotKimi;
    }
    // H1: the same lock `csq setkey` / bind / unbind hold for their RMW of
    // this file (`<file>.lock`, accounts::third_party), held across the whole
    // read -> classify -> write span, so a concurrent re-key can never be
    // overwritten by this migration's stale copy. Expiry or error leaves the
    // file untouched (fail closed).
    let _lock = match crate::platform::lock::lock_credential_file(&path.with_extension("lock")) {
        Ok(Some(guard)) => guard,
        // Contention: another writer is rewriting this file right now. A
        // permanent skip (see `migrate_with_reader`): the file keeps its
        // current, working model.
        Ok(None) => {
            warn!(
                event = "kimi_model_migration_locked",
                location = loc,
                "kimi model migration: settings lock held by another writer; file left as is"
            );
            return Outcome::Locked;
        }
        // Not contention (the lock file cannot be opened / locked at all):
        // a permanent skip of this file; it does not hold the marker back.
        Err(_) => {
            warn!(
                event = "kimi_model_migration_lock_skipped",
                location = loc,
                "kimi model migration: settings lock unusable; file permanently skipped"
            );
            return Outcome::ReadSkipped;
        }
    };
    // M1: one handle-checked read — no symlink follow, no FIFO block, bounded.
    // EVERY read error (EACCES, EIO, a Windows folder's PermissionDenied,
    // ELOOP for a symlink, InvalidData for a FIFO / non-regular / oversized
    // file) is a PERMANENT skip of this file and does not hold the marker
    // back: only lock contention and a residency refusal do. Holding it back
    // for a read error re-runs the pass on every launch and re-migrates
    // every OTHER file, undoing deliberate switches (C-H1).
    let raw = match read(path, MAX_SETTINGS_BYTES) {
        Ok(None) => return Outcome::NotKimi,
        Ok(Some(bytes)) => String::from_utf8(bytes).ok(),
        Err(e) => {
            warn!(
                event = "kimi_model_migration_read_skipped",
                location = loc,
                error_kind = read_error_kind(&e),
                "kimi model migration: settings file could not be read; permanently skipped"
            );
            return Outcome::ReadSkipped;
        }
    };
    let parsed = raw
        .as_deref()
        .and_then(|c| serde_json::from_str::<Value>(c).ok());
    let (Some(raw), Some(mut value)) = (raw, parsed) else {
        warn!(
            event = "kimi_model_migration_malformed",
            location = loc,
            "kimi model migration: settings file is not valid UTF-8 JSON; permanently skipped"
        );
        return Outcome::LeftUntouched;
    };
    let Some(env) = value.get_mut("env").and_then(Value::as_object_mut) else {
        // A slot file with no env block is not a Kimi slot; a global profile
        // with none has nothing to migrate.
        return Outcome::NotKimi;
    };
    if matches!(location, Location::Identity | Location::Legacy)
        && !super::merge::is_kimi_endpoint(env)
    {
        return Outcome::NotKimi;
    }
    let outcome = classify(env);
    if outcome != Outcome::Migrated {
        if outcome == Outcome::SkippedCustom {
            info!(
                event = "kimi_model_migration_skipped_custom",
                location = loc,
                "kimi model migration: custom model kept"
            );
        }
        return outcome;
    }
    let had_max_context = env.contains_key(MAX_CONTEXT_KEY);
    apply(env);
    let written = match edit_in_place(&raw, had_max_context, &value) {
        Some(edited) => write_settings_bytes_private(path, edited.as_bytes()),
        None => write_settings_json_private(path, &value),
    };
    match written {
        Ok(()) => {
            info!(
                event = "kimi_model_migrated",
                location = loc,
                "kimi model migration: moved to the K3.1 Pro default"
            );
            Outcome::Migrated
        }
        Err(_) => {
            warn!(
                event = "kimi_model_migration_write_failed",
                location = loc,
                "kimi model migration: write failed; left untouched"
            );
            Outcome::WriteFailed
        }
    }
}

/// Fixed-vocabulary label for a read error (never the OS message).
fn read_error_kind(e: &std::io::Error) -> &'static str {
    #[cfg(unix)]
    if e.raw_os_error() == Some(libc::ELOOP) {
        return "symlink";
    }
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => "permission_denied",
        std::io::ErrorKind::InvalidData => "not_regular_or_oversized",
        std::io::ErrorKind::WouldBlock => "would_block",
        std::io::ErrorKind::Interrupted => "interrupted",
        _ => "io_error",
    }
}

fn model_keys() -> impl Iterator<Item = &'static str> {
    MODEL_KEYS
        .iter()
        .copied()
        .chain(std::iter::once(SUBAGENT_KEY))
}

/// `Migrated` only when every PRESENT model key holds the old csq default
/// (and `ANTHROPIC_MODEL` is present). A non-string value is a custom value.
fn classify(env: &Map<String, Value>) -> Outcome {
    let present: Vec<Option<&str>> = model_keys()
        .filter_map(|k| env.get(k))
        .map(Value::as_str)
        .collect();
    if present.is_empty() || !env.contains_key("ANTHROPIC_MODEL") {
        return Outcome::Current;
    }
    if present.iter().all(|v| *v == Some(OLD_KIMI_DEFAULT)) {
        Outcome::Migrated
    } else if present.iter().all(|v| *v == Some(NEW_KIMI_DEFAULT)) {
        Outcome::Current
    } else {
        Outcome::SkippedCustom
    }
}

fn apply(env: &mut Map<String, Value>) {
    for key in model_keys() {
        if env.contains_key(key) {
            env.insert(key.to_string(), Value::String(NEW_KIMI_DEFAULT.to_string()));
        }
    }
    if !env.contains_key(MAX_CONTEXT_KEY) {
        env.insert(
            MAX_CONTEXT_KEY.to_string(),
            Value::String(MAX_CONTEXT_1M.to_string()),
        );
    }
}

/// Rewrites the model values in the file's own text, so key order,
/// indentation and every other byte survive. Each model key must occur
/// exactly once as `"KEY": "kimi-k3[1m]"`; a missing max-context key is
/// inserted before `"ANTHROPIC_MODEL"` with that line's indentation. The
/// result is kept only when it parses to exactly `expected`; any doubt
/// returns `None` (the caller then re-serialises).
fn edit_in_place(raw: &str, had_max_context: bool, expected: &Value) -> Option<String> {
    let old_lit = format!("\"{OLD_KIMI_DEFAULT}\"");
    let new_lit = format!("\"{NEW_KIMI_DEFAULT}\"");
    let mut text = raw.to_string();
    for key in model_keys() {
        if expected["env"].get(key).is_none() {
            continue;
        }
        let quoted = format!("\"{key}\"");
        if text.matches(&quoted).count() != 1 {
            return None;
        }
        let at = text.find(&quoted)? + quoted.len();
        let rest = &text[at..];
        let after_colon = rest.trim_start().strip_prefix(':')?;
        let value_at = at + (rest.len() - after_colon.trim_start().len());
        if !text[value_at..].starts_with(&old_lit) {
            return None;
        }
        text.replace_range(value_at..value_at + old_lit.len(), &new_lit);
    }
    if !had_max_context {
        let anchor = "\"ANTHROPIC_MODEL\"";
        if text.matches(anchor).count() != 1 {
            return None;
        }
        let at = text.find(anchor)?;
        let line_start = text[..at].rfind('\n').map_or(0, |i| i + 1);
        let indent = &text[line_start..at];
        let sep = if indent.chars().all(char::is_whitespace) && !indent.is_empty() {
            // Keep the file's own line ending (CRLF stays CRLF).
            let eol = if text[..line_start].ends_with("\r\n") {
                "\r\n"
            } else {
                "\n"
            };
            format!("{eol}{indent}")
        } else {
            " ".to_string()
        };
        // The new key takes the anchor's line; the anchor moves to the next
        // line at the same indent.
        let insert = format!("\"{MAX_CONTEXT_KEY}\": \"{MAX_CONTEXT_1M}\",{sep}");
        text.insert_str(at, &insert);
    }
    (serde_json::from_str::<Value>(&text).ok()? == *expected).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// The real pre-K3.1 csq Kimi slot shape (`default_settings` for the
    /// `kimi` provider before 828b54b5b): all tiers + subagent on the old
    /// default, base URL, auth token, the docs-mandated extra env.
    fn old_default_slot() -> Value {
        serde_json::json!({
            "env": {
                "ANTHROPIC_BASE_URL": "https://api.kimi.com/coding",
                "ANTHROPIC_AUTH_TOKEN": "fixture-not-a-key",
                "ANTHROPIC_MODEL": OLD_KIMI_DEFAULT,
                "ANTHROPIC_DEFAULT_OPUS_MODEL": OLD_KIMI_DEFAULT,
                "ANTHROPIC_DEFAULT_SONNET_MODEL": OLD_KIMI_DEFAULT,
                "ANTHROPIC_DEFAULT_HAIKU_MODEL": OLD_KIMI_DEFAULT,
                "ANTHROPIC_SMALL_FAST_MODEL": OLD_KIMI_DEFAULT,
                "ENABLE_TOOL_SEARCH": "false",
                "CLAUDE_CODE_AUTO_COMPACT_WINDOW": "1048576",
                "CLAUDE_CODE_EFFORT_LEVEL": "high",
                "CLAUDE_CODE_SUBAGENT_MODEL": OLD_KIMI_DEFAULT
            },
            "statusLine": {"type": "command", "command": "csq statusline"}
        })
    }

    fn write(path: &Path, v: &Value) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_vec_pretty(v).unwrap()).unwrap();
    }

    fn read(path: &Path) -> Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn expected_migrated() -> Value {
        let mut v = old_default_slot();
        for key in model_keys() {
            v["env"][key] = Value::String(NEW_KIMI_DEFAULT.into());
        }
        v["env"][MAX_CONTEXT_KEY] = Value::String(MAX_CONTEXT_1M.into());
        v
    }

    fn uuid_dir(base: &Path) -> PathBuf {
        crate::accounts::identity_store::identities_dir(base)
            .join("0b9b6a52-1c1f-4e2e-9a49-6f7f2d1c3a10")
    }

    #[test]
    fn default_valued_slots_migrate_on_both_paths_and_the_global_profile() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let legacy = base.join("config-3").join("settings.json");
        let identity = uuid_dir(base).join("settings.json");
        let global = base.join(KIMI_SETTINGS_FILENAME);
        for p in [&legacy, &identity, &global] {
            write(p, &old_default_slot());
        }
        let s = migrate_kimi_default_model(base);
        assert_eq!(s.migrated, 3, "{s:?}");
        for p in [&legacy, &identity, &global] {
            assert_eq!(read(p), expected_migrated(), "{}", p.display());
        }
    }

    /// Hand-ordered, non-alphabetical keys and the file's own formatting
    /// survive: only the model values change and the max-context line is
    /// inserted above `ANTHROPIC_MODEL`.
    #[test]
    fn migration_preserves_key_order_and_formatting() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config-7").join("settings.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let before = "{\n  \"statusLine\": {\"type\": \"command\", \"command\": \"csq statusline\"},\n  \"env\": {\n    \"ANTHROPIC_BASE_URL\": \"https://api.kimi.com/coding\",\n    \"ZZ_FIRST\": \"1\",\n    \"ANTHROPIC_MODEL\": \"kimi-k3[1m]\",\n    \"ANTHROPIC_DEFAULT_OPUS_MODEL\":\"kimi-k3[1m]\",\n    \"CLAUDE_CODE_SUBAGENT_MODEL\" : \"kimi-k3[1m]\",\n    \"AA_LAST\": \"2\"\n  },\n  \"effortLevel\": \"high\"\n}\n";
        std::fs::write(&path, before).unwrap();
        assert_eq!(migrate_kimi_default_model(dir.path()).migrated, 1);
        let after = "{\n  \"statusLine\": {\"type\": \"command\", \"command\": \"csq statusline\"},\n  \"env\": {\n    \"ANTHROPIC_BASE_URL\": \"https://api.kimi.com/coding\",\n    \"ZZ_FIRST\": \"1\",\n    \"CLAUDE_CODE_MAX_CONTEXT_TOKENS\": \"1048576\",\n    \"ANTHROPIC_MODEL\": \"k3.1-pro[1m]\",\n    \"ANTHROPIC_DEFAULT_OPUS_MODEL\":\"k3.1-pro[1m]\",\n    \"CLAUDE_CODE_SUBAGENT_MODEL\" : \"k3.1-pro[1m]\",\n    \"AA_LAST\": \"2\"\n  },\n  \"effortLevel\": \"high\"\n}\n";
        assert_eq!(std::fs::read_to_string(&path).unwrap(), after);
    }

    /// C-L1: a CRLF file stays CRLF, including the inserted line.
    #[test]
    fn migration_keeps_crlf_line_endings() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config-7").join("settings.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let before = "{\r\n  \"env\": {\r\n    \"ANTHROPIC_BASE_URL\": \"https://api.kimi.com/coding\",\r\n    \"ANTHROPIC_MODEL\": \"kimi-k3[1m]\"\r\n  }\r\n}\r\n";
        std::fs::write(&path, before).unwrap();
        assert_eq!(migrate_kimi_default_model(dir.path()).migrated, 1);
        let after = "{\r\n  \"env\": {\r\n    \"ANTHROPIC_BASE_URL\": \"https://api.kimi.com/coding\",\r\n    \"CLAUDE_CODE_MAX_CONTEXT_TOKENS\": \"1048576\",\r\n    \"ANTHROPIC_MODEL\": \"k3.1-pro[1m]\"\r\n  }\r\n}\r\n";
        assert_eq!(std::fs::read_to_string(&path).unwrap(), after);
    }

    #[test]
    fn a_present_max_context_value_is_kept() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config-1").join("settings.json");
        let mut v = old_default_slot();
        v["env"][MAX_CONTEXT_KEY] = Value::String("524288".into());
        write(&path, &v);
        assert_eq!(migrate_kimi_default_model(dir.path()).migrated, 1);
        assert_eq!(read(&path)["env"][MAX_CONTEXT_KEY], "524288");
        assert_eq!(read(&path)["env"]["ANTHROPIC_MODEL"], NEW_KIMI_DEFAULT);
    }

    #[test]
    fn a_mixed_or_custom_slot_is_untouched() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let mut mixed = old_default_slot();
        mixed["env"]["ANTHROPIC_DEFAULT_HAIKU_MODEL"] = Value::String("kimi-k3".into());
        let mut custom = old_default_slot();
        for key in model_keys() {
            custom["env"][key] = Value::String("k3".into());
        }
        let mut non_string = old_default_slot();
        non_string["env"][SUBAGENT_KEY] = Value::Null;
        let cases = [
            ("config-1", mixed),
            ("config-2", custom),
            ("config-4", non_string),
        ];
        for (d, v) in &cases {
            write(&base.join(d).join("settings.json"), v);
        }
        let before: Vec<Vec<u8>> = cases
            .iter()
            .map(|(d, _)| std::fs::read(base.join(d).join("settings.json")).unwrap())
            .collect();
        let s = migrate_kimi_default_model(base);
        assert_eq!(s.skipped_custom, 3, "{s:?}");
        assert_eq!(s.migrated, 0);
        for ((d, _), bytes) in cases.iter().zip(before) {
            assert_eq!(
                std::fs::read(base.join(d).join("settings.json")).unwrap(),
                bytes,
                "{d}"
            );
        }
    }

    #[test]
    fn a_non_kimi_slot_on_the_old_model_string_is_untouched() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config-2").join("settings.json");
        let mut v = old_default_slot();
        v["env"]["ANTHROPIC_BASE_URL"] = Value::String("https://api.z.ai/api/anthropic".into());
        write(&path, &v);
        let before = std::fs::read(&path).unwrap();
        assert_eq!(migrate_kimi_default_model(dir.path()), Summary::default());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn running_twice_is_a_no_op() {
        // The marker makes the second run return immediately; the files'
        // own idempotence is covered by removing it first.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config-5").join("settings.json");
        write(&path, &old_default_slot());
        assert_eq!(migrate_kimi_default_model(dir.path()).migrated, 1);
        let once = std::fs::read(&path).unwrap();
        assert_eq!(migrate_kimi_default_model(dir.path()), Summary::default());
        assert_eq!(std::fs::read(&path).unwrap(), once);
        std::fs::remove_file(dir.path().join(MARKER_FILENAME)).unwrap();
        assert_eq!(migrate_kimi_default_model(dir.path()), Summary::default());
        assert_eq!(std::fs::read(&path).unwrap(), once);
    }

    /// Malformed JSON is a permanent skip: the file is untouched and the
    /// marker is still written.
    #[test]
    fn a_malformed_file_is_skipped_permanently_and_the_marker_is_written() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let malformed = base.join("config-1").join("settings.json");
        std::fs::create_dir_all(malformed.parent().unwrap()).unwrap();
        let bytes = b"{\"env\": {\"ANTHROPIC_MODEL\": \"kimi-k3[1m]\"";
        std::fs::write(&malformed, bytes).unwrap();
        let s = migrate_kimi_default_model(base);
        assert_eq!(s.left_untouched, 1, "{s:?}");
        assert_eq!(s.read_skipped, 0);
        assert_eq!(std::fs::read(&malformed).unwrap(), bytes);
        assert!(base.join(MARKER_FILENAME).is_file());
    }

    /// A directory where the file should be is a permanent skip: untouched,
    /// and the marker is still written. Portable: unix reports InvalidData
    /// (fstat on the opened handle), Windows PermissionDenied (a folder
    /// cannot be opened as a file); both are read errors -> read_skipped.
    #[test]
    fn a_non_regular_settings_path_is_skipped_permanently_and_the_marker_is_written() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let not_file = base.join("config-2").join("settings.json");
        std::fs::create_dir_all(&not_file).unwrap();
        let s = migrate_kimi_default_model(base);
        assert_eq!(s.read_skipped, 1, "{s:?}");
        assert!(not_file.is_dir());
        assert!(base.join(MARKER_FILENAME).is_file());
    }

    /// COR MED-1/2: EVERY read error is a permanent per-file skip that does
    /// NOT hold the marker back — injected through the reader seam, so it
    /// cannot pass vacuously on a privileged runner where mode 000 is
    /// readable. The other, readable slot still migrates.
    #[test]
    fn every_read_error_is_a_permanent_skip_and_the_marker_is_written() {
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::Other, // EIO-class
            std::io::ErrorKind::InvalidData,
        ] {
            let dir = TempDir::new().unwrap();
            let base = dir.path();
            let failing = base.join("config-2").join("settings.json");
            write(&failing, &old_default_slot());
            let readable = base.join("config-3").join("settings.json");
            write(&readable, &old_default_slot());
            let before = std::fs::read(&failing).unwrap();
            let reader = |p: &Path, max: u64| {
                if p == failing.as_path() {
                    Err(std::io::Error::from(kind))
                } else {
                    crate::platform::fs::read_regular_nofollow_bounded(p, max)
                }
            };
            let s = migrate_with_reader(base, &reader);
            assert_eq!((s.read_skipped, s.migrated), (1, 1), "{kind:?}: {s:?}");
            assert_eq!(std::fs::read(&failing).unwrap(), before, "{kind:?}");
            assert!(
                base.join(MARKER_FILENAME).is_file(),
                "{kind:?}: marker held back"
            );
        }
    }

    /// C-H1 with a symlinked slot present: the first pass migrates the
    /// regular slot, refuses the symlink permanently and writes the marker;
    /// a later deliberate switch of the regular slot back to `kimi-k3[1m]`
    /// stays byte-identical on the next launch.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_slot_does_not_reopen_re_migration_of_a_switched_slot() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let target = base.join("real.json");
        write(&target, &old_default_slot());
        let link = base.join("config-1").join("settings.json");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let regular = base.join("config-2").join("settings.json");
        write(&regular, &old_default_slot());
        let s = migrate_kimi_default_model(base);
        assert_eq!((s.migrated, s.read_skipped), (1, 1), "{s:?}");
        assert!(base.join(MARKER_FILENAME).is_file());
        write(&regular, &old_default_slot()); // the user's deliberate switch back
        let before = std::fs::read(&regular).unwrap();
        assert_eq!(migrate_kimi_default_model(base), Summary::default());
        assert_eq!(std::fs::read(&regular).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_settings_file_is_never_replaced() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("real.json");
        write(&target, &old_default_slot());
        let link = dir.path().join("config-6").join("settings.json");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let before = std::fs::read(&target).unwrap();
        assert_eq!(migrate_kimi_default_model(dir.path()).read_skipped, 1);
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), before);
    }

    /// C-M2: an EU-only residency policy refuses Kimi settings writes, so the
    /// migration leaves the global profile and every slot byte-identical and
    /// writes no marker.
    #[cfg(feature = "enterprise")]
    #[test]
    fn a_residency_refusal_leaves_every_file_unchanged_and_no_marker() {
        let dir = TempDir::new().unwrap();
        let gate = serde_json::json!({
            "provider": "claude",
            "schema": { "type": "object" },
            "max_tokens": 1024,
            "envelope": {
                "version": "1.3", "role": "D1-R1",
                "allowed_operations": [], "denied_operations": [], "require_approval_for": [],
                "declared_posture": "autonomous", "posture_floor": "supervised",
                "data_access": { "model_residency": {
                    "policy_name": "eu-only", "allowed_regions": ["eu", "on-prem"],
                    "default_action": "deny"
                }}
            }
        });
        std::fs::write(
            dir.path()
                .join(crate::daemon::interactive_live::GATE_FILENAME),
            gate.to_string(),
        )
        .unwrap();
        let global = dir.path().join(KIMI_SETTINGS_FILENAME);
        let slot = dir.path().join("config-2").join("settings.json");
        write(&global, &old_default_slot());
        write(&slot, &old_default_slot());
        let before = (
            std::fs::read(&global).unwrap(),
            std::fs::read(&slot).unwrap(),
        );
        let s = migrate_kimi_default_model(dir.path());
        assert!(s.residency_refused, "{s:?}");
        assert_eq!(s.migrated, 0);
        assert_eq!(
            (
                std::fs::read(&global).unwrap(),
                std::fs::read(&slot).unwrap()
            ),
            before
        );
        assert!(!dir.path().join(MARKER_FILENAME).exists());
    }

    /// C-H1: once migrated, a deliberate switch back to the old default is a
    /// user choice; the next launch must not re-migrate it.
    #[test]
    fn a_later_switch_back_to_kimi_k3_is_kept_by_the_one_shot_marker() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config-3").join("settings.json");
        write(&path, &old_default_slot());
        assert_eq!(migrate_kimi_default_model(dir.path()).migrated, 1);
        assert!(dir.path().join(MARKER_FILENAME).is_file());
        // `csq models switch kimi kimi-k3[1m]` — the user's deliberate choice.
        write(&path, &old_default_slot());
        let before = std::fs::read(&path).unwrap();
        assert_eq!(migrate_kimi_default_model(dir.path()), Summary::default());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    /// A pass that met per-file lock contention still writes the marker,
    /// so a deliberate switch on another slot made before the next launch is
    /// never re-migrated (C-H1); the contended file keeps its model.
    #[cfg(unix)]
    #[test]
    fn a_contended_file_is_skipped_and_a_later_switch_elsewhere_is_kept() {
        let dir = TempDir::new().unwrap();
        let busy = dir.path().join("config-8").join("settings.json");
        let other = dir.path().join("config-9").join("settings.json");
        write(&busy, &old_default_slot());
        write(&other, &old_default_slot());
        {
            let _held = crate::platform::lock::lock_credential_file(&busy.with_extension("lock"))
                .unwrap()
                .unwrap();
            let s = migrate_kimi_default_model(dir.path());
            assert_eq!((s.locked, s.migrated), (1, 1), "{s:?}");
        }
        assert!(dir.path().join(MARKER_FILENAME).is_file());
        // The user switches slot 9 back to the old default before relaunch.
        write(&other, &old_default_slot());
        let switched = std::fs::read(&other).unwrap();
        let s = migrate_kimi_default_model(dir.path());
        assert_eq!(s.migrated, 0, "{s:?}");
        assert_eq!(std::fs::read(&other).unwrap(), switched);
    }

    /// H1: while another writer (setkey) holds the file's settings lock, the
    /// migration must not read-modify-write it.
    #[cfg(unix)]
    #[test]
    fn a_held_settings_lock_leaves_the_file_byte_identical() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config-8").join("settings.json");
        write(&path, &old_default_slot());
        let before = std::fs::read(&path).unwrap();
        let _held = crate::platform::lock::lock_credential_file(&path.with_extension("lock"))
            .unwrap()
            .expect("test takes the lock first");
        let s = migrate_kimi_default_model(dir.path());
        assert_eq!(s.locked, 1, "{s:?}");
        assert_eq!(s.migrated, 0);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    /// C-H2: setkey's lock order starts with ProfilesFileLock; while another
    /// writer holds it, the migration touches nothing.
    #[cfg(unix)]
    #[test]
    fn a_held_profiles_lock_leaves_every_file_byte_identical() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config-8").join("settings.json");
        write(&path, &old_default_slot());
        let before = std::fs::read(&path).unwrap();
        {
            let _held =
                crate::accounts::profiles_lock::ProfilesFileLock::acquire(dir.path()).unwrap();
            let s = migrate_kimi_default_model(dir.path());
            assert!(s.profiles_locked, "{s:?}");
            assert_eq!(s.migrated, 0);
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert!(!dir.path().join(MARKER_FILENAME).exists());
        }
        // Nothing was touched, so the next launch runs the pass.
        assert_eq!(migrate_kimi_default_model(dir.path()).migrated, 1);
    }

    /// M1: a FIFO at the settings path is left untouched and never blocks.
    #[cfg(unix)]
    #[test]
    fn a_fifo_at_the_settings_path_is_left_untouched_without_hanging() {
        use std::os::unix::fs::FileTypeExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config-9").join("settings.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path for the call's duration.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let s = migrate_kimi_default_model(dir.path());
        assert_eq!(s.read_skipped, 1, "{s:?}");
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_fifo());
    }

    /// §5a: when the final replace fails, no tmp file (which would carry the
    /// auth token) survives. The target is a non-empty directory, so the
    /// tmp write succeeds and `atomic_replace` onto it fails.
    #[test]
    fn the_shared_writer_removes_its_tmp_when_the_replace_fails() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("settings.json");
        std::fs::create_dir_all(target.join("occupied")).unwrap();
        let err = write_settings_json_private(&target, &old_default_slot());
        assert!(err.is_err());
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .filter(|n| n != "settings.json")
            .collect();
        assert!(leftovers.is_empty(), "tmp left behind: {leftovers:?}");
    }
}
