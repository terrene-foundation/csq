//! Codex surface constants + `config.toml` pre-seed helpers.
//!
//! Companion to `providers::catalog` that pins the Codex-specific
//! on-disk knobs the login (PR-C3b), refresher (PR-C4), and launch
//! (PR-C3c) paths all need. Entries here mirror spec 07 §7.2.2
//! (on-disk layout) and §7.3.3 (login sequence); any drift between
//! the spec and this module is a spec violation.

use crate::platform::fs::{atomic_replace, unique_tmp_path};
use crate::providers;
use crate::types::AccountNum;
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};

/// Binary name csq spawns for a Codex-surface slot. The full spawn
/// command lives in `Provider.spawn_command` (PR-C3c); kept here so
/// the login path can `find_on_path`-check before shelling out.
pub const CLI_BINARY: &str = "codex";

/// Environment variable codex respects to relocate its state dir.
/// Passed to `codex login --device-auth` in the login path and to
/// the launched codex process in PR-C3c.
pub const HOME_ENV_VAR: &str = "CODEX_HOME";

/// Filename codex-cli writes into `$CODEX_HOME` after a successful
/// `codex login --device-auth`. csq relocates it to
/// `credentials/codex-<N>.json` per spec 07 §7.3.3 step 4.
pub const CODEX_WRITTEN_AUTH_JSON: &str = "auth.json";

/// The config.toml filename inside `config-<N>/` codex reads. Written
/// by csq pre-login (INV-P03) with the `cli_auth_credentials_store` key
/// (csq does NOT write a `model` key at login — CC-parity).
pub const CONFIG_TOML_FILENAME: &str = "config.toml";

/// Per-account persistent Codex-sessions directory. Symlinked from
/// handle dirs so daemon sweep does not delete user transcripts
/// (spec 07 §7.2.2 and INV-P04).
pub const SESSIONS_DIRNAME: &str = "codex-sessions";

/// Returns the absolute path to `config-<N>/config.toml`.
pub fn config_toml_path(base_dir: &Path, account: AccountNum) -> PathBuf {
    base_dir
        .join(format!("config-{}", account))
        .join(CONFIG_TOML_FILENAME)
}

/// Returns the absolute path to `config-<N>/codex-sessions/`.
pub fn sessions_dir(base_dir: &Path, account: AccountNum) -> PathBuf {
    base_dir
        .join(format!("config-{}", account))
        .join(SESSIONS_DIRNAME)
}

/// Returns the absolute path to `config-<N>/auth.json` — where
/// codex-cli writes tokens after `codex login --device-auth` when
/// csq invokes it with `CODEX_HOME=config-<N>`. csq relocates the
/// file post-login.
pub fn written_auth_json_path(base_dir: &Path, account: AccountNum) -> PathBuf {
    base_dir
        .join(format!("config-{}", account))
        .join(CODEX_WRITTEN_AUTH_JSON)
}

/// Returns the Codex provider's default model, read from the catalog
/// so the spec §7.3.3 pre-seed stays aligned with `catalog::PROVIDERS`
/// — one source of truth across login (this module) and model-switch
/// (PR-C7).
pub fn default_model() -> &'static str {
    providers::get_provider("codex")
        .expect("codex provider must be registered in catalog")
        .default_model
}

/// Keys csq controls per-slot — these MUST always come from csq, NEVER
/// from user-global `~/.codex/config.toml`. Every other top-level key in
/// the user-global file is propagated into the slot's `config.toml` so
/// user-global preferences (`approval_policy`, `sandbox_mode`,
/// `model_provider`, `model_reasoning_*`, `[mcp_servers.*]`,
/// `[shell_environment_policy]`, …) reach Codex via `$CODEX_HOME/config.toml`.
///
/// Without this propagation, csq's slot-isolation `CODEX_HOME` redirect
/// silently drops every user-global preference, because Codex reads
/// only `$CODEX_HOME/config.toml`, never `~/.codex/config.toml`. The
/// originating bug report (2026-05-15): user ran `csq run 12` with
/// `approval_policy = "never"` + `sandbox_mode = "danger-full-access"`
/// in `~/.codex/config.toml`, and the session came up with Codex's
/// built-in `workspace-write` defaults instead — because the slot's
/// `config.toml` only had `cli_auth_credentials_store`.
///
/// `model` is intentionally NOT in this list. CC-parity: csq must not own
/// the model key. The user-global `~/.codex/config.toml` `model` key is
/// propagated verbatim so the user's preference reaches the slot; when it
/// is absent, codex uses its own built-in default. csq's catalog
/// `default_model()` is retained as a reference value but MUST NOT be
/// written into the slot's `config.toml`.
const CSQ_CONTROLLED_KEYS: &[&str] = &["cli_auth_credentials_store"];

/// csq's native Codex footer, using item IDs verified in codex-cli 0.162.1.
/// Matches `quota::format::rich_statusline` order: weekly quota, context USED,
/// estimated session cost, model with reasoning, project, git. Codex has no
/// account item or external-command statusline hook, so account is omitted.
/// Codex accounts use the weekly limit only; never add `five-hour-limit`.
/// Absent global values receive this default. Only csq-owned slot values
/// upgrade; explicit global values, including the previous default, survive.
const CSQ_DEFAULT_STATUS_LINE: &[&str] = &[
    "weekly-limit",
    "context-used",
    "estimated-thread-cost",
    "model-with-reasoning",
    "project-name",
    "git-branch",
];

const CSQ_PREVIOUS_STATUS_LINE: &[&str] = &[
    "model-with-reasoning",
    "context-remaining",
    "git-branch",
    "current-dir",
];

fn status_line_matches(value: &toml::Value, items: &[&str]) -> bool {
    value.as_array().is_some_and(|values| {
        values.len() == items.len()
            && values
                .iter()
                .zip(items)
                .all(|(value, item)| value.as_str() == Some(*item))
    })
}

fn is_csq_status_line(value: &toml::Value) -> bool {
    status_line_matches(value, CSQ_PREVIOUS_STATUS_LINE)
        || status_line_matches(value, CSQ_DEFAULT_STATUS_LINE)
}

/// Fill an absent global footer. Every explicit global value belongs to the user.
/// Non-table `tui` values remain untouched.
fn inject_default_status_line(table: &mut toml::value::Table) {
    let tui = table
        .entry("tui")
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
    let Some(tui) = tui.as_table_mut() else {
        return;
    };
    if tui.get("status_line").is_some() {
        return;
    }
    tui.insert(
        "status_line".into(),
        toml::Value::Array(
            CSQ_DEFAULT_STATUS_LINE
                .iter()
                .map(|item| toml::Value::String((*item).into()))
                .collect(),
        ),
    );
}

/// Hash of the last statusline csq rendered, separate from Codex's config schema.
const STATUS_LINE_OWNER_FILENAME: &str = ".csq-status-line.sha256";
/// The per-slot writer lock taken by [`lock_slot_config`]. A persistent file on unix; on
/// Windows the lock is a named mutex and no file is created (`platform::lock`).
const SLOT_CONFIG_LOCK_FILENAME: &str = ".config-toml.lock";

fn status_line_hash(value: &toml::Value) -> Option<String> {
    let mut hash = Sha256::new();
    for item in value.as_array()? {
        let item = item.as_str()?;
        if item.contains('\u{1f}') {
            return None;
        }
        hash.update(item.as_bytes());
        hash.update([0x1f]);
    }
    Some(format!("{:x}", hash.finalize()))
}

fn status_line_owner_path(target: &Path) -> PathBuf {
    target.with_file_name(STATUS_LINE_OWNER_FILENAME)
}

/// Missing, malformed, or unreadable ownership records use the migration rule.
fn read_status_line_owner(target: &Path) -> Option<String> {
    match std::fs::read_to_string(status_line_owner_path(target)) {
        Ok(record) => {
            let record = record.trim_end_matches('\n');
            let hashes: Vec<_> = record.lines().collect();
            if (1..=2).contains(&hashes.len())
                && hashes.iter().all(|hash| {
                    hash.len() == 64
                        && hash
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
            {
                Some(record.to_owned())
            } else {
                tracing::warn!(
                    error_kind = "codex_status_line_owner_invalid",
                    "using statusline ownership migration rule"
                );
                None
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => {
            tracing::warn!(
                error_kind = "codex_status_line_owner_unreadable",
                "using statusline ownership migration rule"
            );
            None
        }
    }
}

/// Return true when retaining the prior value and ownership metadata.
fn preserve_slot_status_line(
    merged: &mut toml::value::Table,
    existing: Option<&toml::Value>,
    owner: Option<&str>,
    global_line: Option<&toml::Value>,
    retain_owned: bool,
) -> io::Result<bool> {
    let Some(slot_tui) = existing.and_then(|value| value.get("tui")) else {
        return Ok(false);
    };
    let Some(slot_table) = slot_tui.as_table() else {
        merged.insert("tui".into(), slot_tui.clone());
        return Ok(true);
    };
    let Some(slot_line) = slot_table.get("status_line") else {
        return Ok(false);
    };
    let csq_owned = match owner {
        Some(record) => status_line_hash(slot_line)
            .is_some_and(|hash| record.lines().any(|owned| owned == hash)),
        None => is_csq_status_line(slot_line) || global_line == Some(slot_line),
    };
    if csq_owned && retain_owned {
        let mut tui = merged
            .get("tui")
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default();
        tui.insert("status_line".into(), slot_line.clone());
        merged.insert("tui".into(), toml::Value::Table(tui));
        return Ok(true);
    }
    if csq_owned {
        return Ok(false);
    }
    let tui = merged
        .entry("tui")
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
    let Some(tui) = tui.as_table_mut() else {
        tracing::warn!(
            error_kind = "codex_status_line_global_tui_not_table",
            "cannot preserve slot statusline; preserving prior config"
        );
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "global Codex tui must be a table to preserve slot-owned statusline",
        ));
    };
    tui.insert("status_line".into(), slot_line.clone());
    Ok(true)
}

struct RenderedSlotConfig {
    contents: String,
    /// None keeps the prior record for a user edit or unsafe global value.
    status_line_owner: Option<String>,
}

#[cfg(test)]
thread_local! {
    static INTERRUPT_STATUS_LINE_PUBLICATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_STATUS_LINE_NARROW: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn interrupt_status_line_publication() -> io::Result<()> {
    if INTERRUPT_STATUS_LINE_PUBLICATION.with(|flag| flag.replace(false)) {
        return Err(io::Error::other(
            "injected interruption after config rename",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct StatusLineOwnerWriteError(io::Error);

impl std::fmt::Display for StatusLineOwnerWriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Codex statusline ownership record publication failed")
    }
}

impl std::error::Error for StatusLineOwnerWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Distinguishes ownership metadata failures from config publication failures.
/// Shared by CLI/desktop login and model-switch diagnostics.
pub fn config_write_error_context(error: &io::Error) -> &'static str {
    if error
        .get_ref()
        .is_some_and(|source| source.is::<StatusLineOwnerWriteError>())
    {
        "Codex statusline ownership record publication failed"
    } else {
        "Codex config.toml publication failed"
    }
}

/// Returns the underlying metadata I/O error for caller diagnostics.
/// Avoids repeating the ownership context as the displayed error source.
pub fn config_write_error_source(error: &io::Error) -> &io::Error {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<StatusLineOwnerWriteError>())
        .map_or(error, |source| &source.0)
}

fn write_status_line_record(target: &Path, record: &str) -> io::Result<()> {
    let path = status_line_owner_path(target);
    let contents = format!("{record}\n");
    if std::fs::read(&path).ok().as_deref() == Some(contents.as_bytes()) {
        return Ok(());
    }
    write_config_toml_contents(&path, &contents).map_err(|error| {
        tracing::warn!(
            error_kind = "codex_status_line_owner_write_failed",
            "could not publish statusline ownership record"
        );
        io::Error::new(error.kind(), StatusLineOwnerWriteError(error))
    })
}

fn write_status_line_owner(target: &Path, rendered: &RenderedSlotConfig) -> io::Result<()> {
    #[cfg(test)]
    if FAIL_STATUS_LINE_NARROW.with(|flag| flag.replace(false)) {
        return Err(io::Error::other(
            "injected statusline metadata narrowing failure",
        ));
    }
    if let Some(owner) = &rendered.status_line_owner {
        write_status_line_record(target, owner)?;
    }
    Ok(())
}

fn publish_slot_config(
    target: &Path,
    existing: Option<&str>,
    rendered: &RenderedSlotConfig,
) -> io::Result<ConditionalWrite> {
    if let Some(new) = &rendered.status_line_owner {
        // Rendering only supplies an owner for a previously recognized owned value.
        // Never include a preserved user edit merely because it exists on disk.
        let old = existing
            .and_then(|text| toml::from_str::<toml::Value>(text).ok())
            .and_then(|value| {
                value
                    .get("tui")
                    .and_then(|tui| tui.get("status_line"))
                    .and_then(status_line_hash)
            });
        let transition = match old {
            Some(old) if old != *new => format!("{old}\n{new}"),
            _ => new.clone(),
        };
        write_status_line_record(target, &transition)?;
    }
    let expected = existing.map(str::as_bytes);
    if write_config_toml_contents_if_unchanged(target, &rendered.contents, expected)?
        == ConditionalWrite::Changed
    {
        return Ok(ConditionalWrite::Changed);
    }
    #[cfg(test)]
    interrupt_status_line_publication()?;
    // A failed narrowing leaves both recognized values recorded. Config is already
    // published, so report a metadata warning rather than a false config failure.
    if write_status_line_owner(target, rendered).is_err() {
        tracing::warn!(
            error_kind = "codex_status_line_owner_narrow_failed",
            "config published; statusline ownership record retains transition"
        );
    }
    Ok(ConditionalWrite::Written)
}

/// Environment variable that overrides the user-global Codex config
/// path. Tests and CI set this to point at a controlled fixture.
/// When unset, `read_user_global_config_toml` looks at
/// `$HOME/.codex/config.toml`.
pub const USER_CONFIG_ENV_OVERRIDE: &str = "CODEX_USER_CONFIG";

/// Reads `~/.codex/config.toml` (or the path in
/// [`USER_CONFIG_ENV_OVERRIDE`] if set) and returns its content as a
/// `String`. Returns `None` if the file is missing, unreadable, or the
/// path resolution fails (no `$HOME`). Never panics — fall back to the
/// 2-key slot config in every failure mode (graceful degradation per
/// `rules/security.md` § "Fail-Closed on Keychain/Lock Contention" — a
/// missing user-global is not an error, just absent preferences).
pub fn read_user_global_config_toml() -> Option<String> {
    let path = user_global_config_path()?;
    std::fs::read_to_string(&path).ok()
}

fn user_global_config_path() -> Option<PathBuf> {
    if let Some(override_path) = std::env::var_os(USER_CONFIG_ENV_OVERRIDE) {
        return Some(PathBuf::from(override_path));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".codex").join("config.toml"))
}

/// Renders the `config.toml` contents csq writes before the first
/// `codex login --device-auth`, with no user-global merge. One key:
///
/// ```toml
/// cli_auth_credentials_store = "file"
/// ```
///
/// String values are TOML-quoted; trailing newline included.
///
/// The `cli_auth_credentials_store = "file"` line is the mandatory
/// INV-P03 directive — codex respects a file-backed auth store only
/// when this key exists BEFORE login. A later rewrite does not
/// migrate an existing keychain entry (spec 07 §7.3.3 step 2
/// rationale).
///
/// csq no longer writes a `model` key. CC-parity: the user-global
/// `~/.codex/config.toml` `model` propagates verbatim; absent →
/// codex uses its own built-in default. [`default_model`] is kept
/// as a catalog-mirror reference but MUST NOT be written here.
///
/// This is a thin wrapper around [`render_config_toml_with_global`] for
/// callers (notably tests) that don't need user-global merging. Pass
/// `Some(model)` to emit an explicit per-slot `model` key (the `csq models
/// set codex` path); pass `None` to omit it (login / spawn / reconciler
/// defaults, where csq must not own the model key).
pub fn render_config_toml(model: Option<&str>) -> String {
    render_config_toml_with_global(model, None)
}

/// Renders the slot's `config.toml` content, merging non-csq-controlled
/// top-level keys from `user_global_toml` (typically the contents of
/// `~/.codex/config.toml`).
///
/// csq's `CODEX_HOME` redirect at spawn time means Codex reads its
/// config from `config-<N>/config.toml`, NEVER from `~/.codex/config.toml`.
/// Without this merge, user-global preferences like `approval_policy`,
/// `sandbox_mode`, `model_provider`, `model_reasoning_effort`,
/// `[mcp_servers.*]`, `[shell_environment_policy]`, and every other
/// top-level Codex configuration silently never apply to csq-managed
/// slots.
///
/// Merge rules:
/// 1. csq-controlled keys (see `CSQ_CONTROLLED_KEYS`) always come from
///    csq. The sole csq-controlled key is `cli_auth_credentials_store`.
/// 2. `model` is conditional. When `model` is `Some(m)` — the explicit
///    `csq models set codex` choice, or a preserved prior explicit choice —
///    csq writes `model = "m"` and DROPS any `model` propagated from the
///    user-global (the explicit per-slot choice wins). When `model` is
///    `None`, csq writes NO model line: the user-global `model` (if any)
///    propagates verbatim, and when neither is present codex uses its own
///    built-in default. csq NEVER injects its catalog default (CC-parity:
///    csq does not own the model key).
/// 3. Every other top-level key in `user_global_toml` is propagated
///    verbatim (tables, arrays, scalars — TOML round-trip via `toml::Value`).
/// 4. On parse error, the user-global is treated as absent and the
///    1-key fallback is returned (graceful degradation — never break
///    the slot operation because the user's global TOML is malformed).
pub fn render_config_toml_with_global(
    model: Option<&str>,
    user_global_toml: Option<&str>,
) -> String {
    // csq-controlled block: the mandatory INV-P03 auth-store directive, plus
    // an explicit per-slot model when one is supplied. Auth-store first keeps
    // the INV-P03 directive at the top of the file (reviewer-ergonomic).
    //
    // The model value is serialized through `toml::Value::String` — NOT raw
    // string interpolation — so a crafted model id (from `csq models set codex
    // <id> --force`, or the IPC-reachable desktop picker) cannot break out of the
    // string literal and inject additional TOML keys (redteam R1 MED: a `"`+`\n`
    // payload could otherwise append `cli_auth_credentials_store = "keychain"`
    // — last-wins overrides csq's INV-P03 directive — or an `[mcp_servers.*]`
    // the operator never set). This mirrors the safe `toml::to_string` treatment
    // the user-global block already gets below.
    let mut csq_block = String::from("cli_auth_credentials_store = \"file\"\n");
    if let Some(m) = model {
        let quoted = toml::Value::String(m.to_string()).to_string();
        csq_block.push_str(&format!("model = {quoted}\n"));
    }

    // Build the user-derived table: parse the user-global if present, else start
    // empty. A missing/malformed/non-table user-global degrades to an empty table
    // (graceful) — but unlike the prior early-returns, we STILL proceed to the
    // statusline injection below so every codex slot gets a `tui.status_line`
    // even when the user has no `~/.codex/config.toml`.
    let mut user_table: toml::value::Table = match user_global_toml {
        None => toml::value::Table::new(),
        Some(user_toml) => match toml::from_str::<toml::Value>(user_toml) {
            Ok(toml::Value::Table(t)) => t,
            Ok(_) => toml::value::Table::new(), // non-table root (defensive)
            Err(_) => {
                tracing::warn!(
                    error_kind = "codex_user_global_config_unparseable",
                    "skipping ~/.codex/config.toml merge — file is not valid TOML; \
                     slot will receive Codex built-in defaults for any keys outside cli_auth_credentials_store"
                );
                toml::value::Table::new()
            }
        },
    };

    for key in CSQ_CONTROLLED_KEYS {
        user_table.remove(*key);
    }
    // When csq writes an explicit per-slot model, that choice is authoritative —
    // drop any `model` propagated from the user-global so it is the ONLY model
    // key. When csq writes none (`model` is None), leave the user-global `model`
    // in place so it propagates verbatim.
    if model.is_some() {
        user_table.remove("model");
    }

    // Fill csq's curated Codex statusline only when absent. Explicit global
    // values always win. Done after the csq-controlled-key removal so it
    // can never collide with them.
    inject_default_status_line(&mut user_table);

    if user_table.is_empty() {
        // Injection guarantees a non-empty table on the normal path; this only
        // triggers if injection was skipped (user `tui` is a non-table) AND
        // nothing else propagated — fall back to the 2-key safe shape.
        return csq_block;
    }

    let user_block = match toml::to_string(&toml::Value::Table(user_table)) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                error_kind = "codex_user_global_config_serialize_failed",
                error = %e,
                "skipping ~/.codex/config.toml merge — could not serialize merged table; \
                 slot will receive Codex built-in defaults"
            );
            return csq_block;
        }
    };

    format!("{}{}", csq_block, user_block)
}

/// The path part of a Codex hook-trust key, `<hooks file path>:<event>:<group>:<handler>`
/// (`None` when the key has fewer than four `:`-separated parts).
fn hook_key_path(key: &str) -> Option<&str> {
    let mut parts = key.rsplitn(4, ':');
    parts.next()?;
    parts.next()?;
    parts.next()?;
    parts.next()
}

/// The user-global `CODEX_HOME` directories: the parent of the user-global config (the real
/// `~/.codex`, or the test override), `$HOME/.codex`, and `$CODEX_HOME` when set.
fn user_global_codex_homes() -> Vec<PathBuf> {
    let mut homes = Vec::new();
    if let Some(parent) = user_global_config_path().and_then(|p| p.parent().map(Path::to_path_buf))
    {
        homes.push(parent);
    }
    if let Some(home) = std::env::var_os("HOME") {
        homes.push(PathBuf::from(home).join(".codex"));
    }
    if let Some(codex_home) = std::env::var_os("CODEX_HOME") {
        homes.push(PathBuf::from(codex_home));
    }
    homes
}

/// Rebuilds a slot's `[hooks.state]` on regeneration.
///
/// - Entries keyed under `base_dir` (a csq handle dir or `config-N`) are the trust records
///   Codex wrote for csq's own hook files: the slot's are kept verbatim.
/// - Entries keyed under a user-global `CODEX_HOME` (`~/.codex`, `$HOME/.codex`, `$CODEX_HOME`)
///   name a file a csq terminal never reads. They are never copied from the global, and a
///   copy frozen in the slot by an earlier csq is dropped.
/// - Entries keyed OUTSIDE every `CODEX_HOME` (project hooks, whose key is identical in a
///   vanilla and a csq terminal) are the UNION of the slot's and the global's. On a key in
///   both, the GLOBAL value wins, which refreshes a stale copy; a slot-only key is kept
///   verbatim, because it is a real approval the user gave inside a csq terminal and dropping
///   it would destroy it. A kept stale entry is safe: Codex re-verifies `trusted_hash`
///   against its own current hash on load, so it can only read "modified", never run an
///   edited hook.
///
/// A key that is not `<path>:<event>:<group>:<handler>` shaped is outside every home.
fn rebuild_hooks_state(
    base_dir: &Path,
    slot_state: Option<&toml::value::Table>,
    global_state: Option<&toml::value::Table>,
) -> toml::value::Table {
    // Codex writes the CANONICAL CODEX_HOME into a key (probed), so both sides are compared in
    // raw and canonical form (a symlinked accounts base or `~/.codex` must not hide a key).
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let base_canon = canon(base_dir);
    let mut homes = user_global_codex_homes();
    let canon_homes: Vec<PathBuf> = homes.iter().map(|h| canon(h)).collect();
    homes.extend(canon_homes);
    let under_csq = |key: &str| {
        hook_key_path(key).is_some_and(|p| {
            Path::new(p).starts_with(base_dir) || Path::new(p).starts_with(&base_canon)
        })
    };
    let under_global_home = |key: &str| {
        hook_key_path(key).is_some_and(|p| {
            Path::new(p)
                .parent()
                .is_some_and(|d| homes.iter().any(|h| h == d))
        })
    };
    let mut out = toml::value::Table::new();
    for (key, value) in slot_state.into_iter().flatten() {
        if under_csq(key) || !under_global_home(key) {
            out.insert(key.clone(), value.clone());
        }
    }
    for (key, value) in global_state.into_iter().flatten() {
        if !under_csq(key) && !under_global_home(key) {
            out.insert(key.clone(), value.clone());
        }
    }
    out
}

/// Agent controls and custom statuslines are owned by the slot. Project trust comes only from
/// the canonical owner source; other settings remain
/// a fresh user-global snapshot, including deletion of old policy/MCP keys.
fn render_slot_config_toml(
    base_dir: &Path,
    model: Option<&str>,
    user_global: Option<&str>,
    existing: Option<&str>,
    owner: Option<&str>,
) -> io::Result<RenderedSlotConfig> {
    render_slot_config_toml_with_ownership_global(
        base_dir,
        model,
        user_global,
        existing,
        owner,
        user_global,
    )
}

fn render_slot_config_toml_with_ownership_global(
    base_dir: &Path,
    model: Option<&str>,
    user_global: Option<&str>,
    existing: Option<&str>,
    owner: Option<&str>,
    ownership_global: Option<&str>,
) -> io::Result<RenderedSlotConfig> {
    let parsed_global = ownership_global.and_then(|text| toml::from_str::<toml::Value>(text).ok());
    let global_malformed = ownership_global.is_some() && parsed_global.is_none();
    let global_line = parsed_global
        .as_ref()
        .and_then(|v| v.get("tui"))
        .and_then(|v| v.get("status_line"));
    let existing = existing
        .map(|text| {
            toml::from_str::<toml::Value>(text).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "existing Codex config.toml is invalid; preserving prior file",
                )
            })
        })
        .transpose()?;
    let agents = existing.as_ref().and_then(|v| v.get("agents"));
    let features = existing.as_ref().and_then(|v| v.get("features"));
    let multi_agent = features.and_then(|v| v.get("multi_agent_v2"));
    for (path, value) in [
        ("agents", agents),
        ("features", features),
        ("features.multi_agent_v2", multi_agent),
    ] {
        if value.is_some_and(|v| !v.is_table()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("existing Codex config.toml {path} must be a table; preserving prior file"),
            ));
        }
    }

    // `[hooks.state."<key>"]` is Codex-owned hook trust (`trusted_hash`, `enabled`), written
    // by Codex into this file when the user approves a hook. csq never authors it. On every
    // regeneration the slot's table is rebuilt from two sources (see `rebuild_hooks_state`):
    // the slot's OWN entries keyed under a csq-owned `CODEX_HOME` (a handle or config dir),
    // plus the user-global's entries keyed OUTSIDE every `CODEX_HOME` (project hooks), taken
    // fresh from the global each time so a stale copy frozen in the slot is replaced.
    // A non-table `hooks` (not `hooks.state`) in the slot is dropped and regenerated, never
    // refused: Codex itself cannot load it, so there is no trust record in it to preserve.
    // `csq doctor` reports the shape ([`slot_config_hooks_not_a_table`]).
    let hooks_state = match existing.as_ref().and_then(|v| v.get("hooks")) {
        Some(hooks) if hooks.is_table() => hooks.get("state"),
        Some(_) => {
            tracing::warn!(
                error_kind = "codex_slot_config_hooks_not_a_table",
                "existing Codex config.toml `hooks` is not a table; dropped and regenerated"
            );
            None
        }
        None => None,
    };
    if hooks_state.is_some_and(|v| !v.is_table()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "existing Codex config.toml hooks.state must be a table; preserving prior file",
        ));
    }

    let rendered = render_config_toml_with_global(model, user_global);
    let mut merged: toml::value::Table = toml::from_str(&rendered).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "rendered Codex config.toml is invalid",
        )
    })?;
    let dropped_bad_hooks = merged.get("hooks").is_some_and(|h| !h.is_table());
    if dropped_bad_hooks {
        tracing::warn!(
            error_kind = "codex_user_global_hooks_not_a_table",
            "user-global Codex config.toml `hooks` is not a table; not propagated"
        );
        merged.remove("hooks");
    }
    let rendered_projects = merged.get("projects").cloned();
    let rendered_had_state = merged.get("hooks").and_then(|h| h.get("state")).is_some();
    let global_state = merged
        .get("hooks")
        .and_then(|h| h.get("state"))
        .and_then(toml::Value::as_table)
        .cloned();
    let mut hooks_now_empty = false;
    if let Some(hooks) = merged.get_mut("hooks").and_then(toml::Value::as_table_mut) {
        hooks.remove("state");
        hooks_now_empty = hooks.is_empty();
    }
    if hooks_now_empty {
        merged.remove("hooks");
    }
    let state = rebuild_hooks_state(
        base_dir,
        hooks_state.and_then(toml::Value::as_table),
        global_state.as_ref(),
    );
    if !state.is_empty() {
        let hooks = merged
            .entry("hooks")
            .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
        let hooks = hooks.as_table_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "global Codex hooks must be a table to carry hook trust",
            )
        })?;
        hooks.insert("state".into(), toml::Value::Table(state));
    }
    let rendered_tui = merged.get("tui").cloned();
    let retain_owned = global_malformed
        || merged
            .get("tui")
            .and_then(|tui| tui.get("status_line"))
            .and_then(status_line_hash)
            .is_none();
    let user_status_line = preserve_slot_status_line(
        &mut merged,
        existing.as_ref(),
        owner,
        global_line,
        retain_owned,
    )?;
    let status_line_owner = (!user_status_line && !global_malformed)
        .then(|| {
            merged
                .get("tui")
                .and_then(|v| v.get("status_line"))
                .and_then(status_line_hash)
        })
        .flatten();
    if let Some(agents) = agents {
        merged.insert("agents".into(), agents.clone());
    }
    if let Some(multi_agent) = multi_agent {
        let features = merged
            .entry("features")
            .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
        let features = features.as_table_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "global Codex features must be a table to preserve slot-owned multi_agent_v2",
            )
        })?;
        features.insert("multi_agent_v2".into(), multi_agent.clone());
    }
    super::trust::ProjectTrust::read().apply(&mut merged, existing.as_ref());
    if agents.is_none()
        && multi_agent.is_none()
        && hooks_state.is_none()
        && !rendered_had_state
        && !dropped_bad_hooks
        && merged.get("projects") == rendered_projects.as_ref()
        && merged.get("tui") == rendered_tui.as_ref()
    {
        return Ok(RenderedSlotConfig {
            contents: rendered,
            status_line_owner,
        });
    }
    let contents = toml::to_string(&merged).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "could not serialize Codex owner config",
        )
    })?;
    Ok(RenderedSlotConfig {
        contents,
        status_line_owner,
    })
}

/// Whether the slot `config.toml` at `path` parses but carries a `hooks` value that is not a
/// table (the next regeneration drops and regenerates it). An absent, unreadable, oversize or
/// unparseable file is `false`. For `csq doctor`; the read is bounded and cannot block.
#[must_use]
pub fn slot_config_hooks_not_a_table(path: &Path) -> bool {
    crate::session::handle_dir::read_regular_bounded(path, false)
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|t| toml::from_str::<toml::Value>(&t).ok())
        .and_then(|v| v.get("hooks").map(|h| !h.is_table()))
        .unwrap_or(false)
}

fn read_existing_config_toml(path: &Path) -> io::Result<Option<String>> {
    use std::io::Read;
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(unreadable(error.kind())),
    };
    // The bound is enforced AT READ, so a file growing past it between a stat and the read
    // is still refused.
    let mut bytes = Vec::new();
    if let Err(error) = file.take(SLOT_CONFIG_MAX_BYTES + 1).read_to_end(&mut bytes) {
        return Err(unreadable(error.kind()));
    }
    if bytes.len() as u64 > SLOT_CONFIG_MAX_BYTES {
        return Err(SlotConfigFault::Oversize.error(io::ErrorKind::InvalidData));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| unreadable(io::ErrorKind::InvalidData))
}

fn unreadable(kind: io::ErrorKind) -> io::Error {
    io::Error::new(
        kind,
        "cannot read existing Codex config.toml; preserving prior file",
    )
}

/// Derives Codex CLI flags from user-global `~/.codex/config.toml`.
/// These flags are passed at spawn time to ensure the sandbox/approval
/// policy reaches Codex's runtime at process start.
///
/// # Why not rely on config.toml alone?
///
/// `write_config_toml` already merges these keys into
/// `config-<N>/config.toml`. Codex CLI reads that file at startup —
/// in principle, that's enough. In practice (2026-05-15 user report),
/// Codex CLI's policy precedence treats CLI flags as authoritative
/// over config.toml for the strict policy layer; setting only the
/// config keys produced sessions where the model still had to request
/// escalation despite `approval_policy = "never"` +
/// `sandbox_mode = "danger-full-access"` being present in the slot's
/// config.toml. Passing the flag at spawn closes the gap.
///
/// # Translation rules
///
/// - **Full-bypass combination** (`approval_policy = "never"` AND
///   `sandbox_mode = "danger-full-access"`): emits
///   `--dangerously-bypass-approvals-and-sandbox`. This is the user's
///   documented intent — global `~/.codex/config.toml` files that set
///   this combination explicitly comment the equivalent CLI flag.
/// - **Partial coverage**: emits granular `-a <policy>` and/or
///   `-s <mode>` flags for whichever keys are present.
/// - **No relevant keys / parse error / no user-global**: returns an
///   empty vec — Codex uses its built-in defaults (or whatever the
///   merged config.toml supplies as fallback).
///
/// Returns owned `String`s so callers can pass them directly to
/// `Command::args(...)` without lifetime gymnastics.
pub fn derive_spawn_flags(user_global_toml: Option<&str>) -> Vec<String> {
    let Some(user_toml) = user_global_toml else {
        return vec![];
    };
    let parsed: toml::Value = match toml::from_str(user_toml) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let table = match parsed {
        toml::Value::Table(t) => t,
        _ => return vec![],
    };

    let approval = table.get("approval_policy").and_then(|v| v.as_str());
    let sandbox = table.get("sandbox_mode").and_then(|v| v.as_str());

    // Full-bypass combination → single flag with bypass semantics.
    if approval == Some("never") && sandbox == Some("danger-full-access") {
        return vec!["--dangerously-bypass-approvals-and-sandbox".into()];
    }

    // Granular flags for partial coverage.
    let mut flags = Vec::new();
    if let Some(p) = approval {
        flags.push("-a".into());
        flags.push(p.into());
    }
    if let Some(s) = sandbox {
        flags.push("-s".into());
        flags.push(s.into());
    }
    flags
}

/// The codex flags through which a `csq run N -- ...` caller takes explicit
/// control of the sandbox / approval policy. When ANY of these appears in the
/// passthrough, [`derive_spawn_flags`] MUST NOT be injected: the derived
/// full-bypass flag (`--dangerously-bypass-approvals-and-sandbox`) is a terminal
/// override that a later `-s read-only` cannot undo (it is not a `-s` value, so
/// codex's last-wins argparse does not apply), so injecting it silently defeats
/// the caller's explicit downscope (GH an internal ticket).
const CALLER_SANDBOX_FLAGS: &[&str] = &[
    "-s",
    "--sandbox",
    "-a",
    "--ask-for-approval",
    "--approval",
    "--full-auto",
    "--dangerously-bypass-approvals-and-sandbox",
    "--yolo",
    "--ignore-user-config",
];

/// True iff the `csq run N -- <rest>` passthrough already specifies a sandbox or
/// approval policy (or `--ignore-user-config`), i.e. the caller is managing the
/// codex sandbox themselves. In that case the account-snapshot-derived spawn
/// flags MUST be suppressed so the caller's explicit policy is the ONLY one codex
/// sees — otherwise csq's injected full-bypass flag wins and the caller cannot
/// enforce a read-only one-shot (GH an internal ticket). Matches both the bare flag (`-s
/// read-only`) and the `=value` form (`--sandbox=read-only`).
pub fn caller_overrides_sandbox(rest: &[String]) -> bool {
    rest.iter().any(|tok| {
        CALLER_SANDBOX_FLAGS
            .iter()
            .any(|f| tok == f || (f.starts_with("--") && tok.starts_with(&format!("{f}="))))
    })
}

/// Atomically writes `config-<N>/config.toml` with the rendered
/// contents of [`render_config_toml_with_global`], re-reading the
/// user-global `~/.codex/config.toml` at call time. Creates the parent
/// `config-<N>/` directory if missing. File permissions are set to
/// 0o600 at creation via
/// [`write_new_private_synced`](crate::platform::fs::write_new_private_synced)
/// — the rendered TOML may carry user-configured MCP server auth under
/// `[mcp_servers.*]`, and keeps the directory's permission story uniform
/// with the other credential-adjacent files csq writes.
///
/// Used by the login path and by the daemon startup reconciler to
/// repair drift after a manual edit. Idempotent.
///
/// Existing slot-owned `[agents]` and `[features.multi_agent_v2]` tables win
/// over the global snapshot. Missing owner tables are seeded from the global.
/// An unreadable/invalid existing config is refused without overwriting it.
///
/// Callers that have ALREADY read (and validated) the user-global
/// content MUST use [`write_config_toml_with_global`] so the validated
/// snapshot and the written snapshot are the same bytes (closes the
/// guard-vs-write TOCTOU in [`regenerate_slot_config`]).
///
/// `model` is `Some(m)` only for the explicit `csq models set codex`
/// path (and the desktop equivalent); login / spawn / reconciler callers
/// pass `None` so csq never forces a model — the user-global `model`
/// propagates and, absent that, codex uses its own built-in default.
pub fn write_config_toml(
    base_dir: &Path,
    account: AccountNum,
    model: Option<&str>,
) -> io::Result<()> {
    // Merge user-global ~/.codex/config.toml into the slot config so
    // user preferences (approval_policy, sandbox_mode, mcp_servers, …)
    // reach Codex via $CODEX_HOME/config.toml. The sole csq-controlled key
    // (cli_auth_credentials_store) always comes from csq; `model` is written
    // only when an explicit choice is supplied.
    let user_global = read_user_global_config_toml();
    write_config_toml_with_global(base_dir, account, model, user_global.as_deref())
}

/// Like [`write_config_toml`] but writes from the caller-supplied
/// `user_global` snapshot instead of re-reading `~/.codex/config.toml`.
/// Reads the existing slot once to preserve its two owner tables, then renders
/// and publishes one snapshot. Project trust independently reads its canonical
/// owner source; the supplied snapshot governs the other settings.
pub fn write_config_toml_with_global(
    base_dir: &Path,
    account: AccountNum,
    model: Option<&str>,
    user_global: Option<&str>,
) -> io::Result<()> {
    let _slot_lock = lock_slot_config(base_dir, account)?;
    let target = config_toml_path(base_dir, account);
    // Publish only if the bytes read under the lock are still on disk at the exchange
    // (an absent file is expected-absent); re-read and re-render on a change.
    for _ in 0..PUBLISH_ATTEMPTS {
        let existing = read_existing_config_toml(&target)?;
        let owner = read_status_line_owner(&target);
        let rendered = render_slot_config_toml(
            base_dir,
            model,
            user_global,
            existing.as_deref(),
            owner.as_deref(),
        )?;
        if publish_slot_config(&target, existing.as_deref(), &rendered)?
            == ConditionalWrite::Written
        {
            return Ok(());
        }
    }
    Err(publish_gave_up())
}

/// Read-render-publish attempts a csq slot-config writer makes when a concurrent writer
/// changes the file under it.
pub(crate) const PUBLISH_ATTEMPTS: usize = 5;

/// The error a writer returns when the slot config kept changing under it.
pub(crate) fn publish_gave_up() -> io::Error {
    SlotConfigFault::KeptChanging.error(io::ErrorKind::WouldBlock)
}

/// The largest slot `config.toml` csq reads or writes. A bigger file is refused with
/// [`SlotConfigFault::Oversize`]: every csq reader gives up past this bound.
pub(crate) const SLOT_CONFIG_MAX_BYTES: u64 = 1 << 20;

/// Why a csq slot-config operation could not proceed. Carried as the inner error of an
/// `io::Error` so a caller keeps the cause class ([`SlotConfigFault::of`]); the `Display`
/// text is fixed vocabulary (no path, no file content).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotConfigFault {
    /// Not UTF-8, not valid TOML, or a `hooks` table of the wrong shape.
    Malformed,
    /// The file exists but cannot be read.
    Unreadable,
    /// Over `SLOT_CONFIG_MAX_BYTES`.
    Oversize,
    /// The per-slot lock stayed held by another csq writer for the whole bounded wait.
    Locked,
    /// The file changed under every bounded read-render-publish attempt.
    KeptChanging,
    /// A purged handle's approvals reappeared after the purge and a second purge.
    ResurrectedKeys,
}

impl SlotConfigFault {
    /// An `io::Error` of `kind` carrying this fault.
    #[must_use]
    pub fn error(self, kind: io::ErrorKind) -> io::Error {
        io::Error::new(kind, self)
    }

    /// The fault an error carries, if it carries one.
    #[must_use]
    pub fn of(e: &io::Error) -> Option<Self> {
        e.get_ref()?.downcast_ref::<Self>().copied()
    }
}

impl std::fmt::Display for SlotConfigFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "Codex slot config.toml is malformed",
            Self::Unreadable => "Codex slot config.toml cannot be read",
            Self::Oversize => {
                "Codex slot config.toml exceeds 1 MiB; csq will not read or rewrite it"
            }
            Self::Locked => "Codex slot config is locked by another csq writer",
            Self::KeptChanging => "Codex slot config kept changing; not published",
            Self::ResurrectedKeys => {
                "stale hook approvals reappeared in the Codex slot config after the purge"
            }
        })
    }
}

impl std::error::Error for SlotConfigFault {}

/// Fixed-vocabulary description of why a slot-config operation failed, for an operator-facing
/// message: the fault class when the error carries one, else the race or "unexpected error".
#[must_use]
pub fn describe_slot_error(e: &io::Error) -> String {
    if let Some(fault) = SlotConfigFault::of(e) {
        return fault.to_string();
    }
    if e.get_ref().is_some_and(|i| i.is::<ExchangeRaced>()) {
        return "a concurrent write raced csq's config update".to_owned();
    }
    "unexpected error".to_owned()
}

/// What `write_config_toml_contents_if_unchanged` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConditionalWrite {
    /// The snapshot was published.
    Written,
    /// The target did not hold the expected bytes at the atomic exchange; the concurrent
    /// file is the target again and csq's tmp file was removed.
    Changed,
}

/// The target is unchanged since the caller's read.
enum Extant<'a> {
    /// The file held exactly these bytes.
    Bytes(&'a [u8]),
    /// The file did not exist.
    Absent,
}

/// A csq write that lost an atomic-exchange race with a concurrent writer AND could not
/// be fully undone with certainty (an exchange or a metadata read failed part-way, or a
/// third writer landed). The slot is flagged for `csq doctor` ([`SlotWriteStatus::Raced`])
/// and the flag stays until the owner acknowledges it ([`ack_slot_raced`]); csq's bytes MAY
/// be in place over a concurrent write in the failure branches documented on
/// [`publish_by_exchange`].
#[derive(Debug)]
pub(crate) struct ExchangeRaced;

impl std::fmt::Display for ExchangeRaced {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "a concurrent write raced csq's slot-config exchange and could not be fully undone",
        )
    }
}

impl std::error::Error for ExchangeRaced {}

/// Publishes `contents` only if `target` still holds what the caller read: `Some(bytes)`
/// the exact bytes, `None` that the file was absent.
///
/// Publication is an ATOMIC EXCHANGE of the tmp file and the target (macOS
/// `renamex_np(RENAME_SWAP)`, Linux `renameat2(RENAME_EXCHANGE)`), after which the file
/// csq displaced sits at the tmp path and is compared with `expected`. A mismatch means a
/// concurrent writer (Codex takes no lock; it writes tmp-then-rename, verified for codex-cli
/// [`CODEX_EXCHANGE_VERIFIED_VERSION`], see the spec 07 trust section) landed between the
/// caller's read and the exchange: csq swaps back and reports [`ConditionalWrite::Changed`].
/// The swap-back is judged by FILE IDENTITY `(dev, ino)`, never by re-reading bytes: csq's
/// own file came back when the tmp path holds csq's inode; a third inode means a newer
/// write landed during the swap-back and it is put back; any metadata error stops where
/// things stand, keeps the tmp file, flags the slot and never exchanges again. The failure
/// branches are exactly: a swap-back exchange that fails (the displaced file is restored
/// with a plain replace; if that fails too csq's bytes stay over it and the tmp file is
/// kept), and a failed third exchange (the newest file is restored with a plain replace).
/// Every such branch fails with [`ExchangeRaced`] and flags the slot. When the swap-back
/// succeeds and the tmp path holds csq's inode, csq's bytes are not left over the concurrent
/// write, so the race only LOSES csq's write. An absent target uses a hard-link publish
/// (atomic, never replaces), or create-exclusive-then-rename where the filesystem has no
/// hard links ([`SlotWriteStatus::ExchangeUnsupported`]). A platform or filesystem without the
/// exchange falls back to compare-then-rename (the instant between them stays open) and flags
/// the slot the same way.
pub(crate) fn write_config_toml_contents_if_unchanged(
    target: &Path,
    contents: &str,
    expected: Option<&[u8]>,
) -> io::Result<ConditionalWrite> {
    let extant = match expected {
        Some(b) => Extant::Bytes(b),
        None => Extant::Absent,
    };
    write_config_toml_inner(target, contents, extant)
}

/// Test seams for the slot-config publish: `BEFORE_RENAME` runs after the tmp file is
/// written and fsynced, before the exchange; `AFTER_EXCHANGE` runs right after the first
/// exchange (target holds csq's bytes), so a test can land a concurrent write in either gap.
#[cfg(test)]
pub(crate) mod test_seam {
    use std::cell::RefCell;
    use std::path::Path;
    type Hook = Box<dyn Fn(&Path)>;
    thread_local! {
        pub(crate) static BEFORE_RENAME: RefCell<Option<Hook>> = const { RefCell::new(None) };
        pub(crate) static AFTER_EXCHANGE: RefCell<Option<Hook>> = const { RefCell::new(None) };
        /// Forces `exchange_paths` to report "no atomic exchange here".
        pub(crate) static NO_EXCHANGE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        /// Runs right after the swap-back exchange (the second one) succeeded.
        pub(crate) static AFTER_SWAP_BACK: RefCell<Option<Hook>> = const { RefCell::new(None) };
        /// Makes the Nth `exchange_paths` call (1-based, counted in `EXCHANGE_COUNT`) fail
        /// with an I/O error.
        pub(crate) static EXCHANGE_FAIL_NTH: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
        pub(crate) static EXCHANGE_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        /// Makes the expected-absent publish see a filesystem without hard links.
        pub(crate) static NO_HARDLINK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        /// Overrides the slot-lock wait (attempts) so a test need not wait seconds.
        /// Makes the Nth `file_id` call (1-based, counted in `ID_COUNT`) fail.
        pub(crate) static ID_FAIL_NTH: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
        pub(crate) static ID_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        /// Forces the NEXT status-marker file name (so a test can plant a symlink there).
        pub(crate) static MARKER_NAME: RefCell<Option<String>> = const { RefCell::new(None) };
        /// Runs right after an ack renamed the overflow marker away (a lock-free writer's window).
        pub(crate) static AFTER_OVERFLOW_HELD: RefCell<Option<Hook>> = const { RefCell::new(None) };
        pub(crate) static LOCK_ATTEMPTS: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
    }
}

/// The Codex CLI version the slot-config publish protocol was verified against: Codex writes
/// the slot `config.toml` (approve, disable, enable) only by same-directory tmp-then-rename,
/// so csq's exchange sees every Codex write. `csq doctor` warns on any other installed
/// version.
pub const CODEX_EXCHANGE_VERIFIED_VERSION: &str = "0.162.1";

/// Atomically exchanges two paths. `Ok(false)` means the platform or filesystem cannot.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn exchange_paths(a: &Path, b: &Path) -> io::Result<bool> {
    #[cfg(test)]
    if test_seam::NO_EXCHANGE.with(std::cell::Cell::get) {
        return Ok(false);
    }
    #[cfg(test)]
    {
        let n = test_seam::EXCHANGE_COUNT.with(|c| {
            c.set(c.get() + 1);
            c.get()
        });
        if test_seam::EXCHANGE_FAIL_NTH.with(std::cell::Cell::get) == Some(n) {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
    }
    use std::os::unix::ffi::OsStrExt;
    let to_c = |p: &Path| {
        std::ffi::CString::new(p.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
    };
    let (ca, cb) = (to_c(a)?, to_c(b)?);
    #[cfg(target_os = "macos")]
    let rc = {
        extern "C" {
            fn renamex_np(
                from: *const libc::c_char,
                to: *const libc::c_char,
                flags: libc::c_uint,
            ) -> libc::c_int;
        }
        const RENAME_SWAP: libc::c_uint = 0x0000_0002;
        // SAFETY: both pointers are valid NUL-terminated C strings that outlive the call.
        unsafe { renamex_np(ca.as_ptr(), cb.as_ptr(), RENAME_SWAP) }
    };
    #[cfg(target_os = "linux")]
    let rc = {
        const RENAME_EXCHANGE: libc::c_uint = 2;
        // SAFETY: both pointers are valid NUL-terminated C strings that outlive the call;
        // AT_FDCWD makes them ordinary paths.
        unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                ca.as_ptr(),
                libc::AT_FDCWD,
                cb.as_ptr(),
                RENAME_EXCHANGE,
            ) as libc::c_int
        }
    };
    if rc == 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::ENOTSUP) | Some(libc::EINVAL) | Some(libc::ENOSYS) => Ok(false),
        _ => Err(e),
    }
}

/// No atomic exchange on this platform: the publish falls back to compare-then-rename.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn exchange_paths(_a: &Path, _b: &Path) -> io::Result<bool> {
    Ok(false)
}

/// Whether this platform has an atomic exchange at all (the doctor notes its absence).
#[must_use]
pub const fn atomic_exchange_available() -> bool {
    cfg!(any(target_os = "macos", target_os = "linux"))
}

fn read_slot_bytes(p: &Path) -> Option<Vec<u8>> {
    crate::session::handle_dir::read_regular_bounded(p, false)
}

fn write_config_toml_inner(
    target: &Path,
    contents: &str,
    extant: Extant<'_>,
) -> io::Result<ConditionalWrite> {
    let parent = target.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Codex config target has no parent",
        )
    })?;
    // A file csq could not read back is a file every csq reader gives up on: never publish
    // one.
    if contents.len() as u64 > SLOT_CONFIG_MAX_BYTES {
        return Err(SlotConfigFault::Oversize.error(io::ErrorKind::InvalidData));
    }
    std::fs::create_dir_all(parent)?;

    let tmp = unique_tmp_path(target);

    // §5a: `write_new_private_synced` creates the tmp file at 0o600 at
    // creation (closing the window a separate `write_and_sync` +
    // `secure_file` pair left open — config.toml's `[mcp_servers.*]` table
    // may carry user-configured MCP auth) AND fsyncs before returning,
    // preserving `write_and_sync`'s durability guarantee for this file
    // (immediately consumed by a spawned Codex subprocess).
    if let Err(e) = crate::platform::fs::write_new_private_synced(&tmp, contents.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io::Error::other(e.to_string()));
    }
    #[cfg(test)]
    test_seam::BEFORE_RENAME.with(|h| {
        if let Some(hook) = h.borrow().as_ref() {
            hook(target);
        }
    });
    match extant {
        Extant::Absent => publish_absent(&tmp, target, parent),
        Extant::Bytes(expected) => publish_by_exchange(&tmp, target, expected),
    }
}

/// Publishes `tmp` at an ABSENT `target`. A hard link never replaces: it fails when a
/// concurrent writer created the file. Where the filesystem has no hard links the fallback
/// claims the name with an exclusive create (a concurrent creator still wins, `Changed`) and
/// renames `tmp` over the claim; the claim is momentarily empty, so the slot is flagged
/// [`SlotWriteStatus::ExchangeUnsupported`].
fn publish_absent(tmp: &Path, target: &Path, config_dir: &Path) -> io::Result<ConditionalWrite> {
    #[cfg(test)]
    let linked = if test_seam::NO_HARDLINK.with(std::cell::Cell::get) {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "hard links are not supported here",
        ))
    } else {
        std::fs::hard_link(tmp, target)
    };
    #[cfg(not(test))]
    let linked = std::fs::hard_link(tmp, target);
    match linked {
        Ok(()) => {
            let _ = std::fs::remove_file(tmp);
            return Ok(ConditionalWrite::Written);
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(tmp);
            return Ok(ConditionalWrite::Changed);
        }
        Err(_) => {}
    }
    set_slot_status(config_dir, SlotWriteStatus::ExchangeUnsupported);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    match opts.open(target) {
        Ok(claim) => drop(claim),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(tmp);
            return Ok(ConditionalWrite::Changed);
        }
        Err(e) => {
            let _ = std::fs::remove_file(tmp);
            return Err(e);
        }
    }
    if let Err(e) = atomic_replace(tmp, target) {
        let _ = std::fs::remove_file(tmp);
        // Remove OUR still-empty claim; a claim a writer already filled is theirs.
        if std::fs::metadata(target).is_ok_and(|m| m.len() == 0) {
            let _ = std::fs::remove_file(target);
        }
        return Err(io::Error::other(e.to_string()));
    }
    Ok(ConditionalWrite::Written)
}

fn replace_or_cleanup(tmp: &Path, target: &Path) -> io::Result<()> {
    if let Err(e) = atomic_replace(tmp, target) {
        let _ = std::fs::remove_file(tmp);
        return Err(io::Error::other(e.to_string()));
    }
    Ok(())
}

/// `(device, inode)` of the entry at `path`, without following a final symlink.
#[cfg(unix)]
fn file_id(path: &Path) -> io::Result<(u64, u64)> {
    #[cfg(test)]
    {
        let n = test_seam::ID_COUNT.with(|c| {
            c.set(c.get() + 1);
            c.get()
        });
        if test_seam::ID_FAIL_NTH.with(std::cell::Cell::get) == Some(n) {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
    }
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path)?;
    Ok((m.dev(), m.ino()))
}

/// No file identity here (the exchange is unavailable on these platforms too).
#[cfg(not(unix))]
fn file_id(_path: &Path) -> io::Result<(u64, u64)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no file identity on this platform",
    ))
}

/// The publish-by-exchange protocol; see `write_config_toml_contents_if_unchanged` for the
/// contract and the failure branches. `tmp` holds csq's complete, fsynced file.
fn publish_by_exchange(tmp: &Path, target: &Path, expected: &[u8]) -> io::Result<ConditionalWrite> {
    let config_dir = target.parent().unwrap_or(Path::new("."));
    // csq's own file identity, recorded before anything is exchanged.
    let csq_id = match file_id(tmp) {
        Ok(id) => Some(id),
        Err(e) if e.kind() == io::ErrorKind::Unsupported => None,
        Err(e) => {
            let _ = std::fs::remove_file(tmp);
            return Err(e);
        }
    };
    let exchanged = match exchange_paths(tmp, target) {
        Ok(x) => x,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // The target vanished since the caller read it.
            let _ = std::fs::remove_file(tmp);
            return Ok(ConditionalWrite::Changed);
        }
        Err(e) => {
            let _ = std::fs::remove_file(tmp);
            return Err(e);
        }
    };
    if !exchanged {
        // No atomic exchange here: compare, then rename (the instant between them is open).
        set_slot_status(config_dir, SlotWriteStatus::ExchangeUnsupported);
        if read_slot_bytes(target).as_deref() != Some(expected) {
            let _ = std::fs::remove_file(tmp);
            return Ok(ConditionalWrite::Changed);
        }
        return replace_or_cleanup(tmp, target).map(|()| ConditionalWrite::Written);
    }
    #[cfg(test)]
    test_seam::AFTER_EXCHANGE.with(|h| {
        if let Some(hook) = h.borrow().as_ref() {
            hook(target);
        }
    });
    // Every failure branch below flags the slot; `keep` leaves the tmp path alone.
    let raced = |keep_tmp: bool| {
        if !keep_tmp {
            let _ = std::fs::remove_file(tmp);
        }
        set_slot_status(config_dir, SlotWriteStatus::Raced);
        io::Error::other(ExchangeRaced)
    };
    // `tmp` now holds the file csq displaced from `target`. Record its identity, then judge
    // it. On a metadata error nothing more is done: csq cannot tell what is where.
    let Some(csq_id) = csq_id else {
        return Err(raced(true));
    };
    let Ok(displaced_id) = file_id(tmp) else {
        return Err(raced(true));
    };
    if read_slot_bytes(tmp).as_deref() == Some(expected) {
        let _ = std::fs::remove_file(tmp);
        return Ok(ConditionalWrite::Written);
    }
    // A concurrent writer landed first (or the displaced file is unreadable): swap back so
    // its file is `target` again.
    match exchange_paths(tmp, target) {
        Ok(true) => {}
        _ => {
            // The swap-back did not happen: `target` holds csq's file, `tmp` the displaced
            // one. Put the displaced file back with a plain replace.
            // If even that fails the tmp file is kept; the slot is flagged either way.
            let _restored = atomic_replace(tmp, target);
            return Err(raced(true));
        }
    }
    #[cfg(test)]
    test_seam::AFTER_SWAP_BACK.with(|h| {
        if let Some(hook) = h.borrow().as_ref() {
            hook(target);
        }
    });
    // What the swap-back displaced from `target` is at `tmp`: csq's own file (identity, not
    // bytes) when nothing else landed.
    let Ok(back_id) = file_id(tmp) else {
        return Err(raced(true));
    };
    if back_id == csq_id {
        let _ = std::fs::remove_file(tmp);
        return Ok(ConditionalWrite::Changed);
    }
    if back_id == displaced_id {
        // Neither a third file nor csq's: the state is not what the protocol produces.
        return Err(raced(true));
    }
    // A THIRD file (a newer concurrent write) was displaced by the swap-back: `target` holds
    // the older displaced file. Put the newest back, verify, and refuse.
    match exchange_paths(tmp, target) {
        Ok(true) => match file_id(tmp) {
            Ok(id) if id == displaced_id => Err(raced(false)),
            _ => Err(raced(true)),
        },
        _ => {
            // The newest is at `tmp`, the older at `target`: restore the newest.
            let _ = atomic_replace(tmp, target);
            Err(raced(true))
        }
    }
}

/// Per-slot condition of csq's slot-config writes, kept in `config-<N>/` for `csq doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SlotWriteStatus {
    /// A concurrent write raced an atomic exchange that could not be fully undone, or a
    /// publish left a tmp file behind; csq's update may be in place over a concurrent Codex
    /// write, so the owner should re-check this slot's hook approvals. STICKY: no publish
    /// clears it; only the owner's acknowledgement does ([`ack_slot_raced`]).
    Raced,
    /// No atomic exchange on this platform or filesystem: a Codex write landing between csq's
    /// compare and rename can still be overwritten.
    ExchangeUnsupported,
    /// A purge of this slot's stale hook approvals (a reused PID's, or a dead handle's) did
    /// not complete. Kept per handle: cleared only by a successful purge of THIS slot by THAT
    /// handle (or once that handle's dir is gone and its keys are pruned).
    PurgeFailed,
    /// A create-time carry of hook approvals was skipped (the config kept changing, a raced
    /// exchange, an unusable hooks file, a config near the size bound); the new terminal
    /// starts untrusted. Kept per handle: cleared only when THAT handle's carry completes (or
    /// once the handle is gone).
    CarrySkipped,
    /// A lock-free status marker csq cannot classify (unknown kind, unparseable, not a plain
    /// file, or a marker directory that is not a plain directory). Never written by csq, never
    /// cleared by the raced ack: the owner inspects and removes it manually.
    UnrecognisedMarker,
}

const ALL_STATUSES: [SlotWriteStatus; 4] = [
    SlotWriteStatus::Raced,
    SlotWriteStatus::ExchangeUnsupported,
    SlotWriteStatus::PurgeFailed,
    SlotWriteStatus::CarrySkipped,
];

impl SlotWriteStatus {
    /// The fixed status word used in the status file, markers, doctor JSON and the desktop.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Raced => "raced",
            Self::ExchangeUnsupported => "exchange-unsupported",
            Self::PurgeFailed => "purge-failed",
            Self::CarrySkipped => "carry-skipped",
            Self::UnrecognisedMarker => "unrecognised-marker",
        }
    }
}

/// One line of the status file: a status, and for the per-handle statuses the handle dir
/// name (`term-<pid>`, ...) it is about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StatusLine {
    status: SlotWriteStatus,
    handle: Option<String>,
}

/// A handle dir name safe to store in the line-oriented status file.
fn valid_handle_name(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 128
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

impl StatusLine {
    fn parse(line: &str) -> Option<Self> {
        let (word, rest) = match line.split_once(' ') {
            Some((w, r)) => (w, Some(r)),
            None => (line, None),
        };
        let status = ALL_STATUSES.iter().copied().find(|s| s.word() == word)?;
        let handle = match rest {
            None => None,
            Some(h) if valid_handle_name(h) => Some(h.to_owned()),
            Some(_) => return None,
        };
        Some(Self { status, handle })
    }

    fn render(&self) -> String {
        match &self.handle {
            Some(h) => format!("{} {h}\n", self.status.word()),
            None => format!("{}\n", self.status.word()),
        }
    }
}

const SLOT_STATUS_FILE: &str = ".csq-config-write-status";

/// File-name prefix of every csq slot-config tmp file (`unique_tmp_path` of `config.toml`).
const CONFIG_TMP_PREFIX: &str = "config.tmp.";

/// The statuses recorded for slot `account` (read-only; unreadable means none known).
#[must_use]
pub fn slot_write_statuses(base_dir: &Path, account: AccountNum) -> Vec<SlotWriteStatus> {
    let dir = base_dir.join(format!("config-{account}"));
    read_statuses(&dir)
}

fn read_lines(dir: &Path) -> Vec<StatusLine> {
    let text = std::fs::read_to_string(dir.join(SLOT_STATUS_FILE)).unwrap_or_default();
    let mut out: Vec<StatusLine> = text.lines().filter_map(StatusLine::parse).collect();
    out.sort();
    out.dedup();
    out
}

fn read_statuses(dir: &Path) -> Vec<SlotWriteStatus> {
    let mut out: Vec<SlotWriteStatus> = read_lines(dir).into_iter().map(|l| l.status).collect();
    out.extend(read_markers(dir));
    out.sort();
    out.dedup();
    out
}

/// Publishes the status file by tmp + fsync + rename (a concurrent doctor read never sees a
/// truncated file); an empty set removes it. The caller holds the slot lock.
fn store_lines(dir: &Path, set: &[StatusLine]) -> io::Result<()> {
    let path = dir.join(SLOT_STATUS_FILE);
    if set.is_empty() {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    let text: String = set.iter().map(StatusLine::render).collect();
    let tmp = unique_tmp_path(&path);
    if let Err(e) = crate::platform::fs::write_new_private_synced(&tmp, text.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io::Error::other(e.to_string()));
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io::Error::other(e.to_string()));
    }
    Ok(())
}

fn update_lines(dir: &Path, f: impl FnOnce(&mut Vec<StatusLine>) -> bool) {
    let mut set = read_lines(dir);
    if !f(&mut set) {
        return;
    }
    set.sort();
    set.dedup();
    if store_lines(dir, &set).is_err() {
        tracing::warn!(
            error_kind = "codex_slot_status_write_failed",
            "could not record a slot config write status"
        );
    }
}

/// Records `status` for the slot dir. The CALLER HOLDS the slot lock
/// (`lock_slot_config`); a failure is logged with a fixed tag, never silent.
pub(crate) fn set_slot_status(dir: &Path, status: SlotWriteStatus) {
    update_lines(dir, |set| {
        let line = StatusLine {
            status,
            handle: None,
        };
        if set.contains(&line) {
            return false;
        }
        set.push(line);
        true
    });
}

/// Records (`set`) or clears a per-handle `status` for slot `account`, under the slot lock
/// (the status file is a read-modify-write, so unlocked updates lose each other's flags). A
/// clear removes THIS handle's line and the lines of handles whose dir is gone (their keys
/// are pruned by any successful rewrite); another live handle's line is never touched. A
/// lock timeout is logged with a fixed tag: the flag is advisory, the launch decision never
/// depends on it.
pub(crate) fn note_handle_status(
    base_dir: &Path,
    account: AccountNum,
    status: SlotWriteStatus,
    handle: &str,
    set: bool,
) {
    let dir = base_dir.join(format!("config-{account}"));
    if !set
        && std::fs::symlink_metadata(dir.join(SLOT_STATUS_FILE)).is_err()
        && std::fs::symlink_metadata(dir.join(SLOT_MARKER_DIR)).is_err()
    {
        return; // nothing recorded, nothing to clear
    }
    let Ok(_lock) = lock_slot_config(base_dir, account) else {
        tracing::warn!(
            error_kind = "codex_slot_status_lock_failed",
            "could not take the slot lock to update a slot config write status"
        );
        if set {
            // The flag cannot be recorded under the lock, so record the EVENT lock-free: a
            // per-event marker file that doctor reads and the owner's ack clears.
            if let Err(e) = write_status_marker_in(&dir, status, Some(handle)) {
                tracing::warn!(
                    error_kind = "codex_slot_status_marker_failed",
                    io_kind = ?e.kind(),
                    "could not record a slot config write status marker"
                );
            }
        }
        return;
    };
    let gone = |name: &str| {
        matches!(
            std::fs::symlink_metadata(base_dir.join(name)),
            Err(e) if e.kind() == io::ErrorKind::NotFound
        )
    };
    update_lines(&dir, |lines| {
        if set {
            if !valid_handle_name(handle) {
                return false;
            }
            let line = StatusLine {
                status,
                handle: Some(handle.to_owned()),
            };
            if lines.contains(&line) {
                return false;
            }
            lines.push(line);
            true
        } else {
            let before = lines.len();
            lines.retain(|l| {
                l.status != status || l.handle.as_deref().is_none_or(|h| h != handle && !gone(h))
            });
            lines.len() != before
        }
    });
    if !set {
        // The same clear rule for the lock-free markers: THIS handle's own marker of this
        // kind, and markers of handles whose dir is gone. Handle-less, other-kind and
        // unrecognised markers are never touched here.
        if let Err(e) = clear_handle_markers(&dir, status, handle, &gone) {
            tracing::warn!(
                error_kind = "codex_slot_status_marker_clear_failed",
                io_kind = ?e.kind(),
                "could not clear a slot config write status marker"
            );
        }
    }
}

/// Directory (inside `config-<N>/`) holding the lock-free per-event status markers.
const SLOT_MARKER_DIR: &str = ".csq-status-markers";

/// Longest marker content read back (one `<kind> <handle>` line, or the overflow kind lines).
const MARKER_READ_CAP: u64 = 512;

/// Most per-event markers one slot keeps. The next event writes ONE overflow marker instead.
const MARKER_CAP: usize = 32;

/// File-name prefix of the overflow marker (and of its held copy during an ack).
const OVERFLOW_PREFIX: &str = "overflow";

static MARKER_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Records one status EVENT for slot `account` without taking the slot lock: a new file
/// `config-<N>/.csq-status-markers/<kind>.<pid>.<n>.<nanos>`, created `O_CREAT|O_EXCL|O_NOFOLLOW`
/// at 0600 and holding one `<kind>` line (plus ` <handle dir name>` for a per-handle event;
/// this entry point records none). It is the fallback for a status-file update whose slot-lock
/// wait timed out, so the event is never lost. `csq doctor` reports every marker and is never
/// OK while one exists. Only `raced` markers are cleared by the owner's ack
/// ([`ack_slot_raced`]); `purge-failed` and `carry-skipped` markers clear like their status-file
/// lines (by that handle's own success, or once its dir is gone). A slot keeps at most
/// `MARKER_CAP` markers: further events fold into ONE overflow marker (see `note_overflow`).
///
/// # Errors
/// The marker directory is a symlink or cannot be made, or the marker cannot be created.
pub fn write_status_marker(
    base_dir: &Path,
    account: AccountNum,
    status: SlotWriteStatus,
) -> io::Result<()> {
    write_status_marker_in(&base_dir.join(format!("config-{account}")), status, None)
}

fn open_marker_dir(slot_dir: &Path) -> io::Result<PathBuf> {
    let dir = slot_dir.join(SLOT_MARKER_DIR);
    match std::fs::symlink_metadata(&dir) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            return Err(io::Error::other(
                "status marker directory is not a plain directory",
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            #[cfg(unix)]
            let b = {
                use std::os::unix::fs::DirBuilderExt as _;
                let mut b = std::fs::DirBuilder::new();
                b.mode(0o700);
                b
            };
            #[cfg(not(unix))]
            let b = std::fs::DirBuilder::new();
            match b.create(&dir) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(e) => return Err(e),
    }
    Ok(dir)
}

/// Opens `path` for a new private marker file: create-new (`O_EXCL`), `O_NOFOLLOW`, 0600.
fn create_marker_file(path: &Path, append: bool) -> io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    if append {
        opts.append(true);
    } else {
        opts.write(true).create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

fn write_status_marker_in(
    slot_dir: &Path,
    status: SlotWriteStatus,
    handle: Option<&str>,
) -> io::Result<()> {
    use std::io::Write as _;
    if status == SlotWriteStatus::UnrecognisedMarker {
        return Err(io::Error::other("an unrecognised marker is never written"));
    }
    let dir = open_marker_dir(slot_dir)?;
    if count_event_markers(&dir) >= MARKER_CAP {
        return note_overflow(&dir, status);
    }
    let line = StatusLine {
        status,
        handle: handle.filter(|h| valid_handle_name(h)).map(str::to_owned),
    }
    .render();
    #[cfg(test)]
    let mut forced = test_seam::MARKER_NAME.with(|c| c.borrow_mut().take());
    #[cfg(not(test))]
    let mut forced: Option<String> = None;
    for _ in 0..8 {
        let name = forced.take().unwrap_or_else(|| {
            let n = MARKER_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            format!("{}.{}.{n}.{nanos:x}", status.word(), std::process::id())
        });
        let path = dir.join(name);
        match create_marker_file(&path, false) {
            Ok(mut f) => {
                if let Err(e) = f.write_all(line.as_bytes()) {
                    drop(f);
                    let _ = std::fs::remove_file(&path);
                    return Err(e);
                }
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other(
        "could not pick a unique status marker name",
    ))
}

/// Per-event markers in `dir` (the overflow marker is not counted). An unreadable directory
/// counts as full, so the event folds into the overflow marker instead of being lost.
fn count_event_markers(dir: &Path) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return usize::MAX;
    };
    rd.flatten()
        .filter(|e| !e.file_name().to_string_lossy().starts_with(OVERFLOW_PREFIX))
        .count()
}

/// Folds an event the cap turned away into the ONE overflow marker `overflow`, which records
/// the KIND of every dropped event (one `overflow <kind>` line per distinct kind, no handle).
/// It reads as exactly those kinds, so a dropped event is never silent. Attribution: the ack
/// clears the overflow marker only when every kind it records is `raced`, i.e. only when it
/// clears the raced events it stood for; one that dropped any other kind stays (the dropped
/// event's handle is unknown, so no handle's success can prove it resolved) until removed
/// manually.
fn note_overflow(dir: &Path, status: SlotWriteStatus) -> io::Result<()> {
    use std::io::Write as _;
    let path = dir.join(OVERFLOW_PREFIX);
    let line = format!("{OVERFLOW_PREFIX} {}\n", status.word());
    match create_marker_file(&path, false) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(line.as_bytes()) {
                drop(f);
                let _ = std::fs::remove_file(&path);
                return Err(e);
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            if read_capped(&path).is_some_and(|t| t.lines().any(|l| l == line.trim_end())) {
                return Ok(());
            }
            create_marker_file(&path, true)?.write_all(line.as_bytes())
        }
        Err(e) => Err(e),
    }
}

/// What one marker file is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Marker {
    /// One recorded event: its kind and, for a per-handle kind, the handle dir name.
    Event(StatusLine),
    /// The overflow marker and the kinds of the events it folded.
    Overflow(Vec<SlotWriteStatus>),
    /// Anything else: unknown kind, unparseable, not a plain file.
    Unrecognised,
}

fn read_capped(path: &Path) -> Option<String> {
    use std::io::Read as _;
    if !std::fs::symlink_metadata(path).ok()?.is_file() {
        return None;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut text = String::new();
    opts.open(path)
        .ok()?
        .take(MARKER_READ_CAP)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

fn classify_marker(path: &Path) -> Marker {
    let Some(text) = read_capped(path) else {
        return Marker::Unrecognised;
    };
    let is_overflow = path
        .file_name()
        .is_some_and(|n| n.to_string_lossy().starts_with(OVERFLOW_PREFIX));
    if is_overflow {
        let kinds: Option<Vec<SlotWriteStatus>> = text
            .lines()
            .map(|l| {
                let word = l.strip_prefix(OVERFLOW_PREFIX)?.strip_prefix(' ')?;
                ALL_STATUSES.iter().copied().find(|s| s.word() == word)
            })
            .collect();
        return match kinds {
            Some(k) if !k.is_empty() => Marker::Overflow(k),
            _ => Marker::Unrecognised,
        };
    }
    let one = text.strip_suffix('\n').unwrap_or(&text);
    if one.contains('\n') {
        return Marker::Unrecognised;
    }
    StatusLine::parse(one).map_or(Marker::Unrecognised, Marker::Event)
}

/// The statuses of every marker in `slot_dir`. Fails CLOSED: anything that is not a recognised
/// marker (unknown kind, unparseable, a symlink, a marker directory that is not a plain
/// directory) reads as `UnrecognisedMarker` (never OK), never as "no marker".
fn read_markers(slot_dir: &Path) -> Vec<SlotWriteStatus> {
    let dir = slot_dir.join(SLOT_MARKER_DIR);
    match std::fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Ok(m) if m.is_dir() => {}
        _ => return vec![SlotWriteStatus::UnrecognisedMarker],
    }
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return vec![SlotWriteStatus::UnrecognisedMarker];
    };
    let mut out = Vec::new();
    for entry in rd {
        match entry.map(|e| classify_marker(&e.path())) {
            Ok(Marker::Event(l)) => out.push(l.status),
            Ok(Marker::Overflow(kinds)) => out.extend(kinds),
            Ok(Marker::Unrecognised) | Err(_) => out.push(SlotWriteStatus::UnrecognisedMarker),
        }
    }
    out
}

/// True when slot `account` has an overflow marker (`note_overflow`) that the raced ack will
/// not clear: it recorded a non-raced kind, or its body is unrecognised. Read-only. Such a
/// marker is removed manually: `config-<N>/.csq-status-markers/overflow`.
#[must_use]
pub fn slot_overflow_stuck(base_dir: &Path, account: AccountNum) -> bool {
    let dir = base_dir
        .join(format!("config-{account}"))
        .join(SLOT_MARKER_DIR);
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return false;
    };
    rd.flatten().any(|e| {
        e.file_name().to_string_lossy().starts_with(OVERFLOW_PREFIX)
            && match classify_marker(&e.path()) {
                Marker::Overflow(k) => k.iter().any(|k| *k != SlotWriteStatus::Raced),
                Marker::Unrecognised => true,
                Marker::Event(_) => false,
            }
    })
}

/// Removes the RACED markers of `slot_dir` (and an overflow marker that stood only for raced
/// events); the caller holds the slot lock. Every other marker stays. A marker that cannot be
/// removed is an error (it, and so the flag, stays).
fn clear_raced_markers(slot_dir: &Path) -> io::Result<usize> {
    let dir = slot_dir.join(SLOT_MARKER_DIR);
    match std::fs::symlink_metadata(&dir) {
        Ok(m) if m.is_dir() => {}
        // Absent: nothing to clear. Anything else squatting the name is unrecognised: stays.
        _ => return Ok(0),
    }
    let mut removed = 0;
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        match classify_marker(&path) {
            Marker::Event(l) if l.status == SlotWriteStatus::Raced => {
                std::fs::remove_file(&path)?;
                removed += 1;
            }
            Marker::Overflow(kinds) if kinds.iter().all(|k| *k == SlotWriteStatus::Raced) => {
                removed += take_raced_overflow(&dir, &path)?;
            }
            _ => {}
        }
    }
    // Teardown of an emptied directory: fails (harmlessly) while any marker remains.
    let _ = std::fs::remove_dir(&dir);
    Ok(removed)
}

/// Removes an all-raced overflow marker without losing a kind a lock-free writer appends
/// meanwhile: the marker is renamed away first (a new overflow event then starts a fresh
/// `overflow`), the held copy re-read, and removed only if it still records raced events only;
/// otherwise it is put back (or, if a new overflow marker already exists, kept under its held
/// name, which still reads as an overflow marker).
fn take_raced_overflow(dir: &Path, path: &Path) -> io::Result<usize> {
    let n = MARKER_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let held = dir.join(format!("{OVERFLOW_PREFIX}.held.{}.{n}", std::process::id()));
    std::fs::rename(path, &held)?;
    #[cfg(test)]
    test_seam::AFTER_OVERFLOW_HELD.with(|c| {
        if let Some(f) = c.borrow().as_ref() {
            f(dir);
        }
    });
    match classify_marker(&held) {
        Marker::Overflow(k) if k.iter().all(|k| *k == SlotWriteStatus::Raced) => {
            std::fs::remove_file(&held)?;
            Ok(1)
        }
        _ => {
            if std::fs::hard_link(&held, path).is_ok() {
                std::fs::remove_file(&held)?;
            }
            Ok(0)
        }
    }
}

/// Removes the markers a successful per-handle clear resolves: kind `status`, recorded for
/// `handle` or for a handle whose dir is gone. The caller holds the slot lock.
fn clear_handle_markers(
    slot_dir: &Path,
    status: SlotWriteStatus,
    handle: &str,
    gone: &dyn Fn(&str) -> bool,
) -> io::Result<()> {
    let dir = slot_dir.join(SLOT_MARKER_DIR);
    match std::fs::symlink_metadata(&dir) {
        Ok(m) if m.is_dir() => {}
        _ => return Ok(()),
    }
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        if let Marker::Event(l) = classify_marker(&path) {
            if l.status == status && l.handle.as_deref().is_some_and(|h| h == handle || gone(h)) {
                std::fs::remove_file(&path)?;
            }
        }
    }
    let _ = std::fs::remove_dir(&dir);
    Ok(())
}

/// What [`ack_slot_raced`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckOutcome {
    /// A `raced` flag was recorded and is now cleared.
    pub cleared: bool,
    /// Leftover `config.tmp.*` files that were removed.
    pub tmp_removed: usize,
    /// Raced lock-free status markers ([`write_status_marker`]) that were removed.
    pub markers_removed: usize,
}

/// The owner's acknowledgement of a `raced` slot (`csq doctor --ack-raced <N>`): under the
/// slot lock, removes the leftover `config.tmp.*` files of crashed or raced publishes (the
/// owner has re-checked this slot's hook approvals), clears the sticky flag and removes the
/// RACED lock-free status markers ([`write_status_marker`]). It never clears a `purge-failed`,
/// `carry-skipped` or unrecognised marker (only that handle's own success does, r4 items 4/5),
/// nor an overflow marker that dropped a non-raced event. No publish ever does any of these.
///
/// # Errors
/// The slot has no config dir, the lock times out, or a leftover cannot be removed (the flag
/// then stays).
pub fn ack_slot_raced(base_dir: &Path, account: AccountNum) -> io::Result<AckOutcome> {
    let dir = base_dir.join(format!("config-{account}"));
    if !dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no such Codex slot config dir",
        ));
    }
    let _lock = lock_slot_config(base_dir, account)?;
    let mut tmp_removed = 0;
    for tmp in stale_config_tmps(&dir) {
        std::fs::remove_file(&tmp)?;
        tmp_removed += 1;
    }
    let mut cleared = false;
    let mut set = read_lines(&dir);
    let before = set.len();
    set.retain(|l| l.status != SlotWriteStatus::Raced);
    if set.len() != before {
        store_lines(&dir, &set)?;
        cleared = true;
    }
    let markers_removed = clear_raced_markers(&dir)?;
    Ok(AckOutcome {
        cleared,
        tmp_removed,
        markers_removed,
    })
}

/// Regular files in `dir` named like a csq slot-config tmp file.
fn stale_config_tmps(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(CONFIG_TMP_PREFIX))
                && e.file_type().is_ok_and(|t| t.is_file())
        })
        .map(|e| e.path())
        .collect()
}

/// A leftover tmp file can only come from a publish that stopped part-way (every csq writer
/// holds the slot lock for the whole life of its tmp file, and the lock is held here), so it
/// may hold a concurrent Codex write csq displaced: flag the slot `raced`, never delete.
fn flag_stale_config_tmps(dir: &Path) {
    if !stale_config_tmps(dir).is_empty() {
        set_slot_status(dir, SlotWriteStatus::Raced);
    }
}

/// How long a csq slot-config writer waits for the per-slot lock (attempts x delay).
const SLOT_CONFIG_LOCK_ATTEMPTS: u32 = 100;
const SLOT_CONFIG_LOCK_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

/// The per-slot lock every csq writer of `config-<N>/config.toml` holds across its
/// read-render-write: [`regenerate_slot_config`], [`write_config_toml_with_global`], the
/// Codex hook-trust carry and `trust::sync_slot_project_trust`; and every update of the
/// slot status file. One lock file per slot, opened `O_NOFOLLOW` 0o600; the wait is
/// bounded (`SLOT_CONFIG_LOCK_ATTEMPTS` x `SLOT_CONFIG_LOCK_DELAY`) and a timeout is an
/// error, never a write without the lock. Not re-entrant: a holder must not call another
/// locking writer. It serializes csq's own writers only; Codex takes no lock. Taking the
/// lock also flags any leftover `config.tmp.*` in the slot dir as `raced`
/// ([`flag_stale_config_tmps`]).
pub(crate) fn lock_slot_config(
    base_dir: &Path,
    account: AccountNum,
) -> io::Result<crate::platform::lock::FileLockGuard> {
    let dir = base_dir.join(format!("config-{account}"));
    std::fs::create_dir_all(&dir)?;
    #[cfg(test)]
    let attempts = test_seam::LOCK_ATTEMPTS
        .with(std::cell::Cell::get)
        .unwrap_or(SLOT_CONFIG_LOCK_ATTEMPTS);
    #[cfg(not(test))]
    let attempts = SLOT_CONFIG_LOCK_ATTEMPTS;
    match crate::platform::lock::try_lock_file_bounded_nofollow(
        &dir.join(SLOT_CONFIG_LOCK_FILENAME),
        attempts,
        SLOT_CONFIG_LOCK_DELAY,
    ) {
        Ok(Some(guard)) => {
            flag_stale_config_tmps(&dir);
            Ok(guard)
        }
        Ok(None) => Err(SlotConfigFault::Locked.error(io::ErrorKind::WouldBlock)),
        Err(e) => Err(io::Error::other(e.to_string())),
    }
}

/// Publishes the exact rendered snapshot the caller already compared/validated.
pub(super) fn write_config_toml_contents(target: &Path, contents: &str) -> io::Result<()> {
    let parent = target.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Codex config target has no parent",
        )
    })?;
    std::fs::create_dir_all(parent)?;

    let tmp = unique_tmp_path(target);

    // §5a: `write_new_private_synced` creates the tmp file at 0o600 at
    // creation (closing the window a separate `write_and_sync` +
    // `secure_file` pair left open — config.toml's `[mcp_servers.*]` table
    // may carry user-configured MCP auth) AND fsyncs before returning,
    // preserving `write_and_sync`'s durability guarantee for this file
    // (immediately consumed by a spawned Codex subprocess).
    if let Err(e) = crate::platform::fs::write_new_private_synced(&tmp, contents.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io::Error::other(e.to_string()));
    }
    if let Err(e) = atomic_replace(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io::Error::other(e.to_string()));
    }
    Ok(())
}

/// Outcome of [`regenerate_slot_config`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegenOutcome {
    /// On-disk `config-<N>/config.toml` already byte-equals the desired
    /// re-merge; nothing was written.
    AlreadyCurrent,
    /// The slot config was rewritten from the merge.
    Rewritten {
        /// The explicit per-slot `model` preserved into the rewrite, or
        /// `None` when the slot carries no explicit model (csq wrote none —
        /// the user-global `model`, if any, propagates and otherwise codex
        /// uses its built-in default). csq NEVER injects a catalog default.
        model: Option<String>,
        /// True when the rewrite happened DESPITE a present-but-malformed
        /// `~/.codex` (merge base fell back to the slot's own config; new
        /// global keys could not be pulled). Callers surface the same
        /// "your global is invalid" operator note as for
        /// [`RegenOutcome::SkippedMalformedGlobal`] in this case.
        was_global_malformed: bool,
    },
    /// The user-global `~/.codex/config.toml` is present but not valid
    /// TOML AND the existing slot config was already canonical (the
    /// re-merge from the slot's own config produced byte-identical
    /// content), so nothing was written. The slot is KEPT as-is rather
    /// than wiped to the degraded 2-key fallback. The operator should be
    /// told their global is invalid (edits are not propagating). If a
    /// csq-controlled key had drifted, the outcome is [`RegenOutcome::Rewritten`]
    /// (the repair still runs under a malformed global) — not this variant.
    SkippedMalformedGlobal,
}

/// Regenerates `config-<N>/config.toml` by re-merging the CURRENT
/// user-global `~/.codex/config.toml`, preserving the slot's existing
/// explicit top-level `model` key IF present and its slot-owned `[agents]`
/// and `[features.multi_agent_v2]` tables. Other keys refresh from the
/// legacy-selected global, including removal of deleted keys, except project
/// trust: canonical-source failure preserves existing projects. When the slot carries no
/// explicit model, csq writes NONE — the user-global `model` propagates
/// (or codex's built-in default applies); csq NEVER injects its catalog
/// default (CC-parity). Idempotent — returns [`RegenOutcome::AlreadyCurrent`]
/// without writing when the on-disk content already matches.
///
/// This is the single source of the "re-merge `~/.codex` preserving
/// model" operation. Two boundaries call it:
///
/// - the daemon startup reconciler (`pass2_codex_config_toml`), once per
///   daemon start, and
/// - `csq run <codex-slot>` (`launch_codex`), on every launch — so
///   `~/.codex` is the single source of truth for live Codex slots,
///   matching the Claude Code `~/.claude` live-link model.
///
/// # Malformed-global safety
///
/// A present-but-malformed `~/.codex/config.toml` MUST NOT be used as the
/// merge base — [`render_config_toml_with_global`] would degrade it to the
/// bare 2-key fallback, wiping every previously-merged user key. So on a
/// malformed global the merge base falls back to the slot's OWN existing
/// `config.toml` (csq-written, therefore valid TOML). This:
///
/// - preserves the slot's already-merged user keys (they live in the
///   existing config) AND the slot's explicit `model` if it has one, AND
/// - keeps re-asserting the global-INDEPENDENT csq-controlled key
///   (`cli_auth_credentials_store`) — so a malformed global never
///   SUPPRESSES that repair (e.g. an auth-store directive drifted to
///   `"keychain"` is still corrected back to `"file"`).
///
/// New keys cannot be pulled from the malformed global (it is unparseable)
/// — the correct "keep what we have, tell the operator" result. When the
/// existing slot config is ALREADY canonical, this is a no-op and the
/// outcome is [`RegenOutcome::SkippedMalformedGlobal`] (operator gets the
/// "your global is invalid" note); when a csq-controlled key had drifted,
/// the repair writes and the outcome is [`RegenOutcome::Rewritten`]. A
/// legitimately ABSENT global (`None`) is not malformed — defaults apply.
///
/// The legacy-selected global, canonical trust source, and existing slot each
/// have one read per attempt. The rendered snapshot is published only if the bytes read
/// under the lock are still on disk at the atomic exchange (`write_config_toml_contents_if_unchanged`),
/// re-rendered up to `PUBLISH_ATTEMPTS` times otherwise. csq's own slot-config writers are
/// serialized by `lock_slot_config`; Codex's own writes take no lock.
pub fn regenerate_slot_config(base_dir: &Path, account: AccountNum) -> io::Result<RegenOutcome> {
    let _slot_lock = lock_slot_config(base_dir, account)?;
    let toml_path = config_toml_path(base_dir, account);
    for _ in 0..PUBLISH_ATTEMPTS {
        let existing = read_existing_config_toml(&toml_path)?;
        // Preserve the slot's explicit per-slot model IF present; otherwise None.
        // csq does NOT inject its catalog default (the fix for the stale-default
        // bug): an absent model means the user-global `model` propagates and, absent
        // that, codex uses its built-in default.
        let model = existing.as_deref().and_then(extract_model_key);

        let user_global = read_user_global_config_toml();
        let global_malformed = matches!(
            user_global.as_deref(),
            Some(ug) if toml::from_str::<toml::Value>(ug).is_err()
        );

        // Merge base: the valid user-global normally; the slot's own existing
        // config when the global is malformed (so user keys survive AND
        // csq-controlled keys are still re-asserted — see the doc above).
        let merge_base = if global_malformed {
            existing.as_deref()
        } else {
            user_global.as_deref()
        };

        let owner = read_status_line_owner(&toml_path);
        let desired = render_slot_config_toml_with_ownership_global(
            base_dir,
            model.as_deref(),
            merge_base,
            existing.as_deref(),
            owner.as_deref(),
            user_global.as_deref(),
        )?;
        if existing.as_deref() == Some(desired.contents.as_str()) {
            // Seed/repair ownership even when config bytes need no rewrite.
            write_status_line_owner(&toml_path, &desired)?;
            // Nothing to write. A malformed global still warrants the operator
            // note (their edits are not propagating), so distinguish it.
            return Ok(if global_malformed {
                RegenOutcome::SkippedMalformedGlobal
            } else {
                RegenOutcome::AlreadyCurrent
            });
        }

        if publish_slot_config(&toml_path, existing.as_deref(), &desired)?
            == ConditionalWrite::Written
        {
            return Ok(RegenOutcome::Rewritten {
                model,
                was_global_malformed: global_malformed,
            });
        }
    }
    Err(publish_gave_up())
}

/// Extracts the value of the top-level `model = "..."` key, if present.
/// Returns the unquoted string. Tolerates leading/trailing whitespace
/// and inline `# comments`. Shared by [`regenerate_slot_config`]
/// and the daemon startup reconciler.
pub(crate) fn extract_model_key(toml: &str) -> Option<String> {
    for raw in toml.lines() {
        let line = raw.split('#').next().unwrap_or(raw).trim();
        let Some(rest) = line.strip_prefix("model") else {
            continue;
        };
        // `continue`, NOT `?`: a `model`-PREFIXED key that is not exactly
        // `model` (e.g. `model_provider`, `model_reasoning_effort`) has no
        // top-level `=` after the `model` prefix — skip it and keep scanning
        // for the real `model = "..."` line rather than aborting the search.
        let Some(after_eq) = rest.trim_start().strip_prefix('=').map(|s| s.trim()) else {
            continue;
        };
        // Strip quotes (double or single) on both ends.
        if let Some(inner) = after_eq.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            return Some(inner.to_string());
        }
        if let Some(inner) = after_eq
            .strip_prefix('\'')
            .and_then(|s| s.strip_suffix('\''))
        {
            return Some(inner.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn acc(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    /// Asserts the rendered config (a) is valid TOML and (b) carries csq's
    /// curated default `tui.status_line` in its exact order.
    fn assert_default_statusline_present(out: &str) {
        let parsed = toml::from_str::<toml::Value>(out).unwrap();
        assert!(status_line_matches(
            &parsed["tui"]["status_line"],
            CSQ_DEFAULT_STATUS_LINE
        ));
    }

    /// Holds the workspace-wide env mutex + a deterministic
    /// CODEX_USER_CONFIG override. Tests that call write_config_toml or
    /// read_user_global_config_toml acquire this guard to be insulated
    /// from (a) the dev machine's actual `~/.codex/config.toml` and
    /// (b) concurrent tests in this module that set CODEX_USER_CONFIG.
    ///
    /// Default behavior: points the override at a nonexistent path so
    /// `read_user_global_config_toml` returns None and `write_config_toml`
    /// emits the 2-key fallback. Pass `Some(content)` to install a
    /// fixture file and exercise the merge path.
    struct EnvGuard {
        _shared: crate::platform::test_env::EnvTestGuard,
        prev: Option<std::ffi::OsString>,
        _fixture_dir: Option<TempDir>,
    }

    impl EnvGuard {
        /// The directory holding the fixture user-global config (the test stand-in for
        /// `~/.codex`).
        fn global_home(&self) -> PathBuf {
            self._fixture_dir.as_ref().unwrap().path().to_path_buf()
        }

        fn new_isolated() -> Self {
            let shared = crate::platform::test_env::lock();
            let prev = std::env::var_os(USER_CONFIG_ENV_OVERRIDE);
            // SAFETY: test_env::lock serialises env mutations across the
            // workspace per rules/testing.md MUST Rule 6.
            unsafe {
                std::env::set_var(
                    USER_CONFIG_ENV_OVERRIDE,
                    "/nonexistent/csq-codex-surface-test-isolated",
                );
            }
            Self {
                _shared: shared,
                prev,
                _fixture_dir: None,
            }
        }

        fn new_with_fixture(content: &str) -> Self {
            let shared = crate::platform::test_env::lock();
            let prev = std::env::var_os(USER_CONFIG_ENV_OVERRIDE);
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("user-config.toml");
            std::fs::write(&path, content).unwrap();
            // SAFETY: test_env::lock serialises env mutations.
            unsafe {
                std::env::set_var(USER_CONFIG_ENV_OVERRIDE, &path);
            }
            Self {
                _shared: shared,
                prev,
                _fixture_dir: Some(dir),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: test_env::lock is held by self until end of drop.
            unsafe {
                match self.prev.take() {
                    Some(v) => std::env::set_var(USER_CONFIG_ENV_OVERRIDE, v),
                    None => std::env::remove_var(USER_CONFIG_ENV_OVERRIDE),
                }
            }
        }
    }

    #[test]
    fn constants_align_with_spec() {
        assert_eq!(CLI_BINARY, "codex");
        assert_eq!(HOME_ENV_VAR, "CODEX_HOME");
        assert_eq!(CODEX_WRITTEN_AUTH_JSON, "auth.json");
        assert_eq!(CONFIG_TOML_FILENAME, "config.toml");
        assert_eq!(SESSIONS_DIRNAME, "codex-sessions");
    }

    #[test]
    fn config_toml_path_is_under_config_n() {
        let base = Path::new("/tmp/csq");
        let p = config_toml_path(base, acc(4));
        assert_eq!(p, Path::new("/tmp/csq/config-4/config.toml"));
    }

    #[test]
    fn sessions_dir_is_under_config_n() {
        let base = Path::new("/tmp/csq");
        let p = sessions_dir(base, acc(7));
        assert_eq!(p, Path::new("/tmp/csq/config-7/codex-sessions"));
    }

    #[test]
    fn written_auth_json_path_is_under_config_n() {
        let base = Path::new("/tmp/csq");
        let p = written_auth_json_path(base, acc(3));
        assert_eq!(p, Path::new("/tmp/csq/config-3/auth.json"));
    }

    #[test]
    fn default_model_matches_catalog() {
        let m = default_model();
        assert_eq!(
            m,
            providers::get_provider("codex").unwrap().default_model,
            "default_model() must mirror the catalog — one source of truth"
        );
    }

    #[test]
    fn render_config_toml_emits_both_required_keys() {
        let out = render_config_toml(Some("gpt-test"));
        assert!(
            out.contains("cli_auth_credentials_store = \"file\""),
            "must pin file-backed auth store per INV-P03; got: {out}"
        );
        assert!(
            out.contains("model = \"gpt-test\""),
            "must carry the requested model; got: {out}"
        );
        assert!(out.ends_with('\n'), "trailing newline expected");
    }

    #[test]
    fn render_config_toml_omits_model_key_when_none() {
        // THE bug fix: with model=None and no user-global, csq writes NO model
        // key (it never injects its catalog default). Codex uses its built-in
        // default. This is the login / spawn / reconciler-default path.
        let out = render_config_toml(None);
        assert!(
            out.contains("cli_auth_credentials_store = \"file\""),
            "must still pin the INV-P03 auth-store directive; got: {out}"
        );
        assert!(
            !out.contains("model ="),
            "csq must NOT write a model key when model is None; got: {out}"
        );
    }

    #[test]
    fn user_global_model_propagates_when_csq_model_none() {
        // Core CC-parity fix: with model=None, a user-global `model` propagates
        // verbatim (it is no longer a csq-controlled key). The user's ~/.codex
        // model reaches the slot instead of csq's stale catalog default.
        let out = render_config_toml_with_global(None, Some("model = \"gpt-5.6-sol\"\n"));
        assert!(out.contains("cli_auth_credentials_store = \"file\""));
        assert!(
            out.contains("model = \"gpt-5.6-sol\""),
            "user-global model must propagate when csq writes none; got: {out}"
        );
    }

    #[test]
    fn explicit_model_overrides_user_global_model() {
        // An explicit per-slot model (`csq models set codex`) wins over a
        // user-global `model` — the explicit choice is the ONLY model key.
        let out =
            render_config_toml_with_global(Some("gpt-explicit"), Some("model = \"gpt-global\"\n"));
        assert!(
            out.contains("model = \"gpt-explicit\""),
            "explicit per-slot model must win; got: {out}"
        );
        assert!(
            !out.contains("gpt-global"),
            "user-global model must be dropped when csq sets an explicit one; got: {out}"
        );
        assert_eq!(
            out.matches("model =").count(),
            1,
            "exactly one model key; got: {out}"
        );
    }

    #[test]
    fn render_config_toml_model_string_is_toml_escaped_no_injection() {
        // Redteam R1 MED: a crafted model id (via `csq models set codex --force`
        // or the IPC desktop picker) must NOT break out of the `model = "..."`
        // literal to inject TOML keys. A `"`+newline payload attempting to flip
        // the auth-store back to keychain + register a rogue MCP server must be
        // neutralized by toml-value escaping, and the rendered file must still
        // parse with csq's INV-P03 directive intact.
        let payload = "x\"\ncli_auth_credentials_store = \"keychain\"\n[mcp_servers.evil]\ncommand = \"/tmp/x\"";
        let out = render_config_toml(Some(payload));
        let parsed: toml::Value =
            toml::from_str(&out).expect("rendered config must remain valid TOML after escaping");
        let table = parsed.as_table().unwrap();
        // The auth-store directive is still csq's "file" — the injection did NOT
        // override it (it is escaped inside the model string, not a real key).
        assert_eq!(
            table
                .get("cli_auth_credentials_store")
                .and_then(|v| v.as_str()),
            Some("file"),
            "injected keychain directive must not override INV-P03; got:\n{out}"
        );
        // No rogue MCP server was registered.
        assert!(
            table.get("mcp_servers").is_none(),
            "injected [mcp_servers.evil] must not appear as a real table; got:\n{out}"
        );
        // The whole payload survives verbatim as the model value.
        assert_eq!(table.get("model").and_then(|v| v.as_str()), Some(payload));
    }

    #[test]
    fn render_config_toml_keys_are_ordered_auth_before_model() {
        // Reviewer-ergonomic stability: `cli_auth_credentials_store`
        // first flags the INV-P03 directive at the top of the file.
        let out = render_config_toml(Some("x"));
        let auth_idx = out.find("cli_auth_credentials_store").unwrap();
        let model_idx = out.find("model =").unwrap();
        assert!(
            auth_idx < model_idx,
            "auth-store line must precede model line; got: {out}"
        );
    }

    #[test]
    fn write_config_toml_creates_parent_config_n_dir() {
        let _env = EnvGuard::new_isolated();
        let dir = TempDir::new().unwrap();
        let account = acc(2);
        assert!(!dir.path().join("config-2").exists());

        write_config_toml(dir.path(), account, Some("gpt-test")).unwrap();

        assert!(dir.path().join("config-2").is_dir());
        let contents = std::fs::read_to_string(config_toml_path(dir.path(), account)).unwrap();
        assert!(contents.contains("cli_auth_credentials_store = \"file\""));
        assert!(contents.contains("model = \"gpt-test\""));
    }

    #[test]
    fn write_config_toml_is_idempotent() {
        let _env = EnvGuard::new_isolated();
        let dir = TempDir::new().unwrap();
        let account = acc(5);
        write_config_toml(dir.path(), account, Some("m1")).unwrap();
        write_config_toml(dir.path(), account, Some("m1")).unwrap();
        let contents = std::fs::read_to_string(config_toml_path(dir.path(), account)).unwrap();
        // EnvGuard::new_isolated points CODEX_USER_CONFIG at a
        // nonexistent path, so read_user_global_config_toml returns None
        // and write_config_toml emits the 2-key fallback exclusively.
        assert_eq!(contents, render_config_toml(Some("m1")));
    }

    #[test]
    fn write_config_toml_replaces_user_tampered_auth_store_line() {
        // Post-login tamper scenario (spec 07 §7.3.3 step 2 rationale):
        // user hand-edits `cli_auth_credentials_store = "keychain"`,
        // refresher reconciler rewrites it back to file.
        let _env = EnvGuard::new_isolated();
        let dir = TempDir::new().unwrap();
        let account = acc(9);
        write_config_toml(dir.path(), account, Some("m1")).unwrap();

        let tampered = "cli_auth_credentials_store = \"keychain\"\nmodel = \"m1\"\n";
        std::fs::write(config_toml_path(dir.path(), account), tampered).unwrap();

        write_config_toml(dir.path(), account, Some("m1")).unwrap();

        let after = std::fs::read_to_string(config_toml_path(dir.path(), account)).unwrap();
        assert!(after.contains("cli_auth_credentials_store = \"file\""));
        assert!(!after.contains("keychain"));
    }

    #[cfg(unix)]
    #[test]
    fn write_config_toml_sets_600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let _env = EnvGuard::new_isolated();
        let dir = TempDir::new().unwrap();
        let account = acc(6);
        write_config_toml(dir.path(), account, Some("m1")).unwrap();
        let path = config_toml_path(dir.path(), account);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "config.toml should be 0o600 after write");
    }

    // ── User-global merge tests ────────────────────────────────────────

    #[test]
    fn render_with_global_none_injects_csq_block_plus_default_statusline() {
        // No user-global → csq's 2 controlled keys + the curated default
        // statusline (every codex slot gets a useful footer).
        let out = render_config_toml_with_global(Some("m1"), None);
        assert!(out.starts_with("cli_auth_credentials_store = \"file\"\nmodel = \"m1\"\n"));
        assert_default_statusline_present(&out);
    }

    #[test]
    fn render_with_global_propagates_user_top_level_keys() {
        let user_global = r#"
approval_policy = "never"
sandbox_mode = "danger-full-access"
"#;
        let out = render_config_toml_with_global(Some("m1"), Some(user_global));
        // csq-controlled keys appear first.
        assert!(out.starts_with("cli_auth_credentials_store = \"file\"\nmodel = \"m1\"\n"));
        // user-global keys propagated.
        assert!(
            out.contains("approval_policy = \"never\""),
            "approval_policy must propagate from user-global; got:\n{out}"
        );
        assert!(
            out.contains("sandbox_mode = \"danger-full-access\""),
            "sandbox_mode must propagate from user-global; got:\n{out}"
        );
    }

    #[test]
    fn render_with_global_denies_csq_controlled_keys() {
        // User-global tries to override csq-controlled keys. csq wins.
        let user_global = r#"
cli_auth_credentials_store = "keychain"
model = "user-global-model"
approval_policy = "never"
"#;
        let out = render_config_toml_with_global(Some("csq-set-model"), Some(user_global));
        // csq's values for the controlled keys.
        assert!(
            out.contains("cli_auth_credentials_store = \"file\""),
            "csq must override user-global's cli_auth_credentials_store; got:\n{out}"
        );
        assert!(
            out.contains("model = \"csq-set-model\""),
            "csq must override user-global's model; got:\n{out}"
        );
        assert!(
            !out.contains("keychain"),
            "user-global keychain attempt must be denied; got:\n{out}"
        );
        assert!(
            !out.contains("user-global-model"),
            "user-global model attempt must be denied; got:\n{out}"
        );
        // Non-csq-controlled keys still propagate.
        assert!(out.contains("approval_policy = \"never\""));
    }

    #[test]
    fn render_with_global_propagates_nested_tables() {
        // Codex's [mcp_servers.<name>] tables and [shell_environment_policy]
        // are common user-global preferences.
        let user_global = r#"
approval_policy = "on-failure"

[shell_environment_policy]
inherit = "core"

[mcp_servers.github]
command = "/usr/local/bin/github-mcp"
args = []
"#;
        let out = render_config_toml_with_global(Some("m1"), Some(user_global));
        assert!(out.contains("approval_policy = \"on-failure\""));
        assert!(
            out.contains("[shell_environment_policy]"),
            "nested table must propagate; got:\n{out}"
        );
        assert!(
            out.contains("[mcp_servers.github]"),
            "mcp_servers nested table must propagate; got:\n{out}"
        );
        assert!(out.contains("command = \"/usr/local/bin/github-mcp\""));
    }

    #[test]
    fn render_with_global_malformed_drops_user_prefs_but_keeps_csq_block_and_statusline() {
        // Malformed TOML — must not panic, must not propagate the user prefs.
        // The user block is dropped (graceful degradation per rules/security.md
        // § "Fail-Closed on Keychain/Lock Contention"), but csq's controlled keys
        // and the curated statusline still apply.
        let malformed = "approval_policy = \"never\nsandbox_mode = \"unterminated";
        let out = render_config_toml_with_global(Some("m1"), Some(malformed));
        assert!(out.starts_with("cli_auth_credentials_store = \"file\"\nmodel = \"m1\"\n"));
        assert!(
            !out.contains("approval_policy"),
            "malformed user prefs must not propagate; got:\n{out}"
        );
        assert_default_statusline_present(&out);
    }

    #[test]
    fn render_with_global_empty_string_injects_csq_block_plus_default_statusline() {
        // Empty TOML parses to an empty table → csq block + the default
        // statusline (no user prefs to merge).
        let out = render_config_toml_with_global(Some("m1"), Some(""));
        assert!(out.starts_with("cli_auth_credentials_store = \"file\"\nmodel = \"m1\"\n"));
        assert_default_statusline_present(&out);
    }

    #[test]
    fn render_with_global_only_csq_controlled_keys_injects_csq_block_plus_default_statusline() {
        // User-global contains ONLY denylisted keys → after removal the user
        // table is empty → csq block + the default statusline.
        let user_global = r#"
cli_auth_credentials_store = "keychain"
model = "user-model"
"#;
        let out = render_config_toml_with_global(Some("csq-model"), Some(user_global));
        assert!(out.starts_with("cli_auth_credentials_store = \"file\"\nmodel = \"csq-model\"\n"));
        assert!(!out.contains("keychain"), "csq must override; got:\n{out}");
        assert_default_statusline_present(&out);
    }

    #[test]
    fn read_user_global_config_toml_honors_env_override() {
        let _env = EnvGuard::new_with_fixture("approval_policy = \"sentinel\"\n");
        let read = read_user_global_config_toml();
        assert!(read.is_some(), "env override must be honored");
        assert!(
            read.unwrap().contains("sentinel"),
            "must read the override path's content"
        );
    }

    #[test]
    fn read_user_global_config_toml_returns_none_for_missing_file() {
        let _env = EnvGuard::new_isolated();
        let read = read_user_global_config_toml();
        assert!(
            read.is_none(),
            "missing file must return None (no panic, no error)"
        );
    }

    #[test]
    fn derive_spawn_flags_none_returns_empty() {
        assert!(derive_spawn_flags(None).is_empty());
    }

    #[test]
    fn derive_spawn_flags_full_bypass_combination_returns_single_flag() {
        let user_global = r#"
approval_policy = "never"
sandbox_mode = "danger-full-access"
"#;
        let flags = derive_spawn_flags(Some(user_global));
        assert_eq!(flags, vec!["--dangerously-bypass-approvals-and-sandbox"]);
    }

    #[test]
    fn derive_spawn_flags_only_approval_emits_granular() {
        let user_global = r#"approval_policy = "never""#;
        let flags = derive_spawn_flags(Some(user_global));
        assert_eq!(flags, vec!["-a", "never"]);
    }

    #[test]
    fn derive_spawn_flags_only_sandbox_emits_granular() {
        let user_global = r#"sandbox_mode = "workspace-write""#;
        let flags = derive_spawn_flags(Some(user_global));
        assert_eq!(flags, vec!["-s", "workspace-write"]);
    }

    #[test]
    fn derive_spawn_flags_partial_combination_emits_both_granular() {
        // approval_policy = "on-request" + sandbox_mode = "workspace-write"
        // is NOT the full-bypass combination → granular flags.
        let user_global = r#"
approval_policy = "on-request"
sandbox_mode = "workspace-write"
"#;
        let flags = derive_spawn_flags(Some(user_global));
        assert_eq!(flags, vec!["-a", "on-request", "-s", "workspace-write"]);
    }

    #[test]
    fn derive_spawn_flags_no_relevant_keys_returns_empty() {
        let user_global = r#"
model = "gpt-5.5"
[mcp_servers.foo]
command = "/usr/bin/foo"
"#;
        let flags = derive_spawn_flags(Some(user_global));
        assert!(
            flags.is_empty(),
            "no approval/sandbox keys → no flags; got: {flags:?}"
        );
    }

    #[test]
    fn derive_spawn_flags_malformed_returns_empty() {
        let flags = derive_spawn_flags(Some("approval_policy = \"never\nbroken"));
        assert!(flags.is_empty(), "malformed TOML → empty (no panic)");
    }

    #[test]
    fn write_config_toml_merges_user_global() {
        // End-to-end: write_config_toml reads the env-override
        // user-global and produces a merged slot config.toml.
        let _env = EnvGuard::new_with_fixture(
            "approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n",
        );
        let tmp_base = TempDir::new().unwrap();
        let account = acc(7);
        write_config_toml(tmp_base.path(), account, Some("csq-set-model")).unwrap();

        let contents = std::fs::read_to_string(config_toml_path(tmp_base.path(), account)).unwrap();

        assert!(contents.contains("cli_auth_credentials_store = \"file\""));
        assert!(contents.contains("model = \"csq-set-model\""));
        assert!(
            contents.contains("approval_policy = \"never\""),
            "user-global approval_policy must reach the slot; got:\n{contents}"
        );
        assert!(
            contents.contains("sandbox_mode = \"danger-full-access\""),
            "user-global sandbox_mode must reach the slot; got:\n{contents}"
        );
    }

    // ── regenerate_slot_config ─────────────────────────────────────────────

    /// A hook-trust key under a csq handle dir of `base` (the slot's own record).
    fn handle_trust_key(base: &Path) -> String {
        format!("{}/term-1/hooks.json:stop:0:0", base.display())
    }

    /// `key` as a TOML quoted key. A hook key embeds a filesystem path, and a Windows path's
    /// backslashes (`C:\Users\...`) are invalid escapes inside a hand-written `"..."` basic
    /// string, so fixtures must quote through the serializer exactly as Codex's writer does.
    fn toml_key(key: &str) -> String {
        toml::Value::String(key.to_string()).to_string()
    }

    fn assert_hook_trust_kept(path: &Path, key: &str, why: &str) {
        let v: toml::Value = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let entry = &v["hooks"]["state"][key];
        assert_eq!(entry["trusted_hash"].as_str(), Some("abc"), "{why}");
        assert_eq!(entry["enabled"].as_bool(), Some(true), "{why}");
    }

    /// Codex writes `[hooks.state."<key>"]` into the slot config on hook approval. Both csq
    /// writers (`regenerate_slot_config`, `write_config_toml_with_global`) must carry the
    /// entries keyed under a csq handle dir through, and must not copy a user-global entry
    /// keyed under the global `CODEX_HOME`.
    #[test]
    fn slot_config_writers_preserve_codex_hook_trust_state() {
        let env = EnvGuard::new_with_fixture("");
        let global_key = format!("{}/hooks.json:stop:0:0", env.global_home().display());
        std::fs::write(
            env.global_home().join("user-config.toml"),
            format!(
                "[hooks.state.{}]\ntrusted_hash = \"zzz\"\n[hooks.other]\nx = 1\n",
                toml_key(&global_key)
            ),
        )
        .unwrap();
        let base = TempDir::new().unwrap();
        let key = handle_trust_key(base.path());
        let account = acc(3);
        let path = config_toml_path(base.path(), account);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let slot = format!(
            "cli_auth_credentials_store = \"file\"\nmodel = \"m\"\n\n[hooks.state.{}]\ntrusted_hash = \"abc\"\nenabled = true\n",
            toml_key(&key)
        );
        crate::platform::fs::write_new_private_synced(&path, slot.as_bytes()).unwrap();

        regenerate_slot_config(base.path(), account).unwrap();
        assert_hook_trust_kept(&path, &key, "regenerate_slot_config dropped hooks.state");
        // Parsed, not a raw-text search: the writer escapes a Windows path's backslashes, so a
        // copied key would never appear verbatim in the text and a `contains` check is vacuous.
        let after = std::fs::read_to_string(&path).unwrap();
        let parsed: toml::Value = toml::from_str(&after).unwrap();
        assert!(
            parsed["hooks"]["state"].get(&global_key).is_none(),
            "global-home trust copied: {after}"
        );

        write_config_toml_with_global(base.path(), account, Some("m2"), None).unwrap();
        assert_hook_trust_kept(
            &path,
            &key,
            "write_config_toml_with_global dropped hooks.state",
        );

        // A malformed existing hooks.state refuses (prior file preserved), never drops it.
        let bad = "[hooks]\nstate = 5\n";
        std::fs::write(&path, bad.as_bytes()).unwrap(); // CI-ALLOW-fs-write-config-toml
        assert!(write_config_toml_with_global(base.path(), account, None, None).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), bad);
    }

    /// A carried approval survives the slot regeneration that rebuilds `[hooks.state]`
    /// (`rebuild_hooks_state` keeps csq-handle-keyed entries), through BOTH writers, and the
    /// regeneration never resurrects a pruned dead-handle key it does not hold.
    #[cfg(unix)]
    #[test]
    fn a_carried_hook_approval_survives_slot_regeneration() {
        use crate::session::codex_hook_trust::{carry_hook_trust, CarryMode};
        const H_TRUE: &str =
            "sha256:2ba34c7a02841fada06b868a093d041fd3d9de81883c789a321916b0aa118851";
        let _env = EnvGuard::new_isolated();
        let base_dir = TempDir::new().unwrap();
        let root = base_dir.path().canonicalize().unwrap();
        let account = acc(3);
        let path = config_toml_path(root.as_path(), account);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let global = root.as_path().join("g").join("hooks.json");
        std::fs::create_dir_all(global.parent().unwrap()).unwrap();
        std::fs::write(
            &global,
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"true"}]}]}}"#,
        )
        .unwrap();
        let handle = |pid: u32| {
            let h = root.as_path().join(format!("term-{pid}"));
            std::fs::create_dir_all(&h).unwrap();
            std::os::unix::fs::symlink(&path, h.join("config.toml")).unwrap();
            h
        };
        let (src, new) = (handle(100), handle(200));
        let dead = root.as_path().join("term-300");
        let key = |h: &Path| format!("{}/hooks.json:stop:0:0", h.display());
        let slot = format!(
            "cli_auth_credentials_store = \"file\"\n\n[hooks.state.\"{}\"]\ntrusted_hash = \"{H_TRUE}\"\nenabled = false\n\n[hooks.state.\"{}\"]\ntrusted_hash = \"sha256:old\"\n",
            key(&src),
            key(&dead)
        );
        crate::platform::fs::write_new_private_synced(&path, slot.as_bytes()).unwrap();

        let r = carry_hook_trust(
            root.as_path(),
            &new,
            account,
            Some(&global),
            CarryMode::Create,
        )
        .unwrap();
        assert_eq!((r.copied, r.pruned), (1, 1));
        let state = |p: &Path| -> toml::value::Table {
            let v: toml::Value = toml::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
            v["hooks"]["state"].as_table().unwrap().clone()
        };
        let carried = state(&path)[&key(&new)].clone();
        assert_eq!(carried["trusted_hash"].as_str(), Some(H_TRUE));
        assert_eq!(carried["enabled"].as_bool(), Some(false));

        regenerate_slot_config(root.as_path(), account).unwrap();
        let after = state(&path);
        assert_eq!(
            after[&key(&new)],
            carried,
            "regeneration undid the carried entry"
        );
        assert!(after.contains_key(&key(&src)));
        assert!(
            !after.contains_key(&key(&dead)),
            "regeneration resurrected a pruned key"
        );

        write_config_toml_with_global(root.as_path(), account, Some("m2"), None).unwrap();
        assert_eq!(
            state(&path)[&key(&new)],
            carried,
            "writer undid the carried entry"
        );

        // And the carry still composes after a regeneration: a later handle inherits too.
        let later = handle(400);
        let r = carry_hook_trust(
            root.as_path(),
            &later,
            account,
            Some(&global),
            CarryMode::Create,
        )
        .unwrap();
        assert_eq!(r.copied, 1);
        assert_eq!(
            state(&path)[&key(&later)]["trusted_hash"].as_str(),
            Some(H_TRUE)
        );
    }

    /// A slot `config.toml` whose `hooks` is not a table (the old renderer copied one from the
    /// global) is dropped and regenerated, never refused. Both call paths that used to error on
    /// it are covered: `write_config_toml(base, slot, None)` (the call `providers/codex/login.rs`
    /// and `providers/codex/desktop_login.rs` make) and `regenerate_slot_config` (launch).
    #[test]
    fn a_non_table_hooks_in_a_slot_is_dropped_not_refused() {
        let _env = EnvGuard::new_isolated();
        for hooks in ["hooks = 5\n", "hooks = \"x\"\n", "hooks = [1]\n"] {
            let slot_toml = format!("cli_auth_credentials_store = \"file\"\n{hooks}");
            let base = TempDir::new().unwrap();
            let account = acc(6);
            let path = config_toml_path(base.path(), account);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();

            crate::platform::fs::write_new_private_synced(&path, slot_toml.as_bytes()).unwrap();
            assert!(slot_config_hooks_not_a_table(&path), "{hooks}");
            write_config_toml(base.path(), account, None)
                .unwrap_or_else(|e| panic!("login path refused {hooks}: {e}"));
            let v: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert!(v.get("hooks").is_none(), "{hooks}: {v}");
            assert!(!slot_config_hooks_not_a_table(&path));

            std::fs::remove_file(&path).unwrap();
            crate::platform::fs::write_new_private_synced(&path, slot_toml.as_bytes()).unwrap();
            regenerate_slot_config(base.path(), account)
                .unwrap_or_else(|e| panic!("launch path refused {hooks}: {e}"));
            let v: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert!(v.get("hooks").is_none(), "{hooks}: {v}");
        }
    }

    const PROJECT_KEY: &str = "/repo/.codex/hooks.json:pre_tool_use:0:0";

    /// Regenerates a slot holding `slot_state` (`[hooks.state.*]` TOML) against a user-global
    /// holding `global_state`, and returns the resulting `[hooks.state]` table.
    fn regen_hooks_state(
        base: &Path,
        global_state: impl Fn(&str) -> String,
        slot_state: impl Fn(&str) -> String,
    ) -> toml::value::Table {
        let env = EnvGuard::new_with_fixture("");
        let home = env.global_home().display().to_string();
        std::fs::write(
            env.global_home().join("user-config.toml"),
            global_state(&home),
        )
        .unwrap();
        let account = acc(4);
        let path = config_toml_path(base, account);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let slot = format!(
            "cli_auth_credentials_store = \"file\"\n{}",
            slot_state(&home)
        );
        crate::platform::fs::write_new_private_synced(&path, slot.as_bytes()).unwrap();
        regenerate_slot_config(base, account).unwrap();
        let v: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        v.get("hooks")
            .and_then(|h| h.get("state"))
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default()
    }

    /// An upgraded slot holding an old copy of the global's project-keyed entry gets it
    /// refreshed from the global; its own handle-keyed entry survives.
    #[test]
    fn regeneration_refreshes_a_stale_global_copy_frozen_in_an_upgraded_slot() {
        let base = TempDir::new().unwrap();
        let handle_key = handle_trust_key(base.path());
        let state = regen_hooks_state(
            base.path(),
            |_| format!("[hooks.state.\"{PROJECT_KEY}\"]\ntrusted_hash = \"new\"\n"),
            |_| {
                format!(
                    "[hooks.state.\"{PROJECT_KEY}\"]\ntrusted_hash = \"old\"\n\
                     [hooks.state.{}]\ntrusted_hash = \"abc\"\n",
                    toml_key(&handle_key)
                )
            },
        );
        assert_eq!(state[PROJECT_KEY]["trusted_hash"].as_str(), Some("new"));
        assert_eq!(state[&handle_key]["trusted_hash"].as_str(), Some("abc"));
    }

    /// A global entry keyed under the global `CODEX_HOME` is not copied, and a frozen copy of
    /// one already in the slot is dropped.
    #[test]
    fn global_home_keyed_hook_state_is_not_copied_and_a_frozen_copy_is_dropped() {
        let base = TempDir::new().unwrap();
        let state = regen_hooks_state(
            base.path(),
            |home| {
                format!(
                    "[hooks.state.{}]\ntrusted_hash = \"g\"\n",
                    toml_key(&format!("{home}/hooks.json:stop:0:0"))
                )
            },
            |_| String::new(),
        );
        assert!(state.is_empty(), "global-home key copied: {state:?}");
        let base = TempDir::new().unwrap();
        let state = regen_hooks_state(
            base.path(),
            |home| {
                format!(
                    "[hooks.state.{}]\ntrusted_hash = \"g\"\n",
                    toml_key(&format!("{home}/hooks.json:stop:0:0"))
                )
            },
            |home: &str| {
                format!(
                    "[hooks.state.{}]\ntrusted_hash = \"frozen\"\n",
                    toml_key(&format!("{home}/hooks.json:stop:0:0"))
                )
            },
        );
        assert!(state.is_empty(), "frozen copy survived: {state:?}");
    }

    /// (i) A slot-only project-keyed entry (an approval given inside a csq terminal) survives
    /// regeneration verbatim; (ii) a key in both gets the GLOBAL value.
    #[test]
    fn project_keyed_hook_state_is_the_union_with_the_global_winning() {
        let base = TempDir::new().unwrap();
        let other = "/repo2/.codex/hooks.json:stop:0:0";
        let state = regen_hooks_state(
            base.path(),
            |_| format!("[hooks.state.\"{PROJECT_KEY}\"]\ntrusted_hash = \"global\"\n"),
            |_| {
                format!(
                    "[hooks.state.\"{PROJECT_KEY}\"]\ntrusted_hash = \"slot\"\n\
                     [hooks.state.\"{other}\"]\ntrusted_hash = \"slot-only\"\nenabled = true\n"
                )
            },
        );
        assert_eq!(state[other]["trusted_hash"].as_str(), Some("slot-only"));
        assert_eq!(state[other]["enabled"].as_bool(), Some(true));
        assert_eq!(state[PROJECT_KEY]["trusted_hash"].as_str(), Some("global"));
    }

    /// A project-keyed global entry reaches a slot that has none, and is refreshed when the
    /// global changes it.
    #[test]
    fn project_keyed_global_hook_state_reaches_the_slot() {
        let base = TempDir::new().unwrap();
        let state = regen_hooks_state(
            base.path(),
            |_| format!("[hooks.state.\"{PROJECT_KEY}\"]\ntrusted_hash = \"p\"\nenabled = false\n"),
            |_| String::new(),
        );
        assert_eq!(state[PROJECT_KEY]["trusted_hash"].as_str(), Some("p"));
        assert_eq!(state[PROJECT_KEY]["enabled"].as_bool(), Some(false));
    }

    fn assert_regeneration_preserves_owner_settings(global: Option<&str>) {
        let _env = match global {
            Some(content) => EnvGuard::new_with_fixture(content),
            None => EnvGuard::new_isolated(),
        };
        let base = TempDir::new().unwrap();
        let account = acc(3);
        let canonical = r#"cli_auth_credentials_store = "keychain"
model = "owner-model"
approval_policy = "on-request"
sandbox_mode = "workspace-write"

[agents]
max_threads = 8

[features.multi_agent_v2]
max_concurrent_threads_per_session = 8

[owner_extension]
labels = ["private", "fixture"]
[owner_extension.nested]
enabled = true
"#;
        let path = config_toml_path(base.path(), account);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        crate::platform::fs::write_new_private_synced(&path, canonical.as_bytes()).unwrap();
        let before: toml::Value = toml::from_str(canonical).unwrap();

        let outcome = regenerate_slot_config(base.path(), account).unwrap();
        assert_eq!(
            outcome,
            RegenOutcome::Rewritten {
                model: Some("owner-model".into()),
                was_global_malformed: false,
            }
        );
        let contents = std::fs::read_to_string(&path).unwrap();
        let after: toml::Value = toml::from_str(&contents).unwrap();
        for key in ["agents", "features"] {
            assert_eq!(
                after.get(key),
                before.get(key),
                "regeneration must preserve the slot owner's {key} table"
            );
        }
        assert!(after.get("owner_extension").is_none());
        assert_eq!(after["model"].as_str(), Some("owner-model"));
        assert_eq!(after["cli_auth_credentials_store"].as_str(), Some("file"));
        if global.is_some() {
            assert_eq!(after["approval_policy"].as_str(), Some("never"));
            assert_eq!(after["sandbox_mode"].as_str(), Some("read-only"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            regenerate_slot_config(base.path(), account).unwrap(),
            RegenOutcome::AlreadyCurrent
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), contents);
    }

    #[test]
    fn regenerate_preserves_owner_settings_without_global() {
        assert_regeneration_preserves_owner_settings(None);
    }

    #[test]
    fn regenerate_preserves_owner_settings_with_global() {
        assert_regeneration_preserves_owner_settings(Some(
            "approval_policy = \"never\"\nsandbox_mode = \"read-only\"\n",
        ));
    }

    fn assert_model_write_preserves_owner_settings(global: Option<&str>) {
        let _env = match global {
            Some(content) => EnvGuard::new_with_fixture(content),
            None => EnvGuard::new_isolated(),
        };
        let base = TempDir::new().unwrap();
        let account = acc(4);
        let canonical = r#"cli_auth_credentials_store = "keychain"
model = "prior-model"

[agents]
max_threads = 8
job_limit = 12

[features.multi_agent_v2]
max_concurrent_threads_per_session = 8
enabled = true
"#;
        let path = config_toml_path(base.path(), account);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        crate::platform::fs::write_new_private_synced(&path, canonical.as_bytes()).unwrap();
        let before: toml::Value = toml::from_str(canonical).unwrap();

        // Both CLI and desktop model switching call this writer directly.
        write_config_toml(base.path(), account, Some("changed-model")).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        let after: toml::Value = toml::from_str(&contents).unwrap();
        assert_eq!(after.get("agents"), before.get("agents"));
        assert_eq!(
            after.get("features").and_then(|v| v.get("multi_agent_v2")),
            before.get("features").and_then(|v| v.get("multi_agent_v2"))
        );
        assert_eq!(after["model"].as_str(), Some("changed-model"));
        assert_eq!(after["cli_auth_credentials_store"].as_str(), Some("file"));
        if global.is_some() {
            assert_eq!(after["approval_policy"].as_str(), Some("never"));
            assert_eq!(after["sandbox_mode"].as_str(), Some("read-only"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn model_write_preserves_owner_settings_without_global() {
        assert_model_write_preserves_owner_settings(None);
    }

    #[test]
    fn model_write_preserves_owner_settings_with_global() {
        assert_model_write_preserves_owner_settings(Some(
            "approval_policy = \"never\"\nsandbox_mode = \"read-only\"\n",
        ));
    }

    fn assert_selected_owner_table_survives(operation: &str, owner_path: &str) {
        let _env = EnvGuard::new_with_fixture(
            r#"approval_policy = "never"
cli_auth_credentials_store = "keychain"
[agents]
max_threads = 2
global_only = true
[features]
memory_tool = true
[features.multi_agent_v2]
max_concurrent_threads_per_session = 2
global_only = true
[mcp_servers.current]
command = "private-fixture-command"
"#,
        );
        let base = TempDir::new().unwrap();
        let account = acc(2);
        let owner_table = match owner_path {
            "agents" => {
                "[agents]\nmax_threads = 8\n[agents.private_role]\ndescription = \"owner\"\n"
            }
            "features.multi_agent_v2" => {
                "[features.multi_agent_v2]\nmax_concurrent_threads_per_session = 8\n[features.multi_agent_v2.owner]\nenabled = true\n"
            }
            _ => unreachable!(),
        };
        let canonical = format!(
            "cli_auth_credentials_store = \"keychain\"\napproval_policy = \"on-request\"\n{owner_table}\n[mcp_servers.obsolete]\ncommand = \"obsolete\"\n"
        );
        let path = config_toml_path(base.path(), account);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        crate::platform::fs::write_new_private_synced(&path, canonical.as_bytes()).unwrap();
        let before: toml::Value = toml::from_str(&canonical).unwrap();
        match operation {
            "regenerate" => {
                regenerate_slot_config(base.path(), account).unwrap();
            }
            "login" => write_config_toml(base.path(), account, None).unwrap(),
            "model" => write_config_toml(base.path(), account, Some("changed-model")).unwrap(),
            _ => unreachable!(),
        }
        let contents = std::fs::read_to_string(path).unwrap();
        let after: toml::Value = toml::from_str(&contents).unwrap();
        let get_owner = |value: &toml::Value| {
            if owner_path == "agents" {
                value.get("agents").cloned()
            } else {
                value
                    .get("features")
                    .and_then(|v| v.get("multi_agent_v2"))
                    .cloned()
            }
        };
        assert_eq!(
            get_owner(&after),
            get_owner(&before),
            "{operation}: slot wins entire {owner_path} table"
        );
        // The other owner table has no slot value, so the global seeds it.
        if owner_path == "agents" {
            assert_eq!(
                after["features"]["multi_agent_v2"]["max_concurrent_threads_per_session"]
                    .as_integer(),
                Some(2)
            );
        } else {
            assert_eq!(after["agents"]["max_threads"].as_integer(), Some(2));
        }
        assert_eq!(after["features"]["memory_tool"].as_bool(), Some(true));
        assert_eq!(after["approval_policy"].as_str(), Some("never"));
        assert_eq!(after["cli_auth_credentials_store"].as_str(), Some("file"));
        assert!(after["mcp_servers"].get("obsolete").is_none());
        assert!(after["mcp_servers"].get("current").is_some());
        if operation == "model" {
            assert_eq!(after["model"].as_str(), Some("changed-model"));
        }
    }

    #[test]
    fn regenerate_preserves_agents_independently() {
        assert_selected_owner_table_survives("regenerate", "agents");
    }

    #[test]
    fn regenerate_preserves_multi_agent_v2_independently() {
        assert_selected_owner_table_survives("regenerate", "features.multi_agent_v2");
    }

    #[test]
    fn login_write_preserves_agents_independently() {
        assert_selected_owner_table_survives("login", "agents");
    }

    #[test]
    fn login_write_preserves_multi_agent_v2_independently() {
        assert_selected_owner_table_survives("login", "features.multi_agent_v2");
    }

    #[test]
    fn model_write_preserves_agents_independently() {
        assert_selected_owner_table_survives("model", "agents");
    }

    #[test]
    fn model_write_preserves_multi_agent_v2_independently() {
        assert_selected_owner_table_survives("model", "features.multi_agent_v2");
    }

    #[test]
    fn writes_refuse_invalid_existing_config_without_echoing_source() {
        let _env = EnvGuard::new_isolated();
        for canonical in [
            "owner_secret = \"private-marker\"\n[broken",
            "agents = \"private-marker\"\n",
            "features = \"private-marker\"\n",
            "[features]\nmulti_agent_v2 = \"private-marker\"\n",
        ] {
            let base = TempDir::new().unwrap();
            let account = acc(1);
            let path = config_toml_path(base.path(), account);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            crate::platform::fs::write_new_private_synced(&path, canonical.as_bytes()).unwrap();
            let regen_error = regenerate_slot_config(base.path(), account).unwrap_err();
            let write_error =
                write_config_toml(base.path(), account, Some("changed-model")).unwrap_err();
            for error in [regen_error, write_error] {
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert!(!format!("{error:?}").contains("private-marker"));
                assert!(error.to_string().contains("preserving prior file"));
            }
            assert_eq!(std::fs::read_to_string(path).unwrap(), canonical);
        }
    }

    #[test]
    fn writes_refuse_unreadable_existing_config_without_overwriting() {
        let _env = EnvGuard::new_isolated();
        let base = TempDir::new().unwrap();
        let account = acc(1);
        let path = config_toml_path(base.path(), account);
        std::fs::create_dir_all(&path).unwrap();
        let marker = path.join("private-marker");
        std::fs::write(&marker, "owner fixture").unwrap();
        for error in [
            regenerate_slot_config(base.path(), account).unwrap_err(),
            write_config_toml(base.path(), account, None).unwrap_err(),
        ] {
            assert_eq!(
                error.to_string(),
                "cannot read existing Codex config.toml; preserving prior file"
            );
        }
        assert_eq!(std::fs::read_to_string(marker).unwrap(), "owner fixture");
    }

    #[test]
    fn multi_agent_owner_refuses_non_table_global_features_without_overwriting() {
        let _env = EnvGuard::new_with_fixture("features = \"private-marker\"\n");
        let base = TempDir::new().unwrap();
        let account = acc(1);
        let path = config_toml_path(base.path(), account);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let canonical = "[features.multi_agent_v2]\nmax_concurrent_threads_per_session = 8\n";
        crate::platform::fs::write_new_private_synced(&path, canonical.as_bytes()).unwrap();
        for error in [
            regenerate_slot_config(base.path(), account).unwrap_err(),
            write_config_toml(base.path(), account, None).unwrap_err(),
        ] {
            assert!(!format!("{error:?}").contains("private-marker"));
            assert!(error
                .to_string()
                .contains("global Codex features must be a table"));
        }
        assert_eq!(std::fs::read_to_string(path).unwrap(), canonical);
    }

    #[test]
    fn extract_model_key_round_trips() {
        assert_eq!(
            extract_model_key("model = \"gpt-test\"\n"),
            Some("gpt-test".into())
        );
        assert_eq!(
            extract_model_key("model='gpt-single'\n"),
            Some("gpt-single".into())
        );
        assert_eq!(extract_model_key("# model = \"x\"\n"), None);
        assert_eq!(extract_model_key("nomodel = \"x\"\n"), None);
    }

    /// A `model`-prefixed key (e.g. `model_provider`) appearing BEFORE the
    /// real `model = "..."` line must be skipped, not abort the search.
    #[test]
    fn extract_model_key_skips_model_prefixed_keys_before_model() {
        assert_eq!(
            extract_model_key("model_provider = \"openai\"\nmodel = \"gpt-4\"\n"),
            Some("gpt-4".into()),
            "a model_* key before `model` must not abort the search"
        );
        assert_eq!(
            extract_model_key("model_reasoning_effort = \"high\"\nmodel = 'gpt-5'\n"),
            Some("gpt-5".into())
        );
    }

    /// The user's reported scenario: a key removed from `~/.codex`
    /// (`[mcp_servers.figma]`) must disappear from a live slot, while the
    /// slot's per-account `model` is preserved across the re-merge.
    #[test]
    fn regenerate_preserves_model_and_remerges_current_global() {
        let base = TempDir::new().unwrap();
        let account = acc(5);
        // Seed an existing slot config: model + old global keys (incl. figma).
        write_config_toml_with_global(
            base.path(),
            account,
            Some("preserved-model"),
            Some("approval_policy = \"on-request\"\n[mcp_servers.figma]\nurl = \"x\"\n"),
        )
        .unwrap();

        // ~/.codex now differs: figma removed, sandbox_mode added.
        let _env = EnvGuard::new_with_fixture("sandbox_mode = \"danger-full-access\"\n");
        let outcome = regenerate_slot_config(base.path(), account).unwrap();
        assert_eq!(
            outcome,
            RegenOutcome::Rewritten {
                model: Some("preserved-model".into()),
                was_global_malformed: false,
            }
        );

        let contents = std::fs::read_to_string(config_toml_path(base.path(), account)).unwrap();
        assert!(
            contents.contains("model = \"preserved-model\""),
            "per-slot model must be preserved; got:\n{contents}"
        );
        assert!(
            contents.contains("sandbox_mode = \"danger-full-access\""),
            "new ~/.codex key must be merged in; got:\n{contents}"
        );
        assert!(
            !contents.contains("[mcp_servers.figma]"),
            "key removed from ~/.codex MUST NOT persist in the slot; got:\n{contents}"
        );
        assert!(
            !contents.contains("approval_policy"),
            "old ~/.codex key dropped after global edit; got:\n{contents}"
        );
    }

    #[test]
    fn regenerate_idempotent_returns_already_current() {
        let base = TempDir::new().unwrap();
        let account = acc(6);
        let _env = EnvGuard::new_with_fixture("approval_policy = \"never\"\n");
        // Seed a slot that already matches the current global merge.
        write_config_toml(base.path(), account, Some("m")).unwrap();

        let first = regenerate_slot_config(base.path(), account).unwrap();
        assert_eq!(
            first,
            RegenOutcome::AlreadyCurrent,
            "seeded config already matches the current global"
        );
        let before = std::fs::read_to_string(config_toml_path(base.path(), account)).unwrap();
        let second = regenerate_slot_config(base.path(), account).unwrap();
        assert_eq!(second, RegenOutcome::AlreadyCurrent);
        let after = std::fs::read_to_string(config_toml_path(base.path(), account)).unwrap();
        assert_eq!(before, after, "AlreadyCurrent must not rewrite bytes");
    }

    /// A present-but-malformed `~/.codex` MUST keep the existing slot
    /// config — never wipe it to the degraded 2-key fallback.
    #[test]
    fn regenerate_skips_malformed_global_keeping_existing() {
        let base = TempDir::new().unwrap();
        let account = acc(8);
        write_config_toml_with_global(
            base.path(),
            account,
            Some("keep-model"),
            Some("approval_policy = \"never\"\n[mcp_servers.linear]\nurl = \"y\"\n"),
        )
        .unwrap();
        let before = std::fs::read_to_string(config_toml_path(base.path(), account)).unwrap();

        let _env = EnvGuard::new_with_fixture("approval_policy = \"never\nnot valid toml [[[");
        let outcome = regenerate_slot_config(base.path(), account).unwrap();
        assert_eq!(outcome, RegenOutcome::SkippedMalformedGlobal);

        let after = std::fs::read_to_string(config_toml_path(base.path(), account)).unwrap();
        assert_eq!(
            before, after,
            "malformed ~/.codex MUST NOT wipe the slot config"
        );
        assert!(
            after.contains("[mcp_servers.linear]"),
            "previously-merged keys must survive a malformed-global skip; got:\n{after}"
        );
    }

    /// Under a malformed `~/.codex`, a slot whose csq-controlled auth-store
    /// directive has drifted is still REPAIRED (re-asserted to `"file"`)
    /// while user keys are preserved — the malformed global does not
    /// suppress the global-independent csq-key repair (redteam C1).
    #[test]
    fn regenerate_repairs_csq_keys_under_malformed_global() {
        let base = TempDir::new().unwrap();
        let account = acc(12);
        // Seed a slot config whose csq-controlled auth-store has drifted to
        // "keychain", plus a user key, without a statusline.
        let p = config_toml_path(base.path(), account);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let drifted = "cli_auth_credentials_store = \"keychain\"\nmodel = \"keep-model\"\n[mcp_servers.linear]\nurl = \"y\"\n";
        std::fs::write(&p, drifted).unwrap();

        let _env = EnvGuard::new_with_fixture("approval_policy = \"never\nnot valid [[[");
        let outcome = regenerate_slot_config(base.path(), account).unwrap();
        assert_eq!(
            outcome,
            RegenOutcome::Rewritten {
                model: Some("keep-model".into()),
                was_global_malformed: true,
            },
            "drifted csq key under a malformed global must be repaired, not skipped"
        );

        let after = std::fs::read_to_string(&p).unwrap();
        assert!(
            after.contains("cli_auth_credentials_store = \"file\""),
            "auth-store directive repaired to file; got:\n{after}"
        );
        assert!(
            after.contains("model = \"keep-model\""),
            "per-slot model preserved through the repair; got:\n{after}"
        );
        assert!(
            after.contains("[mcp_servers.linear]"),
            "user key preserved through the repair; got:\n{after}"
        );
        assert!(
            !after.contains("keychain"),
            "drifted keychain directive removed; got:\n{after}"
        );
    }

    /// An ABSENT `~/.codex` (`None`) is not malformed — a missing slot config
    /// is created, but csq writes NO model (the stale-default-injection bug is
    /// fixed): `model` is `None` and the file carries no `model` key, so codex
    /// falls back to its own built-in default.
    #[test]
    fn regenerate_absent_global_writes_no_model() {
        let base = TempDir::new().unwrap();
        let account = acc(9);
        let _env = EnvGuard::new_isolated(); // override → nonexistent → None
        let outcome = regenerate_slot_config(base.path(), account).unwrap();
        assert_eq!(
            outcome,
            RegenOutcome::Rewritten {
                model: None,
                was_global_malformed: false,
            },
            "absent global + no existing slot model → csq writes NO model (no catalog default)"
        );
        let contents = std::fs::read_to_string(config_toml_path(base.path(), account)).unwrap();
        assert!(contents.contains("cli_auth_credentials_store = \"file\""));
        assert!(
            !contents.contains("model ="),
            "csq must NOT inject a catalog default model; got:\n{contents}"
        );
    }

    /// `write_config_toml_with_global` writes from the supplied snapshot,
    /// never re-reading the env override — the property that closes the
    /// guard-vs-write TOCTOU in the regenerate helper.
    #[test]
    fn write_config_toml_with_global_uses_supplied_snapshot_not_env() {
        let base = TempDir::new().unwrap();
        let account = acc(11);
        let _env = EnvGuard::new_with_fixture("approval_policy = \"never\"\n");
        write_config_toml_with_global(
            base.path(),
            account,
            Some("m"),
            Some("sandbox_mode = \"read-only\"\n"),
        )
        .unwrap();
        let contents = std::fs::read_to_string(config_toml_path(base.path(), account)).unwrap();
        assert!(
            contents.contains("sandbox_mode = \"read-only\""),
            "must write the supplied snapshot; got:\n{contents}"
        );
        assert!(
            !contents.contains("approval_policy = \"never\""),
            "must NOT re-read the env override; got:\n{contents}"
        );
    }

    // ── Codex statusline (tui.status_line) injection ───────────────────────

    fn status_line_value(config: &str) -> toml::Value {
        toml::from_str::<toml::Value>(config).unwrap()["tui"]["status_line"].clone()
    }

    const OLD_STATUS_LINE_CONFIG: &str = r#"[tui]
status_line = ["model-with-reasoning", "context-remaining", "git-branch", "current-dir"]
"#;

    #[test]
    fn statusline_r3_malformed_global_never_adopts_custom_slot() {
        let _env = EnvGuard::new_with_fixture("invalid[");
        let base = TempDir::new().unwrap();
        let account = acc(8);
        let path = config_toml_path(base.path(), account);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let custom = "[tui]\nstatus_line = [\"reasoning\"]\n";
        std::fs::write(&path, render_config_toml_with_global(None, Some(custom))).unwrap();
        regenerate_slot_config(base.path(), account).unwrap();
        assert_eq!(
            status_line_value(&std::fs::read_to_string(&path).unwrap()),
            status_line_value(custom)
        );
        assert!(
            !status_line_owner_path(&path).exists(),
            "malformed global must not seed ownership"
        );
        std::fs::write(
            std::env::var_os(USER_CONFIG_ENV_OVERRIDE).unwrap(),
            "[tui]\nstatus_line = [\"thread-name\"]\n",
        )
        .unwrap();
        regenerate_slot_config(base.path(), account).unwrap();
        assert_eq!(
            status_line_value(&std::fs::read_to_string(path).unwrap()),
            status_line_value(custom)
        );
    }

    #[test]
    fn statusline_r3_interruption_between_renames_keeps_propagating() {
        let _env = EnvGuard::new_isolated();
        let base = TempDir::new().unwrap();
        let account = acc(8);
        let old = "[tui]\nstatus_line = [\"thread-name\"]\n";
        let next = "[tui]\nstatus_line = [\"reasoning\"]\n";
        write_config_toml_with_global(base.path(), account, None, Some(old)).unwrap();
        INTERRUPT_STATUS_LINE_PUBLICATION.with(|flag| flag.set(true));
        let interrupted = write_config_toml_with_global(base.path(), account, None, Some(next));
        assert!(interrupted.is_err(), "the interruption must actually fire");
        let path = config_toml_path(base.path(), account);
        assert_eq!(
            status_line_value(&std::fs::read_to_string(&path).unwrap()),
            status_line_value(next)
        );
        write_config_toml_with_global(base.path(), account, None, Some(old)).unwrap();
        assert_eq!(
            status_line_value(&std::fs::read_to_string(path).unwrap()),
            status_line_value(old),
            "next merge must recognize either value from interrupted publication"
        );
    }

    #[test]
    fn statusline_r3_hash_uses_csq_item_encoding() {
        let value = toml::Value::Array(vec![
            toml::Value::String("reasoning".into()),
            toml::Value::String("thread-name".into()),
        ]);
        assert_eq!(
            status_line_hash(&value).unwrap(),
            "8335bc7d63be6b2a07cb31910016fe0293e4a2f41969149e8dcbdd50bba942f9"
        );
        assert!(status_line_hash(&toml::Value::String("invalid".into())).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn statusline_r3_unchanged_record_keeps_inode_and_timestamp() {
        use std::os::unix::fs::MetadataExt;
        let _env = EnvGuard::new_isolated();
        let base = TempDir::new().unwrap();
        let account = acc(8);
        write_config_toml_with_global(base.path(), account, None, None).unwrap();
        let path = config_toml_path(base.path(), account);
        let file = std::fs::File::open(status_line_owner_path(&path)).unwrap();
        let before = file.metadata().unwrap();
        assert_eq!(
            regenerate_slot_config(base.path(), account).unwrap(),
            RegenOutcome::AlreadyCurrent
        );
        let after = std::fs::metadata(status_line_owner_path(&path)).unwrap();
        assert_eq!(before.ino(), after.ino());
        assert_eq!(before.modified().unwrap(), after.modified().unwrap());
    }

    #[test]
    fn statusline_r3_record_failure_has_distinct_diagnostic() {
        let _env = EnvGuard::new_isolated();
        let base = TempDir::new().unwrap();
        let account = acc(8);
        let path = config_toml_path(base.path(), account);
        std::fs::create_dir_all(status_line_owner_path(&path)).unwrap();
        let error = write_config_toml_with_global(base.path(), account, None, None).unwrap_err();
        assert_eq!(
            config_write_error_context(&error),
            "Codex statusline ownership record publication failed"
        );
        assert_eq!(
            config_write_error_context(&io::Error::other("config failure")),
            "Codex config.toml publication failed"
        );
        assert!(!path.exists());
    }

    #[test]
    fn statusline_r3_prepared_record_recognizes_old_after_config_failure() {
        let _env = EnvGuard::new_isolated();
        let base = TempDir::new().unwrap();
        let account = acc(8);
        let old = "[tui]\nstatus_line = [\"thread-name\"]\n";
        let next = "[tui]\nstatus_line = [\"reasoning\"]\n";
        write_config_toml_with_global(base.path(), account, None, Some(old)).unwrap();
        let path = config_toml_path(base.path(), account);
        let existing = std::fs::read_to_string(&path).unwrap();
        let owner = read_status_line_owner(&path).unwrap();
        let rendered =
            render_slot_config_toml(base.path(), None, Some(next), Some(&existing), Some(&owner))
                .unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        // Dev's conditional writer preserves a replacement and reports Changed.
        assert_eq!(
            publish_slot_config(&path, Some(&existing), &rendered).unwrap(),
            ConditionalWrite::Changed
        );
        assert!(path.is_dir());
        let transition = read_status_line_owner(&path).unwrap();
        assert_eq!(transition.lines().count(), 2);
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, &existing).unwrap();
        // The atomic-exchange fault seam can produce a real config I/O failure on
        // the platforms that implement that operation. Keep the failure assertion
        // and recovery proof while also covering the new Changed contract above.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let _reset = SeamReset;
            test_seam::EXCHANGE_COUNT.with(|c| c.set(0));
            test_seam::EXCHANGE_FAIL_NTH.with(|c| c.set(Some(1)));
            assert!(publish_slot_config(&path, Some(&existing), &rendered).is_err());
            assert_eq!(test_seam::EXCHANGE_COUNT.with(std::cell::Cell::get), 1);
            assert_eq!(std::fs::read_to_string(&path).unwrap(), existing);
            assert_eq!(read_status_line_owner(&path).unwrap().lines().count(), 2);
        }
        write_config_toml_with_global(base.path(), account, None, Some(next)).unwrap();
        assert_eq!(
            status_line_value(&std::fs::read_to_string(path).unwrap()),
            status_line_value(next)
        );
    }

    #[test]
    fn statusline_final_unsafe_global_retains_owned_slot_and_record() {
        let _env = EnvGuard::new_isolated();
        for bad in ["invalid[", "[tui]\nstatus_line = [1]\n", "tui = \"oops\"\n"] {
            let base = TempDir::new().unwrap();
            let account = acc(8);
            let old = "[tui]\nstatus_line = [\"thread-name\"]\n";
            let next = "[tui]\nstatus_line = [\"reasoning\"]\n";
            write_config_toml_with_global(base.path(), account, None, Some(old)).unwrap();
            let path = config_toml_path(base.path(), account);
            let record = std::fs::read(status_line_owner_path(&path)).unwrap();
            write_config_toml_with_global(base.path(), account, None, Some(bad)).unwrap();
            assert_eq!(
                status_line_value(&std::fs::read_to_string(&path).unwrap()),
                status_line_value(old)
            );
            assert_eq!(
                std::fs::read(status_line_owner_path(&path)).unwrap(),
                record
            );
            write_config_toml_with_global(base.path(), account, None, Some(next)).unwrap();
            assert_eq!(
                status_line_value(&std::fs::read_to_string(path).unwrap()),
                status_line_value(next)
            );
        }
    }

    #[test]
    fn statusline_final_hash_encoding_has_no_separator_collisions() {
        let value = |items: &[&str]| {
            toml::Value::Array(
                items
                    .iter()
                    .map(|item| toml::Value::String((*item).into()))
                    .collect(),
            )
        };
        assert_ne!(
            status_line_hash(&value(&[])),
            status_line_hash(&value(&[""]))
        );
        assert!(status_line_hash(&value(&["a\u{1f}b"])).is_none());
        assert!(status_line_hash(&value(&["a", "b"])).is_some());
    }

    #[test]
    fn statusline_final_diagnostic_prints_underlying_source_once() {
        let error = io::Error::other(StatusLineOwnerWriteError(io::Error::other(
            "TEST-INPUT-write-denied",
        )));
        let message = format!(
            "{}: {}",
            config_write_error_context(&error),
            config_write_error_source(&error)
        );
        assert_eq!(
            message,
            "Codex statusline ownership record publication failed: TEST-INPUT-write-denied"
        );
    }

    #[test]
    fn statusline_final_narrow_failure_is_nonfatal_and_warns() {
        use std::sync::{Arc, Mutex};
        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<String>>>);
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                write!(&mut self.0, "{}={value:?};", field.name()).unwrap();
            }
        }
        impl tracing::Subscriber for Capture {
            fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
                *metadata.level() == tracing::Level::WARN
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                let mut fields = Fields(String::new());
                event.record(&mut fields);
                self.0.lock().unwrap().push(fields.0);
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }
        let _env = EnvGuard::new_isolated();
        let base = TempDir::new().unwrap();
        let account = acc(8);
        let old = "[tui]\nstatus_line = [\"thread-name\"]\n";
        let next = "[tui]\nstatus_line = [\"reasoning\"]\n";
        write_config_toml_with_global(base.path(), account, None, Some(old)).unwrap();
        let logs = Arc::new(Mutex::new(Vec::new()));
        FAIL_STATUS_LINE_NARROW.with(|flag| flag.set(true));
        let _capture = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let outcome = tracing::subscriber::with_default(Capture(logs.clone()), || {
            tracing::callsite::rebuild_interest_cache();
            write_config_toml_with_global(base.path(), account, None, Some(next))
        });
        assert!(outcome.is_ok());
        assert!(
            !FAIL_STATUS_LINE_NARROW.with(|flag| flag.get()),
            "narrow failure must fire"
        );
        let path = config_toml_path(base.path(), account);
        assert_eq!(
            status_line_value(&std::fs::read_to_string(&path).unwrap()),
            status_line_value(next)
        );
        assert_eq!(read_status_line_owner(&path).unwrap().lines().count(), 2);
        let logs = logs.lock().unwrap();
        assert!(logs.iter().any(|line| {
            line.contains("codex_status_line_owner_narrow_failed")
                && line.contains("config published; statusline ownership record retains transition")
        }));
    }

    #[test]
    fn statusline_preserves_exact_old_global_default() {
        let rendered = render_config_toml_with_global(None, Some(OLD_STATUS_LINE_CONFIG));
        assert_eq!(
            status_line_value(&rendered),
            status_line_value(OLD_STATUS_LINE_CONFIG)
        );
    }

    #[test]
    fn statusline_propagated_global_tracks_edits_and_deletion() {
        let y = "[tui]\nstatus_line = [\"reasoning\"]\n";
        let _env = EnvGuard::new_with_fixture(y);
        let base = TempDir::new().unwrap();
        let account = acc(8);
        let x = "[tui]\nstatus_line = [\"thread-name\"]\n";
        write_config_toml_with_global(base.path(), account, None, Some(x)).unwrap();
        regenerate_slot_config(base.path(), account).unwrap();
        let path = config_toml_path(base.path(), account);
        assert_eq!(
            status_line_value(&std::fs::read_to_string(&path).unwrap()),
            status_line_value(y)
        );
        std::fs::remove_file(std::env::var_os(USER_CONFIG_ENV_OVERRIDE).unwrap()).unwrap();
        regenerate_slot_config(base.path(), account).unwrap();
        assert_default_statusline_present(&std::fs::read_to_string(path).unwrap());
    }

    #[test]
    fn statusline_recorded_copy_distinguishes_user_edits_including_exact_default() {
        let _env = EnvGuard::new_isolated();
        for custom in [
            render_config_toml(None),
            "[tui]\nstatus_line = [\"git-branch\"]\n".into(),
        ] {
            let base = TempDir::new().unwrap();
            let account = acc(8);
            let global = "[tui]\nstatus_line = [\"thread-name\"]\n";
            write_config_toml_with_global(base.path(), account, None, Some(global)).unwrap();
            let path = config_toml_path(base.path(), account);
            std::fs::write(&path, &custom).unwrap();
            write_config_toml_with_global(base.path(), account, None, Some(global)).unwrap();
            assert_eq!(
                status_line_value(&std::fs::read_to_string(&path).unwrap()),
                status_line_value(&custom)
            );
            // A second merge must not adopt the preserved user value as csq-owned.
            write_config_toml_with_global(base.path(), account, None, Some(global)).unwrap();
            assert_eq!(
                status_line_value(&std::fs::read_to_string(path).unwrap()),
                status_line_value(&custom)
            );
        }
    }

    #[test]
    fn statusline_bad_global_tui_preserves_custom_slot_and_file() {
        let _env = EnvGuard::new_isolated();
        let base = TempDir::new().unwrap();
        let account = acc(8);
        let path = config_toml_path(base.path(), account);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let custom = "[tui]\nstatus_line = [\"reasoning\"]\n";
        std::fs::write(&path, custom).unwrap();
        let error =
            write_config_toml_with_global(base.path(), account, None, Some("tui = \"oops\"\n"))
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read_to_string(path).unwrap(), custom);
    }

    #[test]
    fn statusline_regeneration_upgrades_old_slot_default() {
        let _env = EnvGuard::new_isolated();
        let base = TempDir::new().unwrap();
        let account = acc(8);
        let path = config_toml_path(base.path(), account);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, OLD_STATUS_LINE_CONFIG).unwrap();
        regenerate_slot_config(base.path(), account).unwrap();
        assert_default_statusline_present(&std::fs::read_to_string(path).unwrap());
    }

    #[test]
    fn statusline_preserves_custom_slot_on_regeneration_and_write() {
        let _env = EnvGuard::new_isolated();
        for regenerate in [true, false] {
            let base = TempDir::new().unwrap();
            let account = acc(8);
            let path = config_toml_path(base.path(), account);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let custom = "[tui]\nstatus_line = [\"thread-name\", \"context-used\"]\n";
            std::fs::write(&path, custom).unwrap();
            if regenerate {
                regenerate_slot_config(base.path(), account).unwrap();
            } else {
                write_config_toml(base.path(), account, None).unwrap();
            }
            assert_eq!(
                status_line_value(&std::fs::read_to_string(path).unwrap()),
                status_line_value(custom)
            );
        }
    }

    #[test]
    fn statusline_custom_values_win_over_defaults_and_each_other() {
        let _env = EnvGuard::new_isolated();
        let base = TempDir::new().unwrap();
        let custom_global =
            "[tui]\nstatus_line = [\"thread-name\"]\nstatus_line_use_colors = false\n";
        let custom_slot = "[tui]\nstatus_line = [\"reasoning\"]\n";
        let current = render_config_toml(None);
        for default in [OLD_STATUS_LINE_CONFIG, current.as_str()] {
            for (global, slot, expected) in [
                (custom_global, default, custom_global),
                (default, custom_slot, custom_slot),
                (custom_global, custom_slot, custom_slot),
            ] {
                let out =
                    render_slot_config_toml(base.path(), None, Some(global), Some(slot), None)
                        .unwrap()
                        .contents;
                assert_eq!(status_line_value(&out), status_line_value(expected));
            }
        }
        {
            let (global, slot) = (custom_global, "tui = \"oops\"");
            let out = render_slot_config_toml(base.path(), None, Some(global), Some(slot), None)
                .unwrap()
                .contents;
            assert_eq!(
                toml::from_str::<toml::Value>(&out).unwrap()["tui"].as_str(),
                Some("oops")
            );
        }
    }

    #[test]
    fn statusline_owner_missing_invalid_and_unreadable_use_migration_rule() {
        let _env = EnvGuard::new_isolated();
        for record in [None, Some("bad-hash"), Some("directory")] {
            for slot in [
                OLD_STATUS_LINE_CONFIG,
                "[tui]\nstatus_line = [\"reasoning\"]\n",
            ] {
                let base = TempDir::new().unwrap();
                let account = acc(8);
                let path = config_toml_path(base.path(), account);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, slot).unwrap();
                let owner_path = status_line_owner_path(&path);
                match record {
                    Some("directory") => std::fs::create_dir(&owner_path).unwrap(),
                    Some(contents) => std::fs::write(&owner_path, contents).unwrap(),
                    None => {}
                }
                // Exercise migration independently from publication failures.
                let owner = read_status_line_owner(&path);
                assert!(owner.is_none());
                let out =
                    render_slot_config_toml(base.path(), None, None, Some(slot), owner.as_deref())
                        .unwrap();
                if slot == OLD_STATUS_LINE_CONFIG {
                    assert_default_statusline_present(&out.contents);
                } else {
                    assert_eq!(status_line_value(&out.contents), status_line_value(slot));
                }
            }
        }
    }

    #[test]
    fn statusline_owner_matches_rendered_value_and_is_private() {
        let _env = EnvGuard::new_isolated();
        let base = TempDir::new().unwrap();
        let account = acc(8);
        write_config_toml_with_global(base.path(), account, None, None).unwrap();
        let path = config_toml_path(base.path(), account);
        let content = std::fs::read_to_string(&path).unwrap();
        let record = read_status_line_owner(&path).unwrap();
        assert_eq!(
            record,
            status_line_hash(&status_line_value(&content)).unwrap()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(status_line_owner_path(&path))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        // Valid records override default-array heuristics too.
        let old = toml::from_str::<toml::Value>(OLD_STATUS_LINE_CONFIG).unwrap();
        std::fs::write(&path, OLD_STATUS_LINE_CONFIG).unwrap();
        std::fs::write(
            status_line_owner_path(&path),
            status_line_hash(&old["tui"]["status_line"]).unwrap(),
        )
        .unwrap();
        regenerate_slot_config(base.path(), account).unwrap();
        assert_default_statusline_present(&std::fs::read_to_string(path).unwrap());
    }

    #[test]
    fn statusline_owner_publication_failure_cleans_tmp_and_repairs() {
        let _env = EnvGuard::new_isolated();
        let base = TempDir::new().unwrap();
        let account = acc(8);
        let path = config_toml_path(base.path(), account);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let owner = status_line_owner_path(&path);
        std::fs::create_dir(&owner).unwrap();
        let global = "[tui]\nstatus_line = [\"thread-name\"]\n";
        assert!(write_config_toml_with_global(base.path(), account, None, Some(global)).is_err());
        // Metadata preparation must succeed before config publication begins.
        assert!(!path.exists());
        let mut names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        let mut expected = vec![std::ffi::OsString::from(STATUS_LINE_OWNER_FILENAME)];
        // The slot lock persists as a file on unix only; Windows locks with a named mutex.
        #[cfg(unix)]
        expected.push(std::ffi::OsString::from(SLOT_CONFIG_LOCK_FILENAME));
        expected.sort();
        assert_eq!(names, expected);
        std::fs::remove_dir(&owner).unwrap();
        write_config_toml_with_global(base.path(), account, None, Some(global)).unwrap();
        assert_eq!(
            read_status_line_owner(&path).unwrap(),
            status_line_hash(&status_line_value(global)).unwrap()
        );
    }

    #[test]
    fn statusline_stale_owner_after_interrupted_publication_preserves_payload() {
        let _env = EnvGuard::new_isolated();
        let base = TempDir::new().unwrap();
        let account = acc(8);
        let old = "[tui]\nstatus_line = [\"thread-name\"]\n";
        let next = "[tui]\nstatus_line = [\"reasoning\"]\n";
        write_config_toml_with_global(base.path(), account, None, Some(old)).unwrap();
        let path = config_toml_path(base.path(), account);
        let record = std::fs::read(status_line_owner_path(&path)).unwrap();
        // Simulate stopping exactly after config rename, before sidecar rename.
        write_config_toml_contents(&path, next).unwrap();
        write_config_toml_with_global(base.path(), account, None, Some(old)).unwrap();
        assert_eq!(
            status_line_value(&std::fs::read_to_string(&path).unwrap()),
            status_line_value(next)
        );
        assert_eq!(
            std::fs::read(status_line_owner_path(&path)).unwrap(),
            record
        );
    }

    #[test]
    fn statusline_config_publication_failure_keeps_owner_and_cleans_tmp() {
        let _env = EnvGuard::new_isolated();
        let base = TempDir::new().unwrap();
        let account = acc(8);
        write_config_toml_with_global(base.path(), account, None, None).unwrap();
        let path = config_toml_path(base.path(), account);
        let owner = status_line_owner_path(&path);
        let record = std::fs::read(&owner).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(write_config_toml_contents(&path, "private config payload").is_err());
        assert_eq!(std::fs::read(&owner).unwrap(), record);
        let mut names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        // No temporary publication file may remain. The slot lock persists as a file on
        // unix only; Windows locks with a named mutex.
        let mut expected = vec![
            std::ffi::OsString::from(STATUS_LINE_OWNER_FILENAME),
            path.file_name().unwrap().to_os_string(),
        ];
        #[cfg(unix)]
        expected.push(std::ffi::OsString::from(SLOT_CONFIG_LOCK_FILENAME));
        expected.sort();
        assert_eq!(names, expected);
    }

    #[test]
    fn statusline_preserves_every_nondefault_global_value() {
        for line in [
            "[]",
            "[\"current-dir\", \"git-branch\", \"context-remaining\", \"model-with-reasoning\"]",
            "[\"model-with-reasoning\", \"context-remaining\", \"git-branch\", \"current-dir\", \"weekly-limit\"]",
            "[\"model-with-reasoning\", \"context-remaining\", \"git-branch\"]",
            "\"malformed-user-value\"",
        ] {
            let config = format!("[tui]\nstatus_line = {line}\n");
            assert_eq!(
                status_line_value(&render_config_toml_with_global(None, Some(&config))),
                status_line_value(&config)
            );
        }
    }

    #[test]
    fn statusline_default_matches_claude_order_and_verified_0162_1_catalog() {
        // Pinned binary-string catalog from owner-approved Q4 Codex statusline
        // brief, 2026-10-16; independent of the production default.
        const VERIFIED_0162_1: &[&str] = &[
            "model-with-reasoning",
            "reasoning",
            "project-name",
            "current-dir",
            "git-branch",
            "run-state",
            "thread-name",
            "thread-title",
            "thread-id",
            "task-progress",
            "fast-mode",
            "codex-version",
            "context-remaining",
            "context-used",
            "used-tokens",
            "total-input-tokens",
            "total-output-tokens",
            "five-hour-limit",
            "weekly-limit",
            "thread-credits",
            "estimated-thread-cost",
        ];
        assert_eq!(
            CSQ_DEFAULT_STATUS_LINE,
            &[
                "weekly-limit",
                "context-used",
                "estimated-thread-cost",
                "model-with-reasoning",
                "project-name",
                "git-branch"
            ]
        );
        assert!(CSQ_DEFAULT_STATUS_LINE
            .iter()
            .all(|item| VERIFIED_0162_1.contains(item)));
        assert_default_statusline_present(&render_config_toml(None));
    }

    #[test]
    fn render_respects_user_configured_status_line() {
        // User chose their own codex statusline (via `/statusline` or by hand) →
        // csq MUST NOT override it (user-wins-if-present).
        let user_global = r#"
[tui]
status_line = ["model", "git-branch"]
"#;
        let out = render_config_toml_with_global(Some("m1"), Some(user_global));
        assert!(
            toml::from_str::<toml::Value>(&out).is_ok(),
            "must be valid TOML; got:\n{out}"
        );
        assert!(
            out.contains("\"model\"") && out.contains("\"git-branch\""),
            "user's status_line must be preserved; got:\n{out}"
        );
        // csq's full curated array must NOT have been injected on top.
        assert!(
            !out.contains("model-with-reasoning"),
            "csq must not override the user's status_line; got:\n{out}"
        );
        // exactly one status_line key (no duplicate / collision).
        assert_eq!(
            out.matches("status_line = [").count(),
            1,
            "exactly one status_line; got:\n{out}"
        );
    }

    #[test]
    fn render_injects_status_line_into_existing_tui_table_preserving_siblings() {
        // User has a [tui] table but no status_line → csq adds status_line and
        // preserves the user's other [tui] keys.
        let user_global = r#"
[tui]
status_line_use_colors = false
"#;
        let out = render_config_toml_with_global(Some("m1"), Some(user_global));
        assert_default_statusline_present(&out);
        assert!(
            out.contains("status_line_use_colors = false"),
            "user's other [tui] keys must be preserved; got:\n{out}"
        );
    }

    #[test]
    fn render_leaves_non_table_tui_untouched() {
        // Defensive: user's `tui` is a scalar (malformed for codex) → csq does
        // NOT clobber it and does NOT panic; no status_line is forced in.
        let user_global = "tui = \"oops\"\n";
        let out = render_config_toml_with_global(Some("m1"), Some(user_global));
        assert!(
            toml::from_str::<toml::Value>(&out).is_ok(),
            "must be valid TOML; got:\n{out}"
        );
        assert!(
            out.contains("tui = \"oops\""),
            "non-table tui must be left untouched; got:\n{out}"
        );
        assert!(
            !out.contains("status_line"),
            "must not force status_line into a non-table tui; got:\n{out}"
        );
    }

    #[test]
    fn write_config_toml_includes_default_statusline_end_to_end() {
        // The shipped path: write_config_toml (login / reconciler / model-switch)
        // produces a slot config.toml carrying csq's curated statusline.
        let _env = EnvGuard::new_isolated();
        let dir = TempDir::new().unwrap();
        let account = acc(8);
        write_config_toml(dir.path(), account, Some("gpt-test")).unwrap();
        let contents = std::fs::read_to_string(config_toml_path(dir.path(), account)).unwrap();
        assert_default_statusline_present(&contents);
    }

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn caller_overrides_sandbox_detects_passthrough_policy_flags() {
        // GH an internal ticket: a caller downscoping a one-shot must suppress the derived flags.
        assert!(caller_overrides_sandbox(&v(&["exec", "-s", "read-only"])));
        assert!(caller_overrides_sandbox(&v(&[
            "exec",
            "--sandbox",
            "read-only"
        ])));
        assert!(caller_overrides_sandbox(&v(&[
            "exec",
            "--sandbox=read-only"
        ])));
        assert!(caller_overrides_sandbox(&v(&["exec", "-a", "never"])));
        assert!(caller_overrides_sandbox(&v(&[
            "exec",
            "--ask-for-approval",
            "on-request"
        ])));
        assert!(caller_overrides_sandbox(&v(&["exec", "--full-auto"])));
        assert!(caller_overrides_sandbox(&v(&[
            "exec",
            "--dangerously-bypass-approvals-and-sandbox"
        ])));
        assert!(caller_overrides_sandbox(&v(&[
            "exec",
            "--ignore-user-config"
        ])));
        // The exact repro from the issue.
        assert!(caller_overrides_sandbox(&v(&[
            "exec",
            "-s",
            "read-only",
            "--skip-git-repo-check",
            "--output-last-message",
            "/tmp/m.txt"
        ])));
    }

    #[test]
    fn caller_overrides_sandbox_false_when_no_policy_flag() {
        // No sandbox/approval flag → derived flags still apply (unchanged behavior).
        assert!(!caller_overrides_sandbox(&v(&[
            "exec",
            "--skip-git-repo-check"
        ])));
        assert!(!caller_overrides_sandbox(&v(&["exec", "hello world"])));
        assert!(!caller_overrides_sandbox(&v(&[])));
        // A value that merely CONTAINS a flag name as a substring must not match.
        assert!(!caller_overrides_sandbox(&v(&[
            "exec",
            "--output-last-message",
            "-secret.txt"
        ])));
    }

    /// Item 4: csq's slot-config writers are serialized by one per-slot lock. While the carry
    /// holds it (inside its pre-rename window) a second writer must be BLOCKED, then run
    /// after, keeping the carried entry.
    #[cfg(unix)]
    #[test]
    fn slot_writers_wait_for_the_lock_the_carry_holds() {
        lock_wait_case(|b| {
            write_config_toml_with_global(b, acc(1), None, Some("approval_policy = \"never\"\n"))
                .unwrap();
        });
    }

    #[cfg(unix)]
    #[test]
    fn regenerate_waits_for_the_lock_the_carry_holds() {
        lock_wait_case(|b| {
            regenerate_slot_config(b, acc(1)).unwrap();
        });
    }

    #[cfg(unix)]
    fn lock_wait_case(writer: fn(&Path)) {
        use crate::session::codex_hook_trust::{carry_hook_trust, CarryMode};
        use std::cell::{Cell, RefCell};
        use std::rc::Rc;
        const H_TRUE: &str =
            "sha256:2ba34c7a02841fada06b868a093d041fd3d9de81883c789a321916b0aa118851";
        let _env = EnvGuard::new_isolated();
        let d = TempDir::new().unwrap();
        let base = d.path().canonicalize().unwrap().join("accounts");
        let account = acc(1);
        let cfg = config_toml_path(&base, account);
        std::fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        let global = d.path().join("hooks.json");
        std::fs::write(
            &global,
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"true"}]}]}}"#,
        )
        .unwrap();
        let src = base.join("term-77701");
        let new = base.join("term-77702");
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(
            &cfg,
            format!(
                "cli_auth_credentials_store = \"file\"\n\n[hooks.state.\"{}/hooks.json:stop:0:0\"]\ntrusted_hash = \"{H_TRUE}\"\nenabled = true\n",
                src.display()
            ),
        )
        .unwrap();

        let jh_slot: Rc<RefCell<Option<std::thread::JoinHandle<()>>>> = Rc::new(RefCell::new(None));
        let finished_in_window = Rc::new(Cell::new(None));
        let (w, fin, b2) = (jh_slot.clone(), finished_in_window.clone(), base.clone());
        test_seam::BEFORE_RENAME.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |_| {
                if w.borrow().is_some() {
                    return;
                }
                let b3 = b2.clone();
                let jh = std::thread::spawn(move || {
                    writer(&b3);
                });
                std::thread::sleep(std::time::Duration::from_millis(400));
                fin.set(Some(jh.is_finished()));
                *w.borrow_mut() = Some(jh);
            }));
        });
        let r = carry_hook_trust(&base, &new, account, Some(&global), CarryMode::Create);
        test_seam::BEFORE_RENAME.with(|h| *h.borrow_mut() = None);
        r.unwrap();
        assert_eq!(
            finished_in_window.get(),
            Some(false),
            "a second writer ran while the carry held the slot lock"
        );
        jh_slot.borrow_mut().take().unwrap().join().unwrap();
        let after = std::fs::read_to_string(&cfg).unwrap();
        assert!(
            after.contains(&format!("{}/hooks.json:stop:0:0", new.display())),
            "carried entry lost: {after}"
        );
    }

    // ── R3: publish-by-exchange, conditional writers ───────────────────────

    /// Runs `f` once, on the FIRST call of the pre-exchange seam, then never again.
    #[cfg(unix)]
    fn once_before_exchange(f: impl Fn(&Path) + 'static) -> SeamReset {
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        test_seam::BEFORE_RENAME.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |t| {
                if !fired.replace(true) {
                    f(t);
                }
            }));
        });
        SeamReset
    }

    /// Clears both thread-local seams on drop (panic included).
    #[cfg(unix)]
    struct SeamReset;
    #[cfg(unix)]
    impl Drop for SeamReset {
        fn drop(&mut self) {
            test_seam::BEFORE_RENAME.with(|h| *h.borrow_mut() = None);
            test_seam::AFTER_EXCHANGE.with(|h| *h.borrow_mut() = None);
            test_seam::AFTER_SWAP_BACK.with(|h| *h.borrow_mut() = None);
            test_seam::NO_EXCHANGE.with(|c| c.set(false));
            test_seam::EXCHANGE_FAIL_NTH.with(|c| c.set(None));
            test_seam::EXCHANGE_COUNT.with(|c| c.set(0));
            test_seam::NO_HARDLINK.with(|c| c.set(false));
            test_seam::LOCK_ATTEMPTS.with(|c| c.set(None));
            test_seam::ID_FAIL_NTH.with(|c| c.set(None));
            test_seam::ID_COUNT.with(|c| c.set(0));
        }
    }

    #[cfg(unix)]
    fn hook_state_entry(key: &str, enabled: bool) -> String {
        format!("\n[hooks.state.\"{key}\"]\ntrusted_hash = \"abc\"\nenabled = {enabled}\n")
    }

    #[cfg(unix)]
    fn append_to(path: &Path, text: &str) {
        let mut cur = std::fs::read_to_string(path).unwrap_or_default();
        cur.push_str(text);
        std::fs::write(path, cur).unwrap();
    }

    /// A user's `enabled = false` that Codex writes while a csq writer is between its read and
    /// its publish must survive: the writer re-reads, re-renders and publishes again.
    #[cfg(unix)]
    #[test]
    fn writers_keep_a_user_decision_landing_mid_publish() {
        for which in ["with_global", "regenerate", "absent"] {
            let _env = EnvGuard::new_isolated();
            let d = TempDir::new().unwrap();
            let root = d.path().canonicalize().unwrap();
            let account = acc(3);
            let path = config_toml_path(&root, account);
            let key = handle_trust_key(&root);
            if which != "absent" {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, "model = \"m\"\n").unwrap();
            }
            let entry = hook_state_entry(&key, false);
            let _seam = once_before_exchange({
                let entry = entry.clone();
                move |t| append_to(t, &entry)
            });
            match which {
                "regenerate" => {
                    regenerate_slot_config(&root, account).unwrap();
                }
                _ => write_config_toml_with_global(&root, account, Some("m2"), None).unwrap(),
            }
            let v: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(
                v["hooks"]["state"][&key]["enabled"].as_bool(),
                Some(false),
                "{which}: a write landing mid-publish was overwritten"
            );
        }
    }

    /// Exchange mismatch: csq swaps back, reports `Changed`, and the concurrent writer's bytes
    /// are the target again (never csq's), with no tmp left behind.
    #[cfg(unix)]
    #[test]
    fn exchange_mismatch_swaps_back_and_leaves_the_concurrent_bytes() {
        let d = TempDir::new().unwrap();
        let target = d.path().join("config.toml");
        std::fs::write(&target, "a = 1\n").unwrap();
        let _seam = once_before_exchange(|t| std::fs::write(t, "b = 2\n").unwrap());
        let r =
            write_config_toml_contents_if_unchanged(&target, "c = 3\n", Some(b"a = 1\n")).unwrap();
        assert_eq!(r, ConditionalWrite::Changed);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "b = 2\n");
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["config.toml".to_owned()], "tmp left: {names:?}");
        // and an unchanged target is published
        std::fs::write(&target, "a = 1\n").unwrap();
        drop(_seam);
        let r =
            write_config_toml_contents_if_unchanged(&target, "c = 3\n", Some(b"a = 1\n")).unwrap();
        assert_eq!(r, ConditionalWrite::Written);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "c = 3\n");
    }

    /// The swap-back races too (a Codex tmp-then-rename lands while csq's file is the target):
    /// csq refuses, the NEWEST concurrent file is the target, and the slot is flagged.
    #[cfg(unix)]
    #[test]
    fn a_racing_swap_back_refuses_keeps_the_newest_file_and_flags_the_slot() {
        let d = TempDir::new().unwrap();
        let target = d.path().join("config.toml");
        std::fs::write(&target, "a = 1\n").unwrap();
        let _seam = once_before_exchange(|t| std::fs::write(t, "b = 2\n").unwrap());
        test_seam::AFTER_EXCHANGE.with(|h| {
            *h.borrow_mut() = Some(Box::new(|t: &Path| {
                // Codex: tmp then rename over the target (csq's file is the target now).
                let tmp = t.with_file_name("codex-tmp");
                std::fs::write(&tmp, "d = 4\n").unwrap();
                std::fs::rename(&tmp, t).unwrap();
            }));
        });
        let e = write_config_toml_contents_if_unchanged(&target, "c = 3\n", Some(b"a = 1\n"))
            .unwrap_err();
        assert!(
            e.get_ref().is_some_and(|i| i.is::<ExchangeRaced>()),
            "{e:?}"
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "d = 4\n");
        assert!(slot_write_statuses_in(d.path()).contains(&SlotWriteStatus::Raced));
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != SLOT_STATUS_FILE)
            .collect();
        assert_eq!(names, vec!["config.toml".to_owned()], "tmp left: {names:?}");
        // r4 item 2: the flag is STICKY, a later clean publish does not clear it
        drop(_seam);
        std::fs::write(&target, "a = 1\n").unwrap();
        write_config_toml_contents_if_unchanged(&target, "c = 3\n", Some(b"a = 1\n")).unwrap();
        assert!(
            slot_write_statuses_in(d.path()).contains(&SlotWriteStatus::Raced),
            "a clean publish cleared the raced flag"
        );
    }

    #[cfg(unix)]
    fn slot_write_statuses_in(dir: &Path) -> Vec<SlotWriteStatus> {
        read_statuses(dir)
    }

    /// No atomic exchange (forced through the seam): the publish falls back to compare-then-
    /// rename, still keeps a changed target, publishes an unchanged one, and records
    /// `exchange-unsupported` for the doctor.
    #[cfg(unix)]
    #[test]
    fn without_an_atomic_exchange_the_compare_fallback_still_guards_and_flags_the_slot() {
        let d = TempDir::new().unwrap();
        let target = d.path().join("config.toml");
        std::fs::write(&target, "a = 1\n").unwrap();
        test_seam::NO_EXCHANGE.with(|c| c.set(true));
        let _reset = SeamReset;
        let seam = once_before_exchange(|t| std::fs::write(t, "b = 2\n").unwrap());
        let r =
            write_config_toml_contents_if_unchanged(&target, "c = 3\n", Some(b"a = 1\n")).unwrap();
        assert_eq!(r, ConditionalWrite::Changed);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "b = 2\n");
        drop(seam);
        test_seam::NO_EXCHANGE.with(|c| c.set(true));
        std::fs::write(&target, "a = 1\n").unwrap();
        let r =
            write_config_toml_contents_if_unchanged(&target, "c = 3\n", Some(b"a = 1\n")).unwrap();
        assert_eq!(r, ConditionalWrite::Written);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "c = 3\n");
        assert!(slot_write_statuses_in(d.path()).contains(&SlotWriteStatus::ExchangeUnsupported));
    }

    /// Item 6: a canonical `term-<pid>` key in the owner's `~/.codex/config.toml` is under the
    /// accounts base even when the base is given through a symlink, so it never overwrites the
    /// slot's own value on regeneration.
    #[cfg(unix)]
    #[test]
    fn rebuild_hooks_state_compares_canonical_forms_under_a_symlinked_base() {
        let d = TempDir::new().unwrap();
        let root = d.path().canonicalize().unwrap();
        let real = root.join("real-accounts");
        std::fs::create_dir_all(&real).unwrap();
        let link = root.join("link-accounts");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let key = format!("{}/term-9/hooks.json:stop:0:0", real.display());
        let entry = |en: bool| -> toml::value::Table {
            toml::from_str(&format!("trusted_hash = \"abc\"\nenabled = {en}\n")).unwrap()
        };
        let slot: toml::value::Table = [(key.clone(), toml::Value::Table(entry(false)))]
            .into_iter()
            .collect();
        let global: toml::value::Table = [(key.clone(), toml::Value::Table(entry(true)))]
            .into_iter()
            .collect();
        let out = rebuild_hooks_state(&link, Some(&slot), Some(&global));
        assert_eq!(
            out[&key]["enabled"].as_bool(),
            Some(false),
            "a global entry overwrote the slot's own csq-handle entry"
        );
    }

    // ── r4: identity-based swap-back, sticky raced, sweep, no-hard-link, oversize ──

    /// r4 item 1 (sec M1): csq's own file is unreadable after the swap-back (here over the
    /// 1 MiB read bound). That is NOT evidence of a second race: the concurrent file must stay
    /// the target and must not be deleted.
    #[cfg(unix)]
    #[test]
    fn a_big_csq_file_after_the_swap_back_never_clobbers_a_concurrent_write() {
        let d = TempDir::new().unwrap();
        let target = d.path().join("config.toml");
        std::fs::write(&target, "e = 1\n").unwrap();
        // Codex lands a disable before csq's exchange.
        std::fs::write(&target, "d = 4 # concurrent\n").unwrap();
        let big = "#".repeat((1 << 20) + 16);
        let tmp = unique_tmp_path(&target);
        crate::platform::fs::write_new_private_synced(&tmp, big.as_bytes()).unwrap();
        let r = publish_by_exchange(&tmp, &target, b"e = 1\n");
        assert!(
            matches!(r, Ok(ConditionalWrite::Changed)),
            "a clean swap-back is Changed, got {r:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "d = 4 # concurrent\n",
            "csq's oversize file replaced the concurrent write"
        );
        assert!(!tmp.exists(), "csq's own tmp was left behind");
    }

    /// r4 item 1 (sec L1a): the swap-back exchange itself fails. The concurrent file is
    /// restored over csq's with a plain replace, nothing is left behind, and the slot is
    /// flagged.
    #[cfg(unix)]
    #[test]
    fn a_failed_swap_back_exchange_restores_the_concurrent_file() {
        let d = TempDir::new().unwrap();
        let target = d.path().join("config.toml");
        std::fs::write(&target, "a = 1\n").unwrap();
        let _seam = once_before_exchange(|t| std::fs::write(t, "b = 2\n").unwrap());
        let _reset = SeamReset;
        test_seam::EXCHANGE_COUNT.with(|c| c.set(0));
        test_seam::EXCHANGE_FAIL_NTH.with(|c| c.set(Some(2)));
        let e = write_config_toml_contents_if_unchanged(&target, "c = 3\n", Some(b"a = 1\n"))
            .unwrap_err();
        assert!(
            e.get_ref().is_some_and(|i| i.is::<ExchangeRaced>()),
            "{e:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "b = 2\n",
            "csq's bytes were left over the concurrent write"
        );
        assert!(slot_write_statuses_in(d.path()).contains(&SlotWriteStatus::Raced));
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != SLOT_STATUS_FILE)
            .collect();
        assert_eq!(names, vec!["config.toml".to_owned()], "tmp left: {names:?}");
    }

    /// r4 item 2: a leftover `config.tmp.*` in a slot dir (a crashed or raced publish) is
    /// flagged `raced` the next time any csq writer takes the slot lock, and is never deleted.
    #[cfg(unix)]
    #[test]
    fn a_stale_config_tmp_is_flagged_raced_and_never_deleted() {
        let _env = EnvGuard::new_isolated();
        let d = TempDir::new().unwrap();
        let root = d.path().canonicalize().unwrap();
        let dir = root.join("config-2");
        std::fs::create_dir_all(&dir).unwrap();
        let stale = dir.join("config.tmp.99999.7");
        std::fs::write(&stale, "model = \"orphan\"\n").unwrap();
        assert!(slot_write_statuses(&root, acc(2)).is_empty());
        write_config_toml_with_global(&root, acc(2), None, None).unwrap();
        assert_eq!(
            std::fs::read_to_string(&stale).unwrap(),
            "model = \"orphan\"\n",
            "the stale tmp was deleted or changed"
        );
        assert!(
            slot_write_statuses(&root, acc(2)).contains(&SlotWriteStatus::Raced),
            "a stale tmp was not flagged"
        );
    }

    /// r4 item 6: a filesystem without hard links. The expected-absent publish falls back to
    /// create-exclusive-then-rename, flags the slot, and still yields to a concurrent creator.
    #[cfg(unix)]
    #[test]
    fn an_absent_config_publishes_on_a_filesystem_without_hard_links() {
        let d = TempDir::new().unwrap();
        let target = d.path().join("config.toml");
        let _reset = SeamReset;
        test_seam::NO_HARDLINK.with(|c| c.set(true));
        let r = write_config_toml_contents_if_unchanged(&target, "c = 3\n", None).unwrap();
        assert_eq!(r, ConditionalWrite::Written);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "c = 3\n");
        assert!(slot_write_statuses_in(d.path()).contains(&SlotWriteStatus::ExchangeUnsupported));
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != SLOT_STATUS_FILE)
            .collect();
        assert_eq!(names, vec!["config.toml".to_owned()], "tmp left: {names:?}");
        // a concurrent creator wins: Changed, and its file is untouched
        std::fs::remove_file(&target).unwrap();
        let _seam = once_before_exchange(|t| std::fs::write(t, "b = 2\n").unwrap());
        let r = write_config_toml_contents_if_unchanged(&target, "c = 3\n", None).unwrap();
        assert_eq!(r, ConditionalWrite::Changed);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "b = 2\n");
    }

    /// r4 item 6: a slot config over 1 MiB gets its own error, not "kept changing".
    #[cfg(unix)]
    #[test]
    fn an_oversize_slot_config_gets_its_own_error() {
        let _env = EnvGuard::new_isolated();
        let d = TempDir::new().unwrap();
        let root = d.path().canonicalize().unwrap();
        let path = config_toml_path(&root, acc(3));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("#{}\n", "x".repeat((1 << 20) + 16))).unwrap();
        let before = std::fs::read(&path).unwrap();
        let e = write_config_toml_with_global(&root, acc(3), None, None).unwrap_err();
        assert!(e.to_string().contains("exceeds 1 MiB"), "{e}");
        let e = regenerate_slot_config(&root, acc(3)).unwrap_err();
        assert!(e.to_string().contains("exceeds 1 MiB"), "{e}");
        assert_eq!(std::fs::read(&path).unwrap(), before, "the config changed");
    }

    /// r4 item 4: the status file is published by tmp + rename (a concurrent doctor read never
    /// sees a truncated file), at 0600, with no tmp left.
    #[cfg(unix)]
    #[test]
    fn the_status_file_is_published_by_rename() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = TempDir::new().unwrap();
        set_slot_status(d.path(), SlotWriteStatus::Raced);
        let path = d.path().join(SLOT_STATUS_FILE);
        let first = std::fs::metadata(&path).unwrap().ino();
        set_slot_status(d.path(), SlotWriteStatus::PurgeFailed);
        let m = std::fs::metadata(&path).unwrap();
        assert_ne!(m.ino(), first, "the status file was rewritten in place");
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![SLOT_STATUS_FILE.to_owned()],
            "tmp left: {names:?}"
        );
    }

    // ── r4: swap-back identity branches, ack, per-handle status ────────────────

    /// Runs one conditional publish where a concurrent file `b = 2` lands before the first
    /// exchange; returns the publish result.
    #[cfg(unix)]
    fn publish_against_a_concurrent_write(dir: &Path) -> (PathBuf, io::Result<ConditionalWrite>) {
        let target = dir.join("config.toml");
        std::fs::write(&target, "a = 1\n").unwrap();
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        test_seam::BEFORE_RENAME.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |t: &Path| {
                if !fired.replace(true) {
                    std::fs::write(t, "b = 2\n").unwrap();
                }
            }));
        });
        let r = write_config_toml_contents_if_unchanged(&target, "c = 3\n", Some(b"a = 1\n"));
        (target, r)
    }

    #[cfg(unix)]
    fn tmp_files(dir: &Path) -> Vec<PathBuf> {
        stale_config_tmps(dir)
    }

    /// r4 item 1: a metadata error after the swap-back stops everything: no third exchange,
    /// the target keeps the concurrent file, the tmp file is KEPT (never deleted), and the
    /// slot is flagged.
    #[cfg(unix)]
    #[test]
    fn a_metadata_error_after_the_swap_back_stops_keeps_the_tmp_and_flags_the_slot() {
        let d = TempDir::new().unwrap();
        let _reset = SeamReset;
        test_seam::ID_COUNT.with(|c| c.set(0));
        test_seam::EXCHANGE_COUNT.with(|c| c.set(0));
        // file_id calls: 1 = csq's tmp before the exchange, 2 = the displaced file, 3 = the
        // file the swap-back displaced.
        test_seam::ID_FAIL_NTH.with(|c| c.set(Some(3)));
        let (target, r) = publish_against_a_concurrent_write(d.path());
        assert!(r
            .unwrap_err()
            .get_ref()
            .is_some_and(|i| i.is::<ExchangeRaced>()));
        assert_eq!(
            test_seam::EXCHANGE_COUNT.with(std::cell::Cell::get),
            2,
            "csq exchanged again after a metadata error"
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "b = 2\n");
        let kept = tmp_files(d.path());
        assert_eq!(kept.len(), 1, "the tmp file was deleted: {kept:?}");
        assert_eq!(std::fs::read_to_string(&kept[0]).unwrap(), "c = 3\n");
        assert!(slot_write_statuses_in(d.path()).contains(&SlotWriteStatus::Raced));
    }

    /// r4 item 1: the metadata error comes right after the FIRST exchange: csq cannot tell
    /// what it displaced, so it does nothing more (one exchange, tmp kept, flagged).
    #[cfg(unix)]
    #[test]
    fn a_metadata_error_after_the_first_exchange_does_nothing_more() {
        let d = TempDir::new().unwrap();
        let _reset = SeamReset;
        test_seam::ID_COUNT.with(|c| c.set(0));
        test_seam::EXCHANGE_COUNT.with(|c| c.set(0));
        test_seam::ID_FAIL_NTH.with(|c| c.set(Some(2)));
        let (target, r) = publish_against_a_concurrent_write(d.path());
        assert!(r.is_err());
        assert_eq!(test_seam::EXCHANGE_COUNT.with(std::cell::Cell::get), 1);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "c = 3\n");
        let kept = tmp_files(d.path());
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert_eq!(std::fs::read_to_string(&kept[0]).unwrap(), "b = 2\n");
        assert!(slot_write_statuses_in(d.path()).contains(&SlotWriteStatus::Raced));
    }

    /// r4 item 1: a third write lands during the swap-back and the exchange that puts it back
    /// fails: the newest file is restored with a plain replace.
    #[cfg(unix)]
    #[test]
    fn a_failed_third_exchange_restores_the_newest_file() {
        let d = TempDir::new().unwrap();
        let _reset = SeamReset;
        test_seam::EXCHANGE_COUNT.with(|c| c.set(0));
        test_seam::EXCHANGE_FAIL_NTH.with(|c| c.set(Some(3)));
        test_seam::AFTER_EXCHANGE.with(|h| {
            *h.borrow_mut() = Some(Box::new(|t: &Path| {
                let tmp = t.with_file_name("codex-tmp");
                std::fs::write(&tmp, "d = 4\n").unwrap();
                std::fs::rename(&tmp, t).unwrap();
            }));
        });
        let (target, r) = publish_against_a_concurrent_write(d.path());
        assert!(r.is_err());
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "d = 4\n",
            "the newest concurrent file was not restored"
        );
        assert!(tmp_files(d.path()).is_empty());
        assert!(slot_write_statuses_in(d.path()).contains(&SlotWriteStatus::Raced));
    }

    /// An oversize rendering is refused before anything is written.
    #[cfg(unix)]
    #[test]
    fn an_oversize_rendering_is_never_published() {
        let d = TempDir::new().unwrap();
        let target = d.path().join("config.toml");
        std::fs::write(&target, "a = 1\n").unwrap();
        let big = format!("#{}\n", "x".repeat((1 << 20) + 16));
        let e =
            write_config_toml_contents_if_unchanged(&target, &big, Some(b"a = 1\n")).unwrap_err();
        assert_eq!(SlotConfigFault::of(&e), Some(SlotConfigFault::Oversize));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "a = 1\n");
        assert!(tmp_files(d.path()).is_empty());
    }

    #[test]
    fn the_tmp_prefix_matches_what_unique_tmp_path_makes() {
        let p = unique_tmp_path(Path::new("/x/config-1/config.toml"));
        assert!(p
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(CONFIG_TMP_PREFIX)));
    }

    /// r4 item 2: only the owner's acknowledgement clears `raced` (and removes the leftovers);
    /// a second acknowledgement is a clean no-op.
    #[cfg(unix)]
    #[test]
    fn only_the_owners_ack_clears_raced_and_removes_the_leftover_tmp() {
        let _env = EnvGuard::new_isolated();
        let d = TempDir::new().unwrap();
        let root = d.path().canonicalize().unwrap();
        let dir = root.join("config-2");
        std::fs::create_dir_all(&dir).unwrap();
        let stale = dir.join("config.tmp.99999.7");
        std::fs::write(&stale, "x = 1\n").unwrap();
        write_config_toml_with_global(&root, acc(2), None, None).unwrap();
        assert!(slot_write_statuses(&root, acc(2)).contains(&SlotWriteStatus::Raced));
        write_config_toml_with_global(&root, acc(2), None, None).unwrap();
        assert!(
            slot_write_statuses(&root, acc(2)).contains(&SlotWriteStatus::Raced),
            "a clean write cleared the sticky flag"
        );
        let out = ack_slot_raced(&root, acc(2)).unwrap();
        assert_eq!(
            out,
            AckOutcome {
                cleared: true,
                tmp_removed: 1,
                markers_removed: 0
            }
        );
        assert!(!stale.exists());
        assert!(slot_write_statuses(&root, acc(2)).is_empty());
        let again = ack_slot_raced(&root, acc(2)).unwrap();
        assert_eq!(
            again,
            AckOutcome {
                cleared: false,
                tmp_removed: 0,
                markers_removed: 0
            }
        );
        // and a later write does not re-flag: nothing is left over
        write_config_toml_with_global(&root, acc(2), None, None).unwrap();
        assert!(slot_write_statuses(&root, acc(2)).is_empty());
        assert_eq!(
            ack_slot_raced(&root, acc(9)).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn status_lines_parse_the_known_forms_and_ignore_the_rest() {
        let p = |l| StatusLine::parse(l);
        assert_eq!(
            p("raced"),
            Some(StatusLine {
                status: SlotWriteStatus::Raced,
                handle: None
            })
        );
        assert_eq!(
            p("purge-failed term-12"),
            Some(StatusLine {
                status: SlotWriteStatus::PurgeFailed,
                handle: Some("term-12".into())
            })
        );
        assert!(p("purge-failed ../x y").is_none());
        assert!(p("purge-failed ").is_none());
        assert!(p("bogus").is_none());
    }

    /// r4 item 4: per-handle lines. One handle's clear never removes another LIVE handle's
    /// line; a gone handle's line goes with any clear.
    #[cfg(unix)]
    #[test]
    fn handle_status_lines_are_cleared_only_by_their_own_handle_or_once_it_is_gone() {
        let _env = EnvGuard::new_isolated();
        let d = TempDir::new().unwrap();
        let root = d.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("config-2")).unwrap();
        std::fs::create_dir_all(root.join("term-1")).unwrap();
        std::fs::create_dir_all(root.join("term-2")).unwrap();
        let a = acc(2);
        let s = SlotWriteStatus::PurgeFailed;
        note_handle_status(&root, a, s, "term-1", true);
        note_handle_status(&root, a, s, "term-2", true);
        note_handle_status(&root, a, s, "term-3", true); // dir never existed: gone
        note_handle_status(&root, a, s, "term-2", false);
        let lines = read_lines(&root.join("config-2"));
        let names: Vec<_> = lines.iter().filter_map(|l| l.handle.clone()).collect();
        assert_eq!(names, vec!["term-1".to_owned()], "{lines:?}");
        note_handle_status(&root, a, s, "term-1", false);
        assert!(slot_write_statuses(&root, a).is_empty());
    }

    /// r4 item 4: a status update waits for the slot lock (no lost update against a writer
    /// holding it).
    #[cfg(unix)]
    #[test]
    fn a_status_update_waits_for_the_slot_lock() {
        let _env = EnvGuard::new_isolated();
        let d = TempDir::new().unwrap();
        let root = d.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("config-2")).unwrap();
        let held = lock_slot_config(&root, acc(2)).unwrap();
        let r2 = root.clone();
        let jh = std::thread::spawn(move || {
            note_handle_status(&r2, acc(2), SlotWriteStatus::CarrySkipped, "term-7", true);
        });
        std::thread::sleep(std::time::Duration::from_millis(400));
        let finished_early = jh.is_finished();
        let early = slot_write_statuses(&root, acc(2));
        drop(held);
        jh.join().unwrap();
        assert!(
            !finished_early,
            "the update ran while the slot lock was held"
        );
        assert!(early.is_empty());
        assert_eq!(
            slot_write_statuses(&root, acc(2)),
            vec![SlotWriteStatus::CarrySkipped]
        );
    }

    /// r4b item 2: a status update whose slot-lock wait times out leaves a lock-free marker
    /// (not nothing); doctor's reader sees it; the ack clears the markers AND the flag.
    #[cfg(unix)]
    #[test]
    fn a_lock_timeout_leaves_a_marker_the_reader_sees_and_the_ack_clears() {
        let _env = EnvGuard::new_isolated();
        let d = TempDir::new().unwrap();
        let root = d.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("config-2")).unwrap();
        std::fs::create_dir_all(root.join("term-7")).unwrap();
        let a = acc(2);
        let held = lock_slot_config(&root, a).unwrap();
        test_seam::LOCK_ATTEMPTS.with(|c| c.set(Some(2)));
        note_handle_status(&root, a, SlotWriteStatus::PurgeFailed, "term-7", true);
        test_seam::LOCK_ATTEMPTS.with(|c| c.set(None));
        drop(held);
        // the status file was NOT written (the lock was never won) ...
        assert!(read_lines(&root.join("config-2")).is_empty());
        // ... but the event is recorded (kind and handle), and the reader reports it.
        let mdir = root.join("config-2").join(SLOT_MARKER_DIR);
        let files: Vec<_> = std::fs::read_dir(&mdir).unwrap().flatten().collect();
        assert_eq!(files.len(), 1);
        assert_eq!(
            std::fs::read_to_string(files[0].path()).unwrap(),
            "purge-failed term-7\n"
        );
        assert_eq!(
            slot_write_statuses(&root, a),
            vec![SlotWriteStatus::PurgeFailed]
        );
        // a later successful flag write does not hide the marker
        set_slot_status(&root.join("config-2"), SlotWriteStatus::Raced);
        let st = slot_write_statuses(&root, a);
        assert!(st.contains(&SlotWriteStatus::PurgeFailed), "{st:?}");
        assert!(st.contains(&SlotWriteStatus::Raced), "{st:?}");
        // the raced ack clears the flag but NOT the purge-failed marker (r4c) ...
        let out = ack_slot_raced(&root, a).unwrap();
        assert!(out.cleared);
        assert_eq!(out.markers_removed, 0);
        assert_eq!(
            slot_write_statuses(&root, a),
            vec![SlotWriteStatus::PurgeFailed]
        );
        // ... only that handle's own success clears it.
        note_handle_status(&root, a, SlotWriteStatus::PurgeFailed, "term-7", false);
        assert!(slot_write_statuses(&root, a).is_empty());
    }

    /// r4b item 2: a clear (set = false) that times out records nothing.
    #[cfg(unix)]
    #[test]
    fn a_timed_out_clear_leaves_no_marker() {
        let _env = EnvGuard::new_isolated();
        let d = TempDir::new().unwrap();
        let root = d.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("config-2")).unwrap();
        set_slot_status(&root.join("config-2"), SlotWriteStatus::Raced);
        let held = lock_slot_config(&root, acc(2)).unwrap();
        test_seam::LOCK_ATTEMPTS.with(|c| c.set(Some(2)));
        note_handle_status(
            &root,
            acc(2),
            SlotWriteStatus::CarrySkipped,
            "term-7",
            false,
        );
        test_seam::LOCK_ATTEMPTS.with(|c| c.set(None));
        drop(held);
        assert!(!root.join("config-2").join(SLOT_MARKER_DIR).exists());
    }

    /// r4b item 2: a symlink squatting on the marker path is never followed; the marker is
    /// created under another name, the symlink's target is untouched, and the squatter
    /// itself reads as a (fail-closed) marker.
    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_marker_path_is_not_followed() {
        let d = TempDir::new().unwrap();
        let slot = d.path().join("config-2");
        let mdir = slot.join(SLOT_MARKER_DIR);
        std::fs::create_dir_all(&mdir).unwrap();
        let victim = d.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        std::os::unix::fs::symlink(&victim, mdir.join("forced-name")).unwrap();
        test_seam::MARKER_NAME.with(|c| *c.borrow_mut() = Some("forced-name".into()));
        write_status_marker_in(&slot, SlotWriteStatus::Raced, None).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        assert!(std::fs::symlink_metadata(mdir.join("forced-name"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_dir(&mdir).unwrap().count(), 2);
        // the symlink is never read through either
        assert_eq!(
            classify_marker(&mdir.join("forced-name")),
            Marker::Unrecognised
        );
        let st = slot_write_statuses(d.path(), acc(2));
        assert!(st.contains(&SlotWriteStatus::Raced), "{st:?}");
        assert!(st.contains(&SlotWriteStatus::UnrecognisedMarker), "{st:?}");
        // the raced ack removes the real raced marker; the squatting link is unrecognised,
        // stays, and its target is never touched
        let _env = EnvGuard::new_isolated();
        let root = d.path().canonicalize().unwrap();
        let out = ack_slot_raced(&root, acc(2)).unwrap();
        assert_eq!(out.markers_removed, 1);
        assert!(std::fs::symlink_metadata(mdir.join("forced-name")).is_ok());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
    }

    /// r4b item 2: the marker is 0600, in a 0700 dir, and holds only the status word.
    #[cfg(unix)]
    #[test]
    fn a_marker_is_private_and_holds_only_the_flag_kind() {
        use std::os::unix::fs::PermissionsExt;
        let d = TempDir::new().unwrap();
        let slot = d.path().join("config-2");
        std::fs::create_dir_all(&slot).unwrap();
        write_status_marker_in(&slot, SlotWriteStatus::CarrySkipped, None).unwrap();
        let mdir = slot.join(SLOT_MARKER_DIR);
        assert_eq!(
            std::fs::metadata(&mdir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let entries: Vec<_> = std::fs::read_dir(&mdir).unwrap().flatten().collect();
        assert_eq!(entries.len(), 1);
        let p = entries[0].path();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "carry-skipped\n");
        // two events, two markers
        write_status_marker_in(&slot, SlotWriteStatus::CarrySkipped, None).unwrap();
        assert_eq!(std::fs::read_dir(&mdir).unwrap().count(), 2);
    }

    /// r4b item 2: an unreadable or unknown marker never reads as "none".
    #[cfg(unix)]
    #[test]
    fn an_unknown_marker_reads_fail_closed() {
        let d = TempDir::new().unwrap();
        let slot = d.path().join("config-2");
        let mdir = slot.join(SLOT_MARKER_DIR);
        std::fs::create_dir_all(&mdir).unwrap();
        std::fs::write(mdir.join("x"), "garbage\n").unwrap();
        assert_eq!(
            read_markers(&slot),
            vec![SlotWriteStatus::UnrecognisedMarker]
        );
    }

    // ── r4c: marker kinds and the 32-marker cap ───────────────────────────

    #[cfg(unix)]
    fn r4c_slot() -> (TempDir, PathBuf, PathBuf) {
        let d = TempDir::new().unwrap();
        let root = d.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("config-2")).unwrap();
        let mdir = root.join("config-2").join(".csq-status-markers");
        (d, root, mdir)
    }

    /// r4c A: the raced ack clears RACED markers only; a purge-failed marker survives it and
    /// is reported until THAT handle's success (r4 item 4) clears it.
    #[cfg(unix)]
    #[test]
    fn ack_raced_keeps_a_purge_failed_marker() {
        let _env = EnvGuard::new_isolated();
        let (_d, root, _m) = r4c_slot();
        write_status_marker(&root, acc(2), SlotWriteStatus::PurgeFailed).unwrap();
        write_status_marker(&root, acc(2), SlotWriteStatus::Raced).unwrap();
        let out = ack_slot_raced(&root, acc(2)).unwrap();
        assert_eq!(out.markers_removed, 1, "only the raced marker goes");
        assert_eq!(
            slot_write_statuses(&root, acc(2)),
            vec![SlotWriteStatus::PurgeFailed]
        );
    }

    #[cfg(unix)]
    #[test]
    fn ack_raced_keeps_a_carry_skipped_marker() {
        let _env = EnvGuard::new_isolated();
        let (_d, root, _m) = r4c_slot();
        write_status_marker(&root, acc(2), SlotWriteStatus::CarrySkipped).unwrap();
        write_status_marker(&root, acc(2), SlotWriteStatus::Raced).unwrap();
        ack_slot_raced(&root, acc(2)).unwrap();
        assert_eq!(
            slot_write_statuses(&root, acc(2)),
            vec![SlotWriteStatus::CarrySkipped]
        );
    }

    /// r4c A: an unknown-kind or unparseable marker is never cleared by the raced ack and
    /// never reads as clean.
    #[cfg(unix)]
    #[test]
    fn ack_raced_keeps_an_unknown_or_unparseable_marker() {
        for content in [
            "garbage\n",
            "future-kind term-3\n",
            "",
            "purge-failed ../x y\n",
        ] {
            let _env = EnvGuard::new_isolated();
            let (_d, root, mdir) = r4c_slot();
            std::fs::create_dir_all(&mdir).unwrap();
            std::fs::write(mdir.join("m1"), content).unwrap();
            ack_slot_raced(&root, acc(2)).unwrap();
            assert!(mdir.join("m1").exists(), "content {content:?} was cleared");
            assert!(
                !slot_write_statuses(&root, acc(2)).is_empty(),
                "content {content:?} read as clean"
            );
        }
    }

    /// r4c A: with only raced markers present the ack leaves the slot clean.
    #[cfg(unix)]
    #[test]
    fn ack_raced_with_only_raced_markers_is_clean() {
        let _env = EnvGuard::new_isolated();
        let (_d, root, mdir) = r4c_slot();
        for _ in 0..3 {
            write_status_marker(&root, acc(2), SlotWriteStatus::Raced).unwrap();
        }
        let out = ack_slot_raced(&root, acc(2)).unwrap();
        assert_eq!(out.markers_removed, 3);
        assert!(slot_write_statuses(&root, acc(2)).is_empty());
        assert!(!mdir.join("overflow").exists());
    }

    #[cfg(unix)]
    fn r4c_fill(root: &Path, n: usize, kind: SlotWriteStatus) {
        for _ in 0..n {
            write_status_marker(root, acc(2), kind).unwrap();
        }
    }

    /// r4c B: at cap-1 and at cap there is no overflow marker; the (cap+1)th event writes
    /// ONE overflow marker that reads as raced, and further events add no more files.
    #[cfg(unix)]
    #[test]
    fn the_marker_cap_is_32_then_one_overflow_marker() {
        let (_d, root, mdir) = r4c_slot();
        r4c_fill(&root, 31, SlotWriteStatus::Raced);
        assert_eq!(std::fs::read_dir(&mdir).unwrap().count(), 31);
        assert!(!mdir.join("overflow").exists(), "cap-1");
        r4c_fill(&root, 1, SlotWriteStatus::Raced);
        assert_eq!(std::fs::read_dir(&mdir).unwrap().count(), 32);
        assert!(!mdir.join("overflow").exists(), "at cap");
        r4c_fill(&root, 1, SlotWriteStatus::Raced);
        assert!(
            mdir.join("overflow").exists(),
            "cap+1 wrote no overflow marker"
        );
        assert_eq!(std::fs::read_dir(&mdir).unwrap().count(), 33);
        r4c_fill(&root, 5, SlotWriteStatus::Raced);
        assert_eq!(
            std::fs::read_dir(&mdir).unwrap().count(),
            33,
            "more than one overflow"
        );
        assert!(slot_write_statuses(&root, acc(2)).contains(&SlotWriteStatus::Raced));
    }

    /// r4c B: an overflow that stood only for raced events goes with the raced ack.
    #[cfg(unix)]
    #[test]
    fn an_overflow_of_raced_events_is_cleared_by_the_raced_ack() {
        let _env = EnvGuard::new_isolated();
        let (_d, root, mdir) = r4c_slot();
        r4c_fill(&root, 34, SlotWriteStatus::Raced);
        assert!(mdir.join("overflow").exists());
        ack_slot_raced(&root, acc(2)).unwrap();
        assert!(slot_write_statuses(&root, acc(2)).is_empty());
        assert!(!mdir.join("overflow").exists());
    }

    /// r4c B: an overflow that dropped a non-raced event is NOT cleared by the raced ack
    /// (the dropped event's handle is unknown, so no handle success can prove it resolved).
    #[cfg(unix)]
    #[test]
    fn an_overflow_that_dropped_a_non_raced_event_survives_the_raced_ack() {
        let _env = EnvGuard::new_isolated();
        let (_d, root, mdir) = r4c_slot();
        r4c_fill(&root, 32, SlotWriteStatus::Raced);
        r4c_fill(&root, 1, SlotWriteStatus::PurgeFailed);
        ack_slot_raced(&root, acc(2)).unwrap();
        assert!(mdir.join("overflow").exists(), "overflow was cleared");
        assert!(slot_write_statuses(&root, acc(2)).contains(&SlotWriteStatus::PurgeFailed));
    }

    /// r4c A: a marker records the handle; THAT handle's success, or its dir being gone,
    /// clears it; another live handle's success and the raced ack do not.
    #[cfg(unix)]
    #[test]
    fn a_handle_marker_clears_only_by_its_own_success_or_when_its_dir_is_gone() {
        let _env = EnvGuard::new_isolated();
        let (_d, root, mdir) = r4c_slot();
        std::fs::create_dir_all(root.join("term-1")).unwrap();
        std::fs::create_dir_all(root.join("term-2")).unwrap();
        let dir = root.join("config-2");
        write_status_marker_in(&dir, SlotWriteStatus::PurgeFailed, Some("term-1")).unwrap();
        write_status_marker_in(&dir, SlotWriteStatus::CarrySkipped, Some("term-1")).unwrap();
        write_status_marker_in(&dir, SlotWriteStatus::PurgeFailed, Some("term-9")).unwrap();
        let count = || std::fs::read_dir(&mdir).map_or(0, Iterator::count);
        assert_eq!(count(), 3);
        // another live handle's success touches nothing of term-1's (term-9 is gone: goes)
        note_handle_status(&root, acc(2), SlotWriteStatus::PurgeFailed, "term-2", false);
        let left = slot_write_statuses(&root, acc(2));
        assert_eq!(
            left,
            vec![SlotWriteStatus::PurgeFailed, SlotWriteStatus::CarrySkipped]
        );
        assert_eq!(count(), 2);
        // the raced ack leaves both
        ack_slot_raced(&root, acc(2)).unwrap();
        assert_eq!(count(), 2);
        // a carry success clears only the carry marker, of that handle
        note_handle_status(
            &root,
            acc(2),
            SlotWriteStatus::CarrySkipped,
            "term-1",
            false,
        );
        assert_eq!(
            slot_write_statuses(&root, acc(2)),
            vec![SlotWriteStatus::PurgeFailed]
        );
        note_handle_status(&root, acc(2), SlotWriteStatus::PurgeFailed, "term-1", false);
        assert!(slot_write_statuses(&root, acc(2)).is_empty());
    }

    /// r4c A: an unrecognised marker reads as the `unrecognised-marker` status (not raced,
    /// not clean) and a per-handle success never clears it.
    #[cfg(unix)]
    #[test]
    fn an_unrecognised_marker_reads_as_its_own_status_and_no_handle_clears_it() {
        let _env = EnvGuard::new_isolated();
        let (_d, root, mdir) = r4c_slot();
        std::fs::create_dir_all(&mdir).unwrap();
        std::fs::write(mdir.join("m"), "future-kind term-1\n").unwrap();
        assert_eq!(
            slot_write_statuses(&root, acc(2)),
            vec![SlotWriteStatus::UnrecognisedMarker]
        );
        note_handle_status(&root, acc(2), SlotWriteStatus::PurgeFailed, "term-1", false);
        ack_slot_raced(&root, acc(2)).unwrap();
        assert_eq!(
            slot_write_statuses(&root, acc(2)),
            vec![SlotWriteStatus::UnrecognisedMarker]
        );
    }

    /// r4c B: a lock-free event appended to the overflow marker in the window after the ack
    /// took it is never lost (the held copy is re-read; a non-raced kind puts it back).
    #[cfg(unix)]
    #[test]
    fn an_overflow_event_landing_during_the_ack_is_not_lost() {
        let _env = EnvGuard::new_isolated();
        let (_d, root, mdir) = r4c_slot();
        r4c_fill(&root, 33, SlotWriteStatus::Raced);
        let m2 = mdir.clone();
        test_seam::AFTER_OVERFLOW_HELD.with(|c| {
            *c.borrow_mut() = Some(Box::new(move |_| {
                // a writer that already opened `overflow` appends to the held inode
                let held = std::fs::read_dir(&m2)
                    .unwrap()
                    .flatten()
                    .map(|e| e.path())
                    .find(|p| p.to_string_lossy().contains("overflow.held"))
                    .unwrap();
                use std::io::Write as _;
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(held)
                    .unwrap()
                    .write_all(b"overflow carry-skipped\n")
                    .unwrap();
            }));
        });
        ack_slot_raced(&root, acc(2)).unwrap();
        test_seam::AFTER_OVERFLOW_HELD.with(|c| *c.borrow_mut() = None);
        assert_eq!(
            slot_write_statuses(&root, acc(2)),
            vec![SlotWriteStatus::Raced, SlotWriteStatus::CarrySkipped],
            "the late non-raced event was dropped or the overflow wrongly cleared"
        );
    }

    /// r4d: the stuck-overflow predicate (drives the operator line naming the file).
    #[cfg(unix)]
    #[test]
    fn slot_overflow_stuck_is_true_only_for_an_overflow_the_ack_cannot_clear() {
        let _env = EnvGuard::new_isolated();
        let (_d, root, _m) = r4c_slot();
        assert!(!slot_overflow_stuck(&root, acc(2)));
        r4c_fill(&root, 34, SlotWriteStatus::Raced);
        assert!(!slot_overflow_stuck(&root, acc(2)), "raced-only overflow");
        r4c_fill(&root, 1, SlotWriteStatus::PurgeFailed);
        assert!(slot_overflow_stuck(&root, acc(2)));
        ack_slot_raced(&root, acc(2)).unwrap();
        assert!(
            slot_overflow_stuck(&root, acc(2)),
            "the ack must not clear it"
        );
    }
}
