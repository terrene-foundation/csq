//! Codex surface constants + `config.toml` pre-seed helpers.
//!
//! Companion to `providers::catalog` that pins the Codex-specific
//! on-disk knobs the login (PR-C3b), refresher (PR-C4), and launch
//! (PR-C3c) paths all need. Entries here mirror spec 07 §7.2.2
//! (on-disk layout) and §7.3.3 (login sequence); any drift between
//! the spec and this module is a spec violation.

use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use crate::providers;
use crate::types::AccountNum;
use std::io::{self, Write};
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

/// csq's curated default for codex's native `tui.status_line` footer — an
/// ordered array of codex built-in status-line item IDs. Codex renders these
/// items itself in its TUI footer (the `/statusline` feature, shipped
/// openai/codex an internal ticket; verified against codex-cli 0.142.3, whose item
/// catalog contains all four IDs below). The selection mirrors what csq surfaces
/// for Claude Code — model, context, git, working dir.
///
/// Applied ONLY when the user has not set `tui.status_line` in
/// `~/.codex/config.toml` (see [`inject_default_status_line`]): unlike the
/// csq-controlled `cli_auth_credentials_store` key (csq-wins), the statusline is
/// a user preference (user-wins-if-present), so an explicit `/statusline` choice
/// is never clobbered.
///
/// NOTE — this configures codex's OWN native footer; it does NOT inject a
/// csq-rendered line the way `csq statusline` does for Claude Code. Codex has no
/// external-command statusline hook (openai/codex #17827, unshipped) — so a
/// csq-rendered codex footer is tracked-upstream, not buildable today.
const CSQ_DEFAULT_STATUS_LINE: &[&str] = &[
    "model-with-reasoning",
    "context-remaining",
    "git-branch",
    "current-dir",
];

/// Inserts csq's [`CSQ_DEFAULT_STATUS_LINE`] as `tui.status_line` into `table`
/// IF the user has not already configured one. Resolves (or creates) the `[tui]`
/// table and adds `status_line` only when absent. Defensive: if the user's `tui`
/// value is not a table, it is left untouched (never clobber user config).
fn inject_default_status_line(table: &mut toml::value::Table) {
    if !table.contains_key("tui") {
        table.insert(
            "tui".to_string(),
            toml::Value::Table(toml::value::Table::new()),
        );
    }
    // `tui` present but not a table (malformed user config) → leave it alone.
    let Some(toml::Value::Table(tui_table)) = table.get_mut("tui") else {
        return;
    };
    // User already chose their statusline (via codex `/statusline` or by hand)
    // → respect it, do not override.
    if tui_table.contains_key("status_line") {
        return;
    }
    let items: Vec<toml::Value> = CSQ_DEFAULT_STATUS_LINE
        .iter()
        .map(|s| toml::Value::String((*s).to_string()))
        .collect();
    tui_table.insert("status_line".to_string(), toml::Value::Array(items));
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
/// 1. csq-controlled keys (see [`CSQ_CONTROLLED_KEYS`]) always come from
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
            Err(e) => {
                tracing::warn!(
                    error_kind = "codex_user_global_config_unparseable",
                    error = %e,
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

    // Fill csq's curated codex statusline when the user has not configured one
    // (user-wins-if-present). Done after the csq-controlled-key removal so it
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
/// the caller's explicit downscope (GH #978).
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
/// enforce a read-only one-shot (GH #978). Matches both the bare flag (`-s
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
/// 0o600 via [`secure_file`] — the pre-seed contains no secrets but
/// keeps the directory's permission story uniform with the other
/// credential-adjacent files csq writes.
///
/// Used by the login path and by the daemon startup reconciler to
/// repair drift after a manual edit. Idempotent.
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
/// Lets a caller that already validated the user-global (e.g.
/// [`regenerate_slot_config`]) render + write from the
/// exact bytes it validated — there is no second read that could observe
/// a different (e.g. mid-edit malformed) `~/.codex`.
pub fn write_config_toml_with_global(
    base_dir: &Path,
    account: AccountNum,
    model: Option<&str>,
    user_global: Option<&str>,
) -> io::Result<()> {
    let target = config_toml_path(base_dir, account);
    let parent = target
        .parent()
        .expect("config_toml_path always has a parent");
    std::fs::create_dir_all(parent)?;

    let tmp = unique_tmp_path(&target);
    let contents = render_config_toml_with_global(model, user_global);

    if let Err(e) = write_and_sync(&tmp, contents.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io::Error::other(e.to_string()));
    }
    if let Err(e) = atomic_replace(&tmp, &target) {
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
/// explicit top-level `model` key IF present. When the slot carries no
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
/// `~/.codex` is read exactly once here; the chosen merge base is the
/// same snapshot passed to [`write_config_toml_with_global`], so no second
/// read can observe a mid-edit malformed global between the check and the
/// write.
pub fn regenerate_slot_config(base_dir: &Path, account: AccountNum) -> io::Result<RegenOutcome> {
    let toml_path = config_toml_path(base_dir, account);
    let existing = std::fs::read_to_string(&toml_path).ok();
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

    let desired = render_config_toml_with_global(model.as_deref(), merge_base);
    if existing.as_deref() == Some(desired.as_str()) {
        // Nothing to write. A malformed global still warrants the operator
        // note (their edits are not propagating), so distinguish it.
        return Ok(if global_malformed {
            RegenOutcome::SkippedMalformedGlobal
        } else {
            RegenOutcome::AlreadyCurrent
        });
    }

    write_config_toml_with_global(base_dir, account, model.as_deref(), merge_base)?;
    Ok(RegenOutcome::Rewritten {
        model,
        was_global_malformed: global_malformed,
    })
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

fn write_and_sync(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn acc(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    /// Asserts the rendered config (a) is valid TOML and (b) carries csq's
    /// curated default `tui.status_line` with all four item IDs.
    fn assert_default_statusline_present(out: &str) {
        toml::from_str::<toml::Value>(out)
            .unwrap_or_else(|e| panic!("rendered config must be valid TOML: {e}\n{out}"));
        assert!(out.contains("[tui]"), "expected [tui] table; got:\n{out}");
        assert!(
            out.contains("status_line = ["),
            "expected status_line array; got:\n{out}"
        );
        for item in CSQ_DEFAULT_STATUS_LINE {
            assert!(
                out.contains(item),
                "status_line must include {item}; got:\n{out}"
            );
        }
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
        _shared: std::sync::MutexGuard<'static, ()>,
        prev: Option<std::ffi::OsString>,
        _fixture_dir: Option<TempDir>,
    }

    impl EnvGuard {
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
        // GH #978: a caller downscoping a one-shot must suppress the derived flags.
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
}
