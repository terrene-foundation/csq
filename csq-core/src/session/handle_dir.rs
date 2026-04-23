//! Handle-dir model: ephemeral `term-<pid>` directories with symlinks to `config-N`.
//!
//! Each `csq run` creates a `term-<pid>` handle directory that contains symlinks
//! pointing at the permanent `config-<N>` account directory. `csq swap` atomically
//! repoints these symlinks. The daemon sweeps orphaned handle dirs when the PID dies.
//!
//! See `specs/02-csq-handle-dir-model.md` for the authoritative spec.

use crate::accounts::markers;
use crate::error::CredentialError;
use crate::session::isolation::{self, SHARED_ITEMS};
use crate::session::merge::merge_settings;
use crate::types::AccountNum;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Items in the handle dir that are symlinks to `config-N/<item>`.
/// These get repointed on swap.
///
/// `.claude.json` is intentionally EXCLUDED — CC writes per-project state
/// (the `projects` map) into it, and symlinking to config-N's copy leaks
/// project history from every directory that account was ever used in.
/// This causes `--resume` to show sessions from all projects instead of
/// filtering to the current CWD. Letting CC create a fresh `.claude.json`
/// per handle dir restores correct project-scoped behavior.
///
/// `settings.json` is also intentionally EXCLUDED — it is materialized as
/// a real file by [`materialize_handle_settings`] by deep-merging the
/// user's `~/.claude/settings.json` (global customization — statusLine,
/// permissions.defaultMode, plugins) with `config-<N>/settings.json`
/// (slot-specific env block for 3P bindings). A bare symlink would
/// replace the user layer entirely because `CLAUDE_CONFIG_DIR` overrides
/// the home settings path.
const ACCOUNT_BOUND_ITEMS: &[&str] = &[
    ".credentials.json",
    ".csq-account",
    ".current-account",
    ".quota-cursor",
];

/// Creates an ephemeral handle directory `term-<pid>` under `base_dir`.
///
/// Populates it with:
/// - Symlinks to `config-<account>/<item>` for each account-bound item
/// - Symlinks to `~/.claude/<item>` for each shared item
/// - A `.live-pid` file with the csq CLI PID
///
/// Returns the absolute path to the created handle directory.
///
/// # Invariant — `pid` MUST equal the caller's `std::process::id()`
///
/// This function MUST only be invoked by the process whose PID will
/// own the handle dir. Production call sites (`csq run`) pass
/// `std::process::id()` at the call site. This invariant is what
/// keeps `sweep_dead_handles` safe against racing creates: the
/// sweep's `is_pid_alive(dir_pid)` check returns `true` as long as
/// the creating process is still alive, so a sweep can never
/// observe a `term-<pid>` whose dir-name PID is dead *while* that
/// process is still populating it. Breaking this invariant (e.g.
/// calling `create_handle_dir(foreign_pid)` from a helper process)
/// would open a race where the sweep deletes a live session's
/// half-populated dir before `write_live_pid` completes.
///
/// Tests may pass arbitrary PIDs because they run in isolated
/// tempdirs with no concurrent sweep.
///
/// # Errors
///
/// - If `config-<account>` doesn't exist
/// - If the handle dir already exists (PID collision from prior crash —
///   caller should sweep first)
/// - On any I/O failure
pub fn create_handle_dir(
    base_dir: &Path,
    claude_home: &Path,
    account: AccountNum,
    pid: u32,
) -> Result<PathBuf, CredentialError> {
    let config_dir = base_dir.join(format!("config-{}", account));
    if !config_dir.is_dir() {
        return Err(CredentialError::Corrupt {
            path: config_dir,
            reason: format!("config-{account} does not exist"),
        });
    }

    let handle_dir = base_dir.join(format!("term-{}", pid));

    // Detect orphan from prior crash with same PID.
    //
    // SAFETY: Before removing, read `.live-pid` and verify the recorded
    // PID is dead. Without this check, PID recycling could make us wipe
    // out a live terminal's handle dir. We only remove dirs whose PID
    // is definitely dead OR whose `.live-pid` is missing/unreadable
    // (corrupt orphan from our own earlier crash).
    if handle_dir.exists() {
        let live_pid_path = handle_dir.join(".live-pid");
        let recorded_pid: Option<u32> = std::fs::read_to_string(&live_pid_path)
            .ok()
            .and_then(|s| s.trim().parse().ok());

        if let Some(recorded) = recorded_pid {
            if is_pid_alive(recorded) {
                return Err(CredentialError::Corrupt {
                    path: handle_dir.clone(),
                    reason: format!(
                        "handle dir term-{pid} is in use by live PID {recorded}. \
                         Refusing to remove. If you believe this is stale, stop \
                         the process and rerun."
                    ),
                });
            }
        }

        warn!(
            pid,
            recorded = ?recorded_pid,
            "handle dir already exists with dead or missing PID — removing orphan"
        );
        std::fs::remove_dir_all(&handle_dir).map_err(|e| CredentialError::Io {
            path: handle_dir.clone(),
            source: e,
        })?;
    }

    // Use create_dir (not create_dir_all) to detect collisions
    std::fs::create_dir(&handle_dir).map_err(|e| CredentialError::Io {
        path: handle_dir.clone(),
        source: e,
    })?;

    // Symlink account-bound items to config-N
    for item in ACCOUNT_BOUND_ITEMS {
        let target = config_dir.join(item);
        let link = handle_dir.join(item);
        // Only create symlink if the target exists in config-N
        if target.exists() || target.symlink_metadata().is_ok() {
            create_symlink(&target, &link).map_err(|e| CredentialError::Io {
                path: link.clone(),
                source: e,
            })?;
            debug!(item, "linked account-bound item");
        }
    }

    // Symlink shared items to ~/.claude. Use the shape-aware
    // `ensure_shared_target` helper so file-named items
    // (`keybindings.json`, `history.jsonl`, `__store.db`, etc.)
    // get seeded as parseable files instead of directories — the
    // pre-alpha.18 bug that left CC logging a keybinding-error on
    // every launch once csq run had run once on a fresh install.
    for item in SHARED_ITEMS {
        let target = claude_home.join(item);
        let link = handle_dir.join(item);

        if let Err(e) = isolation::ensure_shared_target(&target, item) {
            warn!(path = %target.display(), error = %e, "failed to create shared target");
            continue;
        }

        if target.exists() {
            // Use ensure_symlink logic: skip if non-symlink exists
            if link.symlink_metadata().is_ok() {
                continue; // shouldn't happen in a fresh dir, but be safe
            }
            create_symlink(&target, &link).map_err(|e| CredentialError::Io {
                path: link.clone(),
                source: e,
            })?;
            debug!(item, "linked shared item");
        }
    }

    // Copy .claude.json from config-N, scoping `projects` to CWD.
    materialize_handle_claude_json(&config_dir, &handle_dir);

    // Materialize settings.json as a real file (NOT a symlink). CC reads
    // this via CLAUDE_CONFIG_DIR and treats it as the user settings layer,
    // replacing (not merging with) ~/.claude/settings.json. Deep-merge the
    // user global settings with the slot's overlay so the statusLine,
    // permissions, plugins, and any 3P env block all survive.
    materialize_handle_settings(&handle_dir, claude_home, &config_dir)?;

    // Write .live-pid with the csq CLI PID
    markers::write_live_pid(&handle_dir, pid)?;

    info!(pid, account = %account, path = %handle_dir.display(), "handle dir created");
    Ok(handle_dir)
}

/// Creates an ephemeral Codex handle directory `term-<pid>` under
/// `base_dir` for `Surface::Codex`.
///
/// Per spec 07 §7.2.2 the Codex handle dir carries a distinct symlink
/// set from Anthropic:
///
/// - `.csq-account` → `config-<N>/.csq-account`
/// - `auth.json` → `credentials/codex-<N>.json` (canonical-direct;
///   Codex's auth.json IS the credential file)
/// - `config.toml` → `config-<N>/config.toml` (daemon-writable; model
///   + `cli_auth_credentials_store` mode)
/// - `sessions` → `config-<N>/codex-sessions/` (per-account persistent
///   transcripts, per INV-P04 carveout)
/// - `history.jsonl` → `config-<N>/codex-history.jsonl` (per-account
///   persistent history)
///
/// Plus an ephemeral `log/` directory (per-terminal, ignored by the
/// sweeper) and a `.live-pid` marker.
///
/// Unlike [`create_handle_dir`] (Anthropic), this function does NOT:
/// - Symlink `SHARED_ITEMS` to `~/.claude` — Codex reads `CODEX_HOME`
///   and has no dependency on the Claude home directory.
/// - Materialize `settings.json` / `.claude.json` — Codex configuration
///   lives in `config.toml`, which is already a per-account symlink.
///
/// # Invariant — `pid` MUST equal the caller's `std::process::id()`
///
/// Same contract as [`create_handle_dir`]: the sweeper relies on this
/// to avoid racing creates against live handle dirs. See the
/// [`create_handle_dir`] docstring for the full rationale.
///
/// # Errors
///
/// - If `config-<account>` does not exist (Codex slot not provisioned —
///   PR-C3b `csq login --provider codex` must run first).
/// - If the canonical credential file `credentials/codex-<N>.json`
///   does not exist (same reason — login has not completed).
/// - If the handle dir already exists with a live PID (refuses to
///   remove — identical semantics to the Anthropic path).
/// - On any I/O failure.
pub fn create_handle_dir_codex(
    base_dir: &Path,
    account: AccountNum,
    pid: u32,
) -> Result<PathBuf, CredentialError> {
    let config_dir = base_dir.join(format!("config-{}", account));
    if !config_dir.is_dir() {
        return Err(CredentialError::Corrupt {
            path: config_dir,
            reason: format!(
                "config-{account} does not exist — run `csq login {account} --provider codex` first"
            ),
        });
    }

    let canonical_cred = base_dir
        .join("credentials")
        .join(format!("codex-{account}.json"));
    if !canonical_cred.exists() {
        return Err(CredentialError::Corrupt {
            path: canonical_cred,
            reason: format!(
                "credentials/codex-{account}.json does not exist — \
                 Codex slot {account} has not completed login"
            ),
        });
    }

    let handle_dir = base_dir.join(format!("term-{}", pid));

    // Same orphan-detection semantics as create_handle_dir — only
    // remove a stale handle dir whose recorded PID is dead or absent.
    if handle_dir.exists() {
        let live_pid_path = handle_dir.join(".live-pid");
        let recorded_pid: Option<u32> = std::fs::read_to_string(&live_pid_path)
            .ok()
            .and_then(|s| s.trim().parse().ok());

        if let Some(recorded) = recorded_pid {
            if is_pid_alive(recorded) {
                return Err(CredentialError::Corrupt {
                    path: handle_dir.clone(),
                    reason: format!(
                        "handle dir term-{pid} is in use by live PID {recorded}. \
                         Refusing to remove. If you believe this is stale, stop \
                         the process and rerun."
                    ),
                });
            }
        }

        warn!(
            pid,
            recorded = ?recorded_pid,
            "codex handle dir already exists with dead or missing PID — removing orphan"
        );
        std::fs::remove_dir_all(&handle_dir).map_err(|e| CredentialError::Io {
            path: handle_dir.clone(),
            source: e,
        })?;
    }

    std::fs::create_dir(&handle_dir).map_err(|e| CredentialError::Io {
        path: handle_dir.clone(),
        source: e,
    })?;

    // Codex symlink set per spec 07 §7.2.2. Sources are either
    // `config-<N>/<item>` or `credentials/codex-<N>.json` depending
    // on the item — auth.json symlinks canonical-direct.
    let codex_links: &[(&str, PathBuf)] = &[
        (".csq-account", config_dir.join(".csq-account")),
        ("auth.json", canonical_cred.clone()),
        ("config.toml", config_dir.join("config.toml")),
        ("sessions", config_dir.join("codex-sessions")),
        ("history.jsonl", config_dir.join("codex-history.jsonl")),
    ];

    for (name, target) in codex_links {
        let link = handle_dir.join(name);
        // Only symlink items whose target exists OR is a known-expected
        // persistent state dir/file. `codex-sessions/` and
        // `codex-history.jsonl` may legitimately be absent on first
        // spawn — codex-cli creates them lazily. Skip those silently.
        if !target.exists() && target.symlink_metadata().is_err() {
            debug!(
                item = name,
                target = %target.display(),
                "codex symlink target does not exist yet; skipping"
            );
            continue;
        }
        create_symlink(target, &link).map_err(|e| CredentialError::Io {
            path: link.clone(),
            source: e,
        })?;
        debug!(item = name, "linked codex item");
    }

    // Ephemeral per-terminal log dir. Codex-cli writes per-session
    // logs here; the sweeper removes it along with the handle dir.
    let log_dir = handle_dir.join("log");
    std::fs::create_dir(&log_dir).map_err(|e| CredentialError::Io {
        path: log_dir,
        source: e,
    })?;

    markers::write_live_pid(&handle_dir, pid)?;

    info!(
        pid,
        account = %account,
        surface = "codex",
        path = %handle_dir.display(),
        "codex handle dir created"
    );
    Ok(handle_dir)
}

/// Writes `handle_dir/settings.json` as a real file by deep-merging
/// `claude_home/settings.json` (base) with `config_dir/settings.json`
/// (overlay).
///
/// The base carries user-global customization (statusLine, permissions,
/// plugins, env experiments). The overlay carries slot-specific env for
/// 3P bindings (`ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`,
/// `ANTHROPIC_MODEL`). Overlay keys win on merge. For OAuth slots where
/// `config-<N>/settings.json` is absent or empty, the materialized file
/// equals the user's global settings.
///
/// Failures at each step:
/// - Missing `claude_home/settings.json` → base is `{}`
/// - Invalid JSON in either source → logged at WARN, treated as `{}`
/// - Write / secure_file / rename → propagated as [`CredentialError`]
///
/// # Security
///
/// The overlay may contain a 3P `ANTHROPIC_AUTH_TOKEN`. `secure_file`
/// propagates (does not `.ok()`) so a permission failure fails closed
/// rather than leaving a credential file at the umask default.
///
/// Also exposed publicly so `csq run` can defensively re-materialize as a
/// belt-and-suspenders after `create_handle_dir`, in case future refactors
/// factor the step out of `create_handle_dir`. See journal 0059 — stale
/// per-slot settings drifted silently through a csq install upgrade;
/// making the invariant explicit at the call site guards against the same
/// class of regression.
pub fn materialize_handle_settings(
    handle_dir: &Path,
    claude_home: &Path,
    config_dir: &Path,
) -> Result<(), CredentialError> {
    let base = read_json_object_or_empty(&claude_home.join("settings.json"));
    let overlay = read_json_object_or_empty(&config_dir.join("settings.json"));
    let merged = merge_settings(&base, &overlay);

    let settings_path = handle_dir.join("settings.json");
    let json = serde_json::to_string_pretty(&merged).map_err(|e| CredentialError::Corrupt {
        path: settings_path.clone(),
        reason: format!("merged settings serialize failed: {e}"),
    })?;

    let tmp = crate::platform::fs::unique_tmp_path(&settings_path);
    std::fs::write(&tmp, json.as_bytes()).map_err(|e| CredentialError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    crate::platform::fs::secure_file(&tmp).map_err(|e| CredentialError::Corrupt {
        path: tmp.clone(),
        reason: format!("secure_file: {e}"),
    })?;
    crate::platform::fs::atomic_replace(&tmp, &settings_path).map_err(|e| {
        CredentialError::Corrupt {
            path: settings_path.clone(),
            reason: format!("atomic replace: {e}"),
        }
    })?;
    Ok(())
}

/// Reads a JSON file and returns its root object, or an empty object if
/// the file is missing, unreadable, malformed, or not an object at the
/// top level. Warnings are logged for malformed non-empty content so
/// users see why their customization vanished.
fn read_json_object_or_empty(path: &Path) -> Value {
    let content = match std::fs::read_to_string(path) {
        Ok(s) if !s.trim().is_empty() => s,
        _ => return Value::Object(serde_json::Map::new()),
    };
    match serde_json::from_str::<Value>(&content) {
        Ok(v) if v.is_object() => v,
        Ok(_) => {
            warn!(path = %path.display(), "settings file is not a JSON object, treating as empty");
            Value::Object(serde_json::Map::new())
        }
        Err(e) => {
            warn!(path = %path.display(), error = %e, "settings file has invalid JSON, treating as empty");
            Value::Object(serde_json::Map::new())
        }
    }
}

/// Atomically repoints the account-bound symlinks in a handle dir
/// to point at a new `config-<target>` directory.
///
/// Uses rename-over (NOT delete + create) for atomicity.
///
/// # Errors
///
/// - If the handle dir is not a `term-<pid>` dir (refuses legacy `config-N`)
/// - If `config-<target>` doesn't exist
/// - On any I/O failure during repoint
pub fn repoint_handle_dir(
    base_dir: &Path,
    claude_home: &Path,
    handle_dir: &Path,
    target: AccountNum,
) -> Result<(), CredentialError> {
    // Verify this is a handle dir, not a config dir
    let dir_name = handle_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if !dir_name.starts_with("term-") {
        return Err(CredentialError::Corrupt {
            path: handle_dir.to_path_buf(),
            reason: format!(
                "expected term-<pid> handle dir, got {dir_name}. \
                 Run `csq run {target}` to launch with handle-dir isolation."
            ),
        });
    }

    // PR-C9a CRITICAL belt-and-suspenders (journal 0021 finding 1): refuse
    // to rewrite ACCOUNT_BOUND_ITEMS on a handle dir whose symlink set is
    // Codex-shaped. `repoint_handle_dir` only touches the Anthropic
    // `ACCOUNT_BOUND_ITEMS` (`.credentials.json`, `.csq-account`,
    // `.current-account`, `.quota-cursor`) — on a Codex handle dir those
    // items are absent or orthogonal to the real Codex symlinks
    // (`auth.json`, `config.toml`, `sessions`, `history.jsonl`, per spec
    // 07 §7.2.2), so a repoint would leave the Codex symlinks pointing at
    // the old `config-<N>` while rewriting only the ClaudeCode-shape
    // markers. The primary guard lives in `auto_rotate::find_target` (v2.1
    // auto-rotate is ClaudeCode-only), but this secondary guard catches
    // any future caller that forgets the surface check before invoking
    // repoint.
    //
    // Narrowed to items that are **Codex-unique**. `sessions` and
    // `history.jsonl` are not unique — `SHARED_ITEMS` (see
    // `session::isolation`) includes them on ClaudeCode handle dirs as
    // symlinks into `~/.claude/`. Only `auth.json` and `config.toml` are
    // Codex-exclusive markers.
    let codex_unique_items = ["auth.json", "config.toml"];
    for codex_item in codex_unique_items {
        let probe = handle_dir.join(codex_item);
        if probe.symlink_metadata().is_ok() {
            return Err(CredentialError::Corrupt {
                path: handle_dir.to_path_buf(),
                reason: format!(
                    "handle dir contains Codex-unique symlink '{codex_item}'. \
                     `repoint_handle_dir` is the Anthropic repoint path and \
                     must not run on Codex handle dirs. Codex rotation requires \
                     an explicit `csq swap` exec-replace (spec 07 §7.5 INV-P05)."
                ),
            });
        }
    }

    let new_config = base_dir.join(format!("config-{}", target));
    if !new_config.is_dir() {
        return Err(CredentialError::Corrupt {
            path: new_config,
            reason: format!("config-{target} does not exist"),
        });
    }

    // VP-final F3: pre-flight check to prevent mixed-state handle dirs.
    //
    // The rename loop has a "silently continue" path for missing items (the `if
    // !new_target.exists() && new_target.symlink_metadata().is_err()` branch).
    // When the CURRENT handle dir has a symlink for `item` but the NEW config
    // does not have the corresponding target, the loop removes the old symlink
    // without creating a new one — leaving the handle dir in a mixed-state where
    // one symlink is gone and the others still point at the old config. CC then
    // reads a stale or missing identity marker.
    //
    // Pre-flight guards the ONE item that is unconditionally required in EVERY
    // config dir — Anthropic or 3P: `.csq-account`. Without it csq cannot
    // determine which account the handle dir is on after the swap, and the
    // daemon's auto-rotate loop will skip the handle dir on every subsequent
    // tick (sees no marker → skips). All other items may legitimately be absent
    // (e.g. `.credentials.json` is absent for 3P slots that use API keys via
    // `env.ANTHROPIC_AUTH_TOKEN`; `.current-account` and `.quota-cursor` are
    // created lazily). Only `.csq-account` is structurally required in all cases.
    {
        let csq_account_target = new_config.join(".csq-account");
        if !csq_account_target.exists() && csq_account_target.symlink_metadata().is_err() {
            return Err(CredentialError::Corrupt {
                path: csq_account_target,
                reason: format!(
                    "repoint target missing .csq-account in {} — repoint aborted to prevent \
                     mixed-state handle dir",
                    new_config.display()
                ),
            });
        }
    }

    // VP-final F4: serialize concurrent swap + auto-rotate via a per-handle-dir
    // flock. Without this, two callers — e.g. `csq swap` in the terminal AND the
    // daemon's auto-rotate tick — can interleave rename operations and leave the
    // handle dir pointing at two different config-N dirs simultaneously.
    //
    // `.swap.lock` lives inside the handle dir so it is automatically cleaned up
    // when the handle dir is swept. `lock_file` blocks until the lock is available
    // (blocking, not try_lock) so the slower caller is serialized, not dropped.
    let lock_path = handle_dir.join(".swap.lock");
    let _swap_guard =
        crate::platform::lock::lock_file(&lock_path).map_err(|e| CredentialError::Corrupt {
            path: lock_path.clone(),
            reason: format!("repoint lock acquisition failed: {e}"),
        })?;

    // Atomic repoint: create temp symlink then rename over existing
    for item in ACCOUNT_BOUND_ITEMS {
        let new_target = new_config.join(item);
        let link_path = handle_dir.join(item);
        let tmp_path = handle_dir.join(format!("{item}.swap-tmp"));

        // Only repoint if the target exists in the new config dir
        if !new_target.exists() && new_target.symlink_metadata().is_err() {
            // Remove the old symlink if the new config doesn't have this item
            if link_path.symlink_metadata().is_ok() {
                let _ = std::fs::remove_file(&link_path);
            }
            continue;
        }

        // Create new symlink at temp path
        if tmp_path.symlink_metadata().is_ok() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        create_symlink(&new_target, &tmp_path).map_err(|e| CredentialError::Io {
            path: tmp_path.clone(),
            source: e,
        })?;

        // Atomic rename over existing symlink
        std::fs::rename(&tmp_path, &link_path).map_err(|e| CredentialError::Io {
            path: link_path.clone(),
            source: e,
        })?;

        debug!(item, account = %target, "repointed symlink");
    }

    // Re-materialize settings.json for the new slot so the user's global
    // customization is preserved and any 3P env block from the new
    // config-<target>/settings.json overlays correctly. atomic_replace
    // keeps the swap semantics of INV-04: CC sees either the pre-swap or
    // post-swap file, never a half-written one.
    materialize_handle_settings(handle_dir, claude_home, &new_config)?;

    // Re-materialize .claude.json for the new slot. This is the bug fix
    // for alpha.10: `csq swap` used to repoint credential symlinks but
    // leave `.claude.json` as the stale copy from whichever slot the
    // handle dir was created with. CC reads account-scoped caches from
    // .claude.json — `oauthAccount`, `overageCreditGrantCache`,
    // `cachedExtraUsageDisabledReason`, `cachedGrowthBookFeatures`,
    // `additionalModelCostsCache`, `clientDataCache`, etc. — and
    // displays "you've hit your limit" from those caches without
    // necessarily making a fresh API call. Swapping without refreshing
    // .claude.json meant CC continued reporting the pre-swap account's
    // state for the remainder of the session.
    //
    // Session-scoped project entries from the old handle dir (CC writes
    // them during the session) are preserved so `--resume` and per-CWD
    // state survive the swap. See `rebuild_claude_json_for_swap` for
    // the atomic write + projects merge.
    rebuild_claude_json_for_swap(&new_config, handle_dir);

    info!(account = %target, handle = %handle_dir.display(), "handle dir repointed");
    Ok(())
}

/// Atomically repoints the Codex symlinks in a Codex handle dir to
/// point at a new `config-<target>` directory.
///
/// Counterpart to [`repoint_handle_dir`] for the Codex surface. The
/// Codex symlink set per spec 07 §7.2.2 is:
/// - `.csq-account` → `config-<N>/.csq-account`
/// - `auth.json` → `credentials/codex-<N>.json` (canonical-direct)
/// - `config.toml` → `config-<N>/config.toml`
/// - `sessions` → `config-<N>/codex-sessions`
/// - `history.jsonl` → `config-<N>/codex-history.jsonl`
///
/// In-flight semantics are identical to the ClaudeCode path: codex-cli
/// re-stats `auth.json` before every API call, so the next request
/// after `csq swap` resolves through the new symlink. UNIX
/// open-after-rename semantics keep any open fds into the old
/// `codex-sessions/` valid until the holding process closes them — a
/// session in flight continues writing to its existing session file via
/// the old fd, while any new open (`codex resume`, a new session) hits
/// the new slot. This matches the ClaudeCode model and replaces the
/// prior `exec`-replace path that silently dropped the user's
/// conversation (M10, journal 0023).
///
/// # Errors
///
/// - If the handle dir is not a `term-<pid>` dir
/// - If the handle dir is not Codex-shaped (missing `auth.json` symlink)
/// - If `config-<target>` doesn't exist
/// - If the new slot is missing `.csq-account` (mixed-state guard)
/// - If `credentials/codex-<target>.json` doesn't exist
/// - On any I/O failure during repoint
pub fn repoint_handle_dir_codex(
    base_dir: &Path,
    handle_dir: &Path,
    target: AccountNum,
) -> Result<(), CredentialError> {
    let dir_name = handle_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if !dir_name.starts_with("term-") {
        return Err(CredentialError::Corrupt {
            path: handle_dir.to_path_buf(),
            reason: format!(
                "expected term-<pid> handle dir, got {dir_name}. \
                 Run `csq run {target}` to launch with handle-dir isolation."
            ),
        });
    }

    // Surface guard (PR-C9b L-CDX-1): refuse to repoint a non-Codex handle dir.
    // Codex-shape requires BOTH `auth.json` AND `config.toml` to be present
    // AND each must be a symlink — not a regular file or directory. The
    // dual-marker check matches the inverse guard in `repoint_handle_dir`
    // (which scans both items); the is_symlink check rejects planted
    // regular files that would otherwise pass `symlink_metadata().is_ok()`
    // and trip the rename loop into overwriting attacker-controlled state.
    for codex_item in ["auth.json", "config.toml"] {
        let probe = handle_dir.join(codex_item);
        let is_symlink = probe
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if !is_symlink {
            return Err(CredentialError::Corrupt {
                path: handle_dir.to_path_buf(),
                reason: format!(
                    "handle dir is not Codex-shaped: '{codex_item}' is missing or \
                     not a symlink. `repoint_handle_dir_codex` only operates on \
                     Codex handle dirs (spec 07 §7.2.2 symlink set); for ClaudeCode \
                     use `repoint_handle_dir`."
                ),
            });
        }
    }

    let new_config = base_dir.join(format!("config-{}", target));
    if !new_config.is_dir() {
        return Err(CredentialError::Corrupt {
            path: new_config,
            reason: format!("config-{target} does not exist"),
        });
    }

    // Pre-flight mirror of `repoint_handle_dir`'s VP-final F3: the
    // `.csq-account` marker is structurally required in the target slot.
    // Without it csq cannot determine the post-swap account and the
    // daemon's auto-rotate / sweep loops would skip the handle dir on
    // every tick. Refuse before any rename so the handle dir cannot end
    // up half-pointed at the old slot.
    let csq_account_target = new_config.join(".csq-account");
    if !csq_account_target.exists() && csq_account_target.symlink_metadata().is_err() {
        return Err(CredentialError::Corrupt {
            path: csq_account_target,
            reason: format!(
                "repoint target missing .csq-account in {} — repoint aborted to prevent \
                 mixed-state handle dir",
                new_config.display()
            ),
        });
    }

    // The canonical Codex credential file is required for `auth.json`
    // to resolve. Codex auth.json symlinks canonical-direct (NOT
    // through `config-<N>`) per spec 07 §7.2.2.
    let canonical_cred = base_dir
        .join("credentials")
        .join(format!("codex-{target}.json"));
    if !canonical_cred.exists() {
        return Err(CredentialError::Corrupt {
            path: canonical_cred,
            reason: format!(
                "credentials/codex-{target}.json does not exist — \
                 Codex slot {target} has not completed login. Run \
                 `csq login {target} --provider codex` first."
            ),
        });
    }

    // Per-handle flock (mirrors ClaudeCode VP-final F4) so concurrent
    // swaps cannot interleave renames into a split state. The lock
    // file lives inside the handle dir so it is reaped with the dir.
    let lock_path = handle_dir.join(".swap.lock");
    let _swap_guard =
        crate::platform::lock::lock_file(&lock_path).map_err(|e| CredentialError::Corrupt {
            path: lock_path.clone(),
            reason: format!("repoint lock acquisition failed: {e}"),
        })?;

    // Codex symlink set per spec 07 §7.2.2. Sources are either
    // `config-<N>/<item>` or `credentials/codex-<N>.json` depending on
    // the item — auth.json symlinks canonical-direct, the rest go
    // through config-<N>.
    //
    // PR-C9b M-CDX-1: order matters under partial-failure. Credential
    // (`auth.json`) MUST be rewritten BEFORE the marker (`.csq-account`).
    // If a mid-loop rename fails (ENOSPC, EROFS, transient I/O), the
    // marker must not flip to slot N+1 while `auth.json` still resolves
    // to slot N's tokens — that mismatch causes silent quota-attribution
    // drift in the daemon (which polls `/api/oauth/usage` keyed on the
    // marker) and trips the F3 `.csq-account` mismatch guard on the next
    // swap. ClaudeCode's `ACCOUNT_BOUND_ITEMS` follows the same
    // invariant: `.credentials.json` first, `.csq-account` second.
    let codex_links: &[(&str, PathBuf)] = &[
        ("auth.json", canonical_cred.clone()),
        (".csq-account", new_config.join(".csq-account")),
        ("config.toml", new_config.join("config.toml")),
        ("sessions", new_config.join("codex-sessions")),
        ("history.jsonl", new_config.join("codex-history.jsonl")),
    ];

    for (name, new_target) in codex_links {
        let link_path = handle_dir.join(name);
        let tmp_path = handle_dir.join(format!("{name}.swap-tmp"));

        // `codex-sessions/` and `codex-history.jsonl` may legitimately
        // be absent in the new slot if the user has never used codex
        // on that account — codex-cli creates them lazily. Mirror
        // create_handle_dir_codex: skip the symlink AND remove any
        // existing one so we do not leave a dangling-link orphan
        // pointed at the old slot.
        if !new_target.exists() && new_target.symlink_metadata().is_err() {
            if link_path.symlink_metadata().is_ok() {
                let _ = std::fs::remove_file(&link_path);
            }
            continue;
        }

        // Stage at temp path + atomic rename-over the live link
        // (matches ClaudeCode INV-04 swap semantics: codex-cli sees
        // either the pre-swap or post-swap symlink, never a half-state).
        if tmp_path.symlink_metadata().is_ok() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        create_symlink(new_target, &tmp_path).map_err(|e| CredentialError::Io {
            path: tmp_path.clone(),
            source: e,
        })?;
        std::fs::rename(&tmp_path, &link_path).map_err(|e| CredentialError::Io {
            path: link_path.clone(),
            source: e,
        })?;
        debug!(item = name, account = %target, "repointed codex symlink");
    }

    info!(
        account = %target,
        handle = %handle_dir.display(),
        surface = "codex",
        "codex handle dir repointed"
    );
    Ok(())
}

/// Builds a `.claude.json` for `handle_dir` from `config_dir/.claude.json`
/// with the `projects` map scoped to the current working directory.
///
/// CC uses `projects` in `.claude.json` to track per-project settings AND
/// to enumerate resumable sessions. If we copy the full map, `--resume`
/// shows sessions from every directory this account was ever used in.
/// If we strip it entirely, CC thinks there are no projects. The middle
/// ground: keep only entries whose key matches the current CWD or is a
/// subdirectory of it.
///
/// On swap (`preserve_handle_projects = Some`), project entries that CC
/// has written to the handle dir's own `.claude.json` during the session
/// are overlaid on top of the new slot's projects. This preserves
/// session-scoped state like the `--resume` list and per-project
/// settings that CC populated while the session was running, even
/// though the rest of the file is refreshed from the new slot.
///
/// Returns the merged JSON ready to write, or `None` if the new slot's
/// source file is missing or unparseable (in which case the caller
/// should leave the existing handle-dir file alone).
fn build_scoped_claude_json(source: &Path, preserve_handle: Option<&Path>) -> Option<Value> {
    let content = std::fs::read_to_string(source).ok()?;
    let mut json: Value = serde_json::from_str(&content).ok()?;

    let cwd = match std::env::current_dir() {
        Ok(c) => c.to_string_lossy().to_string(),
        Err(_) => return Some(json),
    };

    // Collect session-scoped project entries that CC wrote into the
    // handle dir during this session. These are newer than the entries
    // in the new source file, so they win the merge.
    let mut session_projects: serde_json::Map<String, Value> = serde_json::Map::new();
    if let Some(preserve_path) = preserve_handle {
        if let Ok(old_content) = std::fs::read_to_string(preserve_path) {
            if let Ok(Value::Object(old_obj)) = serde_json::from_str::<Value>(&old_content) {
                if let Some(Value::Object(old_projects)) = old_obj.get("projects") {
                    for (k, v) in old_projects {
                        if k == &cwd || k.starts_with(&format!("{cwd}/")) {
                            session_projects.insert(k.clone(), v.clone());
                        }
                    }
                }
            }
        }
    }

    // Build the final projects map: source's CWD-scoped entries, then
    // overlay session-scoped entries from the handle dir (newer wins).
    let mut scoped = serde_json::Map::new();
    if let Some(obj) = json.as_object() {
        if let Some(Value::Object(src_projects)) = obj.get("projects") {
            for (k, v) in src_projects {
                if k == &cwd || k.starts_with(&format!("{cwd}/")) {
                    scoped.insert(k.clone(), v.clone());
                }
            }
        }
    }
    for (k, v) in session_projects {
        scoped.insert(k, v);
    }

    if let Some(obj) = json.as_object_mut() {
        obj.insert("projects".to_string(), Value::Object(scoped));
    }

    Some(json)
}

/// Writes the handle dir's `.claude.json` from `config_dir` at
/// handle-dir-creation time. Best-effort: if the source is missing
/// or unparseable, the handle dir simply has no `.claude.json` and
/// CC will create one on first run.
fn materialize_handle_claude_json(config_dir: &Path, handle_dir: &Path) {
    let Some(json) = build_scoped_claude_json(&config_dir.join(".claude.json"), None) else {
        return;
    };
    let dst = handle_dir.join(".claude.json");
    if let Ok(out) = serde_json::to_string_pretty(&json) {
        // Non-atomic write is fine at create time — CC isn't running yet.
        let _ = std::fs::write(&dst, out);
        debug!("materialized .claude.json (scoped projects to CWD)");
    }
}

/// Rebuilds the handle dir's `.claude.json` during a swap. Unlike
/// `materialize_handle_claude_json`, this function **atomically
/// replaces** the existing file so a concurrent CC read never sees a
/// half-written one, and it preserves any session-scoped project
/// entries that CC wrote into the handle dir during the running
/// session.
///
/// On the rare event of a missing or unparseable source
/// (`config_dir/.claude.json`) we leave the handle dir's file alone.
/// Wiping it would strand CC with zero state, which is strictly worse
/// than keeping the stale copy.
fn rebuild_claude_json_for_swap(config_dir: &Path, handle_dir: &Path) {
    let handle_claude_json = handle_dir.join(".claude.json");
    let Some(json) =
        build_scoped_claude_json(&config_dir.join(".claude.json"), Some(&handle_claude_json))
    else {
        warn!(
            src = %config_dir.join(".claude.json").display(),
            "swap: new slot has no readable .claude.json, leaving handle dir file as-is"
        );
        return;
    };

    let out = match serde_json::to_string_pretty(&json) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "swap: failed to serialize new .claude.json");
            return;
        }
    };

    // Atomic write: temp + rename. CC may be reading .claude.json
    // concurrently with this swap; a partial write would corrupt its
    // parse and potentially wipe session state.
    let tmp = crate::platform::fs::unique_tmp_path(&handle_claude_json);
    if let Err(e) = std::fs::write(&tmp, out.as_bytes()) {
        warn!(path = %tmp.display(), error = %e, "swap: temp .claude.json write failed");
        return;
    }
    if let Err(e) = crate::platform::fs::atomic_replace(&tmp, &handle_claude_json) {
        warn!(
            path = %handle_claude_json.display(),
            error = %e,
            "swap: atomic replace of .claude.json failed"
        );
        return;
    }
    debug!("swap: rebuilt .claude.json for new slot");
}

/// Sweeps orphaned `term-*` handle directories under `base_dir`.
///
/// A handle dir is orphaned when its recorded owner PID (in `.live-pid`)
/// is no longer alive. This function is idempotent — safe to call
/// repeatedly.
///
/// Before removing a dead handle dir, any `image-cache/<session-id>/`
/// sub-directories are moved to `claude_home/image-cache/<session-id>/`
/// so pasted images survive the sweep. See journal 0035 for the design.
///
/// # PID recycling safety
///
/// The dir name's parsed PID is only a first-pass filter. The
/// authoritative owner is `.live-pid` (set by `create_handle_dir`).
/// We re-read `.live-pid` TWICE: once to confirm the dir is dead
/// before preservation, once more immediately before deletion to
/// catch a recycled-PID takeover during the preservation window.
/// The deletion itself uses atomic `rename` to a tombstone path,
/// which frees the `term-<pid>` name in a single syscall so a
/// concurrent `create_handle_dir` sees the path as available and
/// creates fresh rather than racing the recursive delete.
///
/// # Windows child-PID check
///
/// On non-Unix, `csq run` spawns claude as a child process (Unix
/// uses `exec`, replacing the process in place with a single PID).
/// The child's PID is recorded in `.live-cc-pid`. Sweep treats the
/// handle dir as live if EITHER the csq PID or the CC child PID is
/// alive. This closes the Windows crash-recovery case where
/// csq-cli died but CC is still running as an orphaned child.
///
/// # Tombstones
///
/// Deletion uses `rename(path, tombstone)` + `remove_dir_all(tombstone)`.
/// If the daemon is killed between rename and delete, the next sweep
/// finds a stale `.sweep-tombstone-*` entry and removes it via the
/// initial cleanup pass.
///
/// If `claude_home` is `None`, preservation is skipped entirely —
/// the sweep still removes orphans but pasted images are lost.
/// Callers should only pass `None` when they cannot safely determine
/// where `~/.claude/image-cache/` lives.
///
/// Returns the number of directories removed.
pub fn sweep_dead_handles(base_dir: &Path, claude_home: Option<&Path>) -> usize {
    let mut removed = 0;

    // Clean up any stale tombstones from a crashed previous sweep
    // before scanning for live handle dirs. Idempotent: if the
    // tombstone removal fails (ENOENT, EBUSY), the next tick retries.
    cleanup_stale_tombstones(base_dir);

    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "sweep: failed to read directory entry");
                continue;
            }
        };

        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };

        if !name.starts_with("term-") {
            continue;
        }

        let dir_pid: u32 = match name.strip_prefix("term-").and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };

        let path = entry.path();

        // Read the authoritative PID from `.live-pid`. Fall back to
        // the dir-name PID if the marker is missing or corrupt — a
        // crash-survivor dir with no marker is still sweepable if its
        // dir-name PID is dead.
        //
        // `initial_marker.is_some()` records whether the first read
        // saw a real marker; the re-check below bails if the marker
        // disappears between the two reads, which would signal a
        // racing `create_handle_dir` that has not yet finished
        // writing `.live-pid`.
        let initial_marker = markers::read_live_pid(&path);
        let owner_pid = initial_marker.unwrap_or(dir_pid);
        if is_pid_alive(owner_pid) {
            continue;
        }

        // Windows: also honor `.live-cc-pid` (the spawned CC child).
        // On Unix, exec replaces csq-cli with claude so there is a
        // single PID and this marker is not written.
        let cc_pid = markers::read_live_cc_pid(&path);
        if let Some(cc) = cc_pid {
            if is_pid_alive(cc) {
                continue;
            }
        }

        info!(
            pid = owner_pid,
            cc_pid = ?cc_pid,
            path = %path.display(),
            "sweeping orphaned handle dir"
        );

        // Preserve per-session image caches before the dead dir is deleted.
        // We cannot share `image-cache/` via SHARED_ITEMS because CC's
        // internal cleanup (`Dv7()`) deletes every entry that doesn't match
        // the live session ID, causing concurrent terminals to race on a
        // shared directory — see journal 0035.
        if let Some(home) = claude_home {
            preserve_image_cache(&path, home);
        }

        // Re-verify ownership immediately before the destructive step.
        // A racing `csq run` with a recycled PID could have replaced
        // this dir while we were preserving. Three bail conditions:
        //   1. The marker now names a different PID than we started with.
        //   2. The marker now names a PID that is alive.
        //   3. The marker was present initially but has now disappeared
        //      — this means the dir was replaced by a `csq run` that
        //      has not yet finished writing `.live-pid`; bail.
        let current_marker = markers::read_live_pid(&path);
        match (initial_marker, current_marker) {
            (Some(_), None) => {
                warn!(
                    original = owner_pid,
                    path = %path.display(),
                    "sweep: .live-pid disappeared mid-sweep, bailing"
                );
                continue;
            }
            (_, Some(current_owner))
                if current_owner != owner_pid || is_pid_alive(current_owner) =>
            {
                warn!(
                    original = owner_pid,
                    current = current_owner,
                    path = %path.display(),
                    "sweep: handle dir ownership changed mid-sweep, bailing"
                );
                continue;
            }
            _ => {}
        }

        // Also re-check the child CC marker on the second pass.
        if let Some(cc) = markers::read_live_cc_pid(&path) {
            if is_pid_alive(cc) {
                warn!(
                    cc_pid = cc,
                    path = %path.display(),
                    "sweep: CC child became alive mid-sweep, bailing"
                );
                continue;
            }
        }

        // Atomic rename-to-tombstone frees the term-<pid> path in
        // one syscall. Any concurrent `create_handle_dir` calls
        // after the rename see a missing path and create fresh
        // without racing the recursive delete. The tombstone is
        // deleted afterwards; if we crash in between, the next
        // sweep's initial `cleanup_stale_tombstones` pass catches
        // the leftover.
        let tombstone = base_dir.join(format!(
            ".sweep-tombstone-{}-{}",
            dir_pid,
            tombstone_suffix()
        ));
        if let Err(e) = std::fs::rename(&path, &tombstone) {
            warn!(pid = owner_pid, error = %e, "failed to rename orphan to tombstone");
            continue;
        }

        // The `term-<pid>` path is freed by the rename above. Whether
        // or not the tombstone removal succeeds, the orphan is gone
        // from the user's perspective. Count it as removed and let
        // the next sweep tick's `cleanup_stale_tombstones` pass mop
        // up any leftover.
        removed += 1;
        if let Err(e) = std::fs::remove_dir_all(&tombstone) {
            warn!(
                pid = owner_pid,
                error = %e,
                "failed to remove tombstone — will be cleaned on next tick"
            );
        }
    }

    if removed > 0 {
        info!(removed, "handle dir sweep complete");
    }
    removed
}

/// Generates a unique tombstone suffix so concurrent sweeps do not
/// collide on the rename target. Uses nanoseconds since epoch; the
/// `PidFile` guarantee means only one daemon runs per `base_dir`, so
/// the monotonic-ish clock is enough even under rapid sweep cycles.
fn tombstone_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("{nanos:x}")
}

/// Removes any `.sweep-tombstone-*` entries left behind by a
/// previously crashed sweep. Idempotent — called at the top of
/// every sweep tick so a daemon restart doesn't leave forever-trash.
fn cleanup_stale_tombstones(base_dir: &Path) {
    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if !name.starts_with(".sweep-tombstone-") {
            continue;
        }
        let path = entry.path();
        if let Err(e) = std::fs::remove_dir_all(&path) {
            warn!(path = %path.display(), error = %e, "failed to remove stale tombstone");
        } else {
            debug!(path = %path.display(), "cleaned up stale tombstone");
        }
    }
}

/// Validates a directory entry name as a plausible session-id component.
///
/// CC session IDs are canonical lowercase UUIDs like
/// `01234567-89ab-4cde-8f01-23456789abcd`. We accept any non-empty
/// name up to 64 characters that contains only *lowercase* hex digits
/// and dashes. Rejecting uppercase closes an APFS/HFS+ case-folding
/// vector where `DEADBEEF-...` and `deadbeef-...` hash to the same
/// directory, which could let a buggy plugin collide an unrelated
/// session with one written earlier.
///
/// This is defense-in-depth — `read_dir` already filters `.` and `..`,
/// and POSIX/Windows filenames cannot contain path separators — but
/// restricting to the UUID alphabet keeps the shared
/// `~/.claude/image-cache/` dir free of arbitrary names that could
/// come from a buggy CC plugin or MCP server.
fn is_valid_session_name(name: &std::ffi::OsStr) -> bool {
    let s = match name.to_str() {
        Some(s) => s,
        None => return false,
    };
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c) || c == '-')
}

/// Moves `dead_handle/image-cache/<session-id>/` entries into
/// `claude_home/image-cache/<session-id>/`.
///
/// Each pasted image is stored by CC under a session-scoped directory
/// (`$CLAUDE_CONFIG_DIR/image-cache/<session-id>/`). When the handle
/// dir is swept, those entries vanish unless we preserve them.
///
/// # Symlink handling
///
/// Refuses to operate if `image-cache/` is a symlink, if any
/// `image-cache/<sid>/` entry is a symlink, or if the destination
/// `claude_home/image-cache/` is a symlink. Same-user is the csq
/// threat model, but refusing symlinks is cheap defense-in-depth
/// against a poisoned handle dir redirecting into `~/.ssh/` or
/// similar.
///
/// # Collision
///
/// If `claude_home/image-cache/<session-id>/` already exists, we skip
/// the entry. Session IDs are UUIDs so collisions are effectively
/// impossible in practice. The narrow exception is `--resume` of the
/// same session from two handle dirs; the first-to-sweep wins and
/// the second-to-sweep's newer images are lost. This is documented
/// in journal 0036 as a known limitation — a merge-on-collision fix
/// is a follow-up.
///
/// # Cross-filesystem rename (`EXDEV`)
///
/// `std::fs::rename` fails with `EXDEV` if source and destination are
/// on different filesystems. We fall back to a recursive copy +
/// remove to preserve the data anyway. Under normal setups
/// `~/.claude/accounts/term-*` and `~/.claude/image-cache/` are on
/// the same mount, so the fallback is cold-path.
///
/// # Crash safety
///
/// If the daemon is killed mid-preservation, any sessions already
/// renamed are safe under `~/.claude/image-cache/`; the partially-
/// drained handle dir is re-swept on restart. `rename` is atomic and
/// the EXDEV fallback removes the source tree only after the copy
/// completes, so a crash during copy leaves the source intact for
/// the next tick.
///
/// Failures are logged and swallowed — preservation is best-effort
/// and MUST NOT block sweeping dead dirs. Returns the number of
/// session entries successfully moved.
fn preserve_image_cache(dead_handle: &Path, claude_home: &Path) -> usize {
    let src_cache = dead_handle.join("image-cache");

    // Source must be a real directory, not a symlink. Using symlink_metadata
    // instead of metadata prevents a poisoned handle dir from redirecting us
    // elsewhere via a symlink named `image-cache`.
    let src_meta = match src_cache.symlink_metadata() {
        Ok(m) => m,
        Err(_) => return 0, // no image-cache at all — common case
    };
    let src_ftype = src_meta.file_type();
    if src_ftype.is_symlink() {
        warn!(
            path = %src_cache.display(),
            "image-cache is a symlink, refusing to traverse"
        );
        return 0;
    }
    if !src_ftype.is_dir() {
        return 0;
    }

    // Destination must not be a symlink — refuse to write into an
    // attacker-redirected location (e.g. `~/.claude/image-cache`
    // swapped to point at `/tmp/attacker/`).
    let dst_cache = claude_home.join("image-cache");
    if let Ok(meta) = dst_cache.symlink_metadata() {
        if meta.file_type().is_symlink() {
            warn!(
                path = %dst_cache.display(),
                "destination image-cache is a symlink, refusing to preserve"
            );
            return 0;
        }
        if !meta.file_type().is_dir() {
            warn!(
                path = %dst_cache.display(),
                "destination image-cache exists but is not a directory"
            );
            return 0;
        }
    } else if let Err(e) = std::fs::create_dir_all(&dst_cache) {
        warn!(path = %dst_cache.display(), error = %e, "failed to create shared image-cache dir");
        return 0;
    }

    let entries = match std::fs::read_dir(&src_cache) {
        Ok(e) => e,
        Err(e) => {
            warn!(path = %src_cache.display(), error = %e, "failed to read image-cache");
            return 0;
        }
    };

    let mut moved = 0;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "preserve_image_cache: directory entry read failed");
                continue;
            }
        };

        // Must be a real directory, not a symlink. `DirEntry::file_type`
        // on Unix/Windows does not follow symlinks — symlinks report
        // `is_symlink() == true` and `is_dir() == false`, so this check
        // is safe. Still, we stat the full path explicitly for safety
        // on filesystems where `d_type` is `DT_UNKNOWN`.
        let src = entry.path();
        let meta = match src.symlink_metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            continue;
        }

        let session_name = entry.file_name();
        if !is_valid_session_name(&session_name) {
            warn!(
                session = ?session_name,
                "image-cache entry name rejected by session-id validator"
            );
            continue;
        }

        let dst = dst_cache.join(&session_name);

        // Collision: the shared image-cache already has an entry for
        // this session ID. Happens when CC `--resume`s the same
        // session from a second handle dir after the first one was
        // swept. Merge file-by-file, preserving existing destination
        // files untouched (they might belong to a still-live sibling
        // terminal). New file names from the dead handle are moved in.
        if dst.symlink_metadata().is_ok() {
            match merge_session_into_existing(&src, &dst) {
                Ok(n) if n > 0 => {
                    moved += 1;
                    debug!(
                        session = ?session_name,
                        files = n,
                        "merged image-cache session into existing shared entry"
                    );
                }
                Ok(_) => {
                    debug!(
                        session = ?session_name,
                        "image-cache session had no new files to merge"
                    );
                }
                Err(e) => {
                    warn!(
                        session = ?session_name,
                        error = %e,
                        "failed to merge image-cache session"
                    );
                }
            }
            continue;
        }

        match std::fs::rename(&src, &dst) {
            Ok(_) => {
                moved += 1;
                debug!(session = ?session_name, "preserved image-cache session");
            }
            Err(e) if is_cross_device(&e) => {
                // EXDEV: fall back to recursive copy + remove.
                match copy_and_remove_tree(&src, &dst) {
                    Ok(_) => {
                        moved += 1;
                        debug!(session = ?session_name, "preserved image-cache session (EXDEV fallback)");
                    }
                    Err(e) => {
                        warn!(
                            session = ?session_name,
                            error = %e,
                            "EXDEV fallback failed for image-cache session"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(session = ?session_name, error = %e, "failed to preserve image-cache session");
            }
        }
    }

    if moved > 0 {
        info!(
            count = moved,
            handle = %dead_handle.display(),
            "preserved image-cache sessions from dead handle"
        );
    }
    moved
}

/// Returns `true` if the I/O error indicates a cross-device rename (`EXDEV`).
fn is_cross_device(err: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        err.raw_os_error() == Some(libc::EXDEV)
    }
    #[cfg(not(unix))]
    {
        // Windows maps cross-volume moves to `ERROR_NOT_SAME_DEVICE` (17).
        err.raw_os_error() == Some(17)
    }
}

/// Copies `src` tree to `dst` then removes `src`. Used as the EXDEV
/// fallback when `rename` cannot move across filesystems.
///
/// Refuses to traverse symlinks inside the tree — an attacker-planted
/// symlink would otherwise copy its target's contents into the shared
/// image cache. All non-symlink regular files and directories are
/// copied. Sub-directories inherit the source directory's permission
/// bits; file contents are preserved bit-for-bit via `std::fs::copy`.
fn copy_and_remove_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    copy_tree_iterative(src, dst)?;
    std::fs::remove_dir_all(src)
}

/// Iterative tree walker used by the EXDEV fallback.
///
/// Previously implemented as straight recursion, which worked in
/// practice for CC's flat `image-cache/<sid>/<file>` layout but had
/// no guardrail against pathologically deep attacker-planted trees.
/// Converted to an explicit work-queue so stack depth is bounded by
/// `DEPTH_LIMIT` regardless of filesystem contents.
fn copy_tree_iterative(root_src: &Path, root_dst: &Path) -> std::io::Result<()> {
    /// Defensive cap on walker depth. PATH_MAX on typical filesystems
    /// is 4096 bytes — an image-cache tree deep enough to hit this
    /// would already be malformed. The cap is `2048` so a legitimate
    /// nested CC project still fits with plenty of headroom.
    const DEPTH_LIMIT: usize = 2048;

    let mut stack: Vec<(PathBuf, PathBuf, usize)> =
        vec![(root_src.to_path_buf(), root_dst.to_path_buf(), 0)];

    while let Some((src, dst, depth)) = stack.pop() {
        if depth > DEPTH_LIMIT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("copy_tree_iterative: depth limit {DEPTH_LIMIT} exceeded"),
            ));
        }

        let meta = src.symlink_metadata()?;
        if meta.file_type().is_symlink() {
            // Refuse to follow symlinks during copy.
            continue;
        }

        if meta.file_type().is_dir() {
            std::fs::create_dir_all(&dst)?;
            // Preserve the source directory's mode bits. `create_dir_all`
            // uses the process umask (typically dropping to 0755); CC
            // writes image-cache with 0700 under ~/.claude, so without
            // this the EXDEV fallback widens readability from private
            // to world-readable-within-mode.
            let _ = std::fs::set_permissions(&dst, meta.permissions());
            for entry in std::fs::read_dir(&src)? {
                let entry = entry?;
                stack.push((entry.path(), dst.join(entry.file_name()), depth + 1));
            }
        } else if meta.file_type().is_file() {
            std::fs::copy(&src, &dst)?;
        }
        // Sockets, fifos, device nodes — skip silently.
    }

    Ok(())
}

/// Merges `src_session` into an already-existing `dst_session`,
/// file-by-file. Preserves any file or sub-directory that already
/// exists at the destination (presumed to belong to a still-live
/// sibling terminal). Only moves entries whose full path at the
/// destination is clear.
///
/// This is the collision path of `preserve_image_cache`. It
/// replaces the previous "skip entirely" behavior so that
/// `--resume`d sessions across multiple handle dirs no longer drop
/// the second-to-sweep's newer images.
///
/// Iterative walker — bounded by the same `DEPTH_LIMIT` as
/// `copy_tree_iterative`. Refuses to follow symlinks at every
/// level. Returns the count of successfully-moved top-level
/// entries (files or whole sub-trees); individual failures are
/// logged and swallowed so a single bad entry doesn't block the
/// rest of the merge.
///
/// On EXDEV at merge time, falls back to copy-then-remove via
/// `copy_tree_iterative`.
fn merge_session_into_existing(src_session: &Path, dst_session: &Path) -> std::io::Result<usize> {
    const DEPTH_LIMIT: usize = 2048;
    let mut moved = 0;

    // Work-queue: (src, dst, depth). Each dir that already exists at
    // the destination is expanded so we can merge into it per file.
    let mut stack: Vec<(PathBuf, PathBuf, usize)> =
        vec![(src_session.to_path_buf(), dst_session.to_path_buf(), 0)];

    while let Some((src, dst, depth)) = stack.pop() {
        if depth > DEPTH_LIMIT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("merge_session_into_existing: depth limit {DEPTH_LIMIT} exceeded"),
            ));
        }

        let entries = match std::fs::read_dir(&src) {
            Ok(e) => e,
            Err(e) => {
                warn!(path = %src.display(), error = %e, "merge: failed to read source dir");
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warn!(error = %e, "merge: entry read failed");
                    continue;
                }
            };

            let child_src = entry.path();
            let child_meta = match child_src.symlink_metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if child_meta.file_type().is_symlink() {
                // Refuse to follow symlinks — same policy as the
                // preservation walker above.
                continue;
            }

            let child_dst = dst.join(entry.file_name());

            if let Ok(dst_meta) = child_dst.symlink_metadata() {
                // Destination already exists. For files, preserve the
                // existing (live) version. For two-sided directories,
                // recurse to merge unique entries inside. For symlinks
                // at the destination (defense-in-depth — should not
                // happen since we control the shared cache), refuse
                // to traverse and preserve the existing entry.
                if dst_meta.file_type().is_symlink() {
                    warn!(
                        entry = %child_dst.display(),
                        "merge: destination entry is a symlink, refusing to recurse"
                    );
                    continue;
                }
                if dst_meta.file_type().is_dir() && child_meta.file_type().is_dir() {
                    stack.push((child_src, child_dst, depth + 1));
                }
                // Else: preserve existing destination entry, skip.
                continue;
            }

            // Destination is clear — move the whole entry in.
            match std::fs::rename(&child_src, &child_dst) {
                Ok(_) => moved += 1,
                Err(e) if is_cross_device(&e) => {
                    if child_meta.file_type().is_dir() {
                        if let Err(e) = copy_and_remove_tree(&child_src, &child_dst) {
                            warn!(
                                entry = %child_src.display(),
                                error = %e,
                                "merge: EXDEV fallback failed for sub-tree"
                            );
                        } else {
                            moved += 1;
                        }
                    } else if child_meta.file_type().is_file() {
                        if let Err(e) = std::fs::copy(&child_src, &child_dst) {
                            warn!(
                                entry = %child_src.display(),
                                error = %e,
                                "merge: EXDEV file copy failed"
                            );
                        } else {
                            let _ = std::fs::remove_file(&child_src);
                            moved += 1;
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        entry = %child_src.display(),
                        error = %e,
                        "merge: rename failed"
                    );
                }
            }
        }
    }

    // Best-effort: clean up the drained source session directory.
    // If anything is left (all files collided), remove_dir will fail
    // silently — we prefer that to `remove_dir_all` which might wipe
    // a sub-tree we just failed to merge.
    let _ = std::fs::remove_dir(src_session);

    Ok(moved)
}

/// Checks if the handle dir at `CLAUDE_CONFIG_DIR` is a `term-<pid>` dir.
/// Returns the resolved path if it is, or an error string if it's a legacy `config-N`.
pub fn resolve_handle_dir_from_env(base_dir: &Path) -> Result<PathBuf, String> {
    let raw = std::env::var("CLAUDE_CONFIG_DIR")
        .map_err(|_| "CLAUDE_CONFIG_DIR not set — run inside a csq-managed session".to_string())?;

    let config_dir = PathBuf::from(&raw);
    let dir_name = config_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if dir_name.starts_with("config-") {
        return Err(format!(
            "This terminal is using the legacy config-dir model ({dir_name}). \
             Swap affects ALL terminals sharing this config dir. \
             Relaunch with `csq run N` for per-terminal handle-dir isolation."
        ));
    }

    if !dir_name.starts_with("term-") {
        return Err(format!(
            "CLAUDE_CONFIG_DIR does not point to a csq handle dir: {raw}"
        ));
    }

    // Verify it's under base_dir
    let canon_base = base_dir
        .canonicalize()
        .map_err(|e| format!("bad base: {e}"))?;
    let canon_dir = config_dir
        .canonicalize()
        .map_err(|e| format!("bad config dir: {e}"))?;

    if !canon_dir.starts_with(&canon_base) {
        return Err(format!(
            "CLAUDE_CONFIG_DIR escapes base directory: {}",
            canon_dir.display()
        ));
    }

    Ok(canon_dir)
}

/// Cross-platform PID liveness check.
fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // kill(pid, 0) succeeds if the process exists AND we have permission.
        // ESRCH (3) = no such process. EPERM (1) = exists but different user.
        //
        // Uses `io::Error::last_os_error` rather than `libc::__error` /
        // `libc::__errno_location` directly — the stdlib wrapper is
        // portable across Linux/macOS/BSD without platform-specific
        // symbol juggling.
        // SAFETY: kill(pid, 0) is a pure syscall with no memory effects.
        let ret = unsafe { libc::kill(pid as i32, 0) };
        if ret == 0 {
            return true;
        }
        // Any error other than ESRCH (no such process) means the
        // process exists but we couldn't signal it — EPERM (different
        // user), EINVAL (shouldn't happen for sig 0), etc.
        std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }

    #[cfg(windows)]
    {
        use std::ptr;
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
            fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
        }
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() || handle == ptr::null_mut() {
                return false;
            }
            CloseHandle(handle);
            true
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

/// Sweep interval: 60 seconds.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Handle to a running sweep task.
pub struct SweepHandle {
    pub join: tokio::task::JoinHandle<()>,
}

/// Spawns a periodic handle-dir sweep task.
///
/// Scans `base_dir/term-*/` every 60 seconds and removes orphans
/// whose recorded owner PID is no longer alive. Pasted images under
/// each dead dir's `image-cache/` are moved to
/// `claude_home/image-cache/` so they survive the sweep (see journal
/// 0035).
///
/// `claude_home` is `Option<PathBuf>` so callers that cannot resolve
/// `~/.claude` (rare sandbox case with no `$HOME`) can pass `None`
/// and fall back to sweep-without-preservation rather than routing
/// images into a fallback directory that CC will never find. Shares
/// a cancellation token with the daemon so it stops on shutdown.
pub fn spawn_sweep(
    base_dir: PathBuf,
    claude_home: Option<PathBuf>,
    shutdown: tokio_util::sync::CancellationToken,
) -> SweepHandle {
    let join = tokio::spawn(async move {
        // Small startup delay to avoid racing with session creation
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
        }

        loop {
            let dir = base_dir.clone();
            let home = claude_home.clone();
            let _ = tokio::task::spawn_blocking(move || sweep_dead_handles(&dir, home.as_deref()))
                .await;

            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("handle-dir sweep cancelled, exiting");
                    return;
                }
                _ = tokio::time::sleep(SWEEP_INTERVAL) => {}
            }
        }
    });

    SweepHandle { join }
}

/// Platform-specific symlink creation.
fn create_symlink(target: &Path, link: &Path) -> Result<(), std::io::Error> {
    isolation::create_symlink_pub(target, link)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_config_dir(base: &Path, account: u16) -> PathBuf {
        let config = base.join(format!("config-{account}"));
        std::fs::create_dir_all(&config).unwrap();
        // Write minimal credential marker
        std::fs::write(config.join(".csq-account"), account.to_string()).unwrap();
        std::fs::write(config.join(".credentials.json"), "{}").unwrap();
        std::fs::write(config.join("settings.json"), "{}").unwrap();
        std::fs::write(config.join(".claude.json"), "{}").unwrap();
        config
    }

    #[test]
    fn create_handle_dir_populates_symlinks() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);

        let account = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account, 99999).unwrap();

        assert!(handle.exists());
        assert_eq!(handle.file_name().unwrap().to_str().unwrap(), "term-99999");

        // Account-bound symlinks should exist
        #[cfg(unix)]
        {
            let cred_link = handle.join(".credentials.json");
            assert!(cred_link
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink());
            let target = std::fs::read_link(&cred_link).unwrap();
            assert!(target.ends_with("config-1/.credentials.json"));
        }

        // .live-pid should contain PID
        assert_eq!(markers::read_live_pid(&handle), Some(99999));
    }

    #[test]
    fn repoint_handle_dir_changes_targets() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        setup_config_dir(base, 2);

        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account1, 88888).unwrap();

        // Repoint to account 2
        repoint_handle_dir(base, &claude_home, &handle, account2).unwrap();

        #[cfg(unix)]
        {
            let target = std::fs::read_link(handle.join(".credentials.json")).unwrap();
            assert!(target.ends_with("config-2/.credentials.json"));
            let target = std::fs::read_link(handle.join(".csq-account")).unwrap();
            assert!(target.ends_with("config-2/.csq-account"));
        }
    }

    #[test]
    fn create_handle_dir_materializes_user_settings() {
        // The core bug alpha.9 fixes: user has statusLine + bypass mode
        // in ~/.claude/settings.json, but csq run N used to symlink the
        // handle dir's settings.json at a (usually empty) config-N copy,
        // so CC — reading CLAUDE_CONFIG_DIR — saw no customization.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(
            claude_home.join("settings.json"),
            r#"{
                "statusLine": { "type": "command", "command": "echo hi" },
                "permissions": { "defaultMode": "bypassPermissions" },
                "enabledPlugins": { "my-plugin": true }
            }"#,
        )
        .unwrap();
        setup_config_dir(base, 1);

        let account = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account, 77777).unwrap();

        let materialized = handle.join("settings.json");
        // MUST be a real file, not a symlink. CC reads this as the
        // user-settings layer and CLAUDE_CONFIG_DIR replaces the home
        // settings path, so a symlink to an empty config-N copy would
        // silently drop everything.
        #[cfg(unix)]
        assert!(
            !materialized
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "handle dir settings.json must be a real file"
        );

        let json: Value =
            serde_json::from_str(&std::fs::read_to_string(&materialized).unwrap()).unwrap();
        assert_eq!(
            json.pointer("/statusLine/type").and_then(|v| v.as_str()),
            Some("command"),
            "user statusLine must survive materialization"
        );
        assert_eq!(
            json.pointer("/permissions/defaultMode")
                .and_then(|v| v.as_str()),
            Some("bypassPermissions"),
            "user bypassPermissions must survive materialization"
        );
        assert_eq!(
            json.pointer("/enabledPlugins/my-plugin")
                .and_then(|v| v.as_bool()),
            Some(true),
            "user plugin list must survive materialization"
        );
    }

    #[test]
    fn create_handle_dir_merges_third_party_env_overlay() {
        // 3P slot: user has global statusLine, and config-N/settings.json
        // carries the provider env block. Both must appear in the
        // materialized handle dir settings.json — the user keeps their
        // statusline, CC picks up ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(
            claude_home.join("settings.json"),
            r#"{
                "statusLine": { "type": "command", "command": "echo hi" },
                "env": { "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1" }
            }"#,
        )
        .unwrap();

        let config = base.join("config-9");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join(".csq-account"), "9").unwrap();
        std::fs::write(
            config.join("settings.json"),
            r#"{
                "env": {
                    "ANTHROPIC_BASE_URL": "https://api.minimax.io/anthropic",
                    "ANTHROPIC_AUTH_TOKEN": "sk-slot-test",
                    "ANTHROPIC_MODEL": "MiniMax-M2"
                }
            }"#,
        )
        .unwrap();

        let handle = create_handle_dir(
            base,
            &claude_home,
            AccountNum::try_from(9u16).unwrap(),
            66666,
        )
        .unwrap();

        let json: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap();

        // User keeps statusline
        assert_eq!(
            json.pointer("/statusLine/command").and_then(|v| v.as_str()),
            Some("echo hi")
        );
        // 3P env block merged in
        let env = json.get("env").unwrap();
        assert_eq!(
            env.get("ANTHROPIC_BASE_URL").and_then(|v| v.as_str()),
            Some("https://api.minimax.io/anthropic")
        );
        assert_eq!(
            env.get("ANTHROPIC_AUTH_TOKEN").and_then(|v| v.as_str()),
            Some("sk-slot-test")
        );
        // User's other env keys also preserved alongside the 3P overlay
        assert_eq!(
            env.get("CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS")
                .and_then(|v| v.as_str()),
            Some("1")
        );
    }

    #[test]
    fn create_handle_dir_tolerates_missing_user_settings() {
        // Fresh install: no ~/.claude/settings.json yet. Handle dir
        // materialization must not fail; the file is just the config-N
        // overlay (or empty for OAuth slots).
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 2);

        let handle = create_handle_dir(
            base,
            &claude_home,
            AccountNum::try_from(2u16).unwrap(),
            55555,
        )
        .unwrap();

        let content = std::fs::read_to_string(handle.join("settings.json")).unwrap();
        let json: Value = serde_json::from_str(&content).unwrap();
        assert!(json.is_object());
    }

    #[test]
    fn create_handle_dir_tolerates_malformed_user_settings() {
        // User has a typo in ~/.claude/settings.json. We log a warning
        // and proceed with an empty base — the alternative is leaving
        // the user stranded with no handle dir at all.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(claude_home.join("settings.json"), r#"{ not valid json"#).unwrap();
        setup_config_dir(base, 3);

        let handle = create_handle_dir(
            base,
            &claude_home,
            AccountNum::try_from(3u16).unwrap(),
            44444,
        )
        .unwrap();

        let json: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap();
        assert!(json.is_object());
    }

    #[test]
    fn repoint_rewrites_claude_json_for_new_slot() {
        // Alpha.10 regression fix: csq swap used to leave .claude.json
        // as the copy from whichever slot the handle dir was created
        // with. CC reads per-account caches from that file
        // (oauthAccount, overageCreditGrantCache,
        // cachedExtraUsageDisabledReason, cachedGrowthBookFeatures,
        // etc.) and displays "you've hit your limit" off the stale
        // cache without hitting Anthropic for a fresh answer. This
        // test asserts swap rewrites .claude.json so the new slot's
        // state wins.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Two slots. Each has a distinct .claude.json with account
        // identity and an account-scoped cache.
        let slot1 = base.join("config-1");
        std::fs::create_dir_all(&slot1).unwrap();
        std::fs::write(slot1.join(".csq-account"), "1").unwrap();
        std::fs::write(slot1.join(".credentials.json"), "{}").unwrap();
        std::fs::write(
            slot1.join(".claude.json"),
            r#"{
                "oauthAccount": { "emailAddress": "one@example.com", "accountUuid": "uuid-1" },
                "cachedExtraUsageDisabledReason": "org_level_disabled",
                "overageCreditGrantCache": { "uuid-1": { "info": { "available": false } } }
            }"#,
        )
        .unwrap();

        let slot2 = base.join("config-2");
        std::fs::create_dir_all(&slot2).unwrap();
        std::fs::write(slot2.join(".csq-account"), "2").unwrap();
        std::fs::write(slot2.join(".credentials.json"), "{}").unwrap();
        std::fs::write(
            slot2.join(".claude.json"),
            r#"{
                "oauthAccount": { "emailAddress": "two@example.com", "accountUuid": "uuid-2" }
            }"#,
        )
        .unwrap();

        let handle = create_handle_dir(
            base,
            &claude_home,
            AccountNum::try_from(1u16).unwrap(),
            22222,
        )
        .unwrap();

        // Before swap: handle dir's .claude.json matches slot 1.
        let pre: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join(".claude.json")).unwrap())
                .unwrap();
        assert_eq!(
            pre.pointer("/oauthAccount/emailAddress")
                .and_then(|v| v.as_str()),
            Some("one@example.com")
        );
        assert_eq!(
            pre.pointer("/cachedExtraUsageDisabledReason")
                .and_then(|v| v.as_str()),
            Some("org_level_disabled"),
            "pre-swap should reflect slot 1's stale cache"
        );

        // Swap to slot 2.
        repoint_handle_dir(
            base,
            &claude_home,
            &handle,
            AccountNum::try_from(2u16).unwrap(),
        )
        .unwrap();

        // Post-swap: handle dir's .claude.json matches slot 2. Stale
        // cache from slot 1 must be gone — slot 2 never had it.
        let post: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join(".claude.json")).unwrap())
                .unwrap();
        assert_eq!(
            post.pointer("/oauthAccount/emailAddress")
                .and_then(|v| v.as_str()),
            Some("two@example.com"),
            "swap must rewrite .claude.json to reflect new slot identity"
        );
        assert!(
            post.get("cachedExtraUsageDisabledReason").is_none(),
            "swap must drop account-scoped cache from previous slot: {post}"
        );
        assert!(
            post.get("overageCreditGrantCache").is_none(),
            "swap must drop overage credit cache from previous slot: {post}"
        );
    }

    #[test]
    fn repoint_preserves_session_scoped_projects() {
        // CC writes per-project state into .claude.json's projects map
        // during a session (MCP server state, model selection, resume
        // list, etc.). That state is scoped to the current CWD and must
        // survive a swap — otherwise --resume forgets the current
        // session and users lose their continuity.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        setup_config_dir(base, 2);

        // Write slot 2's .claude.json with a project entry for a
        // DIFFERENT cwd (should be stripped on swap).
        std::fs::write(
            base.join("config-2/.claude.json"),
            r#"{
                "oauthAccount": { "emailAddress": "two@example.com" },
                "projects": {
                    "/some/other/dir": { "lastModel": "old" }
                }
            }"#,
        )
        .unwrap();

        let handle = create_handle_dir(
            base,
            &claude_home,
            AccountNum::try_from(1u16).unwrap(),
            11111,
        )
        .unwrap();

        // Simulate CC writing a session-scoped project entry after
        // handle dir creation. Use the CWD so the scoping preserves it.
        let cwd = std::env::current_dir().unwrap();
        let cwd_str = cwd.to_string_lossy().to_string();
        let handle_cj = handle.join(".claude.json");
        let existing: Value = serde_json::from_str(
            &std::fs::read_to_string(&handle_cj).unwrap_or_else(|_| "{}".into()),
        )
        .unwrap_or(Value::Object(serde_json::Map::new()));
        let mut existing_obj = existing.as_object().cloned().unwrap_or_default();
        let mut projects = serde_json::Map::new();
        projects.insert(
            cwd_str.clone(),
            serde_json::json!({ "cc_session_state": "session-in-progress" }),
        );
        existing_obj.insert("projects".to_string(), Value::Object(projects));
        std::fs::write(
            &handle_cj,
            serde_json::to_string_pretty(&Value::Object(existing_obj)).unwrap(),
        )
        .unwrap();

        // Swap to slot 2.
        repoint_handle_dir(
            base,
            &claude_home,
            &handle,
            AccountNum::try_from(2u16).unwrap(),
        )
        .unwrap();

        let post: Value =
            serde_json::from_str(&std::fs::read_to_string(&handle_cj).unwrap()).unwrap();

        // Slot 2 identity is now in place.
        assert_eq!(
            post.pointer("/oauthAccount/emailAddress")
                .and_then(|v| v.as_str()),
            Some("two@example.com")
        );

        // Session-scoped project entry survived the swap (CC's
        // running-session state is preserved).
        assert_eq!(
            post.pointer(&format!(
                "/projects/{}/cc_session_state",
                cwd_str.replace('/', "~1")
            ))
            .and_then(|v| v.as_str()),
            Some("session-in-progress"),
            "session-scoped project state must survive swap: {post}"
        );

        // Slot 2's unrelated-CWD project entry was stripped.
        assert!(
            post.pointer("/projects/~1some~1other~1dir").is_none(),
            "foreign-CWD project from new slot must be stripped: {post}"
        );
    }

    #[test]
    fn repoint_rewrites_materialized_settings_for_new_slot() {
        // Swap from OAuth slot 1 (no env block) to 3P slot 9 (has env
        // block). The handle dir's settings.json must be re-materialized
        // so the new slot's env lands in it.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(
            claude_home.join("settings.json"),
            r#"{"statusLine": {"type": "command", "command": "user-cmd"}}"#,
        )
        .unwrap();
        setup_config_dir(base, 1);

        // 3P slot
        let slot9 = base.join("config-9");
        std::fs::create_dir_all(&slot9).unwrap();
        std::fs::write(slot9.join(".csq-account"), "9").unwrap();
        std::fs::write(
            slot9.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.z.ai/api/anthropic","ANTHROPIC_AUTH_TOKEN":"zai-tok"}}"#,
        )
        .unwrap();

        let handle = create_handle_dir(
            base,
            &claude_home,
            AccountNum::try_from(1u16).unwrap(),
            33333,
        )
        .unwrap();

        // Before swap: only user statusline, no env block
        let pre: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap();
        assert!(pre.pointer("/env/ANTHROPIC_BASE_URL").is_none());

        // Swap → slot 9
        repoint_handle_dir(
            base,
            &claude_home,
            &handle,
            AccountNum::try_from(9u16).unwrap(),
        )
        .unwrap();

        let post: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap();
        // User statusline preserved
        assert_eq!(
            post.pointer("/statusLine/command").and_then(|v| v.as_str()),
            Some("user-cmd")
        );
        // New slot's env block materialized
        assert_eq!(
            post.pointer("/env/ANTHROPIC_BASE_URL")
                .and_then(|v| v.as_str()),
            Some("https://api.z.ai/api/anthropic")
        );
        assert_eq!(
            post.pointer("/env/ANTHROPIC_AUTH_TOKEN")
                .and_then(|v| v.as_str()),
            Some("zai-tok")
        );
    }

    #[test]
    fn repoint_refuses_legacy_config_dir() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        let config = base.join("config-1");
        std::fs::create_dir_all(&config).unwrap();

        let result = repoint_handle_dir(
            base,
            &claude_home,
            &config,
            AccountNum::try_from(2u16).unwrap(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("term-"), "error should mention term-: {err}");
    }

    #[test]
    fn sweep_removes_dead_handles() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Create a handle dir with PID 1 (init, always alive on Unix)
        // and one with a definitely-dead PID
        let alive = base.join("term-1");
        std::fs::create_dir_all(&alive).unwrap();
        std::fs::write(alive.join(".live-pid"), "1").unwrap();

        let dead = base.join("term-999999999");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join(".live-pid"), "999999999").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        assert!(!dead.exists(), "dead handle dir should be removed");
        // PID 1 (init) should still be alive on unix, so term-1 stays
        #[cfg(unix)]
        assert!(alive.exists(), "live handle dir should remain");

        assert!(removed >= 1);
    }

    #[test]
    fn sweep_ignores_config_dirs() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let config = base.join("config-1");
        std::fs::create_dir_all(&config).unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));
        assert_eq!(removed, 0);
        assert!(config.exists(), "config dirs must not be swept");
    }

    #[test]
    fn sweep_preserves_image_cache_entries() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Dead handle dir with a populated per-session image cache.
        let dead = base.join("term-999999999");
        let session_a = "01f5a2b8-1234-4abc-9def-fedcba987654";
        let session_b = "02a1b2c3-d4e5-6f70-8910-abcdef012345";
        std::fs::create_dir_all(dead.join("image-cache").join(session_a)).unwrap();
        std::fs::create_dir_all(dead.join("image-cache").join(session_b)).unwrap();
        std::fs::write(
            dead.join("image-cache")
                .join(session_a)
                .join("pasted-0.png"),
            b"PNG-A",
        )
        .unwrap();
        std::fs::write(
            dead.join("image-cache")
                .join(session_b)
                .join("pasted-0.png"),
            b"PNG-B",
        )
        .unwrap();
        std::fs::write(dead.join(".live-pid"), "999999999").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        assert!(!dead.exists(), "dead handle dir should be removed");
        assert_eq!(removed, 1);

        let preserved_a = claude_home
            .join("image-cache")
            .join(session_a)
            .join("pasted-0.png");
        let preserved_b = claude_home
            .join("image-cache")
            .join(session_b)
            .join("pasted-0.png");
        assert!(preserved_a.exists(), "session A image should be preserved");
        assert!(preserved_b.exists(), "session B image should be preserved");
        assert_eq!(std::fs::read(preserved_a).unwrap(), b"PNG-A");
        assert_eq!(std::fs::read(preserved_b).unwrap(), b"PNG-B");
    }

    #[test]
    fn sweep_merges_image_cache_on_collision_preserving_live_side() {
        // Dead and live sides share the same session id. The merge
        // branch preserves the live side for any colliding filename,
        // moves in only unique filenames from the dead side. (The old
        // "skip entirely" behavior was a round-1 known limitation —
        // see sweep_merges_colliding_image_cache_session for the
        // positive merge case.)
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let session_id = "deadbeef-1234-4abc-9def-000000000000";

        let existing = claude_home.join("image-cache").join(session_id);
        std::fs::create_dir_all(&existing).unwrap();
        std::fs::write(existing.join("live.png"), b"LIVE").unwrap();

        let dead = base.join("term-999999998");
        std::fs::create_dir_all(dead.join("image-cache").join(session_id)).unwrap();
        std::fs::write(
            dead.join("image-cache").join(session_id).join("dead.png"),
            b"DEAD",
        )
        .unwrap();
        // Same filename as the live side — must NOT be clobbered.
        std::fs::write(
            dead.join("image-cache").join(session_id).join("live.png"),
            b"DEAD-COLLIDER",
        )
        .unwrap();
        std::fs::write(dead.join(".live-pid"), "999999998").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        assert!(!dead.exists(), "dead handle dir should still be removed");
        assert_eq!(removed, 1);

        // Live side untouched
        assert_eq!(
            std::fs::read(existing.join("live.png")).unwrap(),
            b"LIVE",
            "pre-existing session data must not be clobbered"
        );
        // New filename merged in
        assert_eq!(
            std::fs::read(existing.join("dead.png")).unwrap(),
            b"DEAD",
            "unique filename from dead side must be merged into live session"
        );
    }

    #[test]
    fn sweep_handles_missing_image_cache() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Dead handle dir with no image-cache subdir — common case.
        let dead = base.join("term-999999997");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join(".live-pid"), "999999997").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));
        assert_eq!(removed, 1);
        assert!(!dead.exists());
    }

    // ─── hardening tests from redteam round 1 ─────────────────────

    #[test]
    fn is_valid_session_name_accepts_uuids_and_rejects_hostile_names() {
        // Valid (canonical lowercase UUID)
        assert!(is_valid_session_name(std::ffi::OsStr::new(
            "01234567-89ab-4cde-8f01-23456789abcd"
        )));
        assert!(is_valid_session_name(std::ffi::OsStr::new("deadbeef")));
        assert!(is_valid_session_name(std::ffi::OsStr::new(
            "0123456789abcdef"
        )));

        // Hostile / non-UUID names
        assert!(!is_valid_session_name(std::ffi::OsStr::new("")));
        assert!(!is_valid_session_name(std::ffi::OsStr::new("..")));
        assert!(!is_valid_session_name(std::ffi::OsStr::new("foo/bar")));
        assert!(!is_valid_session_name(std::ffi::OsStr::new("foo.png")));
        assert!(!is_valid_session_name(std::ffi::OsStr::new("foo bar")));
        assert!(!is_valid_session_name(std::ffi::OsStr::new("GHIJKL")));

        // Uppercase hex rejected — APFS/HFS+ case-folding could
        // otherwise collide `DEADBEEF-...` with `deadbeef-...`.
        assert!(!is_valid_session_name(std::ffi::OsStr::new(
            "DEADBEEF-1234-4ABC-9DEF-000000000000"
        )));
        assert!(!is_valid_session_name(std::ffi::OsStr::new("ABCDEF")));

        // Too long
        assert!(!is_valid_session_name(std::ffi::OsStr::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefX"
        )));
    }

    #[test]
    fn sweep_rejects_non_uuid_session_names() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let dead = base.join("term-999999996");
        // Valid name — should move
        let valid = "01234567-89ab-4cde-8f01-23456789abcd";
        // Hostile name — should be skipped (not moved, not clobbering anything)
        let hostile = "hostile.dir";
        std::fs::create_dir_all(dead.join("image-cache").join(valid)).unwrap();
        std::fs::create_dir_all(dead.join("image-cache").join(hostile)).unwrap();
        std::fs::write(dead.join("image-cache").join(valid).join("ok.png"), b"OK").unwrap();
        std::fs::write(
            dead.join("image-cache").join(hostile).join("evil.png"),
            b"EVIL",
        )
        .unwrap();
        std::fs::write(dead.join(".live-pid"), "999999996").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        assert_eq!(removed, 1);
        assert!(
            claude_home
                .join("image-cache")
                .join(valid)
                .join("ok.png")
                .exists(),
            "valid session should be preserved"
        );
        assert!(
            !claude_home.join("image-cache").join(hostile).exists(),
            "hostile session name must not land in shared cache"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sweep_refuses_symlink_src_image_cache() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Something sensitive the attacker wants to redirect to.
        let sensitive = dir.path().join("sensitive-target");
        std::fs::create_dir_all(&sensitive).unwrap();
        std::fs::write(sensitive.join("id_rsa"), b"SECRET").unwrap();

        // Dead handle dir with image-cache as a symlink to sensitive/
        let dead = base.join("term-999999995");
        std::fs::create_dir_all(&dead).unwrap();
        std::os::unix::fs::symlink(&sensitive, dead.join("image-cache")).unwrap();
        std::fs::write(dead.join(".live-pid"), "999999995").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        // Sweep still removes the dead dir (removing a symlink doesn't
        // touch the target).
        assert_eq!(removed, 1);

        // Sensitive file must NOT have been moved into the shared cache.
        assert!(
            sensitive.join("id_rsa").exists(),
            "symlink target must survive sweep"
        );
        assert!(
            !claude_home.join("image-cache").join("id_rsa").exists(),
            "symlink must not have redirected sweep into target dir"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sweep_refuses_symlink_session_entry() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let sensitive = dir.path().join("secrets");
        std::fs::create_dir_all(&sensitive).unwrap();
        std::fs::write(sensitive.join("key"), b"SECRET").unwrap();

        // Dead handle dir; image-cache/<session-id>/ is a symlink
        let dead = base.join("term-999999994");
        let session_id = "01234567-89ab-4cde-8f01-23456789abcd";
        std::fs::create_dir_all(dead.join("image-cache")).unwrap();
        std::os::unix::fs::symlink(&sensitive, dead.join("image-cache").join(session_id)).unwrap();
        std::fs::write(dead.join(".live-pid"), "999999994").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        assert_eq!(removed, 1);
        // Sensitive data untouched
        assert!(sensitive.join("key").exists());
        // No corresponding entry under the shared cache
        assert!(!claude_home.join("image-cache").join(session_id).exists());
    }

    #[cfg(unix)]
    #[test]
    fn sweep_refuses_symlink_dst_image_cache() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Attacker-planted symlink: claude_home/image-cache -> /tmp/attacker
        let attacker = dir.path().join("attacker-controlled");
        std::fs::create_dir_all(&attacker).unwrap();
        std::os::unix::fs::symlink(&attacker, claude_home.join("image-cache")).unwrap();

        let dead = base.join("term-999999993");
        let session_id = "01234567-89ab-4cde-8f01-23456789abcd";
        std::fs::create_dir_all(dead.join("image-cache").join(session_id)).unwrap();
        std::fs::write(
            dead.join("image-cache").join(session_id).join("img.png"),
            b"DATA",
        )
        .unwrap();
        std::fs::write(dead.join(".live-pid"), "999999993").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        // Sweep still removes dead dir, but must NOT write into the
        // redirected attacker location.
        assert_eq!(removed, 1);
        assert!(
            !attacker.join(session_id).exists(),
            "preservation must not follow a symlink at the destination"
        );
    }

    #[test]
    fn sweep_none_claude_home_skips_preservation_but_still_sweeps() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let dead = base.join("term-999999992");
        let session_id = "01234567-89ab-4cde-8f01-23456789abcd";
        std::fs::create_dir_all(dead.join("image-cache").join(session_id)).unwrap();
        std::fs::write(
            dead.join("image-cache").join(session_id).join("img.png"),
            b"DATA",
        )
        .unwrap();
        std::fs::write(dead.join(".live-pid"), "999999992").unwrap();

        let removed = sweep_dead_handles(base, None);

        assert_eq!(removed, 1);
        assert!(!dead.exists(), "sweep still removes orphan");
        // Image is lost — documented fallback behavior.
    }

    #[test]
    fn sweep_skips_when_live_pid_alive_but_dir_name_pid_dead() {
        // Scenario: handle dir is `term-999999991` but `.live-pid`
        // contains PID 1 (init). The dir-name PID is dead; the
        // marker PID is alive. The authoritative check is .live-pid,
        // so the dir must NOT be swept.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let dead_dirname = base.join("term-999999991");
        std::fs::create_dir_all(&dead_dirname).unwrap();
        // Marker says PID 1 (init, always alive on Unix)
        std::fs::write(dead_dirname.join(".live-pid"), "1").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        #[cfg(unix)]
        {
            assert_eq!(removed, 0, "dir with alive .live-pid must not be swept");
            assert!(dead_dirname.exists());
        }
        // On non-unix we can't guarantee PID 1 is alive, so skip the
        // assertion there.
        #[cfg(not(unix))]
        {
            let _ = removed;
        }
    }

    #[test]
    fn copy_tree_recursive_preserves_nested_subdirs_and_files() {
        // Not strictly needed for rename (which is atomic on directories)
        // but the EXDEV fallback path must handle nested trees correctly.
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join("sub1").join("sub2")).unwrap();
        std::fs::write(src.join("top.png"), b"TOP").unwrap();
        std::fs::write(src.join("sub1").join("mid.png"), b"MID").unwrap();
        std::fs::write(src.join("sub1").join("sub2").join("deep.png"), b"DEEP").unwrap();

        let dst = dir.path().join("dst");
        copy_tree_iterative(&src, &dst).unwrap();

        assert_eq!(std::fs::read(dst.join("top.png")).unwrap(), b"TOP");
        assert_eq!(
            std::fs::read(dst.join("sub1").join("mid.png")).unwrap(),
            b"MID"
        );
        assert_eq!(
            std::fs::read(dst.join("sub1").join("sub2").join("deep.png")).unwrap(),
            b"DEEP"
        );
    }

    #[cfg(unix)]
    #[test]
    fn copy_tree_recursive_preserves_directory_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(src.join("a"), b"X").unwrap();

        let dst = dir.path().join("dst");
        copy_tree_iterative(&src, &dst).unwrap();

        let mode = dst.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "copy must preserve source dir mode bits (got {:o})",
            mode
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_live_pid_refuses_symlink() {
        // Targets markers::read_live_pid — the sweep path consumes
        // it via the shared markers module rather than a local
        // duplicate. A symlink-at-.live-pid must not be followed.
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-12345");
        std::fs::create_dir_all(&handle).unwrap();

        // Plant a symlink at .live-pid pointing at a regular file
        // with "1" (init, always alive). Without the symlink refusal
        // this would read through and report PID 1 alive.
        let target = dir.path().join("outside-file");
        std::fs::write(&target, "1").unwrap();
        std::os::unix::fs::symlink(&target, handle.join(".live-pid")).unwrap();

        assert_eq!(
            markers::read_live_pid(&handle),
            None,
            "symlink .live-pid must be refused"
        );
    }

    #[cfg(unix)]
    #[test]
    fn copy_tree_recursive_refuses_symlinks() {
        // Verifies that the EXDEV fallback's tree walker refuses to
        // follow symlinks, closing the same attack surface as
        // sweep_refuses_symlink_session_entry but at the copy layer.
        let dir = TempDir::new().unwrap();
        let sensitive = dir.path().join("secret");
        std::fs::create_dir_all(&sensitive).unwrap();
        std::fs::write(sensitive.join("key"), b"TOP-SECRET").unwrap();

        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("normal.txt"), b"ok").unwrap();
        std::os::unix::fs::symlink(&sensitive, src.join("redirect")).unwrap();

        let dst = dir.path().join("dst");
        copy_tree_iterative(&src, &dst).unwrap();

        assert!(dst.join("normal.txt").exists());
        assert!(
            !dst.join("redirect").exists(),
            "symlink copy must not follow"
        );
        assert!(
            !dst.join("redirect").join("key").exists(),
            "symlink target must not leak into destination"
        );
    }

    // ─── residual-risk resolution tests (post-redteam round 6) ────

    #[test]
    fn sweep_merges_colliding_image_cache_session() {
        // Terminal A ran session UUID-1, pasted image-0.png, was
        // swept → ~/.claude/image-cache/UUID-1/image-0.png. Terminal B
        // resumed UUID-1, pasted image-1.png in a new handle dir, died.
        // Sweep must MERGE image-1.png into the existing shared
        // session without clobbering image-0.png.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let session_id = "deadbeef-1234-4abc-9def-111111111111";

        let existing = claude_home.join("image-cache").join(session_id);
        std::fs::create_dir_all(&existing).unwrap();
        std::fs::write(existing.join("image-0.png"), b"A0").unwrap();

        let dead = base.join("term-999999990");
        std::fs::create_dir_all(dead.join("image-cache").join(session_id)).unwrap();
        std::fs::write(
            dead.join("image-cache")
                .join(session_id)
                .join("image-1.png"),
            b"B1",
        )
        .unwrap();
        std::fs::write(
            dead.join("image-cache")
                .join(session_id)
                .join("image-0.png"),
            b"B0-newer",
        )
        .unwrap();
        std::fs::write(dead.join(".live-pid"), "999999990").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));
        assert_eq!(removed, 1);
        assert!(!dead.exists());

        assert_eq!(
            std::fs::read(existing.join("image-1.png")).unwrap(),
            b"B1",
            "new filename must be merged"
        );
        assert_eq!(
            std::fs::read(existing.join("image-0.png")).unwrap(),
            b"A0",
            "existing file must not be clobbered"
        );
    }

    #[test]
    fn sweep_merges_colliding_session_with_nested_dirs() {
        // Merge handles sub-directory collision by recursing: a
        // `subfolder/` existing on both sides must not be clobbered,
        // but unique files inside the dead side's `subfolder/` must
        // be moved in.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let sid = "deadbeef-5678-4abc-9def-222222222222";
        let existing = claude_home.join("image-cache").join(sid);
        std::fs::create_dir_all(existing.join("sub")).unwrap();
        std::fs::write(existing.join("sub").join("live.png"), b"LIVE").unwrap();

        let dead = base.join("term-999999989");
        std::fs::create_dir_all(dead.join("image-cache").join(sid).join("sub")).unwrap();
        std::fs::write(
            dead.join("image-cache")
                .join(sid)
                .join("sub")
                .join("new.png"),
            b"NEW",
        )
        .unwrap();
        std::fs::write(
            dead.join("image-cache")
                .join(sid)
                .join("sub")
                .join("live.png"),
            b"COLLIDER",
        )
        .unwrap();
        std::fs::write(dead.join(".live-pid"), "999999989").unwrap();

        sweep_dead_handles(base, Some(&claude_home));

        assert_eq!(
            std::fs::read(existing.join("sub").join("live.png")).unwrap(),
            b"LIVE"
        );
        assert_eq!(
            std::fs::read(existing.join("sub").join("new.png")).unwrap(),
            b"NEW"
        );
    }

    #[test]
    fn copy_tree_iterative_handles_deep_nesting() {
        // 64 levels — well under the 2048 DEPTH_LIMIT — verifies the
        // iterative walker handles nesting without stack overflow.
        let dir = TempDir::new().unwrap();
        let mut p = dir.path().join("src");
        std::fs::create_dir_all(&p).unwrap();
        for i in 0..64 {
            p = p.join(format!("level-{i}"));
            std::fs::create_dir(&p).unwrap();
        }
        std::fs::write(p.join("leaf.png"), b"LEAF").unwrap();

        let dst = dir.path().join("dst");
        copy_tree_iterative(&dir.path().join("src"), &dst).unwrap();

        let mut dst_p = dst.clone();
        for i in 0..64 {
            dst_p = dst_p.join(format!("level-{i}"));
        }
        assert_eq!(std::fs::read(dst_p.join("leaf.png")).unwrap(), b"LEAF");
    }

    #[test]
    fn sweep_leaves_no_tombstone_after_success() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let dead = base.join("term-999999988");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join(".live-pid"), "999999988").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));
        assert_eq!(removed, 1);

        let residue: Vec<_> = std::fs::read_dir(base)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".sweep-tombstone-")
            })
            .collect();
        assert!(
            residue.is_empty(),
            "tombstones left behind: {:?}",
            residue.iter().map(|e| e.file_name()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn sweep_cleans_up_stale_tombstones_from_previous_crash() {
        // Simulate a previous sweep that crashed mid-delete, leaving
        // a .sweep-tombstone-* dir behind. Next sweep removes it via
        // the initial cleanup pass.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let tomb = base.join(".sweep-tombstone-12345-abc");
        std::fs::create_dir_all(tomb.join("junk")).unwrap();
        std::fs::write(tomb.join("junk").join("file"), b"X").unwrap();

        sweep_dead_handles(base, Some(&claude_home));
        assert!(
            !tomb.exists(),
            "stale tombstone must be cleaned up on sweep entry"
        );
    }

    #[test]
    fn sweep_skips_when_live_cc_pid_alive() {
        // Windows crash-recovery path: .live-pid names a dead csq-cli
        // PID but .live-cc-pid names an alive CC child. Sweep must
        // honor the live child and skip the dir.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let dead = base.join("term-999999987");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join(".live-pid"), "999999987").unwrap();
        // PID 1 (init) is always alive on Unix.
        std::fs::write(dead.join(".live-cc-pid"), "1").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));

        #[cfg(unix)]
        {
            assert_eq!(removed, 0);
            assert!(
                dead.exists(),
                "dir with alive .live-cc-pid must not be swept"
            );
        }
        #[cfg(not(unix))]
        {
            let _ = removed;
        }
    }

    #[test]
    fn sweep_proceeds_when_live_cc_pid_dead() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let dead = base.join("term-999999986");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join(".live-pid"), "999999986").unwrap();
        std::fs::write(dead.join(".live-cc-pid"), "999999985").unwrap();

        let removed = sweep_dead_handles(base, Some(&claude_home));
        assert_eq!(removed, 1);
        assert!(!dead.exists());
    }

    #[cfg(unix)]
    #[test]
    fn read_live_cc_pid_refuses_symlink() {
        // Same symlink defense as read_live_pid, applied to the
        // new Windows child PID marker.
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-54321");
        std::fs::create_dir_all(&handle).unwrap();

        let target = dir.path().join("outside");
        std::fs::write(&target, "1").unwrap();
        std::os::unix::fs::symlink(&target, handle.join(".live-cc-pid")).unwrap();

        assert_eq!(
            markers::read_live_cc_pid(&handle),
            None,
            "symlink .live-cc-pid must be refused"
        );
    }

    // ── Issue 2 reproduction: onboarding "re-init" claim ────────────
    //
    // User reports that after `csq install` + manual keybindings.json
    // + first `csq run`, their `~/.claude/settings.json` and
    // statusline "disappear". The tests below pin the actual contract
    // so any future regression is caught:
    //
    //   - `create_handle_dir` must NEVER mutate `~/.claude/settings.json`.
    //   - The handle dir's materialized settings MUST carry through
    //     every user-customized key (statusLine, permissions, plugins,
    //     mcpServers, env).
    //   - On fresh install the global `keybindings.json` must be a
    //     file (issue 1 regression) so a user who manually edits it
    //     doesn't have their `{"bindings": []}` overwritten by a
    //     later `csq run` turning it into a dir.

    #[test]
    #[cfg(unix)]
    fn user_global_settings_json_is_byte_identical_after_csq_run() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Realistic user global: statusLine, permissions, plugins,
        // mcpServers, env. Mirrors what `csq install` + a few weeks
        // of customization would leave behind.
        let user_settings = r#"{
          "$schema": "https://json.schemastore.org/claude-code-settings.json",
          "env": { "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1" },
          "permissions": {
            "allow": ["Bash(git rm:*)", "WebSearch"],
            "defaultMode": "bypassPermissions"
          },
          "statusLine": { "type": "command", "command": "csq statusline" },
          "enabledPlugins": { "rust-analyzer-lsp@claude-plugins-official": true },
          "alwaysThinkingEnabled": true,
          "effortLevel": "xhigh"
        }
        "#;
        std::fs::write(claude_home.join("settings.json"), user_settings).unwrap();
        let settings_path = claude_home.join("settings.json");
        let before_bytes = std::fs::read(&settings_path).unwrap();

        setup_config_dir(base, 1);
        let account = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account, 55555).unwrap();
        assert!(handle.exists());

        // The global MUST be untouched — not a single byte changed.
        let after_bytes = std::fs::read(&settings_path).unwrap();
        assert_eq!(
            before_bytes, after_bytes,
            "csq run must never mutate ~/.claude/settings.json"
        );
    }

    #[test]
    #[cfg(unix)]
    fn handle_dir_settings_carries_every_user_customization() {
        // Core of the "re-init" claim: the handle dir CC reads must
        // expose the same keys the user set in the global, so CC
        // doesn't behave as if this is a first-run session.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        let user_settings = r#"{
          "env": { "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1" },
          "permissions": {
            "allow": ["Bash(git *)"],
            "defaultMode": "bypassPermissions"
          },
          "statusLine": { "type": "command", "command": "csq statusline" },
          "enabledPlugins": { "frontend-design@claude-plugins-official": true },
          "enableAllProjectMcpServers": true,
          "alwaysThinkingEnabled": true,
          "effortLevel": "xhigh",
          "voiceEnabled": true
        }
        "#;
        std::fs::write(claude_home.join("settings.json"), user_settings).unwrap();
        setup_config_dir(base, 1);

        let account = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account, 44444).unwrap();

        let materialized: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join("settings.json")).unwrap())
                .unwrap();

        // Every user-touched key must be present in the handle dir.
        assert_eq!(
            materialized
                .pointer("/statusLine/command")
                .and_then(|v| v.as_str()),
            Some("csq statusline"),
        );
        assert_eq!(
            materialized
                .pointer("/permissions/defaultMode")
                .and_then(|v| v.as_str()),
            Some("bypassPermissions"),
        );
        assert_eq!(
            materialized
                .pointer("/permissions/allow/0")
                .and_then(|v| v.as_str()),
            Some("Bash(git *)"),
        );
        assert_eq!(
            materialized
                .pointer("/enabledPlugins/frontend-design@claude-plugins-official")
                .and_then(|v| v.as_bool()),
            Some(true),
        );
        assert_eq!(
            materialized
                .pointer("/env/CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS")
                .and_then(|v| v.as_str()),
            Some("1"),
        );
        assert_eq!(
            materialized
                .pointer("/enableAllProjectMcpServers")
                .and_then(|v| v.as_bool()),
            Some(true),
        );
        assert_eq!(
            materialized
                .pointer("/alwaysThinkingEnabled")
                .and_then(|v| v.as_bool()),
            Some(true),
        );
        assert_eq!(
            materialized
                .pointer("/effortLevel")
                .and_then(|v| v.as_str()),
            Some("xhigh"),
        );
        assert_eq!(
            materialized
                .pointer("/voiceEnabled")
                .and_then(|v| v.as_bool()),
            Some(true),
        );
    }

    #[test]
    #[cfg(unix)]
    fn keybindings_json_stays_a_file_through_multiple_csq_runs() {
        // The pre-alpha.18 bug turned `~/.claude/keybindings.json`
        // into a directory the first time csq run was invoked on a
        // fresh install. If the user then tried to manually create
        // `{"bindings":[]}` they'd hit "is a directory" or end up
        // writing INTO the dir — which the user reports as "settings
        // and statusline disappears" (CC fails to parse its config).
        //
        // Post-fix: the file gets seeded with parseable JSON, and
        // subsequent runs must never promote it to a dir.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);

        let account = AccountNum::try_from(1u16).unwrap();
        // First run: seeds keybindings.json as a FILE.
        let h1 = create_handle_dir(base, &claude_home, account, 11111).unwrap();
        let kb = claude_home.join("keybindings.json");
        let meta = std::fs::metadata(&kb).unwrap();
        assert!(
            meta.is_file(),
            "first csq run must leave keybindings.json as a file"
        );
        let first_content = std::fs::read_to_string(&kb).unwrap();
        let _: serde_json::Value = serde_json::from_str(&first_content)
            .expect("seeded keybindings.json must be valid JSON");

        // User now edits keybindings.json with their custom bindings.
        std::fs::write(&kb, r#"{"bindings":[{"key":"cmd+s","cmd":"save"}]}"#).unwrap();

        // Clean up first handle so second run can reuse PID 11111
        // (simulates `exec` or the handle-dir being swept).
        std::fs::remove_dir_all(&h1).unwrap();

        // Second run: must not overwrite or promote to dir.
        let _h2 = create_handle_dir(base, &claude_home, account, 22222).unwrap();
        let meta = std::fs::metadata(&kb).unwrap();
        assert!(meta.is_file(), "second csq run must preserve the file");
        let second_content = std::fs::read_to_string(&kb).unwrap();
        assert!(
            second_content.contains("cmd+s"),
            "user custom bindings must not be overwritten"
        );
    }

    // ── VP-final F3: pre-flight existence guard ───────────────────────────

    /// Regression guard: VP-final F3.
    ///
    /// `repoint_handle_dir` must refuse to start the rename loop when the
    /// `.csq-account` marker is absent from the target `config-<N>` directory.
    /// Without it csq cannot determine which account the handle dir is on after
    /// the swap. The old "silently continue" path would remove the existing
    /// `.csq-account` symlink without creating a new one.
    #[test]
    #[cfg(unix)]
    fn repoint_aborts_when_target_config_missing_csq_account() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Config-1: complete
        setup_config_dir(base, 1);
        // Config-2: intentionally missing .csq-account (the required marker)
        let config_2 = base.join("config-2");
        std::fs::create_dir_all(&config_2).unwrap();
        // NOT writing .csq-account — this is the missing item under test
        std::fs::write(config_2.join(".credentials.json"), "{}").unwrap();
        std::fs::write(config_2.join("settings.json"), "{}").unwrap();
        std::fs::write(config_2.join(".claude.json"), "{}").unwrap();

        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account1, 55551).unwrap();

        // Attempt to repoint to account 2 — should fail because .csq-account
        // is missing from config-2, preventing a mixed-state handle dir.
        let result = repoint_handle_dir(base, &claude_home, &handle, account2);

        assert!(
            result.is_err(),
            "repoint must return Err when target config is missing .csq-account"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains(".csq-account"),
            "error must name the missing item, got: {err_msg}"
        );
        assert!(
            err_msg.contains("mixed-state") || err_msg.contains("repoint aborted"),
            "error must describe the abort reason, got: {err_msg}"
        );

        // Handle dir must still be bound to account 1 (no partial repoint)
        assert_eq!(
            markers::read_csq_account(&handle),
            Some(account1),
            "handle dir must remain on account 1 after aborted repoint"
        );
    }

    // ── VP-final F4: concurrent swap serialization ────────────────────────

    /// Regression guard: VP-final F4.
    ///
    /// Two threads both calling `repoint_handle_dir` on the SAME handle dir
    /// but with DIFFERENT targets must produce a consistent final state:
    /// all 4 symlinks must point at the SAME config-<N> dir (whichever
    /// thread won the lock). Without the flock the two threads can interleave
    /// rename operations, leaving the handle dir in a mixed-state where
    /// `.credentials.json` points at config-2 but `.csq-account` still
    /// points at config-3.
    #[test]
    #[cfg(unix)]
    fn repoint_handle_dir_serializes_concurrent_writers() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Create three accounts: handle starts on 1, threads race to set 2 vs 3
        setup_config_dir(dir.path(), 1);
        setup_config_dir(dir.path(), 2);
        setup_config_dir(dir.path(), 3);

        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let account3 = AccountNum::try_from(3u16).unwrap();

        let handle = create_handle_dir(dir.path(), &claude_home, account1, 55552).unwrap();

        // Barrier: both threads enter repoint_handle_dir at the same time
        let barrier = Arc::new(Barrier::new(2));

        let base_a = base.clone();
        let claude_a = claude_home.clone();
        let handle_a = handle.clone();
        let barrier_a = barrier.clone();
        let t1 = thread::spawn(move || {
            barrier_a.wait();
            repoint_handle_dir(&base_a, &claude_a, &handle_a, account2)
        });

        let base_b = base.clone();
        let claude_b = claude_home.clone();
        let handle_b = handle.clone();
        let barrier_b = barrier.clone();
        let t2 = thread::spawn(move || {
            barrier_b.wait();
            repoint_handle_dir(&base_b, &claude_b, &handle_b, account3)
        });

        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();

        // Both must succeed (no panic, no I/O error from interleaving)
        assert!(r1.is_ok(), "thread 1 repoint failed: {:?}", r1);
        assert!(r2.is_ok(), "thread 2 repoint failed: {:?}", r2);

        // The handle dir must be in a CONSISTENT state: all symlinks point
        // at the SAME config-<N>. Read the account marker to determine winner.
        let final_account = markers::read_csq_account(&handle)
            .expect("handle dir must have a readable .csq-account after concurrent repoint");

        // Verify every symlink that EXISTS in the handle dir resolves to the
        // winner's config dir. Optional items (.current-account, .quota-cursor)
        // may be absent if they were never created in config-<N> — skip those.
        // Required items (.credentials.json, .csq-account) must be consistent.
        let winner_config = base.join(format!("config-{}", final_account));
        for item in ACCOUNT_BOUND_ITEMS {
            let link = handle.join(item);
            // If the item is absent, it was never created in either config dir —
            // skip. This handles optional items that don't exist yet.
            if link.symlink_metadata().is_err() {
                continue;
            }
            let resolved = std::fs::read_link(&link).unwrap_or_else(|e| {
                panic!("{item} link exists but read_link failed: {e}");
            });
            assert!(
                resolved.starts_with(&winner_config),
                "{item} points at {} but winner config is {} — mixed-state handle dir \
                 (concurrent repoint without flock would allow this)",
                resolved.display(),
                winner_config.display()
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn settings_local_and_default_are_files_not_directories() {
        // Same bug class as keybindings.json — any file-named
        // SHARED_ITEMS entry must land as a FILE on fresh install.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);

        let account = AccountNum::try_from(1u16).unwrap();
        let _h = create_handle_dir(base, &claude_home, account, 33333).unwrap();

        for name in [
            "keybindings.json",
            "settings.local.json",
            "settings-default.json",
            "stats-cache.json",
        ] {
            let path = claude_home.join(name);
            if !path.exists() {
                continue;
            }
            let meta = std::fs::metadata(&path).unwrap();
            assert!(meta.is_file(), "{name} must be a FILE");
            let content = std::fs::read_to_string(&path).unwrap();
            let _: serde_json::Value = serde_json::from_str(&content)
                .unwrap_or_else(|_| panic!("{name} must be valid JSON"));
        }

        // Non-JSON file-shaped items also check out.
        for name in ["history.jsonl", "__store.db"] {
            let path = claude_home.join(name);
            if !path.exists() {
                continue;
            }
            assert!(
                std::fs::metadata(&path).unwrap().is_file(),
                "{name} must be a file"
            );
        }
    }

    // ── create_handle_dir_codex (PR-C3a) ───────────────────────────────

    fn setup_codex_slot(base: &Path, account: u16) -> PathBuf {
        // Create config-<N> with the Codex-specific bits: marker,
        // config.toml, codex-sessions dir, codex-history.jsonl file.
        let config = base.join(format!("config-{account}"));
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join(".csq-account"), account.to_string()).unwrap();
        std::fs::write(config.join("config.toml"), "[model]\nname = \"o1\"\n").unwrap();
        std::fs::create_dir_all(config.join("codex-sessions")).unwrap();
        std::fs::write(config.join("codex-history.jsonl"), "").unwrap();

        // Canonical credential file that auth.json will symlink to.
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(
            creds_dir.join(format!("codex-{account}.json")),
            r#"{"auth_mode":"chatgpt","tokens":{"access_token":"at","refresh_token":"rt","id_token":"it","account_id":"uuid"}}"#,
        )
        .unwrap();

        config
    }

    #[test]
    fn create_handle_dir_codex_populates_codex_symlink_set() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_codex_slot(base, 2);

        let account = AccountNum::try_from(2u16).unwrap();
        let handle = create_handle_dir_codex(base, account, 88888).unwrap();

        assert!(handle.exists());
        assert_eq!(handle.file_name().unwrap().to_str().unwrap(), "term-88888");

        #[cfg(unix)]
        {
            // Every Codex symlink in the set should land and resolve
            // to its spec-defined target.
            let auth = handle.join("auth.json");
            assert!(auth.symlink_metadata().unwrap().file_type().is_symlink());
            let target = std::fs::read_link(&auth).unwrap();
            assert!(
                target.ends_with("credentials/codex-2.json"),
                "auth.json target: {:?}",
                target
            );

            let csq_acc = handle.join(".csq-account");
            assert!(csq_acc.symlink_metadata().unwrap().file_type().is_symlink());
            assert!(std::fs::read_link(&csq_acc)
                .unwrap()
                .ends_with("config-2/.csq-account"));

            let cfg = handle.join("config.toml");
            assert!(cfg.symlink_metadata().unwrap().file_type().is_symlink());
            assert!(std::fs::read_link(&cfg)
                .unwrap()
                .ends_with("config-2/config.toml"));

            let sessions = handle.join("sessions");
            assert!(sessions
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink());
            assert!(std::fs::read_link(&sessions)
                .unwrap()
                .ends_with("config-2/codex-sessions"));

            let hist = handle.join("history.jsonl");
            assert!(hist.symlink_metadata().unwrap().file_type().is_symlink());
            assert!(std::fs::read_link(&hist)
                .unwrap()
                .ends_with("config-2/codex-history.jsonl"));
        }

        // Ephemeral per-terminal log dir is a real directory, not a symlink.
        let log = handle.join("log");
        assert!(log.is_dir());
        #[cfg(unix)]
        assert!(!log.symlink_metadata().unwrap().file_type().is_symlink());

        // .live-pid contains the supplied PID.
        let pid_str = std::fs::read_to_string(handle.join(".live-pid")).unwrap();
        assert_eq!(pid_str.trim(), "88888");
    }

    #[test]
    fn create_handle_dir_codex_does_not_materialize_settings_or_claude_json() {
        // Codex handle dirs MUST NOT carry settings.json or
        // .claude.json — those are Anthropic-specific (PR-C3a
        // docstring). Confirm they are absent after creation.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_codex_slot(base, 3);

        let account = AccountNum::try_from(3u16).unwrap();
        let handle = create_handle_dir_codex(base, account, 88889).unwrap();

        assert!(
            !handle.join("settings.json").exists(),
            "Codex handle dir must not carry settings.json"
        );
        assert!(
            !handle.join(".claude.json").exists(),
            "Codex handle dir must not carry .claude.json"
        );
        assert!(
            !handle.join(".credentials.json").exists(),
            "Codex handle dir must not carry Anthropic-shaped .credentials.json"
        );
    }

    #[test]
    fn create_handle_dir_codex_refuses_when_config_dir_missing() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(5u16).unwrap();
        let result = create_handle_dir_codex(dir.path(), account, 1);
        match result {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(
                    reason.contains("config-5"),
                    "error must name the missing config dir: {reason}"
                );
                assert!(
                    reason.contains("login"),
                    "error must hint at `csq login ... --provider codex`: {reason}"
                );
            }
            other => panic!("expected Corrupt for missing config-N, got: {other:?}"),
        }
    }

    #[test]
    fn create_handle_dir_codex_refuses_when_canonical_credential_missing() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        // Provision config-<N> but NOT the canonical credential file.
        let config = base.join("config-6");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join(".csq-account"), "6").unwrap();
        std::fs::write(config.join("config.toml"), "").unwrap();

        let account = AccountNum::try_from(6u16).unwrap();
        let result = create_handle_dir_codex(base, account, 1);
        match result {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(
                    reason.contains("codex-6.json"),
                    "error must name the missing canonical file: {reason}"
                );
            }
            other => panic!("expected Corrupt for missing canonical, got: {other:?}"),
        }
    }

    #[test]
    fn create_handle_dir_codex_refuses_live_pid_collision() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_codex_slot(base, 7);

        let account = AccountNum::try_from(7u16).unwrap();
        // Pre-create a handle dir with a PID that is definitely alive
        // — use our own PID. The function must refuse rather than
        // clobber it.
        let own_pid = std::process::id();
        let handle = base.join(format!("term-{own_pid}"));
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(handle.join(".live-pid"), own_pid.to_string()).unwrap();

        let result = create_handle_dir_codex(base, account, own_pid);
        match result {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(
                    reason.contains("in use by live PID"),
                    "error must refuse live-pid collision: {reason}"
                );
            }
            other => panic!("expected Corrupt for live pid collision, got: {other:?}"),
        }
    }

    #[test]
    fn create_handle_dir_codex_tolerates_missing_sessions_and_history() {
        // codex-sessions/ and codex-history.jsonl may be absent on
        // first spawn — codex-cli creates them lazily. The function
        // must silently skip those symlinks rather than erroring.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let config = base.join("config-8");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join(".csq-account"), "8").unwrap();
        std::fs::write(config.join("config.toml"), "").unwrap();
        // Deliberately DO NOT create codex-sessions/ or codex-history.jsonl.

        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(
            creds_dir.join("codex-8.json"),
            r#"{"tokens":{"access_token":"at"}}"#,
        )
        .unwrap();

        let account = AccountNum::try_from(8u16).unwrap();
        let handle = create_handle_dir_codex(base, account, 88880).expect("should succeed");

        assert!(handle.exists());
        // Required symlinks present:
        assert!(handle.join("auth.json").symlink_metadata().is_ok());
        assert!(handle.join("config.toml").symlink_metadata().is_ok());
        assert!(handle.join(".csq-account").symlink_metadata().is_ok());
        // Optional symlinks absent (targets didn't exist):
        assert!(
            !handle.join("sessions").exists()
                && handle.join("sessions").symlink_metadata().is_err(),
            "sessions symlink must be skipped when target is absent"
        );
        assert!(
            !handle.join("history.jsonl").exists()
                && handle.join("history.jsonl").symlink_metadata().is_err(),
            "history.jsonl symlink must be skipped when target is absent"
        );
        // log/ is always created fresh.
        assert!(handle.join("log").is_dir());
    }

    // ── PR-C9a CRITICAL belt-and-suspenders: repoint refuses Codex-shape ──

    /// Regression guard: journal 0021 finding 1 belt-and-suspenders.
    ///
    /// `repoint_handle_dir` is the ClaudeCode repoint path. It touches
    /// `ACCOUNT_BOUND_ITEMS` (`.credentials.json`, `.csq-account`,
    /// `.current-account`, `.quota-cursor`) only — if called on a Codex
    /// handle dir it would rewrite those Anthropic-shape markers while
    /// leaving the real Codex symlinks (`auth.json`, `config.toml`,
    /// `sessions`, `history.jsonl` per spec 07 §7.2.2) pointing at the
    /// old `config-<N>`. The primary guard lives in
    /// `auto_rotate::find_target`, but this secondary refusal catches
    /// any caller that forgets the surface check.
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_refuses_codex_shape_handle_dir() {
        use crate::credentials::{CodexCredentialFile, CodexTokensFile, CredentialFile};
        use crate::types::AccountNum;

        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        let base = dir.path();

        // Codex slot 5 with canonical credentials + config.toml.
        let codex_account = AccountNum::try_from(5u16).unwrap();
        let codex_creds = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some("uuid-5".into()),
                access_token: "eyJaccess.codex-5.sig".into(),
                refresh_token: Some("rt_codex_5".into()),
                id_token: Some("eyJid.codex-5.sig".into()),
                extra: std::collections::HashMap::new(),
            },
            last_refresh: Some("2026-04-22T00:00:00Z".into()),
            extra: std::collections::HashMap::new(),
        });
        crate::credentials::save(&base.join("credentials").join("codex-5.json"), &codex_creds)
            .unwrap();
        let codex_config = base.join("config-5");
        std::fs::create_dir_all(&codex_config).unwrap();
        markers::write_csq_account(&codex_config, codex_account).unwrap();
        std::fs::write(
            codex_config.join("config.toml"),
            "cli_auth_credentials_store = \"file\"\nmodel = \"gpt-5.4\"\n",
        )
        .unwrap();

        // A plausible ClaudeCode target dir (doesn't matter whether it's
        // valid; the guard refuses before new_config is inspected).
        let target_config = base.join("config-1");
        std::fs::create_dir_all(&target_config).unwrap();
        let target_account = AccountNum::try_from(1u16).unwrap();
        markers::write_csq_account(&target_config, target_account).unwrap();

        // Create a Codex handle dir.
        let handle = create_handle_dir_codex(base, codex_account, 70001).unwrap();

        // Precondition: handle dir has Codex-shape symlinks.
        assert!(
            handle.join("auth.json").symlink_metadata().is_ok(),
            "test precondition: auth.json symlink exists"
        );
        assert!(
            handle.join("config.toml").symlink_metadata().is_ok(),
            "test precondition: config.toml symlink exists"
        );

        // Act: attempt to repoint to target slot 1.
        let result = repoint_handle_dir(base, claude_home.path(), &handle, target_account);

        // Assert: refused with a clear error.
        assert!(
            result.is_err(),
            "repoint_handle_dir MUST refuse a Codex-shape handle dir"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("Codex-unique")
                || err_msg.contains("auth.json")
                || err_msg.contains("config.toml"),
            "error must name the Codex-unique item that triggered the refusal: {err_msg}"
        );

        // Assert: Codex symlinks are intact (the guard refused without
        // touching anything).
        assert!(
            handle.join("auth.json").symlink_metadata().is_ok(),
            "auth.json symlink must survive the refused repoint"
        );
        assert!(
            handle.join("config.toml").symlink_metadata().is_ok(),
            "config.toml symlink must survive the refused repoint"
        );
    }

    // ── repoint_handle_dir_codex (M10 / journal 0023) ──────────────────

    /// Happy path: repointing a Codex handle dir from slot A → slot B
    /// rewrites every Codex symlink to the new slot atomically. Mirrors
    /// the spec 07 §7.2.2 symlink set: `.csq-account`, `auth.json`,
    /// `config.toml`, `sessions`, `history.jsonl`.
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_repoints_codex_symlinks() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Provision two Codex slots.
        setup_codex_slot(base, 4);
        setup_codex_slot(base, 9);

        // Create the handle dir bound to slot 4.
        let from = AccountNum::try_from(4u16).unwrap();
        let to = AccountNum::try_from(9u16).unwrap();
        let handle = create_handle_dir_codex(base, from, 70010).unwrap();

        // Precondition: handle dir is bound to slot 4.
        assert!(std::fs::read_link(handle.join("auth.json"))
            .unwrap()
            .ends_with("credentials/codex-4.json"));
        assert!(std::fs::read_link(handle.join("config.toml"))
            .unwrap()
            .ends_with("config-4/config.toml"));

        // Act: repoint to slot 9.
        repoint_handle_dir_codex(base, &handle, to).expect("repoint must succeed");

        // Assert: every Codex symlink now points at slot 9.
        assert!(std::fs::read_link(handle.join(".csq-account"))
            .unwrap()
            .ends_with("config-9/.csq-account"));
        assert!(std::fs::read_link(handle.join("auth.json"))
            .unwrap()
            .ends_with("credentials/codex-9.json"));
        assert!(std::fs::read_link(handle.join("config.toml"))
            .unwrap()
            .ends_with("config-9/config.toml"));
        assert!(std::fs::read_link(handle.join("sessions"))
            .unwrap()
            .ends_with("config-9/codex-sessions"));
        assert!(std::fs::read_link(handle.join("history.jsonl"))
            .unwrap()
            .ends_with("config-9/codex-history.jsonl"));

        // No exec-replace happened: the handle dir survives in-place.
        assert!(
            handle.exists(),
            "handle dir must remain after in-flight repoint"
        );
        // No tombstone was created (the cross-surface path's signature).
        let tombstone_count = std::fs::read_dir(base)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".sweep-tombstone-")
            })
            .count();
        assert_eq!(
            tombstone_count, 0,
            "same-surface Codex repoint MUST NOT create a sweep tombstone (M10)"
        );
    }

    /// Surface guard: a ClaudeCode-shape handle dir (no `auth.json`
    /// symlink) must be refused with a clear error. Symmetry with the
    /// existing `repoint_handle_dir_refuses_codex_shape_handle_dir`
    /// guard for the inverse direction.
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_refuses_non_codex_handle_dir() {
        let dir = TempDir::new().unwrap();
        let claude_home = TempDir::new().unwrap();
        let base = dir.path();

        // Provision a ClaudeCode slot and target Codex slot.
        setup_config_dir(base, 1);
        setup_codex_slot(base, 2);

        // Create a ClaudeCode handle dir.
        let cc_account = AccountNum::try_from(1u16).unwrap();
        let codex_account = AccountNum::try_from(2u16).unwrap();
        let handle = create_handle_dir(base, claude_home.path(), cc_account, 70011).unwrap();

        // Precondition: handle dir has NO auth.json (ClaudeCode shape).
        assert!(handle.join("auth.json").symlink_metadata().is_err());

        // Act: attempt Codex repoint on ClaudeCode handle dir.
        let result = repoint_handle_dir_codex(base, &handle, codex_account);

        // Assert: refused with a clear error naming the missing marker.
        match result {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(
                    reason.contains("auth.json") || reason.contains("Codex-shaped"),
                    "error must name the missing Codex marker: {reason}"
                );
            }
            other => panic!("expected Corrupt for non-Codex handle dir, got: {other:?}"),
        }
    }

    /// Refuses non-`term-<pid>` source paths (legacy `config-N` or
    /// arbitrary dirs). Codex never had a pre-handle-dir layout, so a
    /// non-`term-` source is always a misuse.
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_refuses_non_handle_dir_source() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_codex_slot(base, 5);

        // A `config-N` directory is not a handle dir.
        let bogus = base.join("config-5");
        let target = AccountNum::try_from(5u16).unwrap();

        let result = repoint_handle_dir_codex(base, &bogus, target);
        match result {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(
                    reason.contains("term-"),
                    "error must mention the required term-<pid> shape: {reason}"
                );
            }
            other => panic!("expected Corrupt for non-handle source, got: {other:?}"),
        }
    }

    /// Refuses repointing when the canonical credential file for the
    /// target slot is missing (login has not completed). Without the
    /// canonical file, `auth.json` would symlink to a dangling path
    /// and codex-cli would fail on the next API call.
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_refuses_when_canonical_credential_missing() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Source slot 6 fully provisioned.
        setup_codex_slot(base, 6);
        // Target slot 7: provision config-7 + .csq-account but DELETE the
        // canonical credential file.
        setup_codex_slot(base, 7);
        std::fs::remove_file(base.join("credentials").join("codex-7.json")).unwrap();

        let from = AccountNum::try_from(6u16).unwrap();
        let to = AccountNum::try_from(7u16).unwrap();
        let handle = create_handle_dir_codex(base, from, 70012).unwrap();

        let result = repoint_handle_dir_codex(base, &handle, to);
        match result {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(
                    reason.contains("codex-7.json"),
                    "error must name the missing canonical credential file: {reason}"
                );
            }
            other => panic!("expected Corrupt for missing canonical, got: {other:?}"),
        }

        // Source symlinks must be untouched (refusal happens pre-flight).
        assert!(std::fs::read_link(handle.join("auth.json"))
            .unwrap()
            .ends_with("credentials/codex-6.json"));
    }

    /// Refuses repointing when the target slot is missing the
    /// `.csq-account` marker. Without it the daemon's auto-rotate /
    /// sweep loops cannot identify the account post-swap. Mirrors the
    /// VP-final F3 guard on the ClaudeCode path.
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_refuses_when_target_missing_csq_account() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        setup_codex_slot(base, 11);
        setup_codex_slot(base, 12);
        // Strip .csq-account from target slot 12.
        std::fs::remove_file(base.join("config-12").join(".csq-account")).unwrap();

        let from = AccountNum::try_from(11u16).unwrap();
        let to = AccountNum::try_from(12u16).unwrap();
        let handle = create_handle_dir_codex(base, from, 70013).unwrap();

        let result = repoint_handle_dir_codex(base, &handle, to);
        match result {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(
                    reason.contains(".csq-account"),
                    "error must name the missing marker: {reason}"
                );
            }
            other => panic!("expected Corrupt for missing marker, got: {other:?}"),
        }
    }

    // ── PR-C9b round 2 fixes ──────────────────────────────────────────

    /// M-CDX-1 regression: the credential symlink (`auth.json`) MUST be
    /// rewritten BEFORE the marker (`.csq-account`) inside the rename
    /// loop. Otherwise a mid-loop I/O failure could flip the marker to
    /// the new slot while `auth.json` still resolved to the old slot's
    /// tokens — silent quota-attribution drift in the daemon plus a
    /// trip on the F3 mismatch guard at the next swap. This test pins
    /// the static `codex_links` slice ordering by introspecting the
    /// post-repoint mtime relationship — the file with the LATER mtime
    /// was written last, so we assert `.csq-account` mtime ≥ `auth.json`
    /// mtime (NEVER the inverse).
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_writes_credential_before_marker() {
        use std::os::unix::fs::MetadataExt;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_codex_slot(base, 21);
        setup_codex_slot(base, 22);

        let from = AccountNum::try_from(21u16).unwrap();
        let to = AccountNum::try_from(22u16).unwrap();
        let handle = create_handle_dir_codex(base, from, 70021).unwrap();

        // Sleep enough to make sub-nanosecond mtime ordering observable
        // even on filesystems with coarse mtime resolution (e.g. HFS+
        // 1s; APFS 1ns; ext4 1ns; some tempfs 1us).
        std::thread::sleep(std::time::Duration::from_millis(20));
        repoint_handle_dir_codex(base, &handle, to).unwrap();

        let auth_meta = std::fs::symlink_metadata(handle.join("auth.json")).unwrap();
        let marker_meta = std::fs::symlink_metadata(handle.join(".csq-account")).unwrap();

        // Ordering invariant: marker is written AT OR AFTER credential.
        // Use ctime (inode-change time, reflects the rename) for the
        // strictest check; mtime is the symlink's own mtime which
        // matches ctime under rename-replace semantics.
        let auth_ctime = (auth_meta.ctime(), auth_meta.ctime_nsec());
        let marker_ctime = (marker_meta.ctime(), marker_meta.ctime_nsec());
        assert!(
            marker_ctime >= auth_ctime,
            "M-CDX-1: .csq-account ctime ({:?}) must be >= auth.json ctime ({:?}) — \
             credential must be written before marker so a mid-loop failure cannot \
             leave the marker pointing at a slot whose credential is still the old one",
            marker_ctime,
            auth_ctime,
        );
    }

    /// L-CDX-1 regression: the surface guard MUST refuse a handle dir
    /// where `auth.json` is a regular file (not a symlink). The pre-fix
    /// guard accepted any `symlink_metadata().is_ok()` entry, which
    /// would let a planted file slip past and trigger the rename loop
    /// to overwrite attacker-controlled state.
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_refuses_when_auth_json_is_regular_file() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_codex_slot(base, 31);
        setup_codex_slot(base, 32);

        // Build a handle dir manually with `auth.json` as a regular file
        // and `config.toml` as a regular file too — both Codex-unique
        // markers present but neither is a symlink.
        let handle = base.join("term-70031");
        std::fs::create_dir(&handle).unwrap();
        std::fs::write(handle.join("auth.json"), b"planted, not a symlink").unwrap();
        std::fs::write(handle.join("config.toml"), b"planted, not a symlink").unwrap();

        let to = AccountNum::try_from(32u16).unwrap();
        let result = repoint_handle_dir_codex(base, &handle, to);

        match result {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(
                    reason.contains("not a symlink") || reason.contains("Codex-shaped"),
                    "L-CDX-1: error must name the non-symlink marker: {reason}"
                );
            }
            other => panic!("expected Corrupt for regular-file marker, got: {other:?}"),
        }

        // Planted files MUST still exist — guard refused before any rename.
        assert_eq!(
            std::fs::read(handle.join("auth.json")).unwrap(),
            b"planted, not a symlink",
            "guard must refuse before touching the planted file"
        );
    }

    /// L-CDX-1 regression: the dual-marker check requires BOTH
    /// `auth.json` AND `config.toml`. A handle dir with only `auth.json`
    /// (corrupted partial-create) MUST be refused.
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_refuses_when_config_toml_symlink_missing() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        setup_codex_slot(base, 41);
        setup_codex_slot(base, 42);

        let from = AccountNum::try_from(41u16).unwrap();
        let to = AccountNum::try_from(42u16).unwrap();
        let handle = create_handle_dir_codex(base, from, 70041).unwrap();

        // Strip the `config.toml` symlink to simulate a corrupted handle dir.
        std::fs::remove_file(handle.join("config.toml")).unwrap();

        let result = repoint_handle_dir_codex(base, &handle, to);
        match result {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(
                    reason.contains("config.toml"),
                    "L-CDX-1: error must name the missing config.toml: {reason}"
                );
            }
            other => panic!("expected Corrupt for missing config.toml, got: {other:?}"),
        }
    }
}
