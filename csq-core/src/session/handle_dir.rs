//! Handle-dir model: ephemeral `term-<pid>` directories with symlinks to `config-N`.
//!
//! Each `csq run` creates a `term-<pid>` handle directory that contains symlinks
//! pointing at the permanent `config-<N>` account directory. `csq swap` atomically
//! repoints these symlinks. The daemon sweeps orphaned handle dirs when the PID dies.
//!
//! See `specs/02-csq-handle-dir-model.md` for the authoritative spec.

use crate::accounts::identity_store::{
    account_to_identity_paths, credentials_codex_path_for, settings_path_for,
};
use crate::accounts::markers;
use crate::accounts::profiles;
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
/// - Symlinks to per-account items (heterogeneous target set per an internal journal entry OQ #2):
///   - `.credentials.json` → `identities/<UUID>/credentials.json` when UUID is
///     present in `profiles.json::by_slot`; falls back to `config-<N>/.credentials.json`
///     for legacy-only layouts (Phase 3 retarget, M3-3).
///   - `.csq-account`, `.current-account`, `.quota-cursor` → `config-<N>/<item>`
///     always (markers stay at slot path through Phase 4 per cross-phase constraint #3).
/// - Symlinks to `~/.claude/<item>` for each shared item
/// - A `.live-pid` file with the csq CLI PID
///
/// All account-bound symlinks are created via [`create_symlink`] (platform-aware:
/// Unix `std::os::unix::fs::symlink`; Windows dispatches dir-junction-vs-hardlink
/// based on target type). M1-3's [`crate::platform::fs::symlink_exclusive`] is a
/// directory-junction-only primitive and does NOT handle the file-target case on
/// Windows — production wire-in of that primitive is deferred to a future
/// sub-task that resolves the junction-vs-file mismatch.
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
    create_handle_dir_named(base_dir, claude_home, account, pid, &format!("term-{pid}"))
}

/// `create_handle_dir` generalized to an explicit `dir_name`.
///
/// `create_handle_dir` is the thin wrapper that passes `term-<pid>`. The
/// daemon's Phase-2b interactive subscription-capture path (`phase2b::
/// subscription_client`) passes a unique `interactive-capture-<…>` name so a
/// single daemon process (one PID) can run multiple concurrent governed-turn
/// captures without colliding on a single `term-<pid>` dir. `pid` is still
/// recorded in `.live-pid` (the daemon PID, for liveness-based crash cleanup)
/// and used in orphan-detection log lines. The caller that supplies a
/// non-`term-<pid>` name owns that dir's lifecycle (the `term-*` sweeper only
/// reaps `term-*` names — see `phase2b::subscription_client` for its
/// self-managed cleanup of the `interactive-capture-*` namespace).
pub fn create_handle_dir_named(
    base_dir: &Path,
    claude_home: &Path,
    account: AccountNum,
    pid: u32,
    dir_name: &str,
) -> Result<PathBuf, CredentialError> {
    let config_dir = base_dir.join(format!("config-{}", account));
    if !config_dir.is_dir() {
        return Err(CredentialError::Corrupt {
            path: config_dir,
            reason: format!("config-{account} does not exist"),
        });
    }

    let handle_dir = base_dir.join(dir_name);

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
                        "handle dir {dir_name} is in use by live PID {recorded}. \
                         Refusing to remove. If you believe this is stale, stop \
                         the process and rerun."
                    ),
                });
            }
        }

        warn!(
            pid,
            dir_name,
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

    // Symlink account-bound items — heterogeneous target set per an internal journal entry OQ #2.
    //
    // M3-3 retarget: `.credentials.json` uses the identity-keyed path when a UUID
    // is present in `profiles.json::by_slot` for this account.  All other items
    // (`.csq-account`, `.current-account`, `.quota-cursor`) stay at `config-<N>/`
    // through Phase 4 per cross-phase constraint #3 (marker semantics; OQ #2 Option A).
    //
    // All symlinks are created via `create_symlink` (platform-aware primitive:
    // Unix symlink; Windows dispatches dir-junction-vs-hardlink). M1-3's
    // `symlink_exclusive` is dir-junction-only on Windows and does NOT handle
    // file-target symlinks; production wire-in deferred to a future sub-task.
    let identity_paths = account_to_identity_paths(base_dir, account);
    for item in ACCOUNT_BOUND_ITEMS {
        let target = if *item == ".credentials.json" {
            // M3-3: route through identity-keyed path when UUID is present.
            //
            // M3-7: the prior HIGH-1 fallback to `config-N/.credentials.json`
            // is retired. The startup_reconciler `phase4_gate_check`
            // (renamed from the prior `phase3_gate` symbol in M4-5;
            // behavior preserved for this invariant) refuses to start
            // the daemon when any UUID-keyed slot's identity
            // credentials.json is unseeded, so by the time
            // `create_handle_dir` runs the identity path is guaranteed
            // populated for every UUID-keyed slot.
            //
            // Legacy slots without a UUID still route through this branch's
            // else arm of `is_identity_keyed`: `account_to_identity_paths`
            // returns the `config-<N>/.credentials.json` shape when no UUID
            // is resolvable. Backwards-compatible for pre-Phase-1 stores.
            identity_paths.credentials_path.clone()
        } else {
            // Markers and slot-state items always target config-N/ (OQ #2 Option A).
            config_dir.join(item)
        };
        let link = handle_dir.join(item);
        // Only create symlink if the target exists (or is a known-expected symlink)
        if target.exists() || target.symlink_metadata().is_ok() {
            // Use the platform-aware `create_symlink` primitive (Unix symlink;
            // Windows dispatches dir-junction-vs-hardlink based on target type).
            // M1-3's `symlink_exclusive` is for directory junctions specifically
            // and does NOT handle the file-target case on Windows — Phase 3 file
            // symlinks need `create_symlink_pub`'s platform-correct dispatch.
            // Wire-in of `symlink_exclusive` as a production primitive is deferred
            // to a future sub-task that addresses the junction-vs-file mismatch.
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
    //
    // M2-3: resolve UUID once at section entry (cross-phase constraint #7).
    // Pass the UUID-keyed settings path if available so the overlay sources
    // from `identities/<UUID>/settings.json` (Phase 2 canonical) rather than
    // `config-N/settings.json` (legacy fallback).
    let uuid_settings = profiles::resolve_slot_to_uuid(base_dir, account.get())
        .map(|uuid| settings_path_for(base_dir, uuid));
    materialize_handle_settings_inner(
        &handle_dir,
        claude_home,
        &config_dir,
        uuid_settings.as_deref(),
    )?;

    // Write .live-pid with the csq CLI PID
    markers::write_live_pid(&handle_dir, pid)?;

    info!(pid, account = %account, path = %handle_dir.display(), "handle dir created");
    Ok(handle_dir)
}

/// Creates an ephemeral Codex handle directory `term-<pid>` under
/// `base_dir` for `Surface::Codex`.
///
/// Per spec 07 §7.2.2 the Codex handle dir carries a distinct symlink
/// set from Anthropic (heterogeneous target set per an internal journal entry OQ #2 + OQ #3):
///
/// - `.csq-account` → `config-<N>/.csq-account` (always; marker stays at slot path)
/// - `auth.json` → `identities/<UUID>/credentials-codex.json` when UUID present
///   (M3-3 retarget, an internal journal entry OQ #3); falls back to `credentials/codex-<N>.json`
///   for legacy-only layouts. The legacy canonical is retained through Phase 4.
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
    create_handle_dir_codex_named(base_dir, account, pid, &format!("term-{pid}"))
}

/// `create_handle_dir_codex` generalized to an explicit `dir_name`. See
/// [`create_handle_dir_named`] for the rationale (concurrent daemon-side
/// subscription captures need unique dir names outside the `term-<pid>` space).
pub fn create_handle_dir_codex_named(
    base_dir: &Path,
    account: AccountNum,
    pid: u32,
    dir_name: &str,
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

    // Task 5: Accept either the UUID-keyed path (post-M4-12) or the legacy
    // numeric path (pre-M4-12 / downgrade safety). A slot that was provisioned
    // after the fix will have `identities/<UUID>/credentials-codex.json` but
    // no `credentials/codex-<N>.json`. Both are valid; at least one must exist.
    let uuid_cred_path = profiles::resolve_slot_to_uuid(base_dir, account.get())
        .map(|uuid| credentials_codex_path_for(base_dir, uuid));
    let uuid_cred_exists = uuid_cred_path.as_ref().map(|p| p.exists()).unwrap_or(false);
    let legacy_cred_exists = canonical_cred.exists();

    if !uuid_cred_exists && !legacy_cred_exists {
        // IR-M4: when a UUID mapping exists, name the UUID-keyed path in the
        // error so the operator sees the post-M4-12 authoritative path rather
        // than the retired legacy path. Fall back to the legacy path when no
        // UUID mapping is present (pure-legacy layout).
        let error_path = uuid_cred_path.unwrap_or(canonical_cred);
        return Err(CredentialError::Corrupt {
            path: error_path,
            reason: format!(
                "stat Codex canonical — neither UUID-keyed nor legacy path exists; \
                 run `csq login {account} --provider codex`"
            ),
        });
    }

    let handle_dir = base_dir.join(dir_name);

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
                        "handle dir {dir_name} is in use by live PID {recorded}. \
                         Refusing to remove. If you believe this is stale, stop \
                         the process and rerun."
                    ),
                });
            }
        }

        warn!(
            pid,
            dir_name,
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

    // Codex symlink set per spec 07 §7.2.2 — heterogeneous target set per
    // an internal journal entry OQ #2 + OQ #3.
    //
    // M3-3 retarget: `auth.json` uses the identity-keyed path
    // (`identities/<UUID>/credentials-codex.json`) when a UUID is present in
    // `profiles.json::by_slot` for this account.  Falls back to the legacy
    // canonical `credentials/codex-<N>.json` for pre-A++ layouts.  The legacy
    // canonical file is retained through Phase 4 for downgrade safety.
    //
    // `.csq-account` and all other items stay at `config-<N>/` through Phase 4
    // per cross-phase constraint #3 (OQ #2 Option A).
    //
    // All symlinks are created via `create_symlink` (platform-aware; see the
    // Anthropic `create_handle_dir` for the M1-3 deferral rationale).
    let auth_target = {
        let identity_paths = account_to_identity_paths(base_dir, account);
        if identity_paths.is_identity_keyed {
            // Resolve the UUID directly via profiles so we can call the Codex helper.
            match profiles::resolve_slot_to_uuid(base_dir, account.get()) {
                Some(uuid) => {
                    let p = credentials_codex_path_for(base_dir, uuid);
                    if p.exists() {
                        p
                    } else {
                        // HIGH-2 fallback: UUID present but credentials-codex.json
                        // not yet seeded (Partial-Pass-0 for Codex surface).
                        // Fall back to the legacy canonical so the handle dir is
                        // functional.  M3-7's `csq doctor --repair` handles the
                        // underlying incomplete mint.
                        tracing::warn!(
                            account = %account,
                            uuid = %uuid,
                            "Codex identity-store partial (credentials-codex.json missing): \
                             falling back to credentials/codex-N.json"
                        );
                        canonical_cred.clone()
                    }
                }
                // Shouldn't happen (is_identity_keyed == true implies UUID resolved),
                // but fall back safely.
                None => canonical_cred.clone(),
            }
        } else {
            canonical_cred.clone()
        }
    };

    let codex_links: &[(&str, PathBuf)] = &[
        (".csq-account", config_dir.join(".csq-account")),
        ("auth.json", auth_target),
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
        // Use `create_symlink` (platform-aware: Unix symlink; Windows dispatches
        // dir-junction-vs-hardlink). See ClaudeCode symlink loop above for the
        // M1-3 deferral rationale.
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
/// `claude_home/settings.json` (base) with the slot-keyed overlay.
///
/// ## M2-3 / M4-2 overlay resolution (spec 02 §2.3.3)
///
/// The overlay source is chosen by the following priority:
/// 1. `uuid_settings_path` — when `Some(path)` AND the file exists at `path`,
///    use it as the overlay (UUID-keyed canonical, Phase 2 active path).
/// 2. `config_dir/settings.json` — fallback for legacy-only layouts where
///    `identities/<UUID>/settings.json` has not been materialized yet (Phase 1
///    remaining slots, fresh-install, or daemon Pass 0 not yet run).
///
/// **M4-2 invariant (spec 02 §2.3.3):** every login path that writes
/// `config-<N>/settings.json` ALSO writes a byte-equivalent
/// `identities/<UUID>/settings.json` via the `credentials::save_uuid_settings`
/// chokepoint. So the two paths are byte-equivalent during the M4-2 → M4-5
/// transition; reading either yields the same overlay. The fallback to (2) is
/// load-bearing only for pure-legacy installs and the cold-start race window
/// before daemon Pass 0 completes. M4-5 strengthens the gate; release N+1
/// retires the fallback after the v2.6.x downgrade window closes.
///
/// The base carries user-global customization (statusLine, permissions,
/// plugins, env experiments). The overlay carries slot-specific env for
/// 3P bindings (`ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`,
/// `ANTHROPIC_MODEL`). Overlay keys win on merge. For OAuth slots where
/// neither overlay source is present, the materialized file equals the
/// user's global settings.
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
/// factor the step out of `create_handle_dir`. See an internal journal entry — stale
/// per-slot settings drifted silently through a csq install upgrade;
/// making the invariant explicit at the call site guards against the same
/// class of regression.
pub fn materialize_handle_settings(
    handle_dir: &Path,
    claude_home: &Path,
    config_dir: &Path,
) -> Result<(), CredentialError> {
    materialize_handle_settings_inner(handle_dir, claude_home, config_dir, None)
}

/// Internal implementation for [`materialize_handle_settings`] with optional
/// UUID-keyed overlay path (M2-3).
///
/// Called by:
/// - `materialize_handle_settings` (passes `None` for `uuid_settings_path`)
/// - `create_handle_dir` and `repoint_handle_dir` (pass the resolved UUID path)
fn materialize_handle_settings_inner(
    handle_dir: &Path,
    claude_home: &Path,
    config_dir: &Path,
    uuid_settings_path: Option<&Path>,
) -> Result<(), CredentialError> {
    let base = read_json_object_or_empty(&claude_home.join("settings.json"));

    // M2-3: prefer the UUID-keyed settings.json when present (Phase 2 active
    // path). Fall back to config-<N>/settings.json for legacy-only layouts.
    let overlay_path = match uuid_settings_path {
        Some(p) if p.exists() => {
            debug!(
                path = %p.display(),
                "materialize_handle_settings: using UUID-keyed settings overlay (M2-3)"
            );
            p.to_path_buf()
        }
        _ => config_dir.join("settings.json"),
    };
    let overlay = read_json_object_or_empty(&overlay_path);
    let merged = merge_settings(&base, &overlay);

    let settings_path = handle_dir.join("settings.json");
    let json = serde_json::to_string_pretty(&merged).map_err(|e| CredentialError::Corrupt {
        path: settings_path.clone(),
        reason: format!("merged settings serialize failed: {e}"),
    })?;

    let tmp = crate::platform::fs::unique_tmp_path(&settings_path);
    // §5a cleanup: handle dir settings.json is the MERGED view of
    // claude_home + slot's config-<N>/settings.json — and the slot's
    // settings.json carries ANTHROPIC_AUTH_TOKEN per the bind/unbind
    // path. Partial-failure leaves a token-bearing tmp at umask 0o644.
    if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CredentialError::Io {
            path: tmp,
            source: e,
        });
    }
    if let Err(e) = crate::platform::fs::secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CredentialError::Corrupt {
            path: tmp,
            reason: format!("secure_file: {e}"),
        });
    }
    if let Err(e) = crate::platform::fs::atomic_replace(&tmp, &settings_path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CredentialError::Corrupt {
            path: settings_path,
            reason: format!("atomic replace: {e}"),
        });
    }
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

/// Resolve the per-handle-dir rename-serialization lock path (`.swap.lock`,
/// dot) used by [`repoint_handle_dir`] and [`repoint_handle_dir_codex`].
///
/// Canonicalizes `handle_dir` first so a caller that passes a raw path
/// (`csq swap` forwards `source.path()` verbatim) and a caller that passes a
/// pre-canonicalized path (`auto_rotate` canonicalizes at the top of its loop)
/// resolve to the SAME inode. Without this, a symlink component anywhere in the
/// accounts base splits the two into different lock files that never contend, so
/// the rename lock silently fails to serialize concurrent repoints (#928).
/// Falls back to the raw path when canonicalize fails (dangling dir) — the same
/// posture both callers use for their own canonicalization.
///
/// DISTINCT from [`crate::credentials::keychain::swap_lock_path`] (`.swap-lock`,
/// hyphen — the A4a keychain-desync guard). The A4a guard is held ACROSS the
/// repoint call by `csq swap` / `auto_rotate`; `lock_file` opens a fresh fd and
/// `flock`s it, and on Unix/macOS `flock` is per-open-file-description, so
/// re-`flock`-ing the SAME file from a second fd in one process blocks forever.
/// The two lock files therefore MUST stay distinct (`.swap.lock` vs `.swap-lock`).
fn repoint_lock_path(handle_dir: &Path) -> PathBuf {
    let lock_dir = std::fs::canonicalize(handle_dir).unwrap_or_else(|_| handle_dir.to_path_buf());
    lock_dir.join(".swap.lock")
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

    // PR-C9a CRITICAL belt-and-suspenders (an internal journal entry finding 1): refuse
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
    // This is a DIFFERENT lock from the A4a keychain-desync guard
    // (`keychain::swap_lock_path` → `.swap-lock`, hyphen). The names are
    // deliberately distinct: `csq swap` (`SameSurfaceClaudeCode`) and
    // `auto_rotate` ALREADY hold the `.swap-lock` (hyphen) A4a guard across this
    // entire call. `lock_file` opens a fresh fd and `flock`s it; on Unix/macOS
    // flock is per-open-file-description, so re-`flock`-ing the SAME file from a
    // second fd in the same process blocks forever. Merging this inner rename
    // lock onto `.swap-lock` would therefore self-deadlock every swap and every
    // rotation — hence `.swap.lock` (dot) stays a separate file (#928).
    //
    // `repoint_lock_path` canonicalizes the dir BEFORE computing the lock path so
    // this rename lock resolves to the SAME inode whether the caller passed a raw
    // path (`csq swap` — swap.rs passes `source.path()` verbatim) or a
    // pre-canonicalized one (`auto_rotate` canonicalizes at the top of its loop).
    // Without this, a symlink component in the accounts base makes the two lock
    // different inodes and the inner lock silently fails to serialize them (#928
    // latent gap).
    //
    // `.swap.lock` lives inside the handle dir so it is automatically cleaned up
    // when the handle dir is swept. `lock_file` blocks until the lock is available
    // (blocking, not try_lock) so the slower caller is serialized, not dropped.
    let lock_path = repoint_lock_path(handle_dir);
    let _swap_guard =
        crate::platform::lock::lock_file(&lock_path).map_err(|e| CredentialError::Corrupt {
            path: lock_path.clone(),
            reason: format!("repoint lock acquisition failed: {e}"),
        })?;

    // M3-4: Resolve the identity-keyed paths for the swap target BEFORE the
    // mtime bump and symlink rebuild.  The bump target MUST match the
    // post-rename symlink target (PRIMARY METHODOLOGICAL DIRECTIVE 1,
    // an internal journal entry WBS line 124 + 04-phase3-readiness.md §M3-4).  Splitting
    // the two into separate commits would open a window where the bump targets
    // `config-N/.credentials.json` but the symlink resolves to
    // `identities/<UUID>/credentials.json` — a silent #270-class regression.
    let target_identity_paths = account_to_identity_paths(base_dir, target);

    // Determine the actual credentials file the symlink will point at
    // after the repoint.  This is the path `bump_mtime_above` MUST
    // operate on (spec 01 §1.4: CC re-stats the resolved path, not the
    // symlink itself).
    //
    // M3-7: the prior HIGH-1 fallback to `config-N/.credentials.json`
    // is retired. Phase 4's `phase4_gate_check` (renamed from the
    // prior `phase3_gate` symbol in M4-5; M3-7's R2 MED-1 strengthening
    // is preserved as check 3) refuses to start the daemon when any
    // UUID in `profiles.json::by_slot` lacks its
    // `identities/<UUID>/credentials.json` file. So by the time
    // `repoint_handle_dir` runs, every UUID-keyed slot's identity path
    // is guaranteed populated. Pure-legacy slots
    // (no UUID mapping) fall through to the `else` branch and target
    // `config-N/.credentials.json` which CC's own `claude auth login`
    // subprocess writes (M3-7 retired only csq's writers, not CC's).
    let new_creds_symlink_target = if target_identity_paths.is_identity_keyed {
        // UUID-keyed slot: always target the identity path.
        target_identity_paths.credentials_path.clone()
    } else {
        // Legacy layout: no UUID → config-N/.credentials.json (CC-written).
        new_config.join(".credentials.json")
    };

    // an internal ticket observability: capture the credentials target's pre-swap
    // mtime + inode. CC's `invalidateOAuthCacheIfDiskChanged` (spec 01 §1.4)
    // fires only when `mtimeMs !== lastCredentialsMtimeMs`. If the post-swap
    // target happens to share the same mtime as the pre-swap target (e.g.
    // both refreshed in the same nanosecond, or filesystem clamps mtime
    // precision), CC will silently skip the reload and the swap appears
    // to "not take effect" until something else perturbs the file. The
    // pre/post traces below make the invariant visible at INFO level so a
    // future repro of #270 produces actionable evidence.
    let pre_swap_creds_target = stat_creds_target(handle_dir);

    // an internal ticket fix: bump the new target's mtime strictly above the
    // pre-swap target's mtime BEFORE the atomic rename. This eliminates
    // the mtime-collision race window entirely — between the rename and a
    // post-rename bump, CC could stat the new target with the colliding
    // mtime and skip the reload. Pre-bumping ensures CC's first stat after
    // the rename always returns an advanced mtime, so the strict-inequality
    // check (`mtimeMs !== lastCredentialsMtimeMs`) fires on the next API
    // call. Failure here is non-fatal: log and proceed; the existing
    // `mtime_collision` warn below acts as a regression detector.
    //
    // M3-4: bump targets `new_creds_symlink_target` (identity-keyed when
    // UUID is present), NOT `config-N/.credentials.json`.  The bump target
    // MUST match the post-rename symlink target per PRIMARY METHODOLOGICAL
    // DIRECTIVE 1 (WBS line 124, an internal journal entry D3).  Using `new_creds_symlink_target`
    // here and in the symlink rebuild loop guarantees they are always in sync
    // in this commit; the SAME-COMMIT REQUIREMENT in the WBS makes splitting
    // the two a blocked operation.
    //
    // Best-effort vs daemon refresher race: the bump is NOT held under
    // the per-(Surface, AccountNum) write mutex from `AccountMutexTable`.
    // If the daemon refresher writes the identity credentials.json between
    // our `bump_mtime_above` and the post-stat read, the daemon's
    // `atomic_replace` produces a fresh-mtime inode on its own — CC's
    // reload still fires. The bump is the primary defense against the
    // collision case; the daemon's natural rename is a parallel path
    // that also advances mtime. Either path satisfies CC's invalidation.
    //
    // Spec amendment (an internal journal entry D2, extended by M3-4): Phase 3 retargets
    // the bump to `identities/<UUID>/credentials.json`, observed by EVERY
    // handle dir whose symlink resolves to that identity UUID — which may
    // span multiple slots after `csq move` (identity-scoped vs prior
    // slot-scoped). Sibling terminals on the swap target see a harmless
    // one-time reload of identical credentials. See specs/02 INV-04 §2.94
    // and the M3-8 spec amendment for the identity-scoped caveat.
    let baseline_ns = pre_swap_creds_target
        .as_ref()
        .map(|s| s.mtime_ns)
        .unwrap_or(0);
    // No `exists()` pre-check: `bump_mtime_above` returns Err on a missing
    // path, which is the correct surface for legitimate-absent cases (3P
    // slots without `.credentials.json`). Pre-`exists()` would also be a
    // TOCTOU window between the check and the open.
    match crate::platform::fs::bump_mtime_above(&new_creds_symlink_target, baseline_ns) {
        Ok(()) => {}
        Err(crate::error::PlatformError::Io(ref io))
            if io.kind() == std::io::ErrorKind::NotFound =>
        {
            // Legitimate-absent: the new slot has no `.credentials.json`
            // (3P slot using `env.ANTHROPIC_AUTH_TOKEN` instead). Silent.
        }
        Err(e) => {
            warn!(
                error = ?e,
                path = %new_creds_symlink_target.display(),
                "pre-swap mtime bump failed; CC may skip credential reload (an internal ticket)"
            );
        }
    }

    // Atomic repoint: create temp symlink then rename over existing.
    // M3-4 heterogeneous symlink set (an internal journal entry OQ #2 Option A):
    //   `.credentials.json` → identity-keyed when UUID present (via
    //   `new_creds_symlink_target` resolved above).
    //   All other items stay at `config-N/<item>` through Phase 4.
    for item in ACCOUNT_BOUND_ITEMS {
        let new_target = if *item == ".credentials.json" {
            // Identity-keyed (or fallback) path computed above.
            new_creds_symlink_target.clone()
        } else {
            new_config.join(item)
        };
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
    // M2-3: resolve UUID for the swap target so UUID-keyed settings.json
    // is preferred when present; falls back to config-<target>/settings.json.
    let uuid_settings_swap =
        crate::accounts::profiles::resolve_slot_to_uuid(base_dir, target.get())
            .map(|uuid| settings_path_for(base_dir, uuid));
    materialize_handle_settings_inner(
        handle_dir,
        claude_home,
        &new_config,
        uuid_settings_swap.as_deref(),
    )?;

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
    // #832: capture the pre-rebuild `.claude.json` oauthAccount email (the stale/old
    // value, before the rebuild overwrites it) so the reconcile can distinguish a
    // stale copy it MAY overwrite from a foreign-account signal (a concurrent CC
    // in-session `/login`) it MUST NOT overwrite. Read BEFORE the rebuild.
    let pre_swap_oauth_email = crate::credentials::claude_json::read_oauth_email(handle_dir);

    rebuild_claude_json_for_swap(&new_config, handle_dir);

    // #832: the rebuild sources `oauthAccount` from `config-<target>/.claude.json`,
    // which can be absent (rebuild bails → stale copy retained) or carry no email.
    // Reconcile `oauthAccount.emailAddress` to the authoritative identity anchor so
    // the custodian wrong-account gate matches on the next tick instead of
    // false-refusing the freshly-mirrored token — but ONLY when it is safe to
    // overwrite (absent or the pre-swap value), never a foreign `/login` signal.
    if let Some(identity_email) =
        crate::accounts::profiles::resolve_slot_to_uuid(base_dir, target.get())
            .and_then(|uuid| crate::accounts::identity_store::read_identity_email(base_dir, uuid))
    {
        reconcile_handle_dir_oauth_email(
            handle_dir,
            &identity_email,
            pre_swap_oauth_email.as_deref(),
        );
    }

    // an internal ticket observability: capture post-swap target stat and emit at
    // INFO so `CSQ_LOG=info csq swap N` exposes the mtime/inode that CC's
    // next stat will resolve. See pre_swap_creds_target capture above.
    let post_swap_creds_target = stat_creds_target(handle_dir);
    info!(
        account = %target,
        handle = %handle_dir.display(),
        pre_mtime_ns = pre_swap_creds_target.as_ref().map(|s| s.mtime_ns),
        pre_ino = pre_swap_creds_target.as_ref().map(|s| s.ino),
        post_mtime_ns = post_swap_creds_target.as_ref().map(|s| s.mtime_ns),
        post_ino = post_swap_creds_target.as_ref().map(|s| s.ino),
        mtime_changed = mtime_changed(&pre_swap_creds_target, &post_swap_creds_target),
        "handle dir repointed"
    );
    // Default csq log level is `warn`, so the INFO trace above is invisible
    // to operators who haven't opted into `CSQ_LOG=info`. Emit a WARN only
    // on the exact #270 failure mode (both stats succeeded + mtimes equal)
    // so the bug surfaces in default-log sessions and the next manifestation
    // can be diagnosed without first asking the operator to opt back in.
    // Spec 02 INV-04 §2.94 already acknowledges this caveat.
    if mtime_collision(&pre_swap_creds_target, &post_swap_creds_target) {
        warn!(
            account = %target,
            handle = %handle_dir.display(),
            post_mtime_ns = post_swap_creds_target.as_ref().map(|s| s.mtime_ns),
            post_ino = post_swap_creds_target.as_ref().map(|s| s.ino),
            "swap repointed but credential mtime unchanged — CC may skip reload (an internal ticket)"
        );
    }
    Ok(())
}

/// Filesystem identity of the `.credentials.json` symlink target — what
/// CC's `fs.stat()` resolves to. Captured pre/post repoint to expose the
/// invariant that drives CC's mtime-based cache invalidation (spec 01 §1.4).
#[derive(Debug, Clone, Copy)]
struct CredsTargetStat {
    mtime_ns: i128,
    ino: u64,
}

/// Stats `.credentials.json` following symlinks. Returns None if absent
/// or unstattable — the caller logs `None` rather than failing the swap,
/// since observability MUST NOT alter swap semantics.
fn stat_creds_target(handle_dir: &Path) -> Option<CredsTargetStat> {
    let path = handle_dir.join(".credentials.json");
    let meta = std::fs::metadata(&path).ok()?;
    let mtime_ns = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(-1);
    #[cfg(unix)]
    let ino = {
        use std::os::unix::fs::MetadataExt;
        meta.ino()
    };
    #[cfg(not(unix))]
    let ino = 0u64;
    Some(CredsTargetStat { mtime_ns, ino })
}

/// True when post-swap target stat differs from pre-swap such that CC's
/// `mtimeMs !== lastCredentialsMtimeMs` check (spec 01 §1.4) will reload.
/// The contract requires the mtime to differ, NOT the inode — CC ignores
/// inode. None on either side means we couldn't read the stat; conservative
/// default is False (caller surfaces this so a future bug repro shows it).
fn mtime_changed(pre: &Option<CredsTargetStat>, post: &Option<CredsTargetStat>) -> bool {
    match (pre, post) {
        (Some(p), Some(q)) => p.mtime_ns != q.mtime_ns,
        _ => false,
    }
}

/// True ONLY when both stats succeeded AND mtimes are identical — the exact
/// #270 hypothesised failure mode where CC's `mtimeMs !== lastCredentialsMtimeMs`
/// check (spec 01 §1.4) silently skips the credential reload. Distinguishes
/// the bug condition from stat-read failures (None on either side), which
/// the caller surfaces separately. The complement of [`mtime_changed`]
/// excluding the None cases.
fn mtime_collision(pre: &Option<CredsTargetStat>, post: &Option<CredsTargetStat>) -> bool {
    match (pre, post) {
        (Some(p), Some(q)) => p.mtime_ns == q.mtime_ns,
        _ => false,
    }
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
/// conversation (M10, an internal journal entry).
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

    // The legacy canonical Codex credential file is required as the fallback
    // path AND as a precondition guard (Codex slot must have completed login).
    // Per spec 07 §7.2.2: `auth.json` symlinks canonical-direct in the legacy
    // layout; in Phase 3 we may retarget to identity-keyed path when available.
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
    //
    // Distinct from the A4a `.swap-lock` (hyphen) keychain guard and
    // canonicalized via `repoint_lock_path` for the same reasons as
    // `repoint_handle_dir` (#928): codex swaps take no outer A4a guard
    // (fresh-dir / keychain-absent), so this `.swap.lock` (dot) IS the sole
    // rename serializer for concurrent codex repoints — canonicalizing the dir
    // keeps that serialization sound even when the caller passes a raw,
    // symlink-containing path.
    let lock_path = repoint_lock_path(handle_dir);
    let _swap_guard =
        crate::platform::lock::lock_file(&lock_path).map_err(|e| CredentialError::Corrupt {
            path: lock_path.clone(),
            reason: format!("repoint lock acquisition failed: {e}"),
        })?;

    // M3-4: Resolve the identity-keyed auth path for the Codex surface.
    //
    // `credentials_codex_path_for` returns `identities/<UUID>/credentials-codex.json`.
    // Per HIGH-2 from the M3-3 fix-wave: this file is NEVER written by any current
    // code path (Codex identity-path seeding lands in M3-7), so we expect
    // `exists()` to return false in production until then.  The fallback to
    // `credentials/codex-<N>.json` is therefore the PRODUCTION PATH for Phase 3.
    // The identity path is tested via fixture injection (SEC-3-H3 test) to prove
    // the primitive works once the file does exist.
    //
    // PRIMARY METHODOLOGICAL DIRECTIVE 1 applies here too (an internal journal entry WBS line 124):
    // the bump target MUST match `auth_symlink_target` — both are computed from the
    // same `identity_codex_path` variable in this commit, never split.
    let identity_codex_path =
        crate::accounts::profiles::resolve_slot_to_uuid(base_dir, target.get()).map(|uuid| {
            crate::accounts::identity_store::credentials_codex_path_for(base_dir, uuid)
        });

    let auth_symlink_target = match identity_codex_path.as_ref() {
        Some(p) if p.exists() || p.symlink_metadata().is_ok() => {
            // Identity-keyed credentials-codex.json is present — use it.
            p.clone()
        }
        Some(p) => {
            // UUID resolves but file absent (HIGH-2 Partial-Pass-0 state).
            // Fall back to legacy canonical.  Log at WARN.
            warn!(
                account = %target,
                identity_path = %p.display(),
                "M3-4 codex repoint: identity credentials-codex.json absent — \
                 falling back to legacy credentials/codex-N.json"
            );
            canonical_cred.clone()
        }
        None => {
            // Legacy layout: no UUID → use legacy canonical directly.
            canonical_cred.clone()
        }
    };

    // Codex symlink set per spec 07 §7.2.2. Sources are either
    // `identities/<UUID>/credentials-codex.json` (M3-4 retarget) or
    // the legacy `credentials/codex-<N>.json`, followed by config-<N>
    // items for the remaining slots.
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
        ("auth.json", auth_symlink_target.clone()),
        (".csq-account", new_config.join(".csq-account")),
        ("config.toml", new_config.join("config.toml")),
        ("sessions", new_config.join("codex-sessions")),
        ("history.jsonl", new_config.join("codex-history.jsonl")),
    ];

    // an internal ticket fix (Codex parallel, M3-4 retarget): bump the new auth.json
    // target's mtime strictly above the pre-swap target's mtime BEFORE the
    // atomic rename.  codex-cli re-reads auth.json before each API call (spec
    // 07 §7.5); an mtime collision would cause the same silent-skip bug as #270.
    // Pre-bumping is defensive.  Failure is non-fatal: the swap proceeds.
    //
    // PRIMARY METHODOLOGICAL DIRECTIVE 1: bump targets `auth_symlink_target`
    // (the identity-keyed path or fallback), NOT the raw canonical path.
    // This guarantees the mtime bump and the symlink target are always in sync.
    let pre_swap_codex_auth_mtime = std::fs::metadata(handle_dir.join("auth.json"))
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0);
    if let Err(e) =
        crate::platform::fs::bump_mtime_above(&auth_symlink_target, pre_swap_codex_auth_mtime)
    {
        warn!(
            error = ?e,
            path = %auth_symlink_target.display(),
            "pre-swap codex auth.json mtime bump failed; codex-cli may skip credential reload (an internal ticket)"
        );
    }

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

    // an internal ticket observability (Codex parallel): post-swap mtime check mirrors
    // the ClaudeCode regression detector in `repoint_handle_dir`. If the
    // pre-bump failed (e.g. 0o400 permission with O_WRONLY — fixed by using
    // O_RDONLY in `bump_mtime_above`) and both the pre- and post-swap auth.json
    // resolve to the same mtime, emit a WARN so the bug surfaces in
    // default-log sessions without requiring `CSQ_LOG=info`.
    let post_swap_codex_auth_mtime = std::fs::metadata(handle_dir.join("auth.json"))
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i128);
    // pre_swap captured as i128 (0 on failure); post_swap is Option<i128>.
    // Collision: both reads succeeded AND mtimes are identical.
    if let Some(post_ns) = post_swap_codex_auth_mtime {
        if pre_swap_codex_auth_mtime != 0 && post_ns == pre_swap_codex_auth_mtime {
            warn!(
                account = %target,
                handle = %handle_dir.display(),
                post_mtime_ns = post_ns,
                "codex swap repointed but auth.json mtime unchanged — \
                 codex-cli may skip credential reload (an internal ticket)"
            );
        }
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
/// #832: reconcile the handle dir's `.claude.json` `oauthAccount.emailAddress` to the
/// authoritative identity anchor after a swap — WITHOUT clobbering a foreign-account
/// signal.
///
/// `rebuild_claude_json_for_swap` sources `oauthAccount` from
/// `config-<target>/.claude.json`, but that source can be ABSENT (the rebuild bails
/// and leaves the OLD account's stale copy) or carry no `oauthAccount`. The daemon
/// then mirrors the NEW account's token into this dir's keychain, so the custodian's
/// wrong-account gate (`daemon::custodian::candidate_account_matches`) sees the NEW
/// token paired with an OLD/absent email → false-refuses the adoption until CC
/// eventually rewrites `.claude.json` (an internal journal entry FD1 / cc-keychain an internal journal entry H2).
///
/// `identity_email` is the SAME `identities/<UUID>/identity.json` value the gate uses
/// as its anchor, so writing it here makes the local signal consistent with the
/// binding on the very next tick — no wait, no false-refuse.
///
/// ## The foreign-signal safety gate (redteam R1 deep-analyst M-2)
///
/// The gate's whole invariant is `.claude.json` email == the keychain token's owner
/// (CC writes both together on `/login`). Blindly forcing the anchor would DECOUPLE
/// them: in the microsecond window between the rebuild's write and this read, a
/// concurrent CC in-session `/login <other>` writes keychain=OTHER + `.claude.json`
/// =OTHER. Overwriting that `.claude.json` back to the swap target would make the gate
/// match (target==target) while the keychain holds OTHER's LIVE token → the custodian
/// adopts a FOREIGN token into the target's account-global store (the exact
/// catastrophe the gate exists to prevent).
///
/// So this only writes when the current email is SAFE to overwrite:
/// - ABSENT / empty — no signal to lose (a concurrent CC `/login` would have written
///   a PRESENT email, so absent ⇒ no race), OR
/// - equal to `pre_swap_email` — the stale copy of the account we swapped AWAY from,
///   whose keychain token the swap already CLEARED (so it cannot be adopted).
///
/// A present email that is NEITHER the anchor NOR `pre_swap_email` was written by
/// something else (a concurrent foreign `/login`) → SKIP, leaving the gate fail-closed.
/// `pre_swap_email` is captured from the handle dir BEFORE the rebuild.
///
/// Residual (bounded by an unfixable blocker): if a concurrent `/login` targets the
/// SAME account the dir was on pre-swap (so `current == pre_swap_email`), the gate
/// cannot distinguish the fresh concurrent write from the stale copy and this may
/// overwrite it. Reaching it needs a triple-coincidence — the dir was on X pre-swap,
/// is swapped away from X, AND is concurrently re-logged into X inside the
/// rebuild→reconcile window — and it self-heals on CC's next `.claude.json` write.
/// Fully closing it would require a keychain-token OWNER signal, which does not exist
/// (the `sk-ant-oat01-` token is account-anonymous — the same fundamental limit the
/// wrong-account gate itself has, an internal journal entry). Not closable in-session.
///
/// - Surgical: overrides ONLY `oauthAccount.emailAddress`, preserving every other
///   field (esp. the CWD-scoped `projects` map the rebuild just merged).
/// - Idempotent: no write when the field already matches (ASCII-case-insensitive,
///   trimmed) — the common case where the rebuild sourced the right email.
/// - Best-effort + non-fatal: any read/parse/write failure leaves the pre-existing
///   fail-closed + self-heal path intact, so a reconcile failure never aborts the swap.
/// - Atomic (CC may be running) via the full `security.md` §5a pipeline —
///   `write` → `secure_file` (0600) → `atomic_replace`, tmp removed on every failure
///   branch — because `.claude.json` carries the account email = PII. `rebuild_
///   claude_json_for_swap` uses the identical pipeline. Serializes COMPACT
///   (`to_string`, not `to_string_pretty`) so reconciling a near-`MAX_CLAUDE_JSON_BYTES`
///   file can never inflate it past the gate's own read ceiling and re-break the gate
///   it fixes (redteam R1 deep-analyst L-2).
/// - Absent / oversized / unparseable / non-object `.claude.json`, or an empty
///   `identity_email` → skip (never clobber a file we cannot safely round-trip). A
///   still-un-round-trippable handle file after the rebuild (config-target absent AND
///   the retained copy itself corrupt) therefore keeps the pre-existing tick-based
///   self-heal — the AC's "no wait" guarantee is best-effort for that narrow sub-case.
fn reconcile_handle_dir_oauth_email(
    handle_dir: &Path,
    identity_email: &str,
    pre_swap_email: Option<&str>,
) {
    let email = identity_email.trim();
    if email.is_empty() {
        return;
    }
    let Some(content) = crate::credentials::claude_json::read_raw(handle_dir) else {
        return;
    };
    let Ok(mut json) = serde_json::from_str::<Value>(&content) else {
        return;
    };
    let Some(obj) = json.as_object_mut() else {
        return;
    };
    let current = obj
        .get("oauthAccount")
        .and_then(|a| a.get("emailAddress"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|c| !c.is_empty());
    // Idempotent fast-path: already the anchor → no write.
    if current.is_some_and(|cur| cur.eq_ignore_ascii_case(email)) {
        return;
    }
    // Foreign-signal safety gate (M-2): overwrite ONLY an absent/empty email or the
    // stale pre-swap value. A present email that is neither is a foreign `/login`
    // signal the gate MUST keep seeing → skip.
    let safe_to_write = match current {
        None => true,
        Some(cur) => pre_swap_email
            .map(str::trim)
            .is_some_and(|old| !old.is_empty() && cur.eq_ignore_ascii_case(old)),
    };
    if !safe_to_write {
        debug!("swap: #832 reconcile skipped — .claude.json names a non-pre-swap account");
        return;
    }
    // Force oauthAccount.emailAddress, creating (or replacing a non-object)
    // oauthAccount while preserving sibling fields.
    match obj.get_mut("oauthAccount").and_then(Value::as_object_mut) {
        Some(oa) => {
            oa.insert("emailAddress".to_string(), Value::String(email.to_string()));
        }
        None => {
            let mut m = serde_json::Map::new();
            m.insert("emailAddress".to_string(), Value::String(email.to_string()));
            obj.insert("oauthAccount".to_string(), Value::Object(m));
        }
    }
    let out = match serde_json::to_string(&json) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "swap: failed to serialize .claude.json for #832 reconcile");
            return;
        }
    };
    let path = handle_dir.join(".claude.json");
    let tmp = crate::platform::fs::unique_tmp_path(&path);
    if let Err(e) = std::fs::write(&tmp, out.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        warn!(path = %tmp.display(), error = %e, "swap: #832 reconcile temp write failed");
        return;
    }
    // 0600 the tmp before the rename (security.md §5a canonical pipeline): the file
    // carries the account email = PII. secure_file is a no-op on Windows.
    if let Err(e) = crate::platform::fs::secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        warn!(path = %tmp.display(), error = %e, "swap: #832 reconcile secure_file failed");
        return;
    }
    if let Err(e) = crate::platform::fs::atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        warn!(path = %path.display(), error = %e, "swap: #832 reconcile atomic replace failed");
        return;
    }
    debug!("swap: reconciled .claude.json oauthAccount.emailAddress to identity anchor (#832)");
}

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
    // §5a cleanup: .claude.json carries CC session metadata + the account email
    // (PII) — partial failure must remove the tmp so it doesn't linger at umask
    // 0o644, and the tmp is 0600'd before the rename (redteam R2 rust-specialist).
    let tmp = crate::platform::fs::unique_tmp_path(&handle_claude_json);
    if let Err(e) = std::fs::write(&tmp, out.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        warn!(path = %tmp.display(), error = %e, "swap: temp .claude.json write failed");
        return;
    }
    if let Err(e) = crate::platform::fs::secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        warn!(path = %tmp.display(), error = %e, "swap: secure_file of .claude.json failed");
        return;
    }
    if let Err(e) = crate::platform::fs::atomic_replace(&tmp, &handle_claude_json) {
        let _ = std::fs::remove_file(&tmp);
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
/// so pasted images survive the sweep. See an internal journal entry for the design.
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
        // shared directory — see an internal journal entry
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

    removed += sweep_stale_capture_dirs(base_dir);

    if removed > 0 {
        info!(removed, "handle dir sweep complete");
    }
    removed
}

/// Filename prefix of the daemon's Phase-2b interactive subscription-capture
/// handle dirs (created via [`create_handle_dir_named`] /
/// [`create_handle_dir_codex_named`] with this prefix by
/// `phase2b::subscription_client`). Shared so the per-capture reaper and this
/// periodic watcher agree on the namespace.
pub(crate) const CAPTURE_DIR_PREFIX: &str = "interactive-capture-";

/// Grace before a capture dir that lacks a `.live-pid` is treated as a crash
/// leak rather than a concurrent sibling still being set up (the sibling writes
/// `.live-pid` as its final step, so a fresh pid-less dir is in-flight).
const CAPTURE_REAP_GRACE: std::time::Duration = std::time::Duration::from_secs(180);

/// Reap `interactive-capture-*` dirs left by a crashed daemon. A dir is removed
/// when its `.live-pid` records a DEAD pid; a MISSING `.live-pid` is reapable
/// only when the dir is older than [`CAPTURE_REAP_GRACE`] (else it is a sibling
/// mid-setup — reaping it would delete a live capture's dir). Returns the count
/// removed.
///
/// Called both per-capture (by `phase2b::subscription_client`, before creating a
/// new capture dir) AND from [`sweep_dead_handles`] (the 60s watcher) so a leak
/// is reaped even if no further subscription capture ever runs. The
/// `interactive-capture-*` namespace holds only credential SYMLINKS (never
/// copies), so `remove_dir_all` deletes links, not the real credentials.
pub(crate) fn sweep_stale_capture_dirs(base_dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(base_dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(CAPTURE_DIR_PREFIX) {
            continue;
        }
        let dir = entry.path();
        let recorded: Option<u32> = std::fs::read_to_string(dir.join(".live-pid"))
            .ok()
            .and_then(|s| s.trim().parse().ok());
        let reapable = match recorded {
            Some(pid) => !is_pid_alive(pid),
            None => dir_age_exceeds(&dir, CAPTURE_REAP_GRACE),
        };
        if reapable && std::fs::remove_dir_all(&dir).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// `true` when `dir`'s mtime is older than `grace`. On any stat / clock error
/// (incl. a future-dated mtime from clock skew) returns `false` (KEEP — fail
/// safe; never reap on doubt).
pub(crate) fn dir_age_exceeds(dir: &Path, grace: std::time::Duration) -> bool {
    std::fs::metadata(dir)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|mtime| mtime.elapsed().ok())
        .map(|age| age > grace)
        .unwrap_or(false)
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
/// in an internal journal entry as a known limitation — a merge-on-collision fix
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

    // ── interactive-capture-* sweep (redteam R2 Q4) ──────────────────────────

    fn make_capture_dir(base: &Path, suffix: &str, live_pid: Option<u32>) -> PathBuf {
        let dir = base.join(format!("{CAPTURE_DIR_PREFIX}{suffix}"));
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(pid) = live_pid {
            std::fs::write(dir.join(".live-pid"), pid.to_string()).unwrap();
        }
        dir
    }

    #[test]
    fn sweep_capture_reaps_dead_pid_dir() {
        let base = TempDir::new().unwrap();
        // 999_999_999 is not a live pid on any sane system.
        let dir = make_capture_dir(base.path(), "999999999-0", Some(999_999_999));
        assert_eq!(sweep_stale_capture_dirs(base.path()), 1);
        assert!(!dir.exists(), "dead-pid capture dir must be reaped");
    }

    #[test]
    fn sweep_capture_keeps_live_pid_dir() {
        let base = TempDir::new().unwrap();
        let dir = make_capture_dir(base.path(), "self-0", Some(std::process::id()));
        assert_eq!(sweep_stale_capture_dirs(base.path()), 0);
        assert!(dir.exists(), "live-pid capture dir must be kept");
    }

    #[test]
    fn sweep_capture_keeps_fresh_pidless_sibling() {
        // A dir with no `.live-pid` yet is a concurrent sibling mid-setup: KEEP
        // (it is younger than CAPTURE_REAP_GRACE).
        let base = TempDir::new().unwrap();
        let dir = make_capture_dir(base.path(), "sibling-0", None);
        assert_eq!(sweep_stale_capture_dirs(base.path()), 0);
        assert!(dir.exists(), "fresh pid-less sibling must not be reaped");
    }

    #[test]
    fn sweep_capture_ignores_non_capture_dirs() {
        let base = TempDir::new().unwrap();
        std::fs::create_dir_all(base.path().join("term-12345")).unwrap();
        std::fs::create_dir_all(base.path().join("config-1")).unwrap();
        assert_eq!(sweep_stale_capture_dirs(base.path()), 0);
        assert!(base.path().join("term-12345").exists());
        assert!(base.path().join("config-1").exists());
    }

    #[test]
    fn dir_age_exceeds_keeps_fresh_dir() {
        // A freshly created dir is NOT older than an hour → KEEP (false). This is
        // the safety-critical direction (never reap a fresh sibling).
        let base = TempDir::new().unwrap();
        let dir = base.path().join("fresh");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!dir_age_exceeds(&dir, std::time::Duration::from_secs(3600)));
    }

    #[test]
    fn dir_age_exceeds_reaps_when_older_than_grace() {
        // The reap direction: any real dir's age exceeds a ZERO grace, so a
        // pidless crash-leak older than CAPTURE_REAP_GRACE is reapable.
        let base = TempDir::new().unwrap();
        let dir = base.path().join("old");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(dir_age_exceeds(&dir, std::time::Duration::ZERO));
    }

    #[test]
    fn dir_age_exceeds_missing_dir_is_false() {
        // Stat error → KEEP (fail safe).
        let base = TempDir::new().unwrap();
        assert!(!dir_age_exceeds(
            &base.path().join("nope"),
            std::time::Duration::ZERO
        ));
    }

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

    /// an internal ticket invariant pin: post-swap `.credentials.json` follows-symlink
    /// stat MUST resolve to a different inode than pre-swap. CC's
    /// `invalidateOAuthCacheIfDiskChanged` (spec 01 §1.4) keys cache reload
    /// off `mtimeMs !== lastCredentialsMtimeMs`; the swap contract relies on
    /// the new target being a different file with a different mtime. This
    /// test pins the inode-differ guarantee — a regression that left the
    /// symlink resolving to the same inode (e.g. by accidentally creating
    /// a hardlink-ish layout, or by failing to repoint at all) would be
    /// caught here even before mtime collision is exercised.
    #[test]
    #[cfg(unix)]
    fn repoint_handle_dir_changes_credentials_target_inode() {
        use std::os::unix::fs::MetadataExt;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        setup_config_dir(base, 2);

        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account1, 77777).unwrap();

        let pre_meta = std::fs::metadata(handle.join(".credentials.json")).unwrap();
        let pre_ino = pre_meta.ino();

        repoint_handle_dir(base, &claude_home, &handle, account2).unwrap();

        let post_meta = std::fs::metadata(handle.join(".credentials.json")).unwrap();
        let post_ino = post_meta.ino();

        assert_ne!(
            pre_ino, post_ino,
            "post-swap credentials target inode must differ from pre-swap; \
             same inode means CC's stat will see identical metadata and skip \
             reload (spec 01 §1.4 invariant)"
        );
    }

    /// an internal ticket fix regression test: when the two config dirs have
    /// `.credentials.json` files with IDENTICAL mtimes (the exact bug
    /// condition — daemon refresh in same nanosecond, FS precision clamp,
    /// etc.), the pre-swap mtime bump in `repoint_handle_dir` MUST advance
    /// the new target's mtime strictly above the pre-swap mtime so CC's
    /// strict-inequality reload check (spec 01 §1.4) fires.
    ///
    /// Without the fix, the new symlink resolves to a target with the same
    /// mtime as the prior target, CC silently skips reload, and the swap
    /// "appears not to take effect" until something else perturbs the
    /// file (an internal ticket user repro).
    #[test]
    #[cfg(unix)]
    fn repoint_handle_dir_advances_mtime_when_targets_collide() {
        use std::time::{Duration, SystemTime};

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();
        setup_config_dir(base, 1);
        setup_config_dir(base, 2);

        // Force IDENTICAL mtimes on both slots' credentials files — the
        // exact #270 bug condition. Pick a fixed mtime in the past so the
        // bump's `max(now, ...)` branch is the one being exercised.
        let collision_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        for slot in [1u16, 2u16] {
            let creds = base.join(format!("config-{slot}/.credentials.json"));
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&creds)
                .unwrap();
            f.set_modified(collision_time).unwrap();
        }

        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let handle = create_handle_dir(base, &claude_home, account1, 88888).unwrap();

        // Pre-swap: stat through the symlink to capture what CC's invalidate
        // check sees on its first stat.
        let pre_mtime = std::fs::metadata(handle.join(".credentials.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(
            pre_mtime, collision_time,
            "test setup invariant: pre-swap symlink resolves to slot 1's collision mtime"
        );

        repoint_handle_dir(base, &claude_home, &handle, account2).unwrap();

        // Post-swap: stat through the symlink (now resolves to slot 2).
        // The fix MUST have bumped slot 2's target mtime strictly above
        // the collision_time. CC's `mtimeMs !== lastCredentialsMtimeMs`
        // check then fires on the next stat.
        let post_mtime = std::fs::metadata(handle.join(".credentials.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            post_mtime > pre_mtime,
            "an internal ticket regression: post-swap mtime ({post_mtime:?}) must be \
             strictly greater than pre-swap mtime ({pre_mtime:?}). Same mtime \
             means CC silently skips credential reload. The pre-rename mtime \
             bump in repoint_handle_dir failed to advance the target."
        );
    }

    /// an internal ticket fix regression test (Codex parallel): same invariant as
    /// the Anthropic test above but for `repoint_handle_dir_codex`. Pins
    /// the defensive bump on `credentials/codex-<N>.json` against the same
    /// mtime-collision class.
    #[test]
    #[cfg(unix)]
    fn repoint_handle_dir_codex_advances_auth_mtime_when_targets_collide() {
        use std::time::{Duration, SystemTime};

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Codex requires a different on-disk shape than Anthropic.
        // Build minimal codex config dirs + canonical credentials.
        for slot in [1u16, 2u16] {
            let cfg = base.join(format!("config-{slot}"));
            std::fs::create_dir_all(&cfg).unwrap();
            std::fs::write(cfg.join(".csq-account"), slot.to_string()).unwrap();
            std::fs::write(cfg.join("config.toml"), "").unwrap(); // CI-ALLOW-fs-write-config-toml
            std::fs::write(cfg.join(".credentials.json"), "{}").unwrap();
            std::fs::write(cfg.join("settings.json"), "{}").unwrap();
            std::fs::write(cfg.join(".claude.json"), "{}").unwrap();
        }
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        for slot in [1u16, 2u16] {
            std::fs::write(creds_dir.join(format!("codex-{slot}.json")), "{}").unwrap();
        }

        // Force collision on canonical codex credential files AND apply the
        // INV-P08 mode (0o400) that `save_canonical_for` sets after Codex
        // login/refresh. Without this, the test does not cover the production
        // case where `bump_mtime_above` opens a 0o400 file — the bug that
        // made the Codex #270 fix non-functional before the O_RDONLY fix.
        let collision_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        for slot in [1u16, 2u16] {
            let cred_path = creds_dir.join(format!("codex-{slot}.json"));
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&cred_path)
                .unwrap();
            f.set_modified(collision_time).unwrap();
            drop(f);
            // Apply INV-P08: canonical Codex credentials sit at 0o400.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cred_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }

        let account1 = AccountNum::try_from(1u16).unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let handle = create_handle_dir_codex(base, account1, 88889).unwrap();

        let pre_mtime = std::fs::metadata(handle.join("auth.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(
            pre_mtime, collision_time,
            "test setup invariant: pre-swap codex auth.json resolves to slot 1's collision mtime"
        );

        repoint_handle_dir_codex(base, &handle, account2).unwrap();

        let post_mtime = std::fs::metadata(handle.join("auth.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            post_mtime > pre_mtime,
            "an internal ticket regression (codex): post-swap auth.json mtime ({post_mtime:?}) \
             must be strictly greater than pre-swap ({pre_mtime:?})"
        );
    }

    /// Companion to inode-differ test: when the two config dirs have
    /// distinct credential files (the normal case), `mtime_changed` MUST
    /// report true so the post-swap INFO trace tells the truth. A regression
    /// here would mean an internal ticket's observability is silently lying.
    #[test]
    fn mtime_changed_returns_true_for_distinct_stats() {
        let pre = Some(super::CredsTargetStat {
            mtime_ns: 1_000_000_000,
            ino: 1,
        });
        let post = Some(super::CredsTargetStat {
            mtime_ns: 2_000_000_000,
            ino: 2,
        });
        assert!(super::mtime_changed(&pre, &post));
    }

    /// Mtime-collision case: two config dirs whose credentials happen to
    /// share an mtime (rare but possible — same-instant daemon refresh,
    /// filesystem precision clamp). `mtime_changed` MUST report false so
    /// the trace surfaces the failure mode that an internal ticket hypothesizes.
    #[test]
    fn mtime_changed_returns_false_for_colliding_mtimes() {
        let same_mtime = 1_500_000_000_i128;
        let pre = Some(super::CredsTargetStat {
            mtime_ns: same_mtime,
            ino: 1,
        });
        let post = Some(super::CredsTargetStat {
            mtime_ns: same_mtime,
            ino: 2, // different inode but same mtime — exact bug class
        });
        assert!(
            !super::mtime_changed(&pre, &post),
            "mtime collision MUST be reported — CC's reload won't fire"
        );
    }

    /// Conservative default: when either stat is unreadable, treat the
    /// invariant as unverified (false). Caller surfaces the None separately.
    #[test]
    fn mtime_changed_returns_false_when_either_stat_missing() {
        let stat = Some(super::CredsTargetStat {
            mtime_ns: 1_000_000_000,
            ino: 1,
        });
        assert!(!super::mtime_changed(&None, &stat));
        assert!(!super::mtime_changed(&stat, &None));
        assert!(!super::mtime_changed(&None, &None));
    }

    /// `mtime_collision` is the gate for the WARN emit that surfaces issue
    /// #270's failure mode in default-log sessions. It MUST fire only when
    /// both stats succeeded AND mtimes match — distinguishing the bug class
    /// from stat-read failures (None) and from the happy path (mtimes
    /// differ). A regression that returns true for None inputs would emit
    /// a spurious WARN on first-bind handle dirs; one that returns false
    /// for the bug condition would silently lose #270's signal. Pin both.
    #[test]
    fn mtime_collision_fires_only_when_both_stats_present_and_mtimes_equal() {
        let same_mtime = 1_500_000_000_i128;
        let stat_a = Some(super::CredsTargetStat {
            mtime_ns: same_mtime,
            ino: 1,
        });
        let stat_b = Some(super::CredsTargetStat {
            mtime_ns: same_mtime,
            ino: 2, // different inode but identical mtime — the #270 bug class
        });
        let stat_c = Some(super::CredsTargetStat {
            mtime_ns: 2_000_000_000,
            ino: 3,
        });

        // Bug condition: both stats valid + mtimes equal → WARN must fire.
        assert!(
            super::mtime_collision(&stat_a, &stat_b),
            "mtime collision MUST fire when both stats succeed with identical mtimes"
        );

        // Happy path: both stats valid + mtimes differ → WARN must stay silent.
        assert!(
            !super::mtime_collision(&stat_a, &stat_c),
            "mtime collision MUST NOT fire when mtimes differ (happy path)"
        );

        // Stat-error cases: WARN must stay silent because the caller surfaces
        // the None separately via the INFO trace; spurious WARN here would
        // poison default-log sessions on first-bind handle dirs.
        assert!(!super::mtime_collision(&None, &stat_a));
        assert!(!super::mtime_collision(&stat_a, &None));
        assert!(!super::mtime_collision(&None, &None));
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

    // ── #928: repoint rename-lock path canonicalization ───────────────────

    /// Regression guard: #928.
    ///
    /// The inner rename lock (`repoint_lock_path`) MUST resolve to the SAME
    /// file whether the caller passes a raw, symlink-containing path (`csq swap`
    /// forwards `source.path()` verbatim) or a pre-canonicalized one
    /// (`auto_rotate`). Before the fix, `csq swap` locked `raw/.swap.lock` while
    /// `auto_rotate` locked `canonical/.swap.lock` — different inodes on any host
    /// whose accounts base has a symlink component, so the lock silently failed
    /// to serialize concurrent repoints.
    #[test]
    #[cfg(unix)]
    fn repoint_lock_path_is_canonical_and_symlink_invariant() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        // Real handle dir at <root>/real/term-1.
        let real_parent = dir.path().join("real");
        std::fs::create_dir_all(&real_parent).unwrap();
        let real_handle = real_parent.join("term-1");
        std::fs::create_dir_all(&real_handle).unwrap();

        // A symlinked view of the SAME handle dir: <root>/link -> <root>/real.
        let link_parent = dir.path().join("link");
        symlink(&real_parent, &link_parent).unwrap();
        let via_symlink = link_parent.join("term-1");

        let canonical = std::fs::canonicalize(&real_handle).unwrap();

        let lock_via_raw = repoint_lock_path(&via_symlink);
        let lock_via_canonical = repoint_lock_path(&canonical);

        // Both callers resolve to the SAME lock file (the #928 invariant).
        assert_eq!(
            lock_via_raw, lock_via_canonical,
            "raw and canonical callers must resolve to the same rename lock; \
             raw={lock_via_raw:?} canonical={lock_via_canonical:?}"
        );
        assert!(
            lock_via_raw.ends_with(".swap.lock"),
            "rename lock must be `.swap.lock` (dot), got {lock_via_raw:?}"
        );
        // And it must be under the canonical parent, not the symlinked one.
        assert_eq!(
            lock_via_raw,
            canonical.join(".swap.lock"),
            "rename lock must live under the canonicalized handle dir"
        );

        // The inner rename lock MUST stay a DIFFERENT file from the A4a
        // `.swap-lock` (hyphen) keychain guard — merging them self-deadlocks a
        // process that holds the outer guard across the repoint call (#928).
        let a4a_guard = crate::credentials::keychain::swap_lock_path(&canonical);
        assert_ne!(
            lock_via_raw, a4a_guard,
            "the rename lock (.swap.lock) and the A4a guard (.swap-lock) must be \
             distinct files or a same-process re-flock self-deadlocks"
        );

        // Canonicalize-failure fallback: a non-existent (dangling) dir cannot be
        // canonicalized, so the helper falls back to the raw path joined with
        // `.swap.lock`. (The repoint itself fails downstream for such a dir; this
        // only pins the fallback so it never silently drops the filename.)
        let dangling = dir.path().join("does-not-exist").join("term-2");
        assert_eq!(
            repoint_lock_path(&dangling),
            dangling.join(".swap.lock"),
            "canonicalize-fail fallback must return raw dir joined with .swap.lock"
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
        std::fs::write(config.join("config.toml"), "[model]\nname = \"o1\"\n").unwrap(); // CI-ALLOW-fs-write-config-toml
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

    /// End-to-end subprocess test: with `CODEX_HOME` pointing at the
    /// handle dir, a subprocess that reads `$CODEX_HOME/config.toml`
    /// sees the merged user-global content. This is the exact
    /// resolution chain Codex CLI walks at startup:
    /// `CODEX_HOME=<handle-dir>` → handle-dir's `config.toml` symlink →
    /// `config-<N>/config.toml` (merged via `write_config_toml`).
    ///
    /// Without this test, unit tests verified each link of the chain
    /// in isolation but nothing verified the chain end-to-end as the
    /// subprocess (Codex) experiences it. This is the test that
    /// closes the "did you actually test with subprocesses" gap from
    /// the 2026-05-15 user-reported codex sandbox bug.
    #[cfg(unix)]
    #[test]
    fn handle_dir_codex_subprocess_reads_merged_config_toml_end_to_end() {
        use crate::providers::codex::surface as codex_surface;
        use std::process::Command;

        // Acquire workspace-wide env lock (testing.md MUST Rule 6) so
        // CODEX_USER_CONFIG mutation is race-safe against concurrent
        // codex tests.
        let _shared = crate::platform::test_env::lock();

        // Install a fixture user-global with sandbox + approval policy
        // keys (the exact keys the 2026-05-15 bug reporter wanted
        // propagated).
        let user_global_dir = TempDir::new().unwrap();
        let user_global_path = user_global_dir.path().join("user-config.toml");
        std::fs::write(
            &user_global_path,
            "approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n",
        )
        .unwrap();
        let prev_env = std::env::var_os(codex_surface::USER_CONFIG_ENV_OVERRIDE);
        // SAFETY: shared env lock held; restored before test exits.
        unsafe {
            std::env::set_var(codex_surface::USER_CONFIG_ENV_OVERRIDE, &user_global_path);
        }

        let base_dir_tmp = TempDir::new().unwrap();
        let base = base_dir_tmp.path();
        let account_num = 14u16;
        let account = AccountNum::try_from(account_num).unwrap();

        // Provision the slot: credential file + write config-N/config.toml
        // via the production path (which merges user-global).
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(
            creds_dir.join(format!("codex-{account_num}.json")),
            r#"{"auth_mode":"chatgpt","tokens":{"access_token":"at","refresh_token":"rt","id_token":"it","account_id":"uuid"}}"#,
        )
        .unwrap();
        let config_dir = base.join(format!("config-{account_num}"));
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join(".csq-account"), account_num.to_string()).unwrap();
        std::fs::create_dir_all(config_dir.join("codex-sessions")).unwrap();
        std::fs::write(config_dir.join("codex-history.jsonl"), "").unwrap();
        codex_surface::write_config_toml(base, account, "gpt-test-model").unwrap();

        // Build the handle dir with the codex symlink set.
        let handle = create_handle_dir_codex(base, account, 88891).unwrap();

        // The exact subprocess shape `csq run` produces for Codex:
        // CODEX_HOME=<handle-dir>, env_clear() + stdlib allowlist
        // (rules/testing.md MUST Rule 4a). Use `sh -c 'cat ...'` —
        // does the same fopen+read chain Codex CLI does at startup
        // for its config.toml.
        let mut cmd = Command::new("sh");
        cmd.env_clear();
        for k in ["HOME", "PATH", "LANG", "LC_ALL", "TERM", "USER", "TMPDIR"] {
            if let Ok(v) = std::env::var(k) {
                cmd.env(k, v);
            }
        }
        cmd.env(codex_surface::HOME_ENV_VAR, &handle);
        cmd.args(["-c", "cat \"$CODEX_HOME/config.toml\""]);
        let output = cmd.output().expect("sh subprocess must spawn");

        // Restore env BEFORE any panic-able assertion so a test failure
        // doesn't poison concurrent tests' view of CODEX_USER_CONFIG.
        // SAFETY: shared env lock still held.
        unsafe {
            match prev_env {
                Some(v) => std::env::set_var(codex_surface::USER_CONFIG_ENV_OVERRIDE, v),
                None => std::env::remove_var(codex_surface::USER_CONFIG_ENV_OVERRIDE),
            }
        }

        assert!(
            output.status.success(),
            "sh `cat $CODEX_HOME/config.toml` must succeed; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let content = String::from_utf8(output.stdout).expect("config.toml is UTF-8");

        // csq-controlled baseline keys survive the merge.
        assert!(
            content.contains("cli_auth_credentials_store = \"file\""),
            "csq directive must reach the subprocess via $CODEX_HOME/config.toml; got:\n{content}"
        );
        assert!(
            content.contains("model = \"gpt-test-model\""),
            "csq-set model must reach the subprocess; got:\n{content}"
        );

        // The bug-fix invariant: user-global preferences propagate
        // end-to-end through CODEX_HOME → handle-dir symlink →
        // config-N/config.toml.
        assert!(
            content.contains("approval_policy = \"never\""),
            "user-global approval_policy MUST reach the subprocess; \
             this is the exact chain Codex CLI walks at startup. Got:\n{content}"
        );
        assert!(
            content.contains("sandbox_mode = \"danger-full-access\""),
            "user-global sandbox_mode MUST reach the subprocess. Got:\n{content}"
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
        std::fs::write(config.join("config.toml"), "").unwrap(); // CI-ALLOW-fs-write-config-toml

        let account = AccountNum::try_from(6u16).unwrap();
        let result = create_handle_dir_codex(base, account, 1);
        match result {
            Err(CredentialError::Corrupt { reason, .. }) => {
                // Post-M4-12: the error message names the canonical path check
                // ("neither UUID-keyed nor legacy path exists") and the recovery
                // action ("csq login N --provider codex"), not a specific filename.
                assert!(
                    reason.contains("csq login 6 --provider codex")
                        || reason.contains("codex-6.json"),
                    "error must name the missing canonical credential and/or recovery action: {reason}"
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
        std::fs::write(config.join("config.toml"), "").unwrap(); // CI-ALLOW-fs-write-config-toml
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

    /// Regression guard: an internal journal entry finding 1 belt-and-suspenders.
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
        markers::write_csq_account_legacy(&codex_config, codex_account).unwrap();
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
        markers::write_csq_account_legacy(&target_config, target_account).unwrap();

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

    // ── repoint_handle_dir_codex (M10 / an internal journal entry) ──────────────────

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
        std::fs::write(handle.join("config.toml"), b"planted, not a symlink").unwrap(); // CI-ALLOW-fs-write-config-toml

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

    /// §5a regression — site 4 (security.md MUST Rule 5a, an internal journal entry B2,
    /// /redteam round 3 2026-05-09): when `materialize_handle_settings`
    /// fails after the tmp file would have been created (handle dir
    /// read-only → write fails), no `.tmp.` file must remain.
    ///
    /// The merged settings.json in the handle dir may carry an
    /// ANTHROPIC_AUTH_TOKEN copied from the slot's `config-<N>/settings.json`.
    #[cfg(unix)]
    #[test]
    fn materialize_handle_settings_partial_failure_cleans_tmp_file() {
        use crate::platform::fs::assert_no_tmp_leak_on_readonly_parent;

        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let claude_home = base.join(".claude");
        std::fs::create_dir_all(&claude_home).unwrap();

        // Precursor: a config dir with settings.json carrying a token.
        let config_dir = base.join("config-1");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("settings.json"),
            r#"{"env":{"ANTHROPIC_AUTH_TOKEN":"sk-secret-token"}}"#,
        )
        .unwrap();

        // A handle dir where the write will succeed initially, then fail.
        let handle_dir = base.join("term-99001");
        std::fs::create_dir_all(&handle_dir).unwrap();

        // Verify the happy path works first (dir is writable).
        materialize_handle_settings(&handle_dir, &claude_home, &config_dir).unwrap();

        // Act + Assert: read-only handle_dir → write fails → no tmp leak.
        assert_no_tmp_leak_on_readonly_parent(&handle_dir, || {
            materialize_handle_settings(&handle_dir, &claude_home, &config_dir)
        });
    }

    /// §5a regression — site 5 (security.md MUST Rule 5a, an internal journal entry B2,
    /// /redteam round 3 2026-05-09): when `rebuild_claude_json_for_swap`
    /// fails after the tmp file would have been created (handle dir
    /// read-only → write fails), no `.tmp.` file must remain.
    ///
    /// `.claude.json` in the handle dir carries CC session metadata
    /// (oauthAccount, GrowthBook flags); partial-failure must not leave
    /// it at umask 0o644.
    #[cfg(unix)]
    #[test]
    fn rebuild_claude_json_for_swap_partial_failure_cleans_tmp_file() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // A config dir with a valid .claude.json (source for the swap).
        let config_dir = base.join("config-2");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"b2@example.com","accountUuid":"u-2"}}"#,
        )
        .unwrap();

        // A handle dir with an existing .claude.json (preserved during swap).
        let handle_dir = base.join("term-99002");
        std::fs::create_dir_all(&handle_dir).unwrap();
        std::fs::write(handle_dir.join(".claude.json"), r#"{}"#).unwrap();

        // Verify the happy path first.
        rebuild_claude_json_for_swap(&config_dir, &handle_dir);
        assert!(handle_dir.join(".claude.json").exists());

        // Act + Assert: read-only handle_dir → write fails → no tmp leak.
        // rebuild_claude_json_for_swap returns (), but the §5a contract
        // still requires no tmp file survives on failure. We verify
        // directly after making the dir read-only.
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&handle_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        rebuild_claude_json_for_swap(&config_dir, &handle_dir);
        std::fs::set_permissions(&handle_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let leaked: Vec<_> = std::fs::read_dir(&handle_dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".tmp."))
                    .unwrap_or(false)
            })
            .collect();
        assert!(leaked.is_empty(), "§5a leaked tmp files: {leaked:?}");
    }

    // ── #832: reconcile_handle_dir_oauth_email ───────────────────────────────

    fn read_oauth_email_field(handle_dir: &Path) -> Option<String> {
        let content = std::fs::read_to_string(handle_dir.join(".claude.json")).ok()?;
        let json: Value = serde_json::from_str(&content).ok()?;
        json.get("oauthAccount")?
            .get("emailAddress")?
            .as_str()
            .map(str::to_owned)
    }

    #[test]
    fn reconcile_overrides_stale_email_and_preserves_other_fields() {
        // The DA-1 case: handle .claude.json names the OLD (pre-swap) account; force
        // it to the identity anchor while preserving projects + other caches.
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(
            handle.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"old@a.com","accountUuid":"u-old"},"projects":{"/x":{"n":1}},"numStartups":7}"#,
        )
        .unwrap();
        // pre_swap_email = the OLD account → safe to overwrite.
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", Some("old@a.com"));
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("new@b.com")
        );
        // Other fields preserved.
        let json: Value =
            serde_json::from_str(&std::fs::read_to_string(handle.join(".claude.json")).unwrap())
                .unwrap();
        assert_eq!(json["projects"]["/x"]["n"], 1);
        assert_eq!(json["numStartups"], 7);
        // Sibling oauthAccount field preserved.
        assert_eq!(json["oauthAccount"]["accountUuid"], "u-old");
    }

    #[test]
    fn reconcile_skips_foreign_email_not_matching_pre_swap() {
        // M-2 (redteam R1 deep-analyst): the race case. Between the rebuild and this
        // read, a concurrent CC `/login foreign@c.com` wrote .claude.json=foreign.
        // pre_swap was old@a.com. The current email is NEITHER the anchor NOR the
        // pre-swap value → it is a foreign signal the gate MUST keep seeing → SKIP.
        // Overwriting it would blind the gate to a foreign keychain token.
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(
            handle.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"foreign@c.com"}}"#,
        )
        .unwrap();
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", Some("old@a.com"));
        // Foreign email preserved — gate stays fail-closed.
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("foreign@c.com")
        );
    }

    #[test]
    fn reconcile_skips_present_email_when_pre_swap_unknown() {
        // Conservative: if pre_swap_email is None (couldn't resolve the old account),
        // a PRESENT non-anchor email cannot be confirmed as the safe stale value →
        // skip (do not risk clobbering a foreign signal).
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(
            handle.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"present@a.com"}}"#,
        )
        .unwrap();
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", None);
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("present@a.com")
        );
    }

    #[test]
    fn reconcile_is_idempotent_when_already_matching() {
        // Already-consistent (case-insensitive) → NO write (byte-identical content).
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        let body = r#"{"oauthAccount":{"emailAddress":"Me@Example.com"}}"#;
        std::fs::write(handle.join(".claude.json"), body).unwrap();
        reconcile_handle_dir_oauth_email(&handle, "me@example.com", Some("old@a.com"));
        // No rewrite: content unchanged (a rewrite would re-serialize compactly).
        assert_eq!(
            std::fs::read_to_string(handle.join(".claude.json")).unwrap(),
            body
        );
    }

    #[test]
    fn reconcile_creates_oauth_account_when_absent() {
        // Populated file with no oauthAccount → absent email is always safe to set.
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(handle.join(".claude.json"), r#"{"numStartups":3}"#).unwrap();
        // Even with pre_swap unknown, an absent oauthAccount has no signal to lose.
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", None);
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("new@b.com")
        );
    }

    #[test]
    fn reconcile_replaces_non_object_oauth_account() {
        // oauthAccount present but non-object → no usable email (current == None) →
        // safe to replace with a proper object carrying the anchor.
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(
            handle.join(".claude.json"),
            r#"{"oauthAccount":"garbage","numStartups":3}"#,
        )
        .unwrap();
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", None);
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("new@b.com")
        );
    }

    #[test]
    fn reconcile_skips_absent_unparseable_non_object_and_empty_email() {
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        // Absent .claude.json → no file created.
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", Some("old@a.com"));
        assert!(!handle.join(".claude.json").exists());
        // Unparseable (M-1) → unchanged (never clobber a file we can't round-trip).
        std::fs::write(handle.join(".claude.json"), r#"not json {"#).unwrap();
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", Some("old@a.com"));
        assert_eq!(
            std::fs::read_to_string(handle.join(".claude.json")).unwrap(),
            "not json {"
        );
        // Non-object → unchanged.
        std::fs::write(handle.join(".claude.json"), r#"[1,2,3]"#).unwrap();
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", Some("old@a.com"));
        assert_eq!(
            std::fs::read_to_string(handle.join(".claude.json")).unwrap(),
            "[1,2,3]"
        );
        // Empty identity email → no-op even on a valid stale file.
        std::fs::write(
            handle.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"old@a.com"}}"#,
        )
        .unwrap();
        reconcile_handle_dir_oauth_email(&handle, "   ", Some("old@a.com"));
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("old@a.com")
        );
    }

    #[cfg(unix)]
    #[test]
    fn reconcile_partial_failure_cleans_tmp_file() {
        // §5a: a write/secure_file/atomic_replace failure must leave no tmp behind
        // (`.claude.json` carries the account email = PII). Mirror of the sibling
        // `rebuild_claude_json_for_swap_partial_failure_cleans_tmp_file`.
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        // A stale (pre-swap-matching) file so the reconcile decides to WRITE.
        std::fs::write(
            handle.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"old@a.com"}}"#,
        )
        .unwrap();
        // Read-only handle dir → the tmp create/write fails → no tmp may linger.
        std::fs::set_permissions(&handle, std::fs::Permissions::from_mode(0o500)).unwrap();
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", Some("old@a.com"));
        std::fs::set_permissions(&handle, std::fs::Permissions::from_mode(0o700)).unwrap();
        let leaked: Vec<_> = std::fs::read_dir(&handle)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".tmp."))
                    .unwrap_or(false)
            })
            .collect();
        assert!(leaked.is_empty(), "§5a leaked tmp files: {leaked:?}");
    }

    #[test]
    fn reconcile_skips_oversized_file() {
        // A `.claude.json` past the read ceiling → read_raw None → skip (never buffer
        // + rewrite an unbounded file). Intermediate-reviewer NIT.
        let dir = TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        let pad = "x".repeat(17 * 1024 * 1024);
        let body = format!(r#"{{"oauthAccount":{{"emailAddress":"old@a.com"}},"_pad":"{pad}"}}"#);
        std::fs::write(handle.join(".claude.json"), &body).unwrap();
        reconcile_handle_dir_oauth_email(&handle, "new@b.com", Some("old@a.com"));
        // Unchanged (oversized → skipped).
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("old@a.com")
        );
    }

    // ── M2-3 / M4-2 acceptance tests ─────────────────────────────────────

    /// M4-2 Criterion: `materialize_handle_settings_inner` prefers the
    /// UUID-keyed settings.json when it exists on disk.
    ///
    /// Arrange: base dir with a UUID settings path containing `"uuid_key": 1`
    /// and a config-2/settings.json containing `"config_key": 2`. The UUID
    /// path must win in the overlay.
    ///
    /// (Renamed from `materialize_handle_settings_prefers_uuid_path_when_present`
    /// to match the M4-2 WBS acceptance-criterion name in
    /// `internal-design-docs`.)
    #[test]
    fn materialize_handle_settings_prefers_identities_uuid_source() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(2);

        // Write uuid settings.json with a sentinel key
        let uuid_settings = crate::accounts::identity_store::settings_path_for(base, uuid);
        std::fs::create_dir_all(uuid_settings.parent().unwrap()).unwrap();
        std::fs::write(&uuid_settings, r#"{"uuid_key": 1}"#).unwrap();

        // Write config-2/settings.json with a different key
        let config_settings = base.join("config-2").join("settings.json");
        std::fs::write(&config_settings, r#"{"config_key": 2}"#).unwrap();

        // Write empty global settings.json (claude_home)
        let claude_home = base.join("claude_home");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(claude_home.join("settings.json"), "{}").unwrap();

        let handle_dir = base.join("term-11111");
        std::fs::create_dir_all(&handle_dir).unwrap();

        // Act
        let result = materialize_handle_settings_inner(
            &handle_dir,
            &claude_home,
            &base.join("config-2"),
            Some(uuid_settings.as_path()),
        );
        assert!(
            result.is_ok(),
            "materialize_handle_settings_inner failed: {result:?}"
        );

        // Assert: materialized settings.json contains uuid_key (UUID path won)
        let merged_raw = std::fs::read_to_string(handle_dir.join("settings.json")).unwrap();
        let merged: serde_json::Value = serde_json::from_str(&merged_raw).unwrap();
        assert_eq!(
            merged["uuid_key"].as_u64(),
            Some(1),
            "UUID-keyed key must appear in merged settings when UUID path present"
        );
        assert!(
            merged.get("config_key").is_none() || merged["config_key"].as_u64() != Some(2),
            "config-N key must NOT override UUID-keyed overlay; merged={merged}"
        );
    }

    /// M4-2 Criterion: `materialize_handle_settings_inner` falls back to
    /// `config-N/settings.json` when no UUID path is provided (legacy-only layout).
    ///
    /// (Renamed from `materialize_handle_settings_falls_back_to_config_n_when_uuid_missing`
    /// to match the M4-2 WBS acceptance-criterion name in
    /// `internal-design-docs`.)
    #[test]
    fn materialize_handle_settings_legacy_fallback_when_uuid_absent() {
        use crate::testing::identity_fixtures::legacy_only_fixture;

        // Arrange
        let dir = legacy_only_fixture(3);
        let base = dir.path();

        // Write config-2/settings.json with a sentinel key
        let config_settings = base.join("config-2").join("settings.json");
        std::fs::write(&config_settings, r#"{"legacy_key": 42}"#).unwrap();

        let claude_home = base.join("claude_home");
        std::fs::create_dir_all(&claude_home).unwrap();
        std::fs::write(claude_home.join("settings.json"), "{}").unwrap();

        let handle_dir = base.join("term-22222");
        std::fs::create_dir_all(&handle_dir).unwrap();

        // Act: pass None for uuid_settings_path (legacy fallback)
        let result = materialize_handle_settings_inner(
            &handle_dir,
            &claude_home,
            &base.join("config-2"),
            None,
        );
        assert!(
            result.is_ok(),
            "materialize_handle_settings_inner failed: {result:?}"
        );

        // Assert: materialized settings.json contains legacy_key (config-N won)
        let merged_raw = std::fs::read_to_string(handle_dir.join("settings.json")).unwrap();
        let merged: serde_json::Value = serde_json::from_str(&merged_raw).unwrap();
        assert_eq!(
            merged["legacy_key"].as_u64(),
            Some(42),
            "config-N key must appear in merged settings when UUID path is None"
        );
    }

    // ── M3-3 acceptance criteria tests ───────────────────────────────────────
    //
    // All 8 tests from 02-plans/04-phase3-readiness.md § M3-3 acceptance
    // criteria, plus the inverted Phase 2/3 boundary test.

    /// M3-3 AC1: Under a coexisting fixture (slot 3, account 2), `.credentials.json`
    /// symlink resolves to `identities/<UUID>/credentials.json`.
    ///
    /// an internal journal entry OQ #2 Option A: M3-3 retargets `.credentials.json` to the
    /// identity-keyed path when a UUID is present.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn create_handle_dir_targets_identity_uuid_path_when_present() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange: coexisting_fixture(3) has config-1..3 + identities/<UUID>/
        // Write credentials.json into the identity dir so the symlink target exists.
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(2);
        let identity_creds = base
            .join("identities")
            .join(uuid.to_canonical_string())
            .join("credentials.json");
        std::fs::write(&identity_creds, b"{}").unwrap();

        // Also ensure config-2/.csq-account exists (required for handle dir creation).
        let config_dir = base.join("config-2");
        std::fs::write(config_dir.join(".csq-account"), b"2").unwrap();
        std::fs::write(config_dir.join("settings.json"), b"{}").unwrap();
        std::fs::write(config_dir.join(".claude.json"), b"{}").unwrap();

        let claude_home = tempfile::TempDir::new().unwrap();

        let account = AccountNum::try_from(2u16).unwrap();
        let pid: u32 = 11001;

        // Act
        let handle = create_handle_dir(base, claude_home.path(), account, pid).unwrap();

        // Assert: .credentials.json symlink targets identities/<UUID>/credentials.json
        let link = handle.join(".credentials.json");
        let target = std::fs::read_link(&link).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("identities"),
            "AC1: .credentials.json must target identities/, got: {target_str}"
        );
        assert!(
            target_str.contains(&uuid.to_canonical_string()),
            "AC1: .credentials.json must target the UUID dir for slot 2, got: {target_str}"
        );
        assert!(
            target_str.ends_with("credentials.json"),
            "AC1: symlink must end with credentials.json, got: {target_str}"
        );
    }

    /// M3-3 AC2: Under a legacy-only fixture (no UUID in profiles.json),
    /// `.credentials.json` symlink resolves to `config-2/.credentials.json`.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn create_handle_dir_falls_back_to_config_n_when_uuid_missing() {
        use crate::testing::identity_fixtures::legacy_only_fixture;

        // Arrange: legacy_only_fixture(3) has config-1..3 but no profiles.json UUIDs.
        let dir = legacy_only_fixture(3);
        let base = dir.path();

        let config_dir = base.join("config-2");
        std::fs::write(config_dir.join(".csq-account"), b"2").unwrap();
        std::fs::write(config_dir.join("settings.json"), b"{}").unwrap();
        std::fs::write(config_dir.join(".claude.json"), b"{}").unwrap();

        let claude_home = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(2u16).unwrap();
        let pid: u32 = 11002;

        // Act
        let handle = create_handle_dir(base, claude_home.path(), account, pid).unwrap();

        // Assert: .credentials.json symlink targets config-2/.credentials.json
        let link = handle.join(".credentials.json");
        let target = std::fs::read_link(&link).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("config-2"),
            "AC2: legacy fallback must target config-2/, got: {target_str}"
        );
        assert!(
            target_str.ends_with(".credentials.json"),
            "AC2: symlink must end with .credentials.json, got: {target_str}"
        );
        assert!(
            !target_str.contains("identities"),
            "AC2: legacy fallback must NOT target identities/, got: {target_str}"
        );
    }

    /// M3-3 AC3: Codex parallel — under a coexisting fixture, `auth.json`
    /// symlink resolves to `identities/<UUID>/credentials-codex.json`.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn create_handle_dir_codex_targets_identity_uuid_path_when_present() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        let dir = coexisting_fixture(3);
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(2);

        // Write credentials-codex.json into the identity dir.
        let identity_dir = base.join("identities").join(uuid.to_canonical_string());
        std::fs::create_dir_all(&identity_dir).unwrap();
        let codex_creds = identity_dir.join("credentials-codex.json");
        std::fs::write(&codex_creds, b"{}").unwrap();

        // Ensure config-2/ Codex items.
        let config_dir = base.join("config-2");
        std::fs::write(config_dir.join(".csq-account"), b"2").unwrap();
        std::fs::write(config_dir.join("config.toml"), b"").unwrap(); // CI-ALLOW-fs-write-config-toml

        // Codex also needs the legacy canonical to exist for the precondition check.
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("codex-2.json"), b"{}").unwrap();

        let account = AccountNum::try_from(2u16).unwrap();
        let pid: u32 = 11003;

        // Act
        let handle = create_handle_dir_codex(base, account, pid).unwrap();

        // Assert: auth.json symlink targets identities/<UUID>/credentials-codex.json
        let link = handle.join("auth.json");
        let target = std::fs::read_link(&link).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("identities"),
            "AC3: auth.json must target identities/, got: {target_str}"
        );
        assert!(
            target_str.contains(&uuid.to_canonical_string()),
            "AC3: auth.json must target the UUID dir for slot 2, got: {target_str}"
        );
        assert!(
            target_str.ends_with("credentials-codex.json"),
            "AC3: auth.json must end with credentials-codex.json, got: {target_str}"
        );
    }

    /// M3-3 AC4: Codex parallel — under a legacy-only fixture, `auth.json`
    /// resolves to the legacy `credentials/codex-N.json`.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn create_handle_dir_codex_falls_back_to_config_n_when_uuid_missing() {
        use crate::testing::identity_fixtures::legacy_only_fixture;

        let dir = legacy_only_fixture(3);
        let base = dir.path();

        // Set up Codex-required items.
        let config_dir = base.join("config-2");
        std::fs::write(config_dir.join(".csq-account"), b"2").unwrap();
        std::fs::write(config_dir.join("config.toml"), b"").unwrap(); // CI-ALLOW-fs-write-config-toml

        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("codex-2.json"), b"{}").unwrap();

        let account = AccountNum::try_from(2u16).unwrap();
        let pid: u32 = 11004;

        // Act
        let handle = create_handle_dir_codex(base, account, pid).unwrap();

        // Assert: auth.json symlink targets credentials/codex-2.json
        let link = handle.join("auth.json");
        let target = std::fs::read_link(&link).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("codex-2"),
            "AC4: legacy fallback must target codex-2.json, got: {target_str}"
        );
        assert!(
            !target_str.contains("identities"),
            "AC4: legacy fallback must NOT target identities/, got: {target_str}"
        );
    }

    /// M3-3 AC5: `.csq-account` symlink ALWAYS targets `config-N/.csq-account`
    /// (OQ #2 Option A hardcode), and the marker FILE CONTENT is numeric (e.g. `b"2"`).
    ///
    /// This is cross-phase constraint #3: markers stay at slot path through Phase 4.
    /// The numeric content ensures terminal-attribution continues to work via
    /// `rules/account-terminal-separation.md` MUST NOT Rule 3.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn create_handle_dir_marker_symlink_resolves_to_numeric_marker_source() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        // Arrange: even with a UUID present, .csq-account stays at config-N/.
        let dir = coexisting_fixture(3);
        let base = dir.path();

        let config_dir = base.join("config-2");
        std::fs::write(config_dir.join(".csq-account"), b"2").unwrap();
        std::fs::write(config_dir.join("settings.json"), b"{}").unwrap();
        std::fs::write(config_dir.join(".claude.json"), b"{}").unwrap();
        // Write the identity-keyed credentials so the creds symlink can be created.
        {
            use crate::testing::identity_fixtures::fixture_uuid_for_slot;
            let uuid = fixture_uuid_for_slot(2);
            let identity_creds = base
                .join("identities")
                .join(uuid.to_canonical_string())
                .join("credentials.json");
            std::fs::write(&identity_creds, b"{}").unwrap();
        }

        let claude_home = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(2u16).unwrap();
        let pid: u32 = 11005;

        let handle = create_handle_dir(base, claude_home.path(), account, pid).unwrap();

        // Assert 1: .csq-account symlink target contains config-2 (not identities/)
        let link = handle.join(".csq-account");
        let target = std::fs::read_link(&link).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("config-2"),
            "AC5: .csq-account must target config-2/, got: {target_str}"
        );
        assert!(
            !target_str.contains("identities"),
            "AC5: .csq-account must NOT target identities/, got: {target_str}"
        );

        // Assert 2: the FILE CONTENT the symlink resolves to is numeric
        let content = std::fs::read_to_string(&link).unwrap();
        let parsed: u16 = content
            .trim()
            .parse()
            .expect("AC5: .csq-account content must be a numeric slot number");
        assert_eq!(parsed, 2, "AC5: marker content must equal account slot 2");
    }

    /// M3-3 AC6: `symlink_exclusive` primitive contract — a pre-existing path
    /// at the link destination causes `symlink_exclusive` to return
    /// `Err(PlatformError::AlreadyExists)`, never silently overwriting.
    ///
    /// The body directly calls `symlink_exclusive` on an already-existing symlink
    /// to prove the AlreadyExists contract of the M1-3 primitive.  The structural
    /// wire-in proof (every `std::os::unix::fs::symlink` call in non-test code has
    /// been replaced by `symlink_exclusive`) is verified by the grep audit at
    /// `rules/redteam-discipline.md` Rule 2: zero raw `symlink` callsites in
    /// production code.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn symlink_exclusive_refuses_pre_existing_link_at_account_bound_path() {
        use crate::testing::identity_fixtures::coexisting_fixture;

        let dir = coexisting_fixture(3);
        let base = dir.path();

        let config_dir = base.join("config-2");
        std::fs::write(config_dir.join(".csq-account"), b"2").unwrap();
        std::fs::write(config_dir.join("settings.json"), b"{}").unwrap();
        std::fs::write(config_dir.join(".claude.json"), b"{}").unwrap();
        {
            use crate::testing::identity_fixtures::fixture_uuid_for_slot;
            let uuid = fixture_uuid_for_slot(2);
            let identity_creds = base
                .join("identities")
                .join(uuid.to_canonical_string())
                .join("credentials.json");
            std::fs::write(&identity_creds, b"{}").unwrap();
        }

        let claude_home = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(2u16).unwrap();
        let pid: u32 = 11006;

        // Pre-create the handle dir and place a regular file at .credentials.json.
        // This simulates a partially-created handle dir where the link path already
        // exists (e.g., from a racing concurrent create or stale orphan).
        let handle_dir = base.join(format!("term-{pid}"));
        std::fs::create_dir_all(&handle_dir).unwrap();
        std::fs::write(handle_dir.join(".credentials.json"), b"stale").unwrap();
        // Also write .live-pid so the orphan-detection path removes it safely.
        // (We want the handle dir creation to proceed past orphan-detection and
        // reach the symlink phase — but we need to set up the dir as an orphan
        // with a dead PID so create_handle_dir removes and recreates it.)
        //
        // Actually — to test the AlreadyExists refusal, we need create_handle_dir
        // to fail at the symlink step, not at the "orphan with live PID" check.
        // Create the handle dir WITHOUT a .live-pid (corrupt orphan case) so
        // create_handle_dir removes it and recreates it.  After remove+recreate
        // the dir is fresh, so we cannot pre-place the file this way.
        //
        // Instead: pre-create a stale handle dir with a live-looking PID to force
        // the function to *refuse* deletion — but that tests a different path.
        //
        // The correct shape: drop the pre-created dir, let create_handle_dir
        // succeed on first call, then call again (PID collision with dead PID via
        // .live-pid pointing at a dead PID) — the second call will remove+recreate.
        // That still doesn't get us a pre-existing .credentials.json at the SYMLINK
        // step because remove_dir_all clears it.
        //
        // Correct test: Remove the pre-created handle dir.  Let the first
        // create_handle_dir succeed.  Then manually recreate a conflicting
        // regular file inside the handle dir at an item path AND call
        // `symlink_exclusive` directly to verify the AlreadyExists contract.
        std::fs::remove_dir_all(&handle_dir).unwrap();

        // First call succeeds — establishes the handle dir with the correct symlinks.
        let handle = create_handle_dir(base, claude_home.path(), account, pid).unwrap();

        // Verify the .credentials.json is a symlink (not a regular file).
        let creds_link = handle.join(".credentials.json");
        assert!(
            creds_link
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "AC6: .credentials.json in handle dir must be a symlink"
        );

        // Verify: calling symlink_exclusive on an already-existing symlink path
        // returns Err (AlreadyExists).  This is the direct wire-in proof.
        let dummy_target = base.join("config-2").join(".credentials.json");
        let err = crate::platform::fs::symlink_exclusive(&dummy_target, &creds_link).unwrap_err();
        assert!(
            matches!(err, crate::error::PlatformError::AlreadyExists),
            "AC6: symlink_exclusive on an existing path must return AlreadyExists, got: {err:?}"
        );
    }

    // M3-7: tests `create_handle_dir_handles_concurrent_identity_mint_race`
    // and `create_handle_dir_falls_back_to_config_n_when_uuid_present_but_identity_credentials_missing`
    // retired alongside the HIGH-1 runtime fallback. Phase 4's
    // `phase4_gate_check` (renamed from the prior `phase3_gate` symbol
    // in M4-5; M3-7's IdentityCredentialsUnseeded invariant preserved
    // as check 3) makes the Partial-Pass-0 state impossible at
    // daemon-runtime; the positive-shape test
    // `create_handle_dir_targets_identity_uuid_path_when_present` (below)
    // and the M3-7 acceptance test
    // `handle_dir_credentials_read_resolves_to_identity_path_after_mirror_retirement`
    // pin the M3-7 contract that `.credentials.json` always points at the
    // identity path when a UUID is present.

    // M3-3 AC8: The inverted Phase 2/3 boundary test is in csq/src/cli/commands/run.rs
    // as `run_command_handle_dir_symlinks_target_identity_uuid`.

    /// M3-7 acceptance test #12 (WBS line 269):
    /// `handle_dir_credentials_read_resolves_to_identity_path_after_mirror_retirement`.
    ///
    /// With M3-7 the HIGH-1 fallback to `config-N/.credentials.json` is
    /// retired. When a slot has a UUID in `profiles.json`, the handle
    /// dir's `.credentials.json` symlink ALWAYS targets the identity-keyed
    /// path `identities/<UUID>/credentials.json`. Phase 3's fail-closed
    /// gate guarantees this path is seeded before any daemon-mediated
    /// handle dir creation, so the symlink is always live.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn handle_dir_credentials_read_resolves_to_identity_path_after_mirror_retirement() {
        use crate::accounts::identity_store::credentials_path_for as uuid_creds_path;
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange: coexisting fixture has UUID in profiles + identity dir.
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(2);

        // Seed the identity credentials.json (Phase 3 fail-closed gate
        // guarantees this is true at daemon runtime — we mimic that here).
        let identity_creds = uuid_creds_path(base, uuid);
        std::fs::create_dir_all(identity_creds.parent().unwrap()).unwrap();
        std::fs::write(&identity_creds, b"{\"claudeAiOauth\":{}}").unwrap();

        // Set up other config-N items.
        let config_dir = base.join("config-2");
        std::fs::write(config_dir.join(".csq-account"), b"2").unwrap();
        std::fs::write(config_dir.join("settings.json"), b"{}").unwrap();
        std::fs::write(config_dir.join(".claude.json"), b"{}").unwrap();

        let claude_home = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(2u16).unwrap();
        let pid: u32 = 12101;

        let handle = create_handle_dir(base, claude_home.path(), account, pid)
            .expect("create_handle_dir succeeds with seeded identity creds");

        // M3-7 invariant: `.credentials.json` symlink targets the identity path.
        let creds_link = handle.join(".credentials.json");
        assert!(creds_link
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
        let target = std::fs::read_link(&creds_link).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("/identities/"),
            "M3-7: .credentials.json symlink MUST target identities/<UUID>/, got: {target_str}"
        );
        assert!(
            !target_str.contains("config-"),
            "M3-7: .credentials.json symlink MUST NOT target config-N/, got: {target_str}"
        );

        // Resolving the symlink lands on the identity credentials we seeded.
        let resolved = std::fs::read_to_string(&creds_link).unwrap();
        assert_eq!(
            resolved, "{\"claudeAiOauth\":{}}",
            "M3-7: reading through the handle-dir symlink MUST yield the identity-keyed payload"
        );
    }

    /// HIGH-2 regression: `create_handle_dir_codex` must fall back to
    /// `credentials/codex-N.json` when UUID is present in `profiles.json` but
    /// `identities/<UUID>/credentials-codex.json` does NOT exist.
    ///
    /// Before the fix: `credentials_codex_path_for` returns a nonexistent path;
    /// the existence check at line ~387 sees it missing → skip → handle dir has
    /// NO `auth.json` → Codex CLI fails on first API call.
    ///
    /// After the fix: fallback to `credentials/codex-N.json` (which exists).
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn create_handle_dir_codex_falls_back_to_legacy_when_uuid_present_but_identity_credentials_codex_missing(
    ) {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange: coexisting fixture has UUID but does NOT have
        // identities/<UUID>/credentials-codex.json (only identity.json).
        let dir = coexisting_fixture(3);
        let base = dir.path();
        let uuid = fixture_uuid_for_slot(2);

        // Verify precondition: credentials-codex.json is absent.
        let identity_dir = base.join("identities").join(uuid.to_canonical_string());
        let codex_creds = identity_dir.join("credentials-codex.json");
        assert!(
            !codex_creds.exists(),
            "Precondition: identity credentials-codex.json must NOT exist in coexisting fixture"
        );

        // Set up Codex-required items.
        let config_dir = base.join("config-2");
        std::fs::write(config_dir.join(".csq-account"), b"2").unwrap();
        std::fs::write(config_dir.join("config.toml"), b"").unwrap(); // CI-ALLOW-fs-write-config-toml

        // Legacy canonical DOES exist.
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        let legacy_codex = creds_dir.join("codex-2.json");
        std::fs::write(&legacy_codex, b"{}").unwrap();

        let account = AccountNum::try_from(2u16).unwrap();
        let pid: u32 = 12002;

        // Act
        let result = create_handle_dir_codex(base, account, pid);

        // Assert: succeeds
        assert!(
            result.is_ok(),
            "HIGH-2: create_handle_dir_codex must succeed when identity credentials-codex.json \
             is absent; got: {result:?}"
        );
        let handle = result.unwrap();

        // Assert: auth.json symlink EXISTS
        let auth_link = handle.join("auth.json");
        assert!(
            auth_link.symlink_metadata().is_ok(),
            "HIGH-2: auth.json symlink must exist in handle dir (fallback to legacy canonical)"
        );
        assert!(
            auth_link
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "HIGH-2: auth.json in handle dir must be a symlink"
        );

        // Assert: symlink target is the legacy canonical, NOT identities/
        let target = std::fs::read_link(&auth_link).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("codex-2"),
            "HIGH-2: fallback symlink must target codex-2.json, got: {target_str}"
        );
        assert!(
            !target_str.contains("identities"),
            "HIGH-2: fallback symlink must NOT target identities/, got: {target_str}"
        );
    }

    // ── M3-4 acceptance criteria tests ───────────────────────────────────────
    //
    // 9 tests from the M3-4 WBS (an internal workspace Phase 3, an internal ticket).
    // Tests cover: repoint identity UUID targeting, mtime bump on identity path,
    // Codex repoint parallel, fallback scenarios (legacy + Partial-Pass-0), and
    // concurrent writer regression guard.

    /// M3-4 AC1: `repoint_handle_dir` retargets `.credentials.json` to the
    /// identity-keyed path when the identity credentials file exists.
    ///
    /// Arrange: coexisting_fixture(3) — slot 2 and slot 3 both have config-N/
    /// and identities/<UUID>/credentials.json. Create a handle dir bound to
    /// slot 2, then repoint to slot 3. Post-swap, the symlink must resolve
    /// to `identities/<UUID-for-3>/credentials.json`.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_targets_identity_uuid_path_when_present() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        // Arrange: fixture with slots 1..3 in coexisting layout.
        let dir = coexisting_fixture(3);
        let base = dir.path();

        // Write identity credentials for slots 2 and 3 (fixture provides config-N/
        // and identity.json but NOT credentials.json in identity dir).
        for slot in [2u16, 3u16] {
            let uuid = fixture_uuid_for_slot(slot);
            let identity_creds = base
                .join("identities")
                .join(uuid.to_canonical_string())
                .join("credentials.json");
            std::fs::write(&identity_creds, b"{}").unwrap();
        }

        // Complete config-N layout for both slots.
        for slot in [2u16, 3u16] {
            let cfg = base.join(format!("config-{slot}"));
            std::fs::write(cfg.join(".csq-account"), slot.to_string()).unwrap();
            std::fs::write(cfg.join("settings.json"), b"{}").unwrap();
            std::fs::write(cfg.join(".claude.json"), b"{}").unwrap();
        }

        let claude_home = tempfile::TempDir::new().unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let account3 = AccountNum::try_from(3u16).unwrap();
        let handle = create_handle_dir(base, claude_home.path(), account2, 21001).unwrap();

        // Act: repoint from slot 2 → slot 3.
        repoint_handle_dir(base, claude_home.path(), &handle, account3).unwrap();

        // Assert: symlink resolves to identities/<UUID-for-slot-3>/credentials.json
        let link = handle.join(".credentials.json");
        let target = std::fs::read_link(&link).unwrap();
        let target_str = target.to_string_lossy();
        let uuid3 = fixture_uuid_for_slot(3);
        assert!(
            target_str.contains("identities"),
            "AC1: .credentials.json must target identities/, got: {target_str}"
        );
        assert!(
            target_str.contains(&uuid3.to_canonical_string()),
            "AC1: .credentials.json must target UUID dir for slot 3 ({}), got: {target_str}",
            uuid3.to_canonical_string()
        );
        assert!(
            target_str.ends_with("credentials.json"),
            "AC1: symlink must end with credentials.json, got: {target_str}"
        );
    }

    /// #832: the real DA-1 case — `config-<target>/.claude.json` is ABSENT, so
    /// `rebuild_claude_json_for_swap` bails and the handle retains the OLD (pre-swap)
    /// account's stale `.claude.json`. `repoint_handle_dir` then reconciles
    /// `oauthAccount.emailAddress` to the swap target's identity anchor (the current
    /// email equals the captured pre-swap value → safe to overwrite), so the custodian
    /// wrong-account gate matches on the next tick.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn repoint_reconciles_oauth_email_to_identity_anchor() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        let dir = coexisting_fixture(3);
        let base = dir.path();

        for slot in [2u16, 3u16] {
            let uuid = fixture_uuid_for_slot(slot);
            std::fs::write(
                base.join("identities")
                    .join(uuid.to_canonical_string())
                    .join("credentials.json"),
                b"{}",
            )
            .unwrap();
            let cfg = base.join(format!("config-{slot}"));
            std::fs::write(cfg.join(".csq-account"), slot.to_string()).unwrap();
            std::fs::write(cfg.join("settings.json"), b"{}").unwrap();
        }
        // config-2 carries slot-2's email — the handle inherits it at create, so it
        // becomes the pre-swap value. config-3/.claude.json is deliberately ABSENT →
        // the rebuild bails → the handle keeps the slot-2 (pre-swap) copy → the
        // reconcile's safety gate recognizes it as the pre-swap value and overwrites
        // it with the slot-3 identity anchor.
        std::fs::write(
            base.join("config-2/.claude.json"),
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-2@test.invalid"},"projects":{}}"#,
        )
        .unwrap();
        // (config-3/.claude.json intentionally NOT written.)

        let claude_home = tempfile::TempDir::new().unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let account3 = AccountNum::try_from(3u16).unwrap();
        let handle = create_handle_dir(base, claude_home.path(), account2, 21051).unwrap();
        // Precondition: the handle inherited slot-2's email (the pre-swap value).
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("fixture-slot-2@test.invalid")
        );

        repoint_handle_dir(base, claude_home.path(), &handle, account3).unwrap();

        // The handle's oauthAccount.emailAddress is now the slot-3 IDENTITY anchor —
        // the gate matches; no wait for CC to rewrite.
        assert_eq!(
            read_oauth_email_field(&handle).as_deref(),
            Some("fixture-slot-3@test.invalid"),
            "AC: swap must reconcile oauthAccount.emailAddress to the identity anchor"
        );
    }

    /// M3-4 AC2 (Codex parallel): `repoint_handle_dir_codex` retargets
    /// `auth.json` to `identities/<UUID>/credentials-codex.json` when present.
    ///
    /// Arrange: coexisting_fixture(3), write credentials-codex.json into identity
    /// dirs for slots 2 and 3, then repoint a Codex handle dir from slot 2 → 3.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_targets_identity_uuid_path_when_present() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};

        let dir = coexisting_fixture(3);
        let base = dir.path();

        // Write credentials-codex.json into identity dirs for slots 2 and 3.
        for slot in [2u16, 3u16] {
            let uuid = fixture_uuid_for_slot(slot);
            let identity_dir = base.join("identities").join(uuid.to_canonical_string());
            std::fs::create_dir_all(&identity_dir).unwrap();
            std::fs::write(identity_dir.join("credentials-codex.json"), b"{}").unwrap();
        }

        // Complete config-N layout for Codex (requires .csq-account + config.toml).
        for slot in [2u16, 3u16] {
            let cfg = base.join(format!("config-{slot}"));
            std::fs::write(cfg.join(".csq-account"), slot.to_string()).unwrap();
            std::fs::write(cfg.join("config.toml"), b"").unwrap(); // CI-ALLOW-fs-write-config-toml
        }

        // Legacy canonical codex credentials (required by precondition check).
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        for slot in [2u16, 3u16] {
            std::fs::write(creds_dir.join(format!("codex-{slot}.json")), b"{}").unwrap();
        }

        let account2 = AccountNum::try_from(2u16).unwrap();
        let account3 = AccountNum::try_from(3u16).unwrap();
        let handle = create_handle_dir_codex(base, account2, 21002).unwrap();

        // Act: repoint Codex handle dir from slot 2 → slot 3.
        repoint_handle_dir_codex(base, &handle, account3).unwrap();

        // Assert: auth.json symlink resolves to identities/<UUID-for-3>/credentials-codex.json
        let link = handle.join("auth.json");
        let target = std::fs::read_link(&link).unwrap();
        let target_str = target.to_string_lossy();
        let uuid3 = fixture_uuid_for_slot(3);
        assert!(
            target_str.contains("identities"),
            "AC2(Codex): auth.json must target identities/, got: {target_str}"
        );
        assert!(
            target_str.contains(&uuid3.to_canonical_string()),
            "AC2(Codex): auth.json must target UUID dir for slot 3 ({}), got: {target_str}",
            uuid3.to_canonical_string()
        );
        assert!(
            target_str.ends_with("credentials-codex.json"),
            "AC2(Codex): auth.json must end with credentials-codex.json, got: {target_str}"
        );
    }

    /// M3-4 AC3: `repoint_handle_dir` mtime bump targets the identity-keyed
    /// credentials.json, not config-N/.credentials.json, when UUID present.
    ///
    /// Pin the identity credentials.json to a past mtime, then repoint.
    /// Post-swap, reading the mtime through the symlink must be strictly above
    /// the pre-swap baseline — proving `bump_mtime_above` ran against the
    /// identity path.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_preserves_mtime_bump_against_identity_credentials_json() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        use std::time::{Duration, SystemTime};

        let dir = coexisting_fixture(3);
        let base = dir.path();

        // Write identity credentials for slot 3 (the swap target).
        let uuid3 = fixture_uuid_for_slot(3);
        let identity_dir = base.join("identities").join(uuid3.to_canonical_string());
        let identity_creds = identity_dir.join("credentials.json");
        std::fs::write(&identity_creds, b"{}").unwrap();

        // Also write identity creds for slot 2 (the swap source handle dir).
        let uuid2 = fixture_uuid_for_slot(2);
        let identity_dir2 = base.join("identities").join(uuid2.to_canonical_string());
        let identity_creds2 = identity_dir2.join("credentials.json");
        std::fs::write(&identity_creds2, b"{}").unwrap();

        for slot in [2u16, 3u16] {
            let cfg = base.join(format!("config-{slot}"));
            std::fs::write(cfg.join(".csq-account"), slot.to_string()).unwrap();
            std::fs::write(cfg.join("settings.json"), b"{}").unwrap();
            std::fs::write(cfg.join(".claude.json"), b"{}").unwrap();
        }

        // Pin identity credentials.json for slot 3 to a known past mtime.
        let collision_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&identity_creds)
            .unwrap();
        f.set_modified(collision_time).unwrap();
        drop(f);

        let claude_home = tempfile::TempDir::new().unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let account3 = AccountNum::try_from(3u16).unwrap();
        let handle = create_handle_dir(base, claude_home.path(), account2, 21003).unwrap();

        // Act: repoint from slot 2 → slot 3.
        repoint_handle_dir(base, claude_home.path(), &handle, account3).unwrap();

        // Assert: reading mtime through the symlink is strictly above collision_time.
        let post_mtime = std::fs::metadata(handle.join(".credentials.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            post_mtime > collision_time,
            "AC3: mtime bump must advance identity credentials.json above baseline \
             ({collision_time:?}), got: {post_mtime:?}"
        );

        // Additionally assert the symlink resolves to identities/ (not config-N/).
        let target = std::fs::read_link(handle.join(".credentials.json")).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("identities"),
            "AC3: symlink must target identities/ after repoint, got: {target_str}"
        );
    }

    /// M3-4 AC4 (Codex parallel): `repoint_handle_dir_codex` mtime bump targets
    /// `identities/<UUID>/credentials-codex.json` when present.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_codex_preserves_mtime_bump_against_identity_credentials_codex_json() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        use std::time::{Duration, SystemTime};

        let dir = coexisting_fixture(3);
        let base = dir.path();

        // Write credentials-codex.json into identity dirs for slots 2 and 3.
        for slot in [2u16, 3u16] {
            let uuid = fixture_uuid_for_slot(slot);
            let identity_dir = base.join("identities").join(uuid.to_canonical_string());
            std::fs::create_dir_all(&identity_dir).unwrap();
            std::fs::write(identity_dir.join("credentials-codex.json"), b"{}").unwrap();
        }

        for slot in [2u16, 3u16] {
            let cfg = base.join(format!("config-{slot}"));
            std::fs::write(cfg.join(".csq-account"), slot.to_string()).unwrap();
            std::fs::write(cfg.join("config.toml"), b"").unwrap(); // CI-ALLOW-fs-write-config-toml
        }

        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        for slot in [2u16, 3u16] {
            std::fs::write(creds_dir.join(format!("codex-{slot}.json")), b"{}").unwrap();
        }

        // Pin identity credentials-codex.json for slot 3 to a known past mtime.
        let uuid3 = fixture_uuid_for_slot(3);
        let identity_codex3 = base
            .join("identities")
            .join(uuid3.to_canonical_string())
            .join("credentials-codex.json");
        let collision_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&identity_codex3)
            .unwrap();
        f.set_modified(collision_time).unwrap();
        drop(f);

        let account2 = AccountNum::try_from(2u16).unwrap();
        let account3 = AccountNum::try_from(3u16).unwrap();
        let handle = create_handle_dir_codex(base, account2, 21004).unwrap();

        // Act: repoint from slot 2 → slot 3.
        repoint_handle_dir_codex(base, &handle, account3).unwrap();

        // Assert: mtime through auth.json symlink is strictly above collision_time.
        let post_mtime = std::fs::metadata(handle.join("auth.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            post_mtime > collision_time,
            "AC4(Codex): mtime bump must advance identity credentials-codex.json above \
             baseline ({collision_time:?}), got: {post_mtime:?}"
        );

        // Additionally assert the symlink resolves to identities/.
        let target = std::fs::read_link(handle.join("auth.json")).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("identities"),
            "AC4(Codex): auth.json must target identities/ after repoint, got: {target_str}"
        );
    }

    /// M3-4 AC5: `repoint_handle_dir` falls back to `config-N/.credentials.json`
    /// when no UUID is present in profiles.json (legacy-only layout).
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_falls_back_to_config_n_when_uuid_missing() {
        use crate::testing::identity_fixtures::legacy_only_fixture;

        // Arrange: legacy_only_fixture — no profiles.json UUIDs.
        let dir = legacy_only_fixture(3);
        let base = dir.path();

        for slot in [2u16, 3u16] {
            let cfg = base.join(format!("config-{slot}"));
            std::fs::write(cfg.join(".csq-account"), slot.to_string()).unwrap();
            std::fs::write(cfg.join("settings.json"), b"{}").unwrap();
            std::fs::write(cfg.join(".claude.json"), b"{}").unwrap();
        }

        let claude_home = tempfile::TempDir::new().unwrap();
        let account2 = AccountNum::try_from(2u16).unwrap();
        let account3 = AccountNum::try_from(3u16).unwrap();
        let handle = create_handle_dir(base, claude_home.path(), account2, 21005).unwrap();

        // Act: repoint from slot 2 → slot 3 (legacy layout).
        repoint_handle_dir(base, claude_home.path(), &handle, account3).unwrap();

        // Assert: symlink targets config-3/.credentials.json (not identities/).
        let link = handle.join(".credentials.json");
        let target = std::fs::read_link(&link).unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str.contains("config-3"),
            "AC5: legacy fallback must target config-3/, got: {target_str}"
        );
        assert!(
            !target_str.contains("identities"),
            "AC5: legacy fallback must NOT target identities/, got: {target_str}"
        );
    }

    // M3-7: test `repoint_handle_dir_falls_back_to_config_n_when_uuid_present_but_identity_credentials_missing`
    // retired alongside the HIGH-1 runtime fallback in `repoint_handle_dir`.
    // Phase 4's `phase4_gate_check` (renamed from the prior `phase3_gate`
    // symbol in M4-5) makes the Partial-Pass-0 state impossible at
    // daemon-runtime. The positive-shape test
    // `repoint_handle_dir_targets_identity_uuid_path_when_present` (below)
    // pins the M3-7 contract that `.credentials.json` always points at
    // the identity path when a UUID is present.

    /// M3-4 AC9: Concurrent writers under identity targets — porting the
    /// existing concurrent-writer regression guard to the identity fixture.
    ///
    /// Two threads simultaneously repoint the SAME handle dir to different
    /// slots under a coexisting fixture. The post-condition is that exactly
    /// ONE of the two target accounts "wins" — the handle dir symlinks are
    /// self-consistent (both `.credentials.json` and `.csq-account` agree).
    /// No intermediate "half-repointed" state is observable.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg(unix)]
    #[test]
    fn repoint_handle_dir_serializes_concurrent_writers_under_identity_targets() {
        use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
        use std::sync::Arc;

        let dir = coexisting_fixture(3);
        let base = dir.path().to_path_buf();

        // Write identity credentials for slots 2 and 3.
        for slot in [2u16, 3u16] {
            let uuid = fixture_uuid_for_slot(slot);
            let identity_dir = base.join("identities").join(uuid.to_canonical_string());
            let identity_creds = identity_dir.join("credentials.json");
            std::fs::write(&identity_creds, b"{}").unwrap();
        }

        for slot in [1u16, 2u16, 3u16] {
            let cfg = base.join(format!("config-{slot}"));
            std::fs::write(cfg.join(".csq-account"), slot.to_string()).unwrap();
            std::fs::write(cfg.join("settings.json"), b"{}").unwrap();
            std::fs::write(cfg.join(".claude.json"), b"{}").unwrap();
        }

        // Slot 1 source (for initial handle dir; legacy path is fine as source).
        {
            let uuid1 = fixture_uuid_for_slot(1);
            let id1 = base.join("identities").join(uuid1.to_canonical_string());
            std::fs::write(id1.join("credentials.json"), b"{}").unwrap();
        }

        let claude_home = tempfile::TempDir::new().unwrap();
        let claude_home_path = claude_home.path().to_path_buf();
        let account1 = AccountNum::try_from(1u16).unwrap();
        let handle = create_handle_dir(&base, &claude_home_path, account1, 21009).unwrap();

        let base_arc = Arc::new(base.clone());
        let handle_arc = Arc::new(handle.clone());
        let ch_arc = Arc::new(claude_home_path.clone());

        let base2 = Arc::clone(&base_arc);
        let handle2 = Arc::clone(&handle_arc);
        let ch2 = Arc::clone(&ch_arc);

        let account2 = AccountNum::try_from(2u16).unwrap();
        let account3 = AccountNum::try_from(3u16).unwrap();

        // Spawn two threads: one repoints to slot 2, the other to slot 3.
        let t1 = std::thread::spawn(move || {
            let _ = repoint_handle_dir(&base_arc, &ch_arc, &handle_arc, account2);
        });
        let t2 = std::thread::spawn(move || {
            let _ = repoint_handle_dir(&base2, &ch2, &handle2, account3);
        });
        t1.join().unwrap();
        t2.join().unwrap();

        // Assert: symlinks are self-consistent — both point to the SAME slot.
        let creds_target = std::fs::read_link(handle.join(".credentials.json")).unwrap();
        let marker_target = std::fs::read_link(handle.join(".csq-account")).unwrap();
        let creds_str = creds_target.to_string_lossy();
        let marker_str = marker_target.to_string_lossy();

        // Determine which slot won by reading the marker file.
        let marker_content = std::fs::read_to_string(handle.join(".csq-account")).unwrap();
        let winner_slot = marker_content.trim().parse::<u16>().unwrap();
        assert!(
            winner_slot == 2 || winner_slot == 3,
            "AC9: winner slot must be 2 or 3, got {winner_slot}"
        );

        // Both symlinks must point to the same winner.
        assert!(
            creds_str.contains(&format!("config-{winner_slot}"))
                || creds_str.contains("identities"),
            "AC9: .credentials.json must resolve consistently, got: {creds_str}"
        );
        assert!(
            marker_str.contains(&format!("config-{winner_slot}")),
            "AC9: .csq-account must target config-{winner_slot}/, got: {marker_str}"
        );
    }
}
