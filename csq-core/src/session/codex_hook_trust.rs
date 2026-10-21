//! Carry Codex-owned hook approvals across csq handle dirs.
//!
//! Codex stores hook trust in the slot `config.toml` as
//! `[hooks.state."<CODEX_HOME>/hooks.json:<event>:<group>:<handler>"]` with
//! `trusted_hash = "sha256:..."` and `enabled = bool`. The key embeds the handle's own
//! path, so every new `term-<pid>` handle starts untrusted even though every handle of a
//! slot shares ONE `config.toml` (the handle's `config.toml` is a symlink to the slot's).
//!
//! OWNER RULING 2026-10-15: carry approvals over. csq copies existing owner approvals for
//! byte-identical hooks, and never originates one.
//!
//! This module therefore only ever COPIES an entry that already exists, under the same
//! `event:group:handler` suffix, and only when that entry's `trusted_hash` EQUALS the current
//! content hash of that hook in the global `hooks.json` (`codex_hook_content_hash`, an
//! exact reproduction of Codex's own `currentHash`, pinned by Codex-produced fixtures). The
//! hash is only ever used to COMPARE: csq never writes a hash it computed, never overwrites an
//! existing entry, and never touches a key outside csq's handle dirs.
//!
//! Approval SOURCES are exactly two: (a) another csq `term-<pid>` handle's key directly under
//! this accounts base, and (b) the owner's plain-Codex approval, the `[hooks.state]` key of
//! `<~/.codex>/hooks.json` in `~/.codex/config.toml` (N1b). Project keys, exec/capture keys
//! and other bases' keys are never sources. Matching sources must agree on `enabled` and
//! carry nothing but `trusted_hash` and a bool `enabled`, else nothing is copied (fail
//! toward re-approval).
//!
//! N1b caveat (probed, codex-cli 0.162.1, `R1-PROBES.md` P6): a workspace-write sandboxed
//! Codex cannot write `~/.codex/hooks.json`, `~/.codex/config.toml`, `$CODEX_HOME/config.toml`
//! or the slot config. That holds ONLY because those paths are not writable roots (no rule
//! denies them): a handle or `HOME` under `/tmp`, or inside the workspace, would let an agent
//! write an "approval" csq then carries. Re-probe if the sandbox layout changes.
//!
//! N1b residual, ACCEPTED by the owner: Jack Hong, named acceptor, 2026-10-16: "a same-user
//! program could write a forged approval to ~/.codex and csq would carry and fan it out; it
//! gains no new capability, only persistence and spread". (Round-2 security L3: an unsandboxed
//! same-user principal can write `~/.codex/hooks.json` plus a matching `[hooks.state]` key.)
//!
//! Every csq write of the slot config publishes by atomic exchange and verifies what it
//! displaced by file identity (see
//! `providers::codex::surface::write_config_toml_contents_if_unchanged`). When the swap-back
//! succeeds a concurrent Codex write (tmp-then-rename, verified for codex-cli 0.162.1) can
//! only LOSE csq's write, never be overwritten by it; the failure branches (a failed exchange,
//! a metadata error, a third writer) are listed there, flag the slot `raced` stickily, and are
//! reported by `csq doctor`.
//!
//! Keys name the CANONICAL handle dir (Codex canonicalizes `CODEX_HOME`, probe P8) and hook
//! indexes are positional with gaps (probe P10b); both are mirrored here.
//!
//! Dead handles' keys (`term-<pid>`, `codex-exec-*`, `interactive-capture-*`) are pruned in
//! the same write. Only `term-<pid>` handles carry. See [`carry_hook_trust`] for the
//! create-time purge of a reused PID's keys from every slot and the marker that makes a
//! later repoint safe.

use super::handle_dir::{
    codex_config_dir_of_handle, is_term_handle_dir_name, read_regular_bounded, CAPTURE_DIR_PREFIX,
    EXEC_CODEX_DIR_PREFIX,
};
use crate::providers::codex::surface::{
    config_toml_path, lock_slot_config, note_handle_status,
    write_config_toml_contents_if_unchanged, ConditionalWrite, SlotConfigFault, SlotWriteStatus,
    SLOT_CONFIG_MAX_BYTES,
};
use crate::types::AccountNum;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

const HOOKS_FILE: &str = "hooks.json";
/// A slot config larger than this is left alone (fail safe).
const MAX_CONFIG_BYTES: u64 = SLOT_CONFIG_MAX_BYTES;
/// Above this size the carry stops ADDING entries (it still drops and prunes) and the doctor
/// warns: the config is nearing the 1 MiB bound past which every csq reader gives up.
pub const NEAR_LIMIT_BYTES: u64 = MAX_CONFIG_BYTES / 4 * 3;
/// Read-modify-write attempts when the slot config changes under the carry.
const MAX_ATTEMPTS: usize = 5;
/// Marker file inside a handle dir: written only after a create-time purge of the handle's
/// own keys succeeded in EVERY Codex slot config. See [`carry_hook_trust`].
const PURGED_MARKER: &str = ".csq-hook-trust-purged";

/// One hook of the global `hooks.json`, addressed the way Codex addresses it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct GlobalHook {
    /// Codex's event key (`Stop` -> `stop`; see [`EVENTS`]).
    pub event: String,
    /// Index of the matcher group inside the event (positional, gaps kept).
    pub group: usize,
    /// Index of the handler inside the group.
    pub handler: usize,
    /// Codex's content hash of this hook as the file stands now; `None` when the hook is
    /// outside the shapes the hash was verified for (`codex_hook_content_hash`).
    pub hash: Option<String>,
}

/// Codex's `currentHash` for ONE command hook, reproduced exactly (codex-cli 0.162.1; 31/31
/// Codex-produced fixtures, `session/codex_hook_trust_fixtures.json`):
///
/// `"sha256:" + hex(SHA-256(P))` where `P` is the compact, key-sorted JSON of
/// `{"event_name": <snake event>, "hooks": [<the ONE effective handler>], "matcher": <only
/// when the effective matcher is non-null>}` and the handler is
/// `{"type":"command","command":..,"timeout":<default 600, 0 -> 1>,"async":<default false>,
/// "statusMessage":<only when non-null>,"additionalContextLimit":<only when non-null>}`.
/// The hash does not depend on file formatting, the path, or the group/handler index.
///
/// Source: `HASH-PREMISE.md` (codex-cli 0.162.1, aarch64-apple-darwin; EXACT MATCH on 31
/// Codex-produced hashes). Codex re-verifies `trusted_hash` against its own `currentHash` on
/// every load, so csq's comparison is a PRECONDITION that keeps stale approvals from being
/// copied; Codex stays the authority, and a divergence between this function and Codex
/// fails toward re-approval, never toward running an edited hook. This function MUST be
/// re-validated against fresh Codex-produced fixtures whenever the Codex version changes.
///
/// Fail closed: a shape the hash was NOT verified for returns `None` (so nothing is ever
/// copied for it) instead of an approximation. Unverified: events other than `stop`,
/// `pre_tool_use`, `post_tool_use`, `session_start` and `user_prompt_submit`; a matcher on
/// `session_start`/`user_prompt_submit`; any handler field not named above (Codex ignores
/// an unknown field when hashing, but csq does not guess: no copy); `additionalContextLimit` anywhere but `stop`
/// (dropped by Codex) and `pre_tool_use`; `commandWindows`; a non-`command` handler.
pub(crate) fn codex_hook_content_hash(
    event: &str,
    group: &Value,
    handler: &Value,
) -> Option<String> {
    use sha2::{Digest, Sha256};
    let matcher_event = match event {
        "pre_tool_use" | "post_tool_use" => true,
        "stop" => false,
        "session_start" | "user_prompt_submit" => false,
        _ => return None,
    };
    let matcher = match group.get("matcher") {
        None | Some(Value::Null) => None,
        Some(Value::String(m)) => Some(m.as_str()),
        Some(_) => return None,
    };
    if matcher.is_some() && !matcher_event && !matches!(event, "stop") {
        return None;
    }
    let obj = handler.as_object()?;
    // Conservative: any field the verified normalization does not name could change what
    // Codex hashes, so the hook is unverifiable (no copy), never guessed at.
    const KNOWN: [&str; 6] = [
        "type",
        "command",
        "timeout",
        "async",
        "statusMessage",
        "additionalContextLimit",
    ];
    if obj.keys().any(|k| !KNOWN.contains(&k.as_str())) {
        return None;
    }
    if obj.get("type").and_then(Value::as_str) != Some("command")
        || obj.contains_key("commandWindows")
    {
        return None;
    }
    let command = obj.get("command")?.as_str()?;
    let timeout = match obj.get("timeout") {
        None | Some(Value::Null) => 600,
        Some(t) => t.as_u64()?.max(1),
    };
    let is_async = match obj.get("async") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return None,
    };
    let status = match obj.get("statusMessage") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => return None,
    };
    let limit = match (event, obj.get("additionalContextLimit")) {
        (_, None | Some(Value::Null)) | ("stop", _) => None,
        ("pre_tool_use", Some(v)) => Some(v.as_u64()?),
        _ => return None,
    };
    let q = |s: &str| serde_json::to_string(s).ok();
    let mut p = format!("{{\"event_name\":{},\"hooks\":[{{", q(event)?);
    if let Some(l) = limit {
        p.push_str(&format!("\"additionalContextLimit\":{l},"));
    }
    p.push_str(&format!("\"async\":{is_async},\"command\":{}", q(command)?));
    if let Some(s) = status {
        p.push_str(&format!(",\"statusMessage\":{}", q(s)?));
    }
    p.push_str(&format!(",\"timeout\":{timeout},\"type\":\"command\"}}]"));
    if let Some(m) = matcher.filter(|_| matcher_event) {
        p.push_str(&format!(",\"matcher\":{}", q(m)?));
    }
    p.push('}');
    Some(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(p.as_bytes()))
    ))
}

/// Codex's `hooks.json` event names (exact PascalCase) and the snake_case key segment.
/// Probed (codex-cli 0.162.1, `R1-PROBES.md` P10a): any other spelling of these events
/// (`stop`, `STOP`, `pre_tool_use`, `preToolUse`) is dropped SILENTLY while the rest of the
/// file loads.
///
/// The first five have a verified content hash. `PreCompact`, `SubagentStop` and
/// `PermissionRequest` are probed as LISTED by Codex (codex-cli 0.162.1, `R3` probe: keys
/// `pre_compact`, `subagent_stop`, `permission_request`) but their hash is not verified, so
/// they count as hooks with no hash: the doctor never reads them as trusted and they are
/// never copied.
const EVENTS: [(&str, &str); 8] = [
    ("Stop", "stop"),
    ("PreToolUse", "pre_tool_use"),
    ("PostToolUse", "post_tool_use"),
    ("SessionStart", "session_start"),
    ("UserPromptSubmit", "user_prompt_submit"),
    ("PreCompact", "pre_compact"),
    ("SubagentStop", "subagent_stop"),
    ("PermissionRequest", "permission_request"),
];

/// PascalCase event names probed as DROPPED silently by Codex (listed nowhere, the rest of
/// the file still loads).
const DROPPED_BY_CODEX: [&str; 1] = ["Notification"];

/// Codex's event-name style: ASCII alphanumerics starting upper case with at least one lower
/// case letter. `STOP`, `stop`, `pre_tool_use` and `preToolUse` are not (probed: dropped).
fn is_pascal_case(name: &str) -> bool {
    name.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && name.chars().all(|c| c.is_ascii_alphanumeric())
        && name.chars().any(|c| c.is_ascii_lowercase())
}

/// Every hook Codex lists for the global `hooks.json` bytes, addressed by Codex's indexes
/// (probed, `R1-PROBES.md` P10b): indexes are POSITIONAL with gaps, never renumbered. A
/// handler that parses but is skipped (`prompt`, `agent`, an empty `command`) keeps its
/// handler slot; a group that lists nothing keeps its group index; an `mcp_tool` handler is
/// listed (with no hash: csq cannot verify it, so it is never copied).
///
/// `None` means csq cannot establish the list: Codex drops the WHOLE file for a malformed
/// entry (unparseable bytes, a root or `hooks` that is not an object, an event that is not an
/// array, a group that is not an object or whose `hooks` is not an array, a handler that is
/// not an object, has an unknown `type`, or is a `command` without a string `command`), and
/// csq also gives up on a PascalCase event name it has neither listed nor probed as dropped.
/// The caller treats `None` as UNKNOWN (never "no hooks", never trusted) and copies nothing.
pub(crate) fn global_hooks(bytes: &[u8]) -> Option<Vec<GlobalHook>> {
    let root = serde_json::from_slice::<Value>(bytes).ok()?;
    let root = root.as_object()?;
    let Some(events) = root.get("hooks") else {
        return Some(Vec::new());
    };
    let events = events.as_object()?;
    let mut out = Vec::new();
    for (name, groups) in events {
        let Some((_, event)) = EVENTS.iter().find(|(n, _)| n == name) else {
            // Probed-dropped names and every non-PascalCase spelling (`STOP`, `stop`, ...) are
            // dropped silently, as Codex does. An unprobed PascalCase name might be a hook
            // Codex lists, so csq cannot establish the list: UNKNOWN.
            if is_pascal_case(name) && !DROPPED_BY_CODEX.contains(&name.as_str()) {
                return None;
            }
            continue;
        };
        let groups = groups.as_array()?;
        for (group, g) in groups.iter().enumerate() {
            let g_obj = g.as_object()?;
            let Some(handlers) = g_obj.get("hooks") else {
                continue;
            };
            for (handler, h) in handlers.as_array()?.iter().enumerate() {
                let ho = h.as_object()?;
                let hash = match ho.get("type")?.as_str()? {
                    "command" => {
                        let cmd = ho.get("command")?.as_str()?;
                        if cmd.is_empty() {
                            continue;
                        }
                        codex_hook_content_hash(event, g, h)
                    }
                    "mcp_tool" => None,
                    "prompt" | "agent" => continue,
                    _ => return None,
                };
                out.push(GlobalHook {
                    hash,
                    event: (*event).to_owned(),
                    group,
                    handler,
                });
            }
        }
    }
    Some(out)
}

/// A directory path in the form Codex writes into a `[hooks.state]` key: canonicalized
/// (probed, `R1-PROBES.md` P8: directory symlinks, a trailing slash and `..` collapse; the
/// `hooks.json` file inside is NOT resolved). An unresolvable path is used as given.
fn canon_dir(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// The global hook list for the doctor and the carry: `Some(vec![])` for no global file or no
/// hooks, `None` (UNKNOWN) for a file that exists but cannot be used.
fn read_global_hooks(global: Option<&Path>) -> Option<Vec<GlobalHook>> {
    let Some(g) = global else {
        return Some(Vec::new());
    };
    if matches!(std::fs::metadata(g), Err(e) if e.kind() == io::ErrorKind::NotFound) {
        return Some(Vec::new());
    }
    global_hooks(&read_regular_bounded(g, false)?)
}

/// A parsed `[hooks.state]` key.
struct StateKey {
    /// `<CODEX_HOME>/hooks.json` as the key names it.
    hooks_path: PathBuf,
    event: String,
    group: usize,
    handler: usize,
}

impl StateKey {
    fn parse(key: &str) -> Option<Self> {
        let mut it = key.rsplitn(4, ':');
        let handler = it.next()?.parse().ok()?;
        let group = it.next()?.parse().ok()?;
        let event = it.next()?.to_owned();
        let hooks_path = PathBuf::from(it.next()?);
        if hooks_path.file_name()?.to_str()? != HOOKS_FILE || event.is_empty() {
            return None;
        }
        Some(Self {
            hooks_path,
            event,
            group,
            handler,
        })
    }

    fn home(&self) -> Option<&Path> {
        self.hooks_path.parent()
    }

    fn same_hook(&self, h: &GlobalHook) -> bool {
        self.event == h.event && self.group == h.group && self.handler == h.handler
    }
}

/// The `[hooks.state]` key Codex uses for `hook` under `handle_dir`.
pub(crate) fn state_key(handle_dir: &Path, hook: &GlobalHook) -> String {
    format!(
        "{}:{}:{}:{}",
        handle_dir.join(HOOKS_FILE).display(),
        hook.event,
        hook.group,
        hook.handler
    )
}

/// Whether `name` is a csq handle dir name whose Codex hook keys may be pruned once the dir
/// is gone: `term-<pid>`, a `csq exec` Codex dir, or a subscription-capture dir.
fn is_prunable_handle_dir_name(name: &str) -> bool {
    is_term_handle_dir_name(name)
        || [EXEC_CODEX_DIR_PREFIX, CAPTURE_DIR_PREFIX]
            .iter()
            .any(|p| name.strip_prefix(p).is_some_and(|rest| !rest.is_empty()))
}

/// Whether `home` is a csq handle dir directly under `base_dir` ([`is_prunable_handle_dir_name`])
/// that no longer exists. An IO error other than NotFound keeps the key (fail safe).
fn is_dead_csq_handle(base_dir: &Path, home: &Path) -> bool {
    let Some(name) = home.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if home.parent() != Some(base_dir) || !is_prunable_handle_dir_name(name) {
        return false;
    }
    matches!(
        std::fs::symlink_metadata(home),
        Err(e) if e.kind() == io::ErrorKind::NotFound
    )
}

/// What one carry pass changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CarryReport {
    /// Entries copied for the handle.
    pub copied: usize,
    /// Dead handles' entries removed.
    pub pruned: usize,
    /// Entries keyed to the handle's own path dropped before any copy.
    pub dropped_own: usize,
    /// The copy half was skipped for ANY cause (the first pass failed, whatever the error; the
    /// slot config is near the size bound; the global hooks file is unusable); at most the
    /// drop-only retry ran. The handle starts untrusted (re-approval). Never silent: the
    /// doctor shows `carry-skipped` and the fixed tag `codex_hook_trust_carry_skipped` is logged.
    pub carry_skipped: bool,
}

impl CarryReport {
    /// Nothing was copied, dropped or pruned (`carry_skipped` is a report, not a change).
    fn is_noop(&self) -> bool {
        self.copied == 0 && self.pruned == 0 && self.dropped_own == 0
    }

    fn add(&mut self, o: Self) {
        self.copied += o.copied;
        self.pruned += o.pruned;
        self.dropped_own += o.dropped_own;
        self.carry_skipped |= o.carry_skipped;
    }
}

/// Which lifecycle event the carry runs for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarryMode {
    /// A new handle: every slot entry already keyed to its own path belongs to an earlier
    /// handle that reused the PID, and is dropped from EVERY Codex slot config before any
    /// copy so it never inherits state (including `enabled = false`), now or after a swap.
    Create,
    /// A live handle moved onto a slot. Entries for its own path in the target slot are the
    /// owner's and stay ONLY when the handle dir carries the purge marker (its creation
    /// purged every slot); without the marker they are treated as a predecessor's and
    /// dropped like [`CarryMode::Create`] does.
    Repoint,
}

/// What one slot-config rewrite does.
struct Plan<'a> {
    base_dir: &'a Path,
    handle_dir: &'a Path,
    drop_own: bool,
    /// Copy sources and targets; `None` for a slot that is only purged.
    copy: Option<Copy<'a>>,
}

struct Copy<'a> {
    hooks: &'a [GlobalHook],
    global_sources: &'a [(StateKey, toml::Table)],
}

/// The ONE entry a copy would write from a matching source: only `trusted_hash` and a bool
/// `enabled`. `None` when the source cannot be copied faithfully (a field beyond those two,
/// or a non-bool `enabled`).
fn copyable(src: &toml::Table) -> Option<(String, Option<bool>)> {
    let mut hash = None;
    let mut enabled = None;
    for (k, v) in src {
        match k.as_str() {
            "trusted_hash" => hash = Some(v.as_str()?.to_owned()),
            "enabled" => enabled = Some(v.as_bool()?),
            _ => return None,
        }
    }
    Some((hash?, enabled))
}

/// Applies drop-own + copy + prune to a parsed slot config.
fn apply(doc: &mut toml::Table, plan: &Plan<'_>) -> CarryReport {
    let mut report = CarryReport::default();
    let mut state = doc
        .get("hooks")
        .and_then(|h| h.get("state"))
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    let home_of = |k: &str| StateKey::parse(k).and_then(|k| k.home().map(Path::to_path_buf));

    // DROP OWN, before any copy.
    if plan.drop_own {
        let own: Vec<String> = state
            .keys()
            .filter(|k| home_of(k).as_deref() == Some(plan.handle_dir))
            .cloned()
            .collect();
        for key in &own {
            state.remove(key);
        }
        report.dropped_own = own.len();
    }

    // COPY: only from an entry that already exists. A source is (a) another csq `term-<pid>`
    // handle's key directly under this accounts base, or (b) the user-global config's key
    // for the global hooks file. Project keys, exec/capture keys and foreign keys are never
    // sources.
    if let Some(copy) = &plan.copy {
        let mut sources: Vec<(StateKey, toml::Table)> = state
            .iter()
            .filter_map(|(k, v)| Some((StateKey::parse(k)?, v.as_table()?.clone())))
            .filter(|(k, _)| {
                k.home().is_some_and(|h| {
                    h != plan.handle_dir
                        && h.parent() == Some(plan.base_dir)
                        && h.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(is_term_handle_dir_name)
                })
            })
            .collect();
        sources.extend(copy.global_sources.iter().map(|(k, t)| {
            (
                StateKey {
                    hooks_path: k.hooks_path.clone(),
                    event: k.event.clone(),
                    group: k.group,
                    handler: k.handler,
                },
                t.clone(),
            )
        }));
        let mut copies: Vec<(String, toml::Table)> = Vec::new();
        for hook in copy.hooks {
            let new_key = state_key(plan.handle_dir, hook);
            if state.contains_key(&new_key) {
                continue;
            }
            // Every source for this hook whose hash EQUALS the hook's hash now (the ONLY
            // proof an approval is current).
            let matching: Vec<&toml::Table> = sources
                .iter()
                .filter(|(k, _)| k.same_hook(hook))
                .filter(|(_, t)| {
                    t.get("trusted_hash").and_then(toml::Value::as_str) == hook.hash.as_deref()
                        && hook.hash.is_some()
                })
                .map(|(_, t)| t)
                .collect();
            let Some(first) = matching.first().and_then(|t| copyable(t)) else {
                continue;
            };
            // Fail toward re-approval: every matching source must be copyable and agree on
            // `enabled` (an absent `enabled` is Codex's default, enabled); a disagreement is
            // nobody's decision, so nothing is copied.
            let decision = |c: &(String, Option<bool>)| c.1.unwrap_or(true);
            let all: Option<Vec<(String, Option<bool>)>> =
                matching.iter().map(|t| copyable(t)).collect();
            let Some(all) = all else { continue };
            if !all.iter().all(|c| decision(c) == decision(&first)) {
                continue;
            }
            let mut entry = toml::Table::new();
            entry.insert("trusted_hash".into(), toml::Value::String(first.0.clone()));
            if all.iter().any(|c| c.1.is_some()) {
                entry.insert("enabled".into(), toml::Value::Boolean(decision(&first)));
            }
            copies.push((new_key, entry));
        }
        for (key, entry) in copies {
            state.insert(key, toml::Value::Table(entry));
            report.copied += 1;
        }
    }

    // PRUNE: only csq handle keys whose dir is gone.
    let dead: Vec<String> = state
        .keys()
        .filter(|k| home_of(k).is_some_and(|home| is_dead_csq_handle(plan.base_dir, &home)))
        .cloned()
        .collect();
    for key in &dead {
        state.remove(key);
    }
    report.pruned = dead.len();

    if report == CarryReport::default() {
        return report;
    }
    if state.is_empty() {
        if let Some(hooks_tbl) = doc.get_mut("hooks").and_then(toml::Value::as_table_mut) {
            hooks_tbl.remove("state");
            if hooks_tbl.is_empty() {
                doc.remove("hooks");
            }
        }
    } else if let Some(hooks_tbl) = doc
        .entry("hooks")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
    {
        hooks_tbl.insert("state".into(), toml::Value::Table(state));
    }
    report
}

/// Approvals the owner made in plain Codex: the user-global config's `[hooks.state]` entries
/// keyed to `<~/.codex>/hooks.json` (`global`). The config is `global`'s sibling
/// `config.toml`. Unreadable or unparseable means no sources.
fn global_config_sources(global: &Path) -> Vec<(StateKey, toml::Table)> {
    // Codex keys the global file as `<canonical ~/.codex>/hooks.json`.
    let Some(global_key) = global
        .parent()
        .zip(global.file_name())
        .map(|(d, f)| canon_dir(d).join(f))
    else {
        return Vec::new();
    };
    let Some(text) = global
        .parent()
        .and_then(|d| read_regular_bounded(&d.join("config.toml"), false))
        .and_then(|b| String::from_utf8(b).ok())
    else {
        return Vec::new();
    };
    let Ok(doc) = toml::from_str::<toml::Table>(&text) else {
        return Vec::new();
    };
    doc.get("hooks")
        .and_then(|h| h.get("state"))
        .and_then(toml::Value::as_table)
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| Some((StateKey::parse(k)?, v.as_table()?.clone())))
        .filter(|(k, _)| k.hooks_path == global_key)
        .collect()
}

/// What one locked rewrite of a slot config left behind.
#[derive(Debug)]
struct SlotRewrite {
    report: CarryReport,
    /// The handle's own `[hooks.state]` entries in the config as csq last published it (or as
    /// it read it when nothing needed writing): what a post-carry re-read must still find.
    own: BTreeMap<String, toml::Value>,
}

/// The `[hooks.state]` entries of `doc` keyed to `handle_dir` (the canonical handle dir).
fn own_keys(doc: &toml::Table, handle_dir: &Path) -> BTreeMap<String, toml::Value> {
    doc.get("hooks")
        .and_then(|h| h.get("state"))
        .and_then(toml::Value::as_table)
        .into_iter()
        .flatten()
        .filter(|(k, _)| {
            StateKey::parse(k)
                .and_then(|k| k.home().map(Path::to_path_buf))
                .as_deref()
                == Some(handle_dir)
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// One locked read-modify-write of `config-<account>/config.toml`. A slot without a
/// `config.toml` is left alone (no lock file is created in it). The per-slot lock is held
/// across the read, the apply and the write. The write PUBLISHES BY ATOMIC EXCHANGE and
/// verifies the file it displaced against the bytes read here (see
/// `write_config_toml_contents_if_unchanged`; Codex takes no lock), and a change re-runs the
/// whole pass up to [`MAX_ATTEMPTS`] times. An unreadable, oversize, unparseable or wrongly
/// shaped config is an error carrying its [`SlotConfigFault`] class, never silently skipped.
fn rewrite_slot(base_dir: &Path, account: AccountNum, plan: &Plan<'_>) -> io::Result<SlotRewrite> {
    let path = config_toml_path(base_dir, account);
    let nothing = || SlotRewrite {
        report: CarryReport::default(),
        own: BTreeMap::new(),
    };
    if matches!(std::fs::symlink_metadata(&path), Err(e) if e.kind() == io::ErrorKind::NotFound) {
        return Ok(nothing());
    }
    let _lock = lock_slot_config(base_dir, account)?;
    let unusable = |fault: SlotConfigFault| io::Error::new(io::ErrorKind::InvalidData, fault);
    for _ in 0..MAX_ATTEMPTS {
        let Some(original) = read_regular_bounded(&path, false) else {
            return match std::fs::metadata(&path) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(nothing()),
                Ok(m) if m.len() > MAX_CONFIG_BYTES => Err(unusable(SlotConfigFault::Oversize)),
                _ => Err(unusable(SlotConfigFault::Unreadable)),
            };
        };
        let text =
            std::str::from_utf8(&original).map_err(|_| unusable(SlotConfigFault::Malformed))?;
        let mut doc = toml::from_str::<toml::Table>(text)
            .map_err(|_| unusable(SlotConfigFault::Malformed))?;
        // A non-table `hooks` / `hooks.state` is not ours to repair.
        let shape_ok = doc.get("hooks").is_none_or(|h| {
            h.as_table()
                .is_some_and(|t| t.get("state").is_none_or(toml::Value::is_table))
        });
        if !shape_ok {
            return Err(unusable(SlotConfigFault::Malformed));
        }
        let near_limit = original.len() as u64 > NEAR_LIMIT_BYTES;
        let size_skipped = near_limit && plan.copy.is_some();
        let limited;
        let plan = if size_skipped {
            warn!(
                error_kind = "codex_hook_trust_config_near_limit",
                "slot config is near the size bound; not adding hook approvals"
            );
            limited = Plan {
                copy: None,
                base_dir: plan.base_dir,
                handle_dir: plan.handle_dir,
                drop_own: plan.drop_own,
            };
            &limited
        } else {
            plan
        };
        let mut report = apply(&mut doc, plan);
        report.carry_skipped = size_skipped;
        let own = own_keys(&doc, plan.handle_dir);
        if report.is_noop() {
            return Ok(SlotRewrite { report, own });
        }
        let out = toml::to_string(&doc)
            .map_err(|_| io::Error::other("could not serialize Codex slot config"))?;
        match write_config_toml_contents_if_unchanged(&path, &out, Some(&original))? {
            ConditionalWrite::Written => {
                if report.pruned > 0 {
                    info!(
                        event_kind = "codex_hook_trust_pruned",
                        count = report.pruned,
                        "pruned dead handle hook trust entries"
                    );
                }
                return Ok(SlotRewrite { report, own });
            }
            ConditionalWrite::Changed => warn!(
                error_kind = "codex_hook_trust_config_changed",
                "slot config changed while carrying hook trust; retrying"
            ),
        }
    }
    Err(SlotConfigFault::KeptChanging.error(io::ErrorKind::WouldBlock))
}

/// Read-only: the handle's own `[hooks.state]` entries as the slot config holds them now
/// (empty when the slot has no config).
fn read_own_keys(
    base_dir: &Path,
    account: AccountNum,
    handle_dir: &Path,
) -> io::Result<BTreeMap<String, toml::Value>> {
    let path = config_toml_path(base_dir, account);
    if matches!(std::fs::symlink_metadata(&path), Err(e) if e.kind() == io::ErrorKind::NotFound) {
        return Ok(BTreeMap::new());
    }
    let fault = |f: SlotConfigFault| io::Error::new(io::ErrorKind::InvalidData, f);
    let bytes =
        read_regular_bounded(&path, false).ok_or_else(|| fault(SlotConfigFault::Unreadable))?;
    let doc = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|t| toml::from_str::<toml::Table>(t).ok())
        .ok_or_else(|| fault(SlotConfigFault::Malformed))?;
    Ok(own_keys(&doc, handle_dir))
}

/// Every Codex-style slot config dir `config-<N>` under `base_dir` (valid [`AccountNum`] only).
fn slot_accounts(base_dir: &Path) -> Vec<AccountNum> {
    let Ok(rd) = std::fs::read_dir(base_dir) else {
        return Vec::new();
    };
    let mut out: Vec<AccountNum> = rd
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let n = name.to_str()?.strip_prefix("config-")?;
            if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            AccountNum::try_from(n.parse::<u16>().ok()?).ok()
        })
        .collect();
    out.sort_by_key(|a| a.get());
    out
}

/// Copies existing approvals to `handle_dir`'s keys in slot `account`'s config (from other
/// csq `term-<pid>` handles of the slot and from the user-global config, never originating
/// one) and prunes dead handles' keys. The target config is `config-<account>/config.toml`
/// built from the validated [`AccountNum`], never read back from the handle's symlink.
///
/// Only `term-<pid>` handles carry: `csq exec` and capture dirs are not interactive and
/// get nothing.
///
/// On create (and on repoint of a handle without the purge marker) the handle's own keys
/// are first dropped from EVERY Codex slot config and dead handle keys are pruned there; the
/// marker `PURGED_MARKER` is written into the handle dir only when every slot was purged,
/// so a later repoint can tell "keys written during this handle's life" from "keys a
/// predecessor with the same PID left in another slot" (a re-created dir has no marker until
/// its own create purges). A failure to purge a slot is returned or logged, never silent.
pub fn carry_hook_trust(
    base_dir: &Path,
    handle_dir: &Path,
    account: AccountNum,
    global: Option<&Path>,
    mode: CarryMode,
) -> io::Result<CarryReport> {
    let none = CarryReport::default();
    let name = handle_dir.file_name().and_then(|n| n.to_str());
    let is_term = name.is_some_and(is_term_handle_dir_name);
    // `csq exec` and capture dirs never carry, but a reused PID's stale keys under their
    // names are still dropped (no copy, no marker).
    let Some(handle_name) = name.filter(|n| is_prunable_handle_dir_name(n)) else {
        return Ok(none);
    };
    if handle_dir.parent() != Some(base_dir) {
        return Ok(none);
    }
    // Keys name the CANONICAL handle dir (Codex canonicalizes CODEX_HOME), so every key
    // comparison below uses the canonical base and handle dir; file paths use the raw ones.
    let base_key = canon_dir(base_dir);
    let handle_key = canon_dir(handle_dir);
    // Unknown global hooks: copy nothing (the drop and prune still run).
    let hooks = if is_term {
        read_global_hooks(global)
    } else {
        None
    };
    // A carry is owed only to a terminal handle with at least one global hook (or an unusable
    // hooks file, which could hold some): every way of not delivering it is flagged.
    let carry_owed = is_term && hooks.as_ref().is_none_or(|h| !h.is_empty());
    let global_sources = global.map_or_else(Vec::new, global_config_sources);
    let marker = handle_dir.join(PURGED_MARKER);
    let purge = !is_term || mode == CarryMode::Create || !marker_present(handle_dir);
    let mut total = none;
    let mut purged_all = purge;
    let flag = |slot: AccountNum, status: SlotWriteStatus, set: bool| {
        note_handle_status(base_dir, slot, status, handle_name, set);
    };
    if purge {
        let deadline = std::time::Instant::now() + purge_deadline();
        for slot in slot_accounts(base_dir) {
            if slot == account {
                continue;
            }
            if std::time::Instant::now() >= deadline {
                // Skip the rest: no marker, so a later swap re-purges; the owner is told.
                purged_all = false;
                if config_toml_path(base_dir, slot).exists() {
                    flag(slot, SlotWriteStatus::PurgeFailed, true);
                }
                warn!(
                    error_kind = "codex_hook_trust_deadline",
                    "create-time hook trust purge hit its deadline; remaining slots skipped"
                );
                continue;
            }
            let plan = Plan {
                base_dir: &base_key,
                handle_dir: &handle_key,
                drop_own: true,
                copy: None,
            };
            match rewrite_slot(base_dir, slot, &plan) {
                Ok(r) => {
                    total.add(r.report);
                    flag(slot, SlotWriteStatus::PurgeFailed, false);
                }
                Err(e) => {
                    purged_all = false;
                    flag(slot, SlotWriteStatus::PurgeFailed, true);
                    warn!(
                        error_kind = "codex_hook_trust_drop_failed",
                        io_kind = ?e.kind(),
                        "could not drop stale hook trust entries from a slot config"
                    );
                }
            }
        }
    }
    let plan = Plan {
        base_dir: &base_key,
        handle_dir: &handle_key,
        drop_own: purge,
        copy: hooks.as_deref().map(|hooks| Copy {
            hooks,
            global_sources: &global_sources,
        }),
    };
    // Whether the copy half was skipped, for any cause.
    let mut skipped = carry_owed && hooks.is_none();
    let mut rewrite = match rewrite_slot(base_dir, account, &plan) {
        Ok(r) => r,
        Err(first) if purge => {
            // The slot the terminal runs on must not keep a predecessor's keys: one
            // drop-only retry (no copy), then the error stands and the launch is refused.
            warn!(
                error_kind = "codex_hook_trust_drop_failed",
                io_kind = ?first.kind(),
                "could not drop stale hook trust entries from the target slot config; retrying drop-only"
            );
            let retry = Plan {
                base_dir: &base_key,
                handle_dir: &handle_key,
                drop_own: true,
                copy: None,
            };
            match rewrite_slot(base_dir, account, &retry) {
                Ok(r) => {
                    // The retry never copies: whatever made the first pass fail, the carry
                    // was skipped.
                    skipped = carry_owed;
                    r
                }
                Err(e) => {
                    flag(account, SlotWriteStatus::PurgeFailed, true);
                    return Err(e);
                }
            }
        }
        Err(e) => {
            if carry_owed {
                flag(account, SlotWriteStatus::CarrySkipped, true);
                warn!(
                    error_kind = "codex_hook_trust_carry_skipped",
                    "hook approvals were not carried: the slot config could not be updated"
                );
            }
            return Err(e);
        }
    };
    total.add(rewrite.report);
    skipped |= carry_owed && rewrite.report.carry_skipped;
    // Post-carry re-read: this handle has not launched, so its own entries in the slot
    // config must be exactly what csq published. A predecessor's entries that a late Codex
    // rename brought back are purged once more; if they keep coming back the launch is
    // refused.
    for pass in 0..2 {
        #[cfg(test)]
        test_seam::AFTER_TARGET_REWRITE.with(|h| {
            if let Some(hook) = h.borrow().as_ref() {
                hook(&config_toml_path(base_dir, account));
            }
        });
        if !purge {
            break;
        }
        let found = read_own_keys(base_dir, account, &handle_key).inspect_err(|_| {
            flag(account, SlotWriteStatus::PurgeFailed, true);
        })?;
        if found == rewrite.own {
            break;
        }
        warn!(
            error_kind = "codex_hook_trust_resurrected_keys",
            "unexpected hook approvals for this handle reappeared after the purge"
        );
        if pass == 1 {
            flag(account, SlotWriteStatus::PurgeFailed, true);
            return Err(SlotConfigFault::ResurrectedKeys.error(io::ErrorKind::InvalidData));
        }
        rewrite = rewrite_slot(base_dir, account, &plan).inspect_err(|_| {
            flag(account, SlotWriteStatus::PurgeFailed, true);
        })?;
        total.add(rewrite.report);
        skipped |= carry_owed && rewrite.report.carry_skipped;
    }
    if purge {
        flag(account, SlotWriteStatus::PurgeFailed, false);
    }
    total.carry_skipped = skipped;
    if skipped {
        flag(account, SlotWriteStatus::CarrySkipped, true);
        warn!(
            error_kind = "codex_hook_trust_carry_skipped",
            "hook approvals were not carried to this handle"
        );
    } else {
        flag(account, SlotWriteStatus::CarrySkipped, false);
    }
    if purged_all && is_term {
        if let Err(e) = write_marker(&marker) {
            // Without the marker a later repoint drops its own keys (re-approval), so the
            // handle is fine; the owner is told through the doctor.
            flag(account, SlotWriteStatus::PurgeFailed, true);
            warn!(
                error_kind = "codex_hook_trust_marker_failed",
                io_kind = ?e.kind(),
                "could not write the hook trust purge marker"
            );
        }
    }
    Ok(total)
}

/// Total wall-clock the cross-slot purge of one create may take before the remaining slots
/// are skipped (each slot already has its own bounded lock wait and attempts).
const PURGE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(8);

fn purge_deadline() -> std::time::Duration {
    #[cfg(test)]
    if let Some(d) = test_seam::DEADLINE.with(std::cell::Cell::get) {
        return d;
    }
    PURGE_DEADLINE
}

/// Test seam: overrides [`PURGE_DEADLINE`].
#[cfg(test)]
pub(crate) mod test_seam {
    use std::cell::RefCell;
    type Hook = Box<dyn Fn(&std::path::Path)>;
    thread_local! {
        pub(crate) static DEADLINE: std::cell::Cell<Option<std::time::Duration>> =
            const { std::cell::Cell::new(None) };
        /// Runs with the target slot's `config.toml` path right after the carry's target
        /// rewrite succeeded and before the post-carry re-read.
        pub(crate) static AFTER_TARGET_REWRITE: RefCell<Option<Hook>> =
            const { RefCell::new(None) };
    }
}

/// Creates the purge marker exclusively: any existing entry (a stale marker, or a planted
/// symlink, which is unlinked and never followed) is removed first, then the file is made
/// with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600.
fn write_marker(marker: &Path) -> io::Result<()> {
    match std::fs::remove_file(marker) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    use std::io::Write;
    opts.open(marker)?.write_all(b"purged\n")
}

/// Whether a repoint of `handle_dir` purges its own keys from the target slot first: only a
/// handle with no purge marker (the marker is written when its create purged every slot).
fn marker_present(handle_dir: &Path) -> bool {
    std::fs::symlink_metadata(handle_dir.join(PURGED_MARKER)).is_ok_and(|m| m.is_file())
}

/// [`carry_hook_trust`] for a repoint. A failure is an ERROR only when the repoint had to
/// purge the target slot (no marker: the handle's keys there may be a predecessor's), so the
/// caller refuses the swap; for a marked handle it is logged with a fixed tag and never fails
/// the swap (hook approval is a convenience, not launch-critical).
pub(crate) fn carry_hook_trust_for_repoint(
    base_dir: &Path,
    handle_dir: &Path,
    account: AccountNum,
    global: Option<&Path>,
) -> io::Result<()> {
    let purges = !marker_present(handle_dir);
    match carry_hook_trust(base_dir, handle_dir, account, global, CarryMode::Repoint) {
        Ok(_) => Ok(()),
        Err(e) if purges => Err(e),
        Err(e) => {
            warn!(
                error_kind = "codex_hook_trust_carry_failed",
                io_kind = ?e.kind(),
                "could not carry codex hook trust to the handle"
            );
            Ok(())
        }
    }
}

/// Per-handle hook trust counts for `csq doctor`.
#[derive(serde::Serialize, Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HookTrustCounts {
    /// Hooks whose entry equals the hook's current hash and is not disabled.
    pub trusted: usize,
    /// Hooks with no entry for this handle, or an entry without a `trusted_hash` (never
    /// approved).
    pub untrusted: usize,
    /// Hooks whose entry carries a different hash (the hook changed since approval).
    pub modified: usize,
    /// Hooks with an entry whose verdict csq cannot give: a hook shape the hash was not
    /// verified for, or an entry that is not a table or has a non-bool `enabled`.
    pub unverifiable: usize,
    /// Hooks approved at their current hash whose entry says `enabled = false`: Codex runs
    /// none of them. Never trusted.
    pub disabled: usize,
    /// csq could not establish the hook list (the global hooks file is unreadable, oversize
    /// or malformed) or could not read the handle's slot config: no verdict is claimed.
    pub unknown: bool,
}

/// Whether the slot config the handle resolves is within [`NEAR_LIMIT_BYTES`] of the read
/// bound (read-only).
#[must_use]
pub fn slot_config_near_limit(handle_dir: &Path) -> bool {
    codex_config_dir_of_handle(handle_dir)
        .and_then(|d| std::fs::metadata(d.join("config.toml")).ok())
        .is_some_and(|m| m.len() > NEAR_LIMIT_BYTES)
}

/// Whether the slot config the handle resolves is OVER the read bound (read-only): csq will
/// neither read nor rewrite it.
#[must_use]
pub fn slot_config_oversize(handle_dir: &Path) -> bool {
    codex_config_dir_of_handle(handle_dir)
        .and_then(|d| std::fs::metadata(d.join("config.toml")).ok())
        .is_some_and(|m| m.len() > MAX_CONFIG_BYTES)
}

/// Read-only: the trust status of every global hook for `handle_dir`, from the slot config
/// the handle resolves. A missing global means no hooks; a global or slot config that
/// exists but cannot be used sets `unknown`; a missing slot config counts every hook
/// untrusted.
#[must_use]
pub fn hook_trust_counts(handle_dir: &Path, global: Option<&Path>) -> HookTrustCounts {
    let mut counts = HookTrustCounts::default();
    let Some(hooks) = read_global_hooks(global) else {
        counts.unknown = true;
        return counts;
    };
    let cfg = codex_config_dir_of_handle(handle_dir).map(|d| d.join("config.toml"));
    let state = match cfg {
        None => None,
        Some(p) => match std::fs::symlink_metadata(&p) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            _ => {
                let parsed = read_regular_bounded(&p, false)
                    .and_then(|b| String::from_utf8(b).ok())
                    .and_then(|t| toml::from_str::<toml::Table>(&t).ok());
                if parsed.is_none() {
                    counts.unknown = true;
                    return counts;
                }
                parsed
            }
        },
    };
    let table = state
        .as_ref()
        .and_then(|d| d.get("hooks"))
        .and_then(|h| h.get("state"))
        .and_then(toml::Value::as_table);
    let handle_key = canon_dir(handle_dir);
    for hook in &hooks {
        let entry = table.and_then(|t| t.get(&state_key(&handle_key, hook)));
        let Some(entry) = entry else {
            counts.untrusted += 1;
            continue;
        };
        let Some(entry) = entry.as_table() else {
            counts.unverifiable += 1;
            continue;
        };
        let Some(hash) = entry.get("trusted_hash").and_then(toml::Value::as_str) else {
            counts.untrusted += 1;
            continue;
        };
        let enabled = match entry.get("enabled") {
            None => Some(true),
            Some(v) => v.as_bool(),
        };
        match (hook.hash.as_deref(), enabled) {
            (None, _) | (_, None) => counts.unverifiable += 1,
            (Some(now), Some(en)) if now == hash => {
                if en {
                    counts.trusted += 1;
                } else {
                    counts.disabled += 1;
                }
            }
            _ => counts.modified += 1,
        }
    }
    counts
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use base64::Engine;
    use tempfile::TempDir;

    // Codex-produced hashes (codex_hook_trust_fixtures.json).
    const H_TRUE: &str = "sha256:2ba34c7a02841fada06b868a093d041fd3d9de81883c789a321916b0aa118851";
    const H_TWO: &str = "sha256:2dca0e87ac3670e9fe795624588c8944512bf53bdb123ceb110cadaee80911ae";
    const H_PRE: &str = "sha256:39057ebd30cc98418da09c661f1ff844e076ba83820ea7f8a14b085993f1a440";
    const H_TRUE_SP: &str =
        "sha256:b609b20342a6355db137b669b1f576d44ecfa0ef9956324cacd4f576d9913d57";
    /// stop:0:0 "true", stop:0:1 "echo two", pre_tool_use(Bash):0:0 "true".
    const GLOBAL: &str = r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"true"},{"type":"command","command":"echo two"}]}],"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"true"}]}]}}"#;
    /// Stop "true " (trailing space): the edited hook.
    const EDITED: &str = r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"true "}]}]}}"#;
    const FIXTURES: &str = include_str!("codex_hook_trust_fixtures.json");

    /// (h) the hash reproduces every Codex-produced fixture. h12 (an unknown handler field)
    /// is the one deliberate exception: Codex ignores the field when hashing, csq refuses
    /// to guess and returns None, which only ever means "no copy".
    #[test]
    fn hash_reproduces_every_codex_fixture() {
        let fixtures: Vec<serde_json::Value> = serde_json::from_str(FIXTURES).unwrap();
        assert_eq!(fixtures.len(), 31);
        let mut checked = 0;
        for fx in &fixtures {
            let name = fx["name"].as_str().unwrap();
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(fx["hooks_json_bytes_b64"].as_str().unwrap())
                .unwrap();
            let suffix = fx["key_suffix"].as_str().unwrap();
            let want = fx["current_hash"].as_str().unwrap();
            let hooks = global_hooks(&bytes).expect(name);
            let hook = hooks
                .iter()
                .find(|h| format!(":{}:{}:{}", h.event, h.group, h.handler) == suffix)
                .unwrap_or_else(|| panic!("{name}: no hook for {suffix}"));
            if name.starts_with("h12") {
                assert_eq!(
                    hook.hash, None,
                    "{name}: unknown field must be unverifiable"
                );
                continue;
            }
            assert_eq!(hook.hash.as_deref(), Some(want), "{name}");
            checked += 1;
        }
        assert_eq!(checked, 30);
    }

    #[test]
    fn hash_is_none_for_every_unverified_shape() {
        let h = |ev: &str, g: &str, hd: &str| {
            codex_hook_content_hash(
                ev,
                &serde_json::from_str(g).unwrap(),
                &serde_json::from_str(hd).unwrap(),
            )
        };
        let ok = r#"{"type":"command","command":"x"}"#;
        assert!(h("stop", "{}", ok).is_some());
        assert!(h("stop", "{}", r#"{"type":"command","command":"x","foo":1}"#).is_none());
        assert!(h(
            "stop",
            "{}",
            r#"{"type":"command","command":"x","commandWindows":"y"}"#
        )
        .is_none());
        assert!(h("stop", "{}", r#"{"type":"prompt","command":"x"}"#).is_none());
        assert!(h("stop", "{}", r#"{"command":"x"}"#).is_none());
        assert!(h("notify_unknown", "{}", ok).is_none());
        assert!(h("session_start", r#"{"matcher":"m"}"#, ok).is_none());
        assert!(h(
            "post_tool_use",
            "{}",
            r#"{"type":"command","command":"x","additionalContextLimit":5}"#
        )
        .is_none());
    }

    struct Fx {
        _d: TempDir,
        base: PathBuf,
        global: PathBuf,
        cfg: PathBuf,
    }

    fn fx(global_json: &str, config: &str) -> Fx {
        let d = TempDir::new().unwrap();
        let root = d.path().canonicalize().unwrap();
        let base = root.join("accounts");
        std::fs::create_dir_all(base.join("config-1")).unwrap();
        let global = root.join("dotcodex/hooks.json");
        std::fs::create_dir_all(global.parent().unwrap()).unwrap();
        std::fs::write(&global, global_json).unwrap();
        let cfg = base.join("config-1/config.toml");
        std::fs::write(&cfg, config).unwrap();
        Fx {
            _d: d,
            base,
            global,
            cfg,
        }
    }

    fn handle(f: &Fx, pid: u32) -> PathBuf {
        let h = f.base.join(format!("term-{pid}"));
        std::fs::create_dir_all(&h).unwrap();
        std::os::unix::fs::symlink(&f.cfg, h.join("config.toml")).unwrap();
        std::os::unix::fs::symlink(&f.global, h.join("hooks.json")).unwrap();
        // As a handle whose create purged every slot has it.
        std::fs::write(h.join(PURGED_MARKER), b"purged\n").unwrap();
        h
    }

    fn acc1() -> AccountNum {
        AccountNum::try_from(1u16).unwrap()
    }

    fn k(home: &Path, ev: &str, i: usize, j: usize) -> String {
        format!("{}/hooks.json:{ev}:{i}:{j}", home.display())
    }

    fn entry(key: &str, hash: &str, enabled: bool) -> String {
        format!("[hooks.state.\"{key}\"]\ntrusted_hash = \"{hash}\"\nenabled = {enabled}\n\n")
    }

    fn state(f: &Fx) -> toml::Table {
        let doc: toml::Table = toml::from_str(&std::fs::read_to_string(&f.cfg).unwrap()).unwrap();
        doc.get("hooks")
            .and_then(|h| h.get("state"))
            .and_then(|s| s.as_table())
            .cloned()
            .unwrap_or_default()
    }

    fn carry(f: &Fx, h: &Path) -> CarryReport {
        carry_hook_trust(&f.base, h, acc1(), Some(&f.global), CarryMode::Repoint).unwrap()
    }

    #[test]
    fn event_keys_state_keys_and_global_hooks_are_addressed_like_codex() {
        let mut got: Vec<_> = global_hooks(GLOBAL.as_bytes())
            .unwrap()
            .into_iter()
            .map(|h| (h.event, h.group, h.handler, h.hash))
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("pre_tool_use".into(), 0, 0, Some(H_PRE.into())),
                ("stop".into(), 0, 0, Some(H_TRUE.into())),
                ("stop".into(), 0, 1, Some(H_TWO.into())),
            ]
        );
        assert!(global_hooks(b"not json").is_none());
        let key = StateKey::parse("/a/b/term-1/hooks.json:pre_tool_use:2:3").unwrap();
        assert_eq!(
            (key.home(), key.event.as_str(), key.group, key.handler),
            (Some(Path::new("/a/b/term-1")), "pre_tool_use", 2, 3)
        );
        assert!(StateKey::parse("/a/b/other.json:stop:0:0").is_none());
        assert!(StateKey::parse("stop:0:0").is_none());
    }

    /// (a) a copy happens only on an exact hash match; fields are copied verbatim.
    #[test]
    fn copies_only_an_approval_whose_hash_equals_the_current_hash() {
        let f = fx(GLOBAL, "");
        let src = handle(&f, 100);
        let new = handle(&f, 200);
        let mut text = entry(&k(&src, "stop", 0, 0), H_TRUE, false);
        // right slot, WRONG hash (the other hook's): must not copy
        text.push_str(&entry(&k(&src, "stop", 0, 1), H_TRUE, true));
        text.push_str(&format!(
            "[hooks.state.\"{}\"]\ntrusted_hash = \"{H_PRE}\"\nextra = 7\n",
            k(&src, "pre_tool_use", 0, 0)
        ));
        std::fs::write(&f.cfg, text).unwrap();
        // the pre_tool_use source carries a field beyond trusted_hash/enabled: refused
        assert_eq!(
            carry(&f, &new),
            CarryReport {
                copied: 1,
                pruned: 0,
                ..Default::default()
            }
        );
        let st = state(&f);
        let a = st[&k(&new, "stop", 0, 0)].as_table().unwrap();
        assert_eq!(a["trusted_hash"].as_str(), Some(H_TRUE));
        assert_eq!(a["enabled"].as_bool(), Some(false));
        assert!(
            !st.contains_key(&k(&new, "pre_tool_use", 0, 0)),
            "an entry with extra fields was partly copied"
        );
        assert!(
            !st.contains_key(&k(&new, "stop", 0, 1)),
            "mismatched hash was copied"
        );
        assert!(st.contains_key(&k(&src, "stop", 0, 0)), "source kept");
    }

    /// A dead source handle's approval still carries: the hash, not the path, is the proof.
    #[test]
    fn approval_of_a_dead_handle_carries_when_its_hash_is_current() {
        let f = fx(GLOBAL, "");
        let gone = f.base.join("term-100");
        std::fs::write(&f.cfg, entry(&k(&gone, "stop", 0, 0), H_TRUE, true)).unwrap();
        let new = handle(&f, 200);
        assert_eq!(
            carry(&f, &new),
            CarryReport {
                copied: 1,
                pruned: 1,
                ..Default::default()
            }
        );
        assert!(state(&f).contains_key(&k(&new, "stop", 0, 0)));
    }

    /// (b) an edited global means the source hash is stale: no copy, config untouched.
    #[test]
    fn edited_global_means_no_copy() {
        let f = fx(EDITED, "");
        let src = handle(&f, 100);
        let new = handle(&f, 200);
        // approved when the hook was "true"; the global now says "true "
        std::fs::write(&f.cfg, entry(&k(&src, "stop", 0, 0), H_TRUE, true)).unwrap();
        let before = std::fs::read(&f.cfg).unwrap();
        assert_eq!(carry(&f, &new), CarryReport::default());
        assert_eq!(std::fs::read(&f.cfg).unwrap(), before);
        // control: an approval of the edited content does copy
        std::fs::write(&f.cfg, entry(&k(&src, "stop", 0, 0), H_TRUE_SP, true)).unwrap();
        assert_eq!(carry(&f, &new).copied, 1);
    }

    /// An unverifiable hook (unknown handler field) is never copied.
    #[test]
    fn unverifiable_hook_is_never_copied() {
        let g = r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"true","foo":1}]}]}}"#;
        let f = fx(g, "");
        let src = handle(&f, 100);
        let new = handle(&f, 200);
        std::fs::write(&f.cfg, entry(&k(&src, "stop", 0, 0), H_TRUE, true)).unwrap();
        assert_eq!(carry(&f, &new), CarryReport::default());
        assert!(!state(&f).contains_key(&k(&new, "stop", 0, 0)));
    }

    /// (c) copy and prune never touch a key that is not a csq `term-<pid>` handle under base.
    #[test]
    fn foreign_and_non_handle_keys_are_untouched() {
        let f = fx(GLOBAL, "");
        let other_base = f.base.parent().unwrap().join("other-accounts");
        let foreign = [
            "/home/u/.codex/hooks.json:stop:0:0".to_owned(),
            "/proj/.codex/hooks.json:stop:0:0".to_owned(),
            k(&f.base.join("term-abc"), "stop", 0, 0),
            k(&f.base.join("term-"), "stop", 0, 0),
            k(&f.base.join("term-5x"), "stop", 0, 0),
            k(&f.base.join("config-1"), "stop", 0, 0),
            k(&f.base.join("term-7/sub"), "stop", 0, 0),
            k(&other_base.join("term-99"), "stop", 0, 0),
            "not-a-hook-key".to_owned(),
        ];
        let dead = k(&f.base.join("term-31337"), "stop", 0, 0);
        let mut text: String = foreign.iter().map(|k| entry(k, "sha256:f", true)).collect();
        text.push_str(&entry(&dead, "sha256:d", true));
        std::fs::write(&f.cfg, text).unwrap();
        let new = handle(&f, 200);
        assert_eq!(
            carry(&f, &new),
            CarryReport {
                copied: 0,
                pruned: 1,
                ..Default::default()
            }
        );
        let st = state(&f);
        for key in &foreign {
            assert!(st.contains_key(key), "foreign key removed: {key}");
        }
        assert!(!st.contains_key(&dead));
    }

    /// (d) the prune keeps live handles' keys and removes dead ones.
    #[test]
    fn prune_keeps_live_handles_and_removes_dead_ones() {
        let f = fx(GLOBAL, "");
        let live = handle(&f, 100);
        let new = handle(&f, 200);
        let dead = f.base.join("term-300");
        let text = entry(&k(&live, "stop", 0, 0), "sha256:l", true)
            + &entry(&k(&dead, "stop", 0, 0), "sha256:d", true)
            + &entry(&k(&dead, "pre_tool_use", 0, 0), "sha256:d", true);
        std::fs::write(&f.cfg, text).unwrap();
        assert_eq!(carry(&f, &new).pruned, 2);
        let st = state(&f);
        assert!(st.contains_key(&k(&live, "stop", 0, 0)));
        assert!(!st.contains_key(&k(&dead, "stop", 0, 0)));
        assert!(!st.contains_key(&k(&dead, "pre_tool_use", 0, 0)));
    }

    /// (d) an existence check that errors with anything but NotFound keeps the entry.
    #[test]
    fn unknowable_existence_keeps_the_entry() {
        let d = TempDir::new().unwrap();
        let not_a_dir = d.path().join("accounts");
        std::fs::write(&not_a_dir, b"file").unwrap();
        assert!(!is_dead_csq_handle(&not_a_dir, &not_a_dir.join("term-5")));
        let real = d.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        assert!(is_dead_csq_handle(&real, &real.join("term-5")));
    }

    /// (e) no entry is ever created without a source entry.
    #[test]
    fn nothing_is_created_without_a_source_entry() {
        for n in 0..2 {
            let f = fx(GLOBAL, "");
            let src = handle(&f, 100);
            let new = handle(&f, 200);
            let mut text = String::from("model = \"m\"\n");
            if n == 1 {
                text.push_str(&entry(&k(&src, "stop", 5, 5), H_TRUE, true));
            }
            // no trusted_hash string: not an approval
            text.push_str(&format!(
                "[hooks.state.\"{}\"]\nenabled = true\n",
                k(&src, "stop", 0, 0)
            ));
            std::fs::write(&f.cfg, &text).unwrap();
            let before = std::fs::read(&f.cfg).unwrap();
            assert_eq!(carry(&f, &new), CarryReport::default());
            assert_eq!(std::fs::read(&f.cfg).unwrap(), before);
        }
        // a config with no hooks.state at all
        let f = fx(GLOBAL, "model = \"m\"\n");
        let new = handle(&f, 200);
        assert_eq!(carry(&f, &new), CarryReport::default());
        assert_eq!(std::fs::read_to_string(&f.cfg).unwrap(), "model = \"m\"\n");
        // no global hooks file: nothing to carry
        let f = fx(GLOBAL, "");
        let src = handle(&f, 100);
        let new = handle(&f, 200);
        std::fs::write(&f.cfg, entry(&k(&src, "stop", 0, 0), H_TRUE, true)).unwrap();
        assert_eq!(
            carry_hook_trust(&f.base, &new, acc1(), None, CarryMode::Create).unwrap(),
            CarryReport::default()
        );
    }

    /// (f) an existing entry for the new key is never overwritten.
    #[test]
    fn existing_entry_for_the_new_key_is_never_overwritten() {
        let f = fx(GLOBAL, "");
        let src = handle(&f, 100);
        let new = handle(&f, 200);
        let text = entry(&k(&src, "stop", 0, 0), H_TRUE, true)
            + &entry(&k(&new, "stop", 0, 0), "sha256:mine", false);
        std::fs::write(&f.cfg, text).unwrap();
        assert_eq!(carry(&f, &new), CarryReport::default());
        let st = state(&f);
        let mine = st[&k(&new, "stop", 0, 0)].as_table().unwrap();
        assert_eq!(mine["trusted_hash"].as_str(), Some("sha256:mine"));
        assert_eq!(mine["enabled"].as_bool(), Some(false));
    }

    /// (g) every other config table survives a copy+prune write.
    #[test]
    fn other_config_tables_survive_the_write() {
        let f = fx(GLOBAL, "");
        let src = handle(&f, 100);
        let new = handle(&f, 200);
        let dead = f.base.join("term-300");
        let rest = "model = \"gpt\"\ncli_auth_credentials_store = \"file\"\n\n[features]\nhooks = true\n\n[mcp_servers.gh]\ncommand = \"gh-mcp\"\nargs = [\"a\", \"b\"]\n\n[projects.\"/p\"]\ntrust_level = \"trusted\"\n\n[hooks.other]\nx = 1\n\n";
        let text = format!(
            "{rest}{}{}{}",
            entry(&k(&src, "stop", 0, 0), H_TRUE, true),
            entry(&k(&dead, "stop", 0, 0), "sha256:d", true),
            entry("/home/u/.codex/hooks.json:stop:0:0", "sha256:u", true),
        );
        std::fs::write(&f.cfg, &text).unwrap();
        let before: toml::Table = toml::from_str(&text).unwrap();
        assert_eq!(
            carry(&f, &new),
            CarryReport {
                copied: 1,
                pruned: 1,
                ..Default::default()
            }
        );
        let after: toml::Table = toml::from_str(&std::fs::read_to_string(&f.cfg).unwrap()).unwrap();
        for key in [
            "model",
            "cli_auth_credentials_store",
            "features",
            "mcp_servers",
            "projects",
        ] {
            assert_eq!(after[key], before[key], "{key} changed");
        }
        assert_eq!(after["hooks"]["other"], before["hooks"]["other"]);
        let (b, a) = (
            before["hooks"]["state"].as_table().unwrap(),
            after["hooks"]["state"].as_table().unwrap(),
        );
        for (key, v) in b {
            if !key.contains("term-300") {
                assert_eq!(&a[key], v, "{key} changed");
            }
        }
        assert_eq!(a.len(), b.len(), "+1 copied, -1 pruned");
    }

    #[test]
    fn malformed_config_is_left_untouched() {
        for text in ["this = = bad", "hooks = 5\n", "[hooks]\nstate = 5\n"] {
            let f = fx(GLOBAL, text);
            let new = handle(&f, 200);
            // never silent: an error (logged by the caller), and the file is untouched
            let e = carry_hook_trust(&f.base, &new, acc1(), Some(&f.global), CarryMode::Repoint)
                .unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{text}");
            assert_eq!(std::fs::read_to_string(&f.cfg).unwrap(), text);
        }
    }

    #[test]
    fn pruning_the_last_entry_removes_the_empty_tables_and_leaves_no_tmp() {
        let f = fx(GLOBAL, "");
        let new = handle(&f, 200);
        let dead = f.base.join("term-300");
        std::fs::write(
            &f.cfg,
            format!(
                "model = \"m\"\n\n{}",
                entry(&k(&dead, "stop", 0, 0), "sha256:d", true)
            ),
        )
        .unwrap();
        assert_eq!(carry(&f, &new).pruned, 1);
        let doc: toml::Table = toml::from_str(&std::fs::read_to_string(&f.cfg).unwrap()).unwrap();
        assert!(doc.get("hooks").is_none());
        assert_eq!(doc["model"].as_str(), Some("m"));
        let names: Vec<_> = std::fs::read_dir(f.cfg.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != ".config-toml.lock")
            .collect();
        assert_eq!(names, vec!["config.toml".to_owned()], "tmp left: {names:?}");
    }

    fn carry_create(f: &Fx, h: &Path) -> CarryReport {
        carry_hook_trust(&f.base, h, acc1(), Some(&f.global), CarryMode::Create).unwrap()
    }

    /// N1b: the owner approving in plain Codex (user-global config, keyed to the global
    /// hooks.json) is an approval source under the same exact-hash rule.
    #[test]
    fn n1b_global_config_approval_with_a_matching_hash_is_copied() {
        let f = fx(GLOBAL, "");
        let new = handle(&f, 200);
        let gcfg = f.global.parent().unwrap().join("config.toml");
        let gkey = |ev: &str, j: usize| format!("{}:{ev}:0:{j}", f.global.display());
        std::fs::write(
            &gcfg,
            format!(
                "[hooks.state.\"{}\"]\ntrusted_hash = \"{H_TRUE}\"\nenabled = true\n\n[hooks.state.\"{}\"]\ntrusted_hash = \"{H_TRUE_SP}\"\nenabled = true\n\n[hooks.state.\"/elsewhere/hooks.json:pre_tool_use:0:0\"]\ntrusted_hash = \"{H_PRE}\"\n",
                gkey("stop", 0),
                gkey("stop", 1),
            ),
        )
        .unwrap();
        let before = std::fs::read(&gcfg).unwrap();
        let r = carry(&f, &new);
        let st = state(&f);
        // matching hash: copied; stale hash (stop:0:1 is H_TWO now): not; other path: not.
        assert_eq!(r.copied, 1);
        assert_eq!(
            st[&k(&new, "stop", 0, 0)]["trusted_hash"].as_str(),
            Some(H_TRUE)
        );
        assert!(
            !st.contains_key(&k(&new, "stop", 0, 1)),
            "stale global hash copied"
        );
        assert!(
            !st.contains_key(&k(&new, "pre_tool_use", 0, 0)),
            "foreign-path key used"
        );
        assert_eq!(
            std::fs::read(&gcfg).unwrap(),
            before,
            "global config is never written"
        );
    }

    /// N1b: with no matching global approval nothing is created.
    #[test]
    fn n1b_stale_global_config_approval_is_not_copied() {
        let f = fx(EDITED, "");
        let new = handle(&f, 200);
        let gcfg = f.global.parent().unwrap().join("config.toml");
        // approved when the hook was "true"; the global file now says "true "
        std::fs::write(
            &gcfg,
            format!(
                "[hooks.state.\"{}:stop:0:0\"]\ntrusted_hash = \"{H_TRUE}\"\n",
                f.global.display()
            ),
        )
        .unwrap();
        assert_eq!(carry(&f, &new), CarryReport::default());
        assert!(state(&f).is_empty());
    }

    /// N3: on create, an entry already keyed to the handle's own path (a reused PID) is
    /// dropped before any copy: it never inherits `enabled = false`, and the new handle gets
    /// only what was copied.
    #[test]
    fn n3_reused_pid_entry_is_dropped_before_copy_on_create() {
        let f = fx(GLOBAL, "");
        let src = handle(&f, 100);
        let new = handle(&f, 200); // the reused PID: its path equals an old handle's
        let text = entry(&k(&src, "stop", 0, 0), H_TRUE, true)
            + &entry(&k(&new, "stop", 0, 0), H_TRUE, false)
            + &entry(&k(&new, "stop", 0, 1), H_TWO, false);
        std::fs::write(&f.cfg, text).unwrap();
        let r = carry_create(&f, &new);
        assert_eq!(
            r,
            CarryReport {
                copied: 1,
                pruned: 0,
                dropped_own: 2,
                ..Default::default()
            }
        );
        let st = state(&f);
        let got = st[&k(&new, "stop", 0, 0)].as_table().unwrap();
        assert_eq!(
            got["enabled"].as_bool(),
            Some(true),
            "old enabled=false inherited"
        );
        assert!(
            !st.contains_key(&k(&new, "stop", 0, 1)),
            "an old own entry with no source survived"
        );
        // Control: a repoint keeps the handle's own entry (the owner's, not stale state).
        let f = fx(GLOBAL, "");
        let new = handle(&f, 200);
        std::fs::write(&f.cfg, entry(&k(&new, "stop", 0, 0), H_TRUE, false)).unwrap();
        assert_eq!(carry(&f, &new), CarryReport::default());
        assert_eq!(
            state(&f)[&k(&new, "stop", 0, 0)]["enabled"].as_bool(),
            Some(false)
        );
    }

    #[test]
    fn doctor_counts_classify_trusted_untrusted_modified_unverifiable() {
        let f = fx(GLOBAL, "");
        let h = handle(&f, 200);
        let text =
            entry(&k(&h, "stop", 0, 0), H_TRUE, true) + &entry(&k(&h, "stop", 0, 1), H_TRUE, true);
        std::fs::write(&f.cfg, text).unwrap();
        assert_eq!(
            hook_trust_counts(&h, Some(&f.global)),
            HookTrustCounts {
                trusted: 1,
                untrusted: 1,
                modified: 1,
                ..Default::default()
            }
        );
        assert_eq!(hook_trust_counts(&h, None), HookTrustCounts::default());
        let g = r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"t","foo":1}]}]}}"#;
        std::fs::write(&f.global, g).unwrap();
        assert_eq!(hook_trust_counts(&h, Some(&f.global)).unverifiable, 1);
    }

    use crate::providers::codex::surface::test_seam::BEFORE_RENAME;
    use std::cell::Cell;
    use std::rc::Rc;

    /// Clears the thread-local pre-rename hook on drop (panic included).
    struct HookReset;
    impl Drop for HookReset {
        fn drop(&mut self) {
            BEFORE_RENAME.with(|h| *h.borrow_mut() = None);
        }
    }
    fn set_hook(f: impl Fn(&Path) + 'static) -> HookReset {
        BEFORE_RENAME.with(|h| *h.borrow_mut() = Some(Box::new(f)));
        HookReset
    }
    fn append(path: &Path, text: &str) {
        let mut cur = std::fs::read_to_string(path).unwrap();
        cur.push_str(text);
        std::fs::write(path, cur).unwrap();
    }
    fn gh(json: &str) -> Option<Vec<(String, usize, usize, bool)>> {
        global_hooks(json.as_bytes()).map(|v| {
            v.into_iter()
                .map(|h| (h.event, h.group, h.handler, h.hash.is_some()))
                .collect()
        })
    }
    fn tmp_leftovers(f: &Fx) -> Vec<String> {
        std::fs::read_dir(f.cfg.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| {
                n != ".config-toml.lock" && n != "config.toml" && n != ".csq-config-write-status"
            })
            .collect()
    }

    /// Item 4 / re-read guard: a write that lands AFTER csq's tmp is written and fsynced and
    /// BEFORE the rename must survive, and the pass re-runs (own stale entry still dropped,
    /// copy still made). Removing the pre-rename compare loses the write; removing the retry
    /// fails the pass.
    #[test]
    fn a_write_between_tmp_and_rename_is_kept_and_the_pass_reruns() {
        let f = fx(GLOBAL, "");
        let src = handle(&f, 100);
        let new = handle(&f, 200);
        std::fs::write(
            &f.cfg,
            entry(&k(&src, "stop", 0, 0), H_TRUE, true)
                + &entry(&k(&new, "stop", 0, 0), H_TRUE, false),
        )
        .unwrap();
        let calls = Rc::new(Cell::new(0u32));
        let c = calls.clone();
        let _h = set_hook(move |t| {
            c.set(c.get() + 1);
            if c.get() == 1 {
                append(t, "\n[codex_user]\nkeep = 1\n");
            }
        });
        let r = carry_create(&f, &new);
        assert_eq!(calls.get(), 2, "first attempt must be detected and retried");
        assert_eq!((r.copied, r.dropped_own), (1, 1));
        let doc: toml::Table = toml::from_str(&std::fs::read_to_string(&f.cfg).unwrap()).unwrap();
        assert_eq!(
            doc["codex_user"]["keep"].as_integer(),
            Some(1),
            "lost update"
        );
        let st = state(&f);
        assert_eq!(st[&k(&new, "stop", 0, 0)]["enabled"].as_bool(), Some(true));
        assert!(tmp_leftovers(&f).is_empty());
    }

    /// A config that keeps changing is an error (not silent), writes nothing of csq's and
    /// leaves no tmp file (security.md 5a).
    #[test]
    fn a_config_that_keeps_changing_is_an_error_and_leaves_no_tmp() {
        let f = fx(GLOBAL, "");
        let src = handle(&f, 100);
        let new = handle(&f, 200);
        // a stale own key of the reused PID: the drop-only retry has work to publish too, so
        // the bounded retry is exercised all the way to the error
        std::fs::write(
            &f.cfg,
            entry(&k(&src, "stop", 0, 0), H_TRUE, true)
                + &entry(&k(&new, "stop", 0, 1), H_TWO, false),
        )
        .unwrap();
        let _h = set_hook(|t| append(t, "\n# x\n"));
        let e = carry_hook_trust(&f.base, &new, acc1(), Some(&f.global), CarryMode::Create)
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
        assert!(!state(&f).contains_key(&k(&new, "stop", 0, 0)));
        assert!(tmp_leftovers(&f).is_empty(), "{:?}", tmp_leftovers(&f));
        // the refusal is flagged for the doctor (the status file is the one allowed artifact)
        assert!(slot_write_statuses(&f.base, acc1()).contains(&SlotWriteStatus::PurgeFailed));
    }

    /// Item 2 / 13: create drops the handle's own keys and prunes dead keys in EVERY slot,
    /// and writes the purge marker only when every slot was purged.
    #[test]
    fn create_purges_every_slot_and_writes_the_marker_only_when_all_purged() {
        let f = fx(GLOBAL, "");
        let new = handle(&f, 200);
        std::fs::remove_file(new.join(PURGED_MARKER)).unwrap();
        let cfg2 = f.base.join("config-2/config.toml");
        std::fs::create_dir_all(cfg2.parent().unwrap()).unwrap();
        let dead = f.base.join("term-555");
        std::fs::write(
            &cfg2,
            entry(&k(&new, "stop", 0, 0), H_TRUE, false)
                + &entry(&k(&dead, "stop", 0, 0), H_TRUE, true),
        )
        .unwrap();
        let r = carry_create(&f, &new);
        assert_eq!((r.dropped_own, r.pruned), (1, 1));
        let doc: toml::Table = toml::from_str(&std::fs::read_to_string(&cfg2).unwrap()).unwrap();
        assert!(doc.get("hooks").is_none(), "slot 2 not purged: {doc:?}");
        assert!(new.join(PURGED_MARKER).exists());

        // An unusable slot config blocks the marker (and is logged), the target still runs.
        std::fs::remove_file(new.join(PURGED_MARKER)).unwrap();
        let cfg3 = f.base.join("config-3/config.toml");
        std::fs::create_dir_all(cfg3.parent().unwrap()).unwrap();
        std::fs::write(&cfg3, "not = [toml").unwrap();
        carry_create(&f, &new);
        assert!(!new.join(PURGED_MARKER).exists());
        assert_eq!(std::fs::read_to_string(&cfg3).unwrap(), "not = [toml");
    }

    /// Item 2: a repoint of a handle WITHOUT the marker (its dir was re-created, or it
    /// predates the marker) drops its own keys in the target slot; WITH the marker it keeps
    /// them (the owner's approvals).
    #[test]
    fn repoint_keeps_own_keys_only_when_the_handle_carries_the_marker() {
        let f = fx(GLOBAL, "");
        let new = handle(&f, 200);
        let own = entry(&k(&new, "stop", 0, 1), H_TWO, false);
        std::fs::write(&f.cfg, &own).unwrap();
        assert_eq!(carry(&f, &new), CarryReport::default());
        assert!(
            state(&f).contains_key(&k(&new, "stop", 0, 1)),
            "marker present: keep"
        );
        std::fs::remove_file(new.join(PURGED_MARKER)).unwrap();
        let r = carry(&f, &new);
        assert_eq!(r.dropped_own, 1);
        assert!(
            !state(&f).contains_key(&k(&new, "stop", 0, 1)),
            "no marker: drop"
        );
        assert!(new.join(PURGED_MARKER).exists());
    }

    /// Item 10: each of event, group and handler must match for a copy.
    #[test]
    fn a_copy_needs_the_same_event_group_and_handler() {
        let two_groups = r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"true"}]},{"hooks":[{"type":"command","command":"true"}]}],"PreToolUse":[{"hooks":[{"type":"command","command":"true"}]}]}}"#;
        let f = fx(two_groups, "");
        let src = handle(&f, 100);
        let new = handle(&f, 200);
        // The two Stop hooks have the SAME hash, so a wrong-group copy cannot be rejected by
        // the hash alone.
        std::fs::write(&f.cfg, entry(&k(&src, "stop", 1, 0), H_TRUE, true)).unwrap();
        let r = carry(&f, &new);
        assert_eq!(r.copied, 1);
        let st = state(&f);
        assert!(st.contains_key(&k(&new, "stop", 1, 0)), "same slot copied");
        assert!(!st.contains_key(&k(&new, "stop", 0, 0)), "group ignored");
        // event and handler: a pre_tool_use key and a stop:0:1 key whose hash equals the
        // stop:0:0 hash must not feed stop:0:0.
        let f = fx(GLOBAL, "");
        let src = handle(&f, 100);
        let new = handle(&f, 200);
        std::fs::write(
            &f.cfg,
            entry(&k(&src, "pre_tool_use", 0, 0), H_TRUE, true)
                + &entry(&k(&src, "stop", 0, 1), H_TRUE, true),
        )
        .unwrap();
        assert_eq!(
            carry(&f, &new),
            CarryReport::default(),
            "event/handler ignored"
        );
        assert_eq!(state(&f).len(), 2);
    }

    /// Item 1: sources that disagree on `enabled` copy nothing; agreeing ones copy it; a
    /// source with extra fields or a non-bool `enabled` is never copied.
    #[test]
    fn copy_rules_for_enabled_and_extra_fields() {
        let key0 = |h: &Path| k(h, "stop", 0, 0);
        // disagree
        let f = fx(GLOBAL, "");
        let (a, b, new) = (handle(&f, 100), handle(&f, 101), handle(&f, 200));
        std::fs::write(
            &f.cfg,
            entry(&key0(&a), H_TRUE, true) + &entry(&key0(&b), H_TRUE, false),
        )
        .unwrap();
        assert_eq!(carry(&f, &new).copied, 0);
        assert!(!state(&f).contains_key(&key0(&new)));
        // agree on false: copied faithfully
        std::fs::write(
            &f.cfg,
            entry(&key0(&a), H_TRUE, false) + &entry(&key0(&b), H_TRUE, false),
        )
        .unwrap();
        assert_eq!(carry(&f, &new).copied, 1);
        assert_eq!(state(&f)[&key0(&new)]["enabled"].as_bool(), Some(false));
        // an absent `enabled` is the default (enabled): it agrees with `true`, not `false`
        let bare = |h: &Path| {
            format!(
                "[hooks.state.\"{}\"]\ntrusted_hash = \"{H_TRUE}\"\n\n",
                key0(h)
            )
        };
        std::fs::write(&f.cfg, entry(&key0(&a), H_TRUE, true) + &bare(&b)).unwrap();
        assert_eq!(carry(&f, &new).copied, 1);
        assert_eq!(state(&f)[&key0(&new)]["enabled"].as_bool(), Some(true));
        std::fs::write(&f.cfg, entry(&key0(&a), H_TRUE, false) + &bare(&b)).unwrap();
        assert_eq!(carry(&f, &new).copied, 0);
        // extra field: refused (no partial copy)
        std::fs::write(
            &f.cfg,
            format!(
                "[hooks.state.\"{}\"]\ntrusted_hash = \"{H_TRUE}\"\nenabled = true\nextra = 7\n",
                key0(&a)
            ),
        )
        .unwrap();
        assert_eq!(carry(&f, &new).copied, 0);
        // non-bool enabled: refused
        std::fs::write(
            &f.cfg,
            format!(
                "[hooks.state.\"{}\"]\ntrusted_hash = \"{H_TRUE}\"\nenabled = \"yes\"\n",
                key0(&a)
            ),
        )
        .unwrap();
        assert_eq!(carry(&f, &new).copied, 0);
    }

    /// Item 5: only csq `term-<pid>` handle keys directly under this base, and the N1b key,
    /// are sources. Project, exec, capture and other-base keys are not.
    #[test]
    fn only_term_handle_keys_and_the_n1b_key_are_sources() {
        let f = fx(GLOBAL, "");
        let new = handle(&f, 200);
        let other_base = f.base.parent().unwrap().join("other-accounts");
        let foreign = [
            PathBuf::from("/some/repo/.codex"),
            f.base.join("codex-exec-300"),
            f.base.join("interactive-capture-1-2"),
            other_base.join("term-100"),
            f.base.join("term-100").join("nested"),
        ];
        let mut text = String::new();
        for h in &foreign {
            text.push_str(&entry(&k(h, "stop", 0, 0), H_TRUE, true));
        }
        std::fs::write(&f.cfg, &text).unwrap();
        let r = carry(&f, &new);
        assert_eq!(r.copied, 0);
        assert!(!state(&f).contains_key(&k(&new, "stop", 0, 0)));
    }

    /// Item 9: only term handles carry (exec and capture dirs get nothing and nothing is
    /// touched); a term create prunes dead exec and capture keys too.
    #[test]
    fn exec_and_capture_dirs_do_not_carry_and_their_dead_keys_are_pruned() {
        let f = fx(GLOBAL, "");
        let src = handle(&f, 100);
        let exec = f.base.join("codex-exec-777");
        std::fs::create_dir_all(&exec).unwrap();
        let text = entry(&k(&src, "stop", 0, 0), H_TRUE, true);
        std::fs::write(&f.cfg, &text).unwrap();
        let r =
            carry_hook_trust(&f.base, &exec, acc1(), Some(&f.global), CarryMode::Create).unwrap();
        assert_eq!(r, CarryReport::default());
        assert_eq!(std::fs::read_to_string(&f.cfg).unwrap(), text);
        assert!(!exec.join(PURGED_MARKER).exists());

        let deadx = f.base.join("codex-exec-555");
        let deadc = f.base.join("interactive-capture-9-1");
        let live_exec = exec.clone();
        std::fs::write(
            &f.cfg,
            text + &entry(&k(&deadx, "stop", 0, 0), H_TRUE, true)
                + &entry(&k(&deadc, "stop", 0, 0), H_TRUE, true)
                + &entry(&k(&live_exec, "stop", 0, 0), H_TRUE, true),
        )
        .unwrap();
        let new = handle(&f, 200);
        let r = carry_create(&f, &new);
        assert_eq!(r.pruned, 2);
        let st = state(&f);
        assert!(
            st.contains_key(&k(&live_exec, "stop", 0, 0)),
            "live exec key kept"
        );
        assert!(!st.contains_key(&k(&deadx, "stop", 0, 0)));
        assert!(!st.contains_key(&k(&deadc, "stop", 0, 0)));
    }

    /// Item 8 (P8): keys name the CANONICAL handle dir. A symlinked accounts base still
    /// copies, drops and reads under the real path.
    #[test]
    fn keys_use_the_canonical_handle_dir_under_a_symlinked_base() {
        let f = fx(GLOBAL, "");
        let src = handle(&f, 100);
        let new = handle(&f, 200);
        let link = f.base.parent().unwrap().join("link-accounts");
        std::os::unix::fs::symlink(&f.base, &link).unwrap();
        std::fs::write(&f.cfg, entry(&k(&src, "stop", 0, 0), H_TRUE, true)).unwrap();
        let via_link = link.join("term-200");
        let r = carry_hook_trust(
            &link,
            &via_link,
            acc1(),
            Some(&f.global),
            CarryMode::Repoint,
        )
        .unwrap();
        assert_eq!(r.copied, 1);
        // canonical key, not the link form
        assert!(state(&f).contains_key(&k(&new, "stop", 0, 0)));
        assert!(!state(&f).keys().any(|key| key.contains("link-accounts")));
        // the doctor reads it through the link too
        assert_eq!(hook_trust_counts(&via_link, Some(&f.global)).trusted, 1);
        // a dead canonical key is pruned when the base is given as the link
        let dead = f.base.join("term-555");
        append(&f.cfg, &entry(&k(&dead, "stop", 0, 0), H_TRUE, true));
        let r = carry_hook_trust(
            &link,
            &via_link,
            acc1(),
            Some(&f.global),
            CarryMode::Repoint,
        )
        .unwrap();
        assert_eq!(r.pruned, 1);
    }

    /// Items 7 / 10 (P10a, P10b): the hook list follows Codex.
    #[test]
    fn global_hooks_follow_codex_naming_gaps_and_whole_file_rejection() {
        let c = |t: &str| format!(r#"{{"type":"{t}","command":"x"}}"#);
        // positional gaps: a skipped handler keeps its slot
        let j = format!(
            r#"{{"hooks":{{"Stop":[{{"hooks":[{},{{"type":"prompt"}},{}]}}]}}}}"#,
            c("command"),
            c("command")
        );
        assert_eq!(
            gh(&j)
                .unwrap()
                .iter()
                .map(|h| (h.1, h.2))
                .collect::<Vec<_>>(),
            vec![(0, 0), (0, 2)]
        );
        // agent and empty command also keep their slot
        let j = r#"{"hooks":{"Stop":[{"hooks":[{"type":"agent"},{"type":"command","command":""},{"type":"command","command":"x"}]}]}}"#;
        assert_eq!(
            gh(j)
                .unwrap()
                .iter()
                .map(|h| (h.1, h.2))
                .collect::<Vec<_>>(),
            vec![(0, 2)]
        );
        // a group with no hooks keeps its group index
        let j = r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"x"}]},{"matcher":"Bash"},{"hooks":[{"type":"command","command":"x"}]}]}}"#;
        assert_eq!(
            gh(j)
                .unwrap()
                .iter()
                .map(|h| (h.1, h.2))
                .collect::<Vec<_>>(),
            vec![(0, 0), (2, 0)]
        );
        // mcp_tool is listed with its own slot and never has a hash
        let j = r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"x"},{"type":"mcp_tool","server":"s","tool":"t"}]}]}}"#;
        assert_eq!(gh(j).unwrap()[1], ("stop".to_owned(), 0, 1, false));
        // only exact PascalCase event names load; others are dropped silently
        let j = r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"a"}]}],"stop":[{"hooks":[{"type":"command","command":"b"}]}],"pre_tool_use":[{"hooks":[{"type":"command","command":"c"}]}],"preToolUse":[{"hooks":[{"type":"command","command":"d"}]}]}}"#;
        assert_eq!(gh(j).unwrap().len(), 1);
        // a malformed entry rejects the WHOLE file
        for bad in [
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"bogus"},{"type":"command","command":"x"}]}]}}"#,
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command"}]}]}}"#,
            r#"{"hooks":{"Stop":["notanobject"]}}"#,
            r#"{"hooks":{"Stop":[{"hooks":"x"}]}}"#,
            r#"{"hooks":{"Stop":{"hooks":[]}}}"#,
            r#"{"hooks":[]}"#,
            r#"{"hooks":{"Stop":[{"hooks":["x"]}]}}"#,
            r#"{"hooks":{"Weird":[{"hooks":[{"type":"command","command":"x"}]}]}}"#,
            "not json",
            "[]",
        ] {
            assert!(gh(bad).is_none(), "{bad}");
        }
        assert_eq!(gh("{}").unwrap().len(), 0);
    }

    /// Items 1, 3, 7, 9, 12: doctor counts.
    #[test]
    fn doctor_counts_cover_disabled_unknown_untrusted_and_the_size_guard() {
        let f = fx(GLOBAL, "");
        let h = handle(&f, 200);
        let key = |j| k(&h, "stop", 0, j);
        // disabled (hash current, enabled=false), no trusted_hash -> untrusted, non-bool
        // enabled -> unverifiable
        std::fs::write(
            &f.cfg,
            entry(&key(0), H_TRUE, false)
                + &format!("[hooks.state.\"{}\"]\nenabled = true\n\n", key(1))
                + &format!(
                    "[hooks.state.\"{}\"]\ntrusted_hash = \"{H_PRE}\"\nenabled = \"x\"\n",
                    k(&h, "pre_tool_use", 0, 0)
                ),
        )
        .unwrap();
        let c = hook_trust_counts(&h, Some(&f.global));
        assert_eq!(
            (
                c.trusted,
                c.disabled,
                c.untrusted,
                c.modified,
                c.unverifiable,
                c.unknown
            ),
            (0, 1, 1, 0, 1, false)
        );
        // malformed / oversize global, unparseable slot config: UNKNOWN
        std::fs::write(
            &f.global,
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"bogus"}]}]}}"#,
        )
        .unwrap();
        assert!(hook_trust_counts(&h, Some(&f.global)).unknown);
        std::fs::write(&f.global, vec![b' '; (1 << 20) + 5]).unwrap();
        assert!(hook_trust_counts(&h, Some(&f.global)).unknown);
        std::fs::write(&f.global, GLOBAL).unwrap();
        std::fs::write(&f.cfg, "x = [").unwrap();
        assert!(hook_trust_counts(&h, Some(&f.global)).unknown);
        // a global that does not exist is "no hooks", not unknown
        std::fs::write(&f.cfg, "").unwrap();
        let c = hook_trust_counts(&h, Some(&f.base.join("absent/hooks.json")));
        assert!(!c.unknown && c.trusted + c.untrusted == 0);
        // size guard: near the bound, no copy and the doctor predicate is set
        let src = handle(&f, 100);
        let pad = "# pad\n".repeat((NEAR_LIMIT_BYTES as usize / 6) + 10);
        std::fs::write(&f.cfg, pad + &entry(&k(&src, "stop", 0, 0), H_TRUE, true)).unwrap();
        assert!(slot_config_near_limit(&h));
        assert_eq!(carry(&f, &h).copied, 0);
    }

    use crate::providers::codex::surface::{slot_write_statuses, SlotWriteStatus};

    fn acc_n(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    /// Item 5 (marker hardening): a planted symlink at the marker path is replaced, never
    /// followed or truncated through; a symlink marker is NOT a marker on repoint.
    #[test]
    fn the_marker_is_created_exclusively_and_never_followed() {
        let f = fx(GLOBAL, "");
        let new = handle(&f, 200);
        let victim = f.base.parent().unwrap().join("victim.txt");
        std::fs::write(&victim, "keep\n").unwrap();
        let marker = new.join(PURGED_MARKER);
        std::fs::remove_file(&marker).unwrap();
        std::os::unix::fs::symlink(&victim, &marker).unwrap();
        carry_create(&f, &new);
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "keep\n",
            "marker write followed the link"
        );
        assert!(
            std::fs::symlink_metadata(&marker).unwrap().is_file(),
            "marker is not a regular file"
        );
        // a symlink at the marker path is not "purged" on repoint: own keys are dropped
        std::fs::remove_file(&marker).unwrap();
        std::os::unix::fs::symlink(&victim, &marker).unwrap();
        std::fs::write(&f.cfg, entry(&k(&new, "stop", 0, 1), H_TWO, false)).unwrap();
        let r = carry(&f, &new);
        assert_eq!(r.dropped_own, 1, "a symlink marker was honoured");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep\n");
    }

    /// Items 5 / corr L2: a marker that cannot be written is logged and flagged for the
    /// doctor, not discarded.
    #[test]
    fn a_failed_marker_write_is_flagged_for_the_doctor() {
        let f = fx(GLOBAL, "");
        let new = handle(&f, 200);
        let marker = new.join(PURGED_MARKER);
        std::fs::remove_file(&marker).unwrap();
        std::fs::create_dir_all(marker.join("not-removable")).unwrap();
        carry_create(&f, &new);
        assert!(slot_write_statuses(&f.base, acc1()).contains(&SlotWriteStatus::PurgeFailed));
    }

    /// Items 4 / 5: another slot that cannot be purged is flagged and clears when a later
    /// purge succeeds; an unpurgeable TARGET slot is an error, flagged too.
    #[test]
    fn purge_failures_are_flagged_and_clear_on_success_and_the_target_failure_is_an_error() {
        let f = fx(GLOBAL, "");
        let new = handle(&f, 200);
        let cfg3 = f.base.join("config-3/config.toml");
        std::fs::create_dir_all(cfg3.parent().unwrap()).unwrap();
        std::fs::write(&cfg3, "not = [toml").unwrap();
        carry_create(&f, &new);
        assert!(slot_write_statuses(&f.base, acc_n(3)).contains(&SlotWriteStatus::PurgeFailed));
        std::fs::write(&cfg3, "").unwrap();
        carry_create(&f, &new);
        assert!(
            slot_write_statuses(&f.base, acc_n(3)).is_empty(),
            "flag not cleared"
        );
        // target slot: an error, flagged
        std::fs::write(&f.cfg, "x = [").unwrap();
        let e = carry_hook_trust(&f.base, &new, acc1(), Some(&f.global), CarryMode::Create)
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(slot_write_statuses(&f.base, acc1()).contains(&SlotWriteStatus::PurgeFailed));
    }

    struct DeadlineReset;
    impl Drop for DeadlineReset {
        fn drop(&mut self) {
            test_seam::DEADLINE.with(|d| d.set(None));
        }
    }

    /// Corr L6: past the overall deadline the remaining slots are skipped (their stale keys
    /// stay, no marker, the slot is flagged) and the TARGET slot is still processed.
    #[test]
    fn the_deadline_skips_other_slots_without_a_marker_and_flags_them() {
        let f = fx(GLOBAL, "");
        let new = handle(&f, 200);
        std::fs::remove_file(new.join(PURGED_MARKER)).unwrap();
        let cfg2 = f.base.join("config-2/config.toml");
        std::fs::create_dir_all(cfg2.parent().unwrap()).unwrap();
        std::fs::write(&cfg2, entry(&k(&new, "stop", 0, 0), H_TRUE, false)).unwrap();
        std::fs::write(&f.cfg, entry(&k(&new, "stop", 0, 1), H_TWO, false)).unwrap();
        test_seam::DEADLINE.with(|d| d.set(Some(std::time::Duration::ZERO)));
        let _reset = DeadlineReset;
        let r = carry_create(&f, &new);
        assert_eq!(r.dropped_own, 1, "only the target slot was purged");
        assert!(
            std::fs::read_to_string(&cfg2).unwrap().contains("term-200"),
            "slot 2 was purged past the deadline"
        );
        assert!(
            !state(&f).contains_key(&k(&new, "stop", 0, 1)),
            "target slot not purged"
        );
        assert!(
            !new.join(PURGED_MARKER).exists(),
            "marker written after a skipped slot"
        );
        assert!(slot_write_statuses(&f.base, acc_n(2)).contains(&SlotWriteStatus::PurgeFailed));
    }

    /// Corr L3 / item 8: the write lands in the slot of the validated account, not the slot the
    /// handle's `config.toml` link names.
    #[test]
    fn the_write_target_comes_from_the_account_not_the_handle_link() {
        let f = fx(GLOBAL, "");
        let src = handle(&f, 100);
        let new = handle(&f, 200);
        let cfg9 = f.base.join("config-9/config.toml");
        std::fs::create_dir_all(cfg9.parent().unwrap()).unwrap();
        std::fs::write(&cfg9, "# slot nine\n").unwrap();
        std::fs::remove_file(new.join("config.toml")).unwrap();
        std::os::unix::fs::symlink(&cfg9, new.join("config.toml")).unwrap();
        std::fs::write(&f.cfg, entry(&k(&src, "stop", 0, 0), H_TRUE, true)).unwrap();
        let r = carry_create(&f, &new);
        assert_eq!(r.copied, 1);
        assert!(
            state(&f).contains_key(&k(&new, "stop", 0, 0)),
            "wrote the wrong slot"
        );
        assert_eq!(std::fs::read_to_string(&cfg9).unwrap(), "# slot nine\n");
    }

    /// Corr L1 (probe `R3`): `STOP` and `Notification` are dropped like Codex does, the rest of
    /// the file still lists; `PreCompact`, `SubagentStop` and `PermissionRequest` are listed
    /// without a hash; an unprobed PascalCase name is UNKNOWN.
    #[test]
    fn the_event_table_follows_the_codex_probe() {
        let j = r#"{"hooks":{"STOP":[{"hooks":[{"type":"command","command":"a"}]}],"Notification":[{"hooks":[{"type":"command","command":"b"}]}],"Stop":[{"hooks":[{"type":"command","command":"c"}]}]}}"#;
        assert_eq!(
            gh(j).unwrap().len(),
            1,
            "STOP / Notification must be dropped, Stop listed"
        );
        let j = r#"{"hooks":{"PreCompact":[{"hooks":[{"type":"command","command":"a"}]}],"SubagentStop":[{"hooks":[{"type":"command","command":"b"}]}],"PermissionRequest":[{"hooks":[{"type":"command","command":"c"}]}]}}"#;
        let mut got = gh(j).unwrap();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("permission_request".to_owned(), 0, 0, false),
                ("pre_compact".to_owned(), 0, 0, false),
                ("subagent_stop".to_owned(), 0, 0, false),
            ]
        );
        let j = r#"{"hooks":{"Weird":[{"hooks":[{"type":"command","command":"a"}]}]}}"#;
        assert!(
            gh(j).is_none(),
            "an unprobed PascalCase event must be UNKNOWN"
        );
    }

    /// Corr L5: a `codex-exec-<pid>` create drops its own stale keys (no copy, no marker).
    #[test]
    fn exec_create_drops_its_own_stale_keys_and_copies_nothing() {
        let f = fx(GLOBAL, "");
        let src = handle(&f, 100);
        let exec = f.base.join("codex-exec-777");
        std::fs::create_dir_all(&exec).unwrap();
        std::fs::write(
            &f.cfg,
            entry(&k(&src, "stop", 0, 0), H_TRUE, true)
                + &entry(&k(&exec, "stop", 0, 0), H_TRUE, false),
        )
        .unwrap();
        let r =
            carry_hook_trust(&f.base, &exec, acc1(), Some(&f.global), CarryMode::Create).unwrap();
        assert_eq!((r.dropped_own, r.copied), (1, 0));
        assert!(!state(&f).contains_key(&k(&exec, "stop", 0, 0)));
        assert!(!exec.join(PURGED_MARKER).exists());
    }

    /// Direct bound test: `rewrite_slot` makes exactly `MAX_ATTEMPTS` attempts against a config
    /// that always changes, then errors with `WouldBlock`, leaving no tmp file.
    #[test]
    fn rewrite_slot_gives_up_after_exactly_the_attempt_bound() {
        let f = fx(GLOBAL, "");
        let new = handle(&f, 200);
        std::fs::write(&f.cfg, entry(&k(&new, "stop", 0, 1), H_TWO, false)).unwrap();
        let calls = Rc::new(Cell::new(0usize));
        let c = calls.clone();
        let _h = set_hook(move |t| {
            c.set(c.get() + 1);
            append(t, "\n# y\n");
        });
        let plan = Plan {
            base_dir: &f.base,
            handle_dir: &new,
            drop_own: true,
            copy: None,
        };
        let e = rewrite_slot(&f.base, acc1(), &plan).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(calls.get(), MAX_ATTEMPTS);
        assert!(tmp_leftovers(&f).is_empty());
    }

    /// An abandoned carry after a race is reported and flagged, never a bare `Ok`: the report
    /// says `carry_skipped`, the doctor flag is set, and the next completed carry clears it.
    #[test]
    fn an_abandoned_carry_after_a_race_is_reported_and_flagged() {
        let f = fx(GLOBAL, "");
        let src = handle(&f, 100);
        let new = handle(&f, 200);
        std::fs::write(&f.cfg, entry(&k(&src, "stop", 0, 0), H_TRUE, true)).unwrap();
        {
            let _h = set_hook(|t| append(t, "\n# z\n"));
            let r = carry_hook_trust(&f.base, &new, acc1(), Some(&f.global), CarryMode::Create)
                .unwrap();
            assert!(r.carry_skipped, "{r:?}");
            assert_eq!(r.copied, 0);
        }
        assert!(slot_write_statuses(&f.base, acc1()).contains(&SlotWriteStatus::CarrySkipped));
        let r =
            carry_hook_trust(&f.base, &new, acc1(), Some(&f.global), CarryMode::Create).unwrap();
        assert!(!r.carry_skipped && r.copied == 1, "{r:?}");
        assert!(!slot_write_statuses(&f.base, acc1()).contains(&SlotWriteStatus::CarrySkipped));
    }
}
