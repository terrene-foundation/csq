//! `csq statusline` — reads CC JSON from stdin, runs the local snapshot,
//! and outputs the formatted statusline (account + quota + model +
//! project + context window + session cost + git).
//!
//! Replaces the shell-script + jq + Rust composition from v1. All
//! parsing and rendering now live in Rust so csq has zero runtime
//! dependencies beyond the system git binary (used only when the
//! user is inside a git repo).
//!
//! ## Account/Terminal Separation
//!
//! This command is a TERMINAL operation. It reads and displays account
//! quota data but NEVER writes it. Quota data is written exclusively
//! by the daemon's usage poller, which polls Anthropic's `/api/oauth/usage`
//! endpoint directly per account.
//!
//! See `rules/account-terminal-separation.md` for the full spec.

use anyhow::Result;
use csq_core::accounts::snapshot;
use csq_core::messaging::store::PendingCount;
use csq_core::quota::format::{
    account_label, parse_cc_stdin, parse_workspace_dir, rich_statusline,
    should_report_broker_failed, statusline_str, GitStatus, StatuslineContext,
};
use csq_core::quota::state;
use csq_core::refresh::sentinel::is_broker_failed;
use csq_core::types::AccountNum;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

/// Maximum bytes of CC JSON we accept on stdin.
/// Real CC payloads are <16KB; 64KB is generous and prevents DoS.
const MAX_STDIN: u64 = 65_536;

pub fn handle(base_dir: &Path) -> Result<()> {
    let config_dir = match super::current_config_dir() {
        Some(d) => d,
        None => {
            println!("csq: no config dir");
            return Ok(());
        }
    };

    // Drain CC's JSON payload. Used for rich rendering (model, cwd,
    // ctx tokens, cost). The payload is NOT used for quota updates —
    // that's the daemon's job via Anthropic's usage API.
    let mut stdin_buf = String::new();
    let _ = std::io::stdin()
        .take(MAX_STDIN)
        .read_to_string(&mut stdin_buf);

    // ── Resolve the active account: authority-first (`.csq-account`), with
    // `.current-account` demoted to a self-healing cache. snapshot_account
    // owns the full resolution (numeric marker → slot directly; UUID marker →
    // reverse-resolved via by_slot) and self-heals a drifted cache, so the
    // statusline no longer second-guesses it with a numeric-only re-read that
    // returned None for UUID markers and trusted a stale cache otherwise
    // (workspace an internal workspace).
    let account: AccountNum = match snapshot::snapshot_account(&config_dir, base_dir) {
        Some(a) => a,
        None => {
            println!("csq: no active account");
            return Ok(());
        }
    };

    // Rendering does not verify/adopt live tokens or launch HTTPS subprocesses.
    // The daemon's pre-refresh custodian harvests and verifies live candidates;
    // handle-dir credential symlinks observe its canonical updates locally.

    // ── Gather account + quota state ──
    // an internal ticket: salvage per-row. Statusline is read-only by
    // `account-terminal-separation.md` MUST-2, so salvaging cannot write a
    // truncated file back; one bad row costs one row.
    let quota = state::load_state_salvage(base_dir);
    let account_quota = quota.get(account.get());
    let label = account_label(base_dir, account);
    // M3-7 fix-wave R1 M2-DA: `is_swap_stuck` is retired (no production
    // "stuck" semantic under the handle-dir model). The statusline no
    // longer renders a `!` glyph for divergence between live mirror and
    // canonical — handle dir symlinks resolve to a single inode written
    // by the daemon refresher.
    let broker_failed =
        should_report_broker_failed(base_dir, account) || is_broker_failed(base_dir, account);

    // ── Compose rich line from CC stdin + git probe ──
    //
    // Failure at any step below degrades gracefully to the minimal
    // `account + quota` line that `csq-statusline` v1.x produced.
    let line = match build_rich_line(
        &stdin_buf,
        base_dir,
        &config_dir,
        account,
        &label,
        account_quota,
        broker_failed,
    ) {
        Some(s) => s,
        None => statusline_str(account, &label, account_quota, broker_failed),
    };

    // Directives queued for this session by an external issuer (spec 31 §5).
    // Read-only: rendering never changes a directive's state.
    let notice = directive_status(csq_core::sessions::directives::pending_for_handle_dir(
        base_dir,
        &config_dir,
    ));
    // Cross-CLI messages waiting for this session (spec 32 §5.2). Read-only, like the above.
    let messages = message_status(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| ())
            .and_then(|now| {
                csq_core::messaging::hook::pending_count_for_handle_dir_at(
                    base_dir,
                    &config_dir,
                    now,
                    &csq_core::sessions::process_start_time,
                )
                .map_err(|_| ())
            }),
    );
    // orgident r7 item 9: the TERMINAL's bound slot (`account`, from its marker) shares
    // its sign-in with another slot. Local state files only: no keychain, no network.
    let shared_sign_in = csq_core::accounts::launch_block::status_segment(base_dir, account.get());
    let line = [Some(line), shared_sign_in, notice, messages]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    println!("{line}");
    Ok(())
}

/// The statusline's message segment: `[<n> message(s)]` when messages are waiting, nothing
/// when there is nothing to show (no store, no marker, none unread), and `[messages: ?]`
/// when the count could not be read. Absence and failure never look alike.
/// The statusline's message segment: `[<n> message(s)]` when messages are waiting, nothing
/// when there is nothing to show (no store, no marker, none unread), and `[messages: ?]`
/// when the count could not be read. Records the store could not read are never folded into
/// "nothing": they add `, <k> unreadable` (or stand alone as `[messages: <k> unreadable]`)
/// until the next hook quarantines them. Absence and failure never look alike.
fn message_status(r: Result<Option<PendingCount>, ()>) -> Option<String> {
    match r {
        Ok(Some(c)) if c.pending > 0 || c.unreadable > 0 => {
            let waiting = (c.pending > 0).then(|| {
                format!(
                    "{} {}",
                    c.pending,
                    if c.pending == 1 {
                        "message"
                    } else {
                        "messages"
                    }
                )
            });
            let bad = (c.unreadable > 0).then(|| format!("{} unreadable", c.unreadable));
            Some(match (waiting, bad) {
                (Some(w), Some(b)) => format!("[{w}, {b}]"),
                (Some(w), None) => format!("[{w}]"),
                (None, Some(b)) => format!("[messages: {b}]"),
                (None, None) => unreachable!("guarded above"),
            })
        }
        Ok(_) => None,
        Err(()) => Some("[messages: ?]".to_string()),
    }
}

/// Longest directive summary the statusline shows, in characters.
const DIRECTIVE_NOTICE_SUMMARY_CHARS: usize = 60;

/// The statusline's directive segment: the notice when directives are pending, nothing
/// when there is nothing to show (no marker, no store yet), and `[directives: ?]` when the
/// store exists but could not be read. Absence and failure never look alike.
fn directive_status(
    r: Result<
        Option<csq_core::sessions::directives::PendingInfo>,
        csq_core::sessions::directives::DirectiveError,
    >,
) -> Option<String> {
    match r {
        Ok(Some(p)) => directive_notice(&p),
        Ok(None) => None,
        Err(_) => Some("[directives: ?]".to_string()),
    }
}

/// `[1 directive: <summary>]` when directives are pending; `None` otherwise. The summary
/// is untrusted issuer text: it is re-sanitised here (controls, bidi/zero-width/format,
/// separators, private-use and unassigned characters and the combining marks Mn/Me
/// dropped, `directives::is_display_unsafe`) even though `deliver`
/// already refused them, so a record altered on disk cannot repaint the terminal line.
fn directive_notice(p: &csq_core::sessions::directives::PendingInfo) -> Option<String> {
    if p.pending == 0 {
        return None;
    }
    let noun = if p.pending == 1 {
        "directive"
    } else {
        "directives"
    };
    let clean =
        csq_core::sessions::directives::sanitize_display(p.first_summary.as_deref().unwrap_or(""));
    let summary = clean.as_str();
    let mut short: String = summary
        .chars()
        .take(DIRECTIVE_NOTICE_SUMMARY_CHARS)
        .collect();
    if summary.chars().count() > DIRECTIVE_NOTICE_SUMMARY_CHARS {
        short.push('…');
    }
    Some(format!("[{} {noun}: {short}]", p.pending))
}

/// Read context metadata from the same runtime snapshot path as model commands.
fn model_context_window(base_dir: &Path, model: &str) -> Result<Option<u64>> {
    let manifest = csq_core::providers::model_manifest::ModelManifest::load(base_dir)?;
    Ok(manifest
        .catalog()
        .find(model)
        .and_then(|row| row.context_window))
}

/// Builds the rich statusline using the parsed CC stdin + a git
/// probe in the workspace directory. Returns `None` when stdin is
/// empty / unparseable and there's nothing rich to add — the caller
/// falls back to [`statusline_str`] in that case.
fn build_rich_line(
    stdin_buf: &str,
    base_dir: &Path,
    config_dir: &Path,
    account: AccountNum,
    label: &str,
    account_quota: Option<&csq_core::quota::AccountQuota>,
    broker_failed: bool,
) -> Option<String> {
    if stdin_buf.trim().is_empty() {
        return None;
    }

    let mut ctx: StatuslineContext = parse_cc_stdin(stdin_buf);
    ctx.is_csq_terminal = is_csq_managed_terminal(base_dir);
    // Resolve the model's TRUE context window from csq's catalog so the context %
    // is recomputed against it. CC computes `used_percentage` against its own ~200k
    // assumption for the Anthropic-compatible endpoint; 3P models with a larger real
    // window (deepseek-v4-pro / minimax / glm = 1M) otherwise render a wildly inflated
    // % (e.g. 177k → 89% against 200k instead of 18% against 1M).
    //
    // Source of the model id: the slot's `config-<slot>/settings.json`
    // (`model_id_for_slot`) — the SAME on-disk source the daemon poller reads.
    // NOT `std::env::var("ANTHROPIC_MODEL")`: `csq run` strips every `ANTHROPIC_*`
    // var from CC's spawn env (`strip_sensitive_env`), so the process env is an
    // unreliable channel (whether CC re-exports settings.json `env` to the
    // spawned statusLine subprocess is a CC-internal behavior csq doesn't control).
    // Env var kept only as a last-resort fallback. Keyed on the model id/alias.
    let model_id = csq_core::providers::settings::model_id_for_slot(base_dir, account.get())
        .or_else(|| {
            std::env::var("ANTHROPIC_MODEL")
                .ok()
                .filter(|m| !m.is_empty())
        });
    let model_id_for_cost = model_id.clone();
    ctx.ctx_window_true = model_id.and_then(|m| match model_context_window(base_dir, &m) {
        Ok(window) => window,
        Err(error) => {
            tracing::warn!(
                error_kind = "model_manifest_invalid",
                "model context unavailable: {error}"
            );
            None
        }
    });
    // Session cost. CC prices EVERY model at Anthropic rates, so for a
    // non-Anthropic slot its `cost.total_cost_usd` is wrong; those slots are priced
    // from csq's runtime manifest, and `$?` is shown when that is not possible.
    // Anthropic slots keep CC's number. Read-only: the per-transcript cache is
    // display state in the handle dir, not quota or ledger data
    // (`account-terminal-separation.md` MUST 2).
    //
    // `config_dir` is the one `handle()` already resolved and validated for this
    // render; re-reading the environment here could yield `None` and fall
    // through to CC's number for a slot that might be third-party.
    {
        let claude_home = super::claude_home().ok();
        match csq_core::usage::session_cost::statusline_cost(
            &csq_core::usage::session_cost::CostRequest {
                base_dir,
                config_dir,
                claude_home: claude_home.as_deref(),
                slot: account,
                model_id: model_id_for_cost.as_deref(),
                transcript_path: ctx.transcript_path.as_deref(),
                session_id: ctx.session_id.as_deref(),
            },
            &csq_core::usage::session_cost::FsTranscriptReader,
            &|| csq_core::providers::model_manifest::ModelManifest::load(base_dir),
        ) {
            csq_core::usage::session_cost::CostDisplay::CcReported => {}
            csq_core::usage::session_cost::CostDisplay::Priced(c) => {
                ctx.session_cost_usd = Some(c);
            }
            csq_core::usage::session_cost::CostDisplay::Unknown(reason) => {
                tracing::debug!(error_kind = ?reason, "session cost unknown");
                ctx.session_cost_unknown = true;
            }
        }
    }
    ctx.git = parse_workspace_dir(stdin_buf)
        .as_deref()
        .and_then(git_status);

    Some(rich_statusline(
        account,
        label,
        account_quota,
        broker_failed,
        &ctx,
    ))
}

/// Returns true when `CLAUDE_CONFIG_DIR` is set AND points inside
/// the csq base dir (handle dirs or legacy config-N). Missing env
/// var or CC running outside csq's tree → false. The distinction
/// controls whether the `⚡csq ` prefix appears on the line.
fn is_csq_managed_terminal(base_dir: &Path) -> bool {
    let Some(config) = std::env::var_os("CLAUDE_CONFIG_DIR") else {
        return false;
    };
    let config_path = Path::new(&config);

    // Canonicalize both paths so a symlinked `~/.claude/accounts`
    // compares equal to its resolved target. Canonicalize failures
    // (deleted dir mid-run) collapse to string prefix comparison
    // rather than returning false incorrectly.
    let base_canon = std::fs::canonicalize(base_dir).unwrap_or_else(|_| base_dir.to_path_buf());
    let config_canon =
        std::fs::canonicalize(config_path).unwrap_or_else(|_| config_path.to_path_buf());

    config_canon.starts_with(&base_canon)
}

/// Unix display-only cache; missing/unsafe cache storage always falls back to Git.
/// Non-Unix keeps live probes until a private native cache policy is established.
fn git_status(dir: &str) -> Option<GitStatus> {
    #[cfg(unix)]
    let cache = dirs::cache_dir().map(|p| p.join("csq-statusline-git-v1"));
    #[cfg(not(unix))]
    let cache: Option<std::path::PathBuf> = None;
    git_status_at(
        Path::new(dir),
        cache.as_deref(),
        std::time::SystemTime::now(),
    )
}

fn git_status_at(
    workdir: &Path,
    cache_root: Option<&Path>,
    now: std::time::SystemTime,
) -> Option<GitStatus> {
    #[cfg(unix)]
    let cache = cache_root.and_then(|root| {
        let key = git_cache_key(workdir)?;
        let millis =
            u64::try_from(now.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis()).ok()?;
        ensure_git_cache_root(root)?;
        Some((root, key, millis))
    });
    #[cfg(unix)]
    if let Some((root, key, millis)) = &cache {
        if let Some(status) = read_git_cache(root, key, *millis) {
            return Some(status);
        }
    }
    #[cfg(not(unix))]
    let _ = (cache_root, now);
    let status = git_status_uncached(workdir)?;
    #[cfg(unix)]
    if let Some((root, key, millis)) = cache {
        // Do not publish a replaced repository's result under its retired key.
        if git_cache_key(workdir).as_ref() == Some(&key) {
            write_git_cache(root, key, millis, &status, now);
        }
    }
    Some(status)
}

#[cfg(unix)]
const GIT_CACHE_TTL_MS: u64 = 10_000;
#[cfg(unix)]
const GIT_CACHE_MAX_BYTES: u64 = 16_384;

#[cfg(unix)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GitCacheRecord {
    version: u8,
    key: String,
    observed_ms: u64,
    branch: String,
    // Require the field even when null, rather than default missing data to None.
    #[serde(deserialize_with = "deserialize_git_dirty")]
    dirty: Option<bool>,
}

#[cfg(unix)]
fn deserialize_git_dirty<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    serde::Deserialize::deserialize(d)
}

/// Filesystem-only identity. Canonical aliases share a key; subdirs/worktrees are
/// deliberately partitioned because Git's workdir/config context can differ.
#[cfg(unix)]
fn git_cache_key(workdir: &Path) -> Option<String> {
    use std::hash::{Hash, Hasher};
    use std::os::unix::fs::MetadataExt;
    // Repository/index overrides make ancestor discovery insufficient.
    if [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some())
    {
        return None;
    }
    let workdir = std::fs::canonicalize(workdir).ok()?;
    let repo = workdir.ancestors().find(|p| p.join(".git").exists())?;
    let dir_meta = std::fs::metadata(&workdir).ok()?;
    let repo_meta = std::fs::metadata(repo).ok()?;
    let marker = std::fs::symlink_metadata(repo.join(".git")).ok()?;
    if !dir_meta.is_dir() || !(marker.is_dir() || marker.is_file()) {
        return None;
    }
    // Environment values (which can contain secrets) are never stored or logged.
    let mut environment = std::collections::BTreeMap::new();
    for (name, value) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("GIT_")
            || name == "PATH"
            || name == "HOME"
            || name == "XDG_CONFIG_HOME"
        {
            environment.insert(name, value);
        }
    }
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    environment.hash(&mut hash);
    serde_json::to_string(&(
        repo.to_str()?,
        workdir.to_str()?,
        repo_meta.dev(),
        repo_meta.ino(),
        dir_meta.dev(),
        dir_meta.ino(),
        marker.dev(),
        marker.ino(),
        hash.finish(),
    ))
    .ok()
}

#[cfg(unix)]
fn git_cache_path(root: &Path, key: &str) -> std::path::PathBuf {
    use std::hash::{Hash, Hasher};
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hash);
    root.join(format!("{:016x}.json", hash.finish()))
}

#[cfg(unix)]
fn git_cache_private(meta: &std::fs::Metadata, directory: bool) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and changes no process state.
    let uid = unsafe { libc::geteuid() };
    let expected_mode = if directory { 0o700 } else { 0o600 };
    let expected_kind = if directory {
        meta.is_dir()
    } else {
        meta.is_file() && meta.nlink() == 1
    };
    meta.uid() == uid && meta.mode() & 0o7777 == expected_mode && expected_kind
}

#[cfg(unix)]
fn ensure_git_cache_root(root: &Path) -> Option<()> {
    use std::os::unix::fs::DirBuilderExt;
    // Do not create/chmod arbitrary ancestors or repair someone else's cache.
    match std::fs::DirBuilder::new().mode(0o700).create(root) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return None,
    }
    let meta = std::fs::symlink_metadata(root).ok()?;
    git_cache_private(&meta, true).then_some(())
}

#[cfg(unix)]
fn read_git_cache(root: &Path, key: &str, now_ms: u64) -> Option<GitStatus> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_NONBLOCK)
        .open(root)
        .ok()?;
    let root_meta = directory.metadata().ok()?;
    if !git_cache_private(&root_meta, true) {
        return None;
    }
    let path = git_cache_path(root, key);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .ok()?;
    let file_meta = file.metadata().ok()?;
    if !git_cache_private(&file_meta, false) || file_meta.len() > GIT_CACHE_MAX_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    (&file)
        .take(GIT_CACHE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > GIT_CACHE_MAX_BYTES {
        return None;
    }
    // Bound accepted bytes to the held private file and unchanged namespace.
    for (held, original, named, directory) in [
        (
            file.metadata().ok()?,
            file_meta,
            std::fs::symlink_metadata(&path).ok()?,
            false,
        ),
        (
            directory.metadata().ok()?,
            root_meta,
            std::fs::symlink_metadata(root).ok()?,
            true,
        ),
    ] {
        if !git_cache_private(&held, directory)
            || !git_cache_private(&named, directory)
            || (held.dev(), held.ino()) != (original.dev(), original.ino())
            || (held.dev(), held.ino()) != (named.dev(), named.ino())
        {
            return None;
        }
    }
    let record: GitCacheRecord = serde_json::from_slice(&bytes).ok()?;
    if record.version != 1
        || record.key != key
        || record.branch.is_empty()
        || record.branch.chars().any(char::is_control)
        || now_ms.checked_sub(record.observed_ms)? >= GIT_CACHE_TTL_MS
    {
        return None;
    }
    Some(GitStatus {
        branch: record.branch,
        dirty: record.dirty,
    })
}

#[cfg(unix)]
fn write_git_cache(
    root: &Path,
    key: String,
    millis: u64,
    status: &GitStatus,
    now: std::time::SystemTime,
) {
    let published = git_cache_path(root, &key);
    write_git_cache_with(
        root,
        key,
        millis,
        status,
        &write_git_cache_tmp,
        &warn_git_cache_failure_once,
    );
    // The record this call just published is never a reclaim candidate.
    // Keep publication and reclamation in the probe's injected clock domain.
    sweep_git_cache_tmp(root, now, published.file_name());
}

/// Production tmp writer. Keeps the io error kind: `AlreadyExists` means the
/// entry is not ours to unlink.
#[cfg(unix)]
fn write_git_cache_tmp(tmp: &Path, bytes: &[u8]) -> std::io::Result<()> {
    csq_core::platform::fs::write_new_private(tmp, bytes).map_err(|e| match e {
        csq_core::error::PlatformError::Io(io) => io,
        other => std::io::Error::other(other),
    })
}

/// Write diagnostics: one WARN per anomaly tag, or DEBUG for an expected
/// tmp-name collision. Tags are fixed; no path or error text is logged.
#[cfg(unix)]
fn warn_git_cache_failure_once(error_kind: &'static str) {
    if error_kind == "git_cache_tmp_exists" {
        tracing::debug!(error_kind, "git cache temporary name already exists");
        return;
    }
    warn_git_cache_once(git_cache_failure_flag(error_kind), error_kind);
}

/// The once-per-process latch for a write-side failure tag: one per tag.
#[cfg(unix)]
fn git_cache_failure_flag(error_kind: &str) -> &'static std::sync::atomic::AtomicBool {
    use std::sync::atomic::AtomicBool;
    static WRITE_WARNED: AtomicBool = AtomicBool::new(false);
    static PUBLISH_WARNED: AtomicBool = AtomicBool::new(false);
    static ROOT_WARNED: AtomicBool = AtomicBool::new(false);
    static PRIVATE_WARNED: AtomicBool = AtomicBool::new(false);
    static STAT_WARNED: AtomicBool = AtomicBool::new(false);
    static SERIALIZE_WARNED: AtomicBool = AtomicBool::new(false);
    static OVERSIZE_WARNED: AtomicBool = AtomicBool::new(false);
    static MISSING_WARNED: AtomicBool = AtomicBool::new(false);
    match error_kind {
        "git_cache_tmp_missing" => &MISSING_WARNED,
        "git_cache_write" => &WRITE_WARNED,
        "git_cache_root" => &ROOT_WARNED,
        "git_cache_destination_private" => &PRIVATE_WARNED,
        "git_cache_destination_stat" => &STAT_WARNED,
        "git_cache_serialize" => &SERIALIZE_WARNED,
        "git_cache_oversize" => &OVERSIZE_WARNED,
        _ => &PUBLISH_WARNED,
    }
}

/// Publishes through `write_tmp`. Owned tmp files are removed after write or
/// publish failure; an `AlreadyExists` collision pre-dates this call and is
/// kept rather than unlinked. A write
/// failure and publish anomaly are reported with fixed tags: `git_cache_root`,
/// `git_cache_destination_private`, `git_cache_destination_stat`,
/// `git_cache_serialize`, `git_cache_oversize`, `git_cache_write`,
/// `git_cache_tmp_missing` (publish ENOENT), and `git_cache_publish` are
/// once-latched WARNs. `git_cache_tmp_exists` is an expected collision DEBUG;
/// that entry is kept, and can be swept only after its writer PID exits and
/// the stale/privacy checks pass in this host and PID namespace.
#[cfg(unix)]
fn write_git_cache_with(
    root: &Path,
    key: String,
    millis: u64,
    status: &GitStatus,
    write_tmp: &dyn Fn(&Path, &[u8]) -> std::io::Result<()>,
    report: &dyn Fn(&'static str),
) {
    if ensure_git_cache_root(root).is_none() {
        report("git_cache_root");
        return;
    }
    let path = git_cache_path(root, &key);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if !git_cache_private(&meta, false) => {
            report("git_cache_destination_private");
            return;
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            report("git_cache_destination_stat");
            return;
        }
        _ => {}
    }
    let record = GitCacheRecord {
        version: 1,
        key,
        observed_ms: millis,
        branch: status.branch.clone(),
        dirty: status.dirty,
    };
    let Ok(bytes) = serde_json::to_vec(&record) else {
        report("git_cache_serialize");
        return;
    };
    if bytes.len() as u64 > GIT_CACHE_MAX_BYTES {
        report("git_cache_oversize");
        return;
    }
    let tmp = csq_core::platform::fs::unique_tmp_path(&path);
    if let Err(e) = write_tmp(&tmp, &bytes) {
        // The writer may have created the file before failing (partial write),
        // but on AlreadyExists the entry pre-dates this call and is not ours;
        // that collision is kept while its PID is live. Only after that PID
        // exits can the stale/private orphan qualify for a sweep here.
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            report("git_cache_tmp_exists");
        } else {
            let _ = std::fs::remove_file(&tmp);
            report("git_cache_write");
        }
        return;
    }
    if let Err(error) = csq_core::platform::fs::atomic_replace(&tmp, &path) {
        let missing = matches!(
            &error,
            csq_core::error::PlatformError::Io(io)
                if io.kind() == std::io::ErrorKind::NotFound
        );
        let _ = std::fs::remove_file(tmp);
        report(if missing {
            "git_cache_tmp_missing"
        } else {
            "git_cache_publish"
        });
    }
}

/// A cache entry older than this is reclaimable. The enforced limit is
/// `GIT_CACHE_TTL_MS`: a record is refused once its age reaches the TTL, and
/// `observed_ms` is captured before the entry's mtime, so an entry whose mtime
/// is older than the TTL holds (or would publish) a record that is already
/// dead. The bound is 6x that limit (60s), a 50s margin over that point.
/// The write itself has no enforced duration. Tmp files are reclaimed only
/// when their positive PID parses and signal zero proves that writer is dead;
/// live, permission-denied and unknown writers are kept regardless of age.
/// These PID probes establish liveness only on the same host and in the same
/// PID namespace as the writer; this local cache does not identify remote
/// writers. PID reuse can retain an orphan. Publish ENOENT is anomalous and
/// emits the once-latched WARN tag `git_cache_tmp_missing`.
#[cfg(unix)]
const GIT_CACHE_STALE: std::time::Duration = std::time::Duration::from_millis(6 * GIT_CACHE_TTL_MS);
#[cfg(unix)]
const _: () = assert!(
    GIT_CACHE_STALE.as_millis() > GIT_CACHE_TTL_MS as u128,
    "the stale bound must exceed the TTL"
);
/// Directory entries (EVERY readdir result, matching or not, `.` and `..`
/// included) examined per sweep, so the walk is bounded by this cap.
#[cfg(unix)]
const GIT_CACHE_SWEEP_SCAN_CAP: usize = 1024;
/// Entries removed per sweep, so a huge backlog cannot slow every render.
/// Removal shrinks the directory, so repeated sweeps reach entries beyond the
/// scan cap, UNLESS the first `GIT_CACHE_SWEEP_SCAN_CAP` `readdir` entries
/// are all non-removable (fresh, foreign, or non-private ones the same user
/// planted). The scan counts `.` and `..` and every non-cache name too, so
/// `GIT_CACHE_SWEEP_SCAN_CAP - 2` planted entries suffice. Given a stable
/// `readdir` order (typical, not guaranteed) the sweep then never gets past
/// those.
#[cfg(unix)]
const GIT_CACHE_SWEEP_REMOVE_CAP: usize = 16;
/// Record-open/read attempts per sweep, independent of successful removals.
/// At most 64 * (GIT_CACHE_MAX_BYTES + 1) record bytes are read in one sweep.
/// A 64-record prefix of genuinely recent observations can consume this window
/// temporarily. Fixed timestamps within the five-minute future grace become
/// stale after that grace plus GIT_CACHE_STALE has elapsed; farther-future
/// values are stale immediately. Successful removals, capped at 16 per sweep,
/// advance this expired prefix. This does not bypass the 1024-readdir limit:
/// a stable prefix of non-removable entries can still prevent later admission.
#[cfg(unix)]
const GIT_CACHE_SWEEP_RECORD_READ_CAP: usize = 64;
/// Parsed observations through five minutes ahead are tolerated as clock skew.
/// Anything strictly beyond this enforced grace is stale, regardless of mtime.
#[cfg(unix)]
const GIT_CACHE_FUTURE_GRACE_MS: u128 = 5 * 60 * 1000;

/// Whether `name` is something this cache wrote: `<16 lowercase hex>.json`
/// (`git_cache_path`) or `<16 hex>.tmp.<digits>.<digits>` (`unique_tmp_path`).
#[cfg(unix)]
fn is_git_cache_entry_name(name: &str) -> bool {
    let digits =
        |p: Option<&str>| p.is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    let mut parts = name.split('.');
    if !parts.next().is_some_and(|stem| {
        stem.len() == 16 && stem.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }) {
        return false;
    }
    match parts.next() {
        Some("json") => parts.next().is_none(),
        Some("tmp") => digits(parts.next()) && digits(parts.next()) && parts.next().is_none(),
        _ => false,
    }
}

/// Parses the PID component written by `unique_tmp_path`. Invalid, zero,
/// overflowing or process-group PIDs never authorize reclamation.
#[cfg(unix)]
fn git_cache_tmp_writer_pid(name: &std::ffi::CStr) -> Option<libc::pid_t> {
    let name = name.to_str().ok()?;
    if !is_git_cache_entry_name(name) {
        return None;
    }
    let mut parts = name.split('.');
    parts.next()?;
    if parts.next()? != "tmp" {
        return None;
    }
    parts
        .next()?
        .parse::<libc::pid_t>()
        .ok()
        .filter(|pid| *pid > 0)
}

/// Only ESRCH proves a dead PID in this host's current PID namespace. It is
/// not proof about a writer on another host or in another PID namespace.
/// EPERM and every other error fail closed.
#[cfg(unix)]
fn git_cache_pid_probe_proves_dead(result: libc::c_int, errno: Option<libc::c_int>) -> bool {
    result == -1 && errno == Some(libc::ESRCH)
}

#[cfg(unix)]
fn git_cache_tmp_writer_dead(name: &std::ffi::CStr) -> bool {
    let Some(pid) = git_cache_tmp_writer_pid(name) else {
        return false;
    };
    // SAFETY: pid is one positive process ID; signal zero sends no signal.
    let result = unsafe { libc::kill(pid, 0) };
    let errno = (result == -1)
        .then(|| std::io::Error::last_os_error().raw_os_error())
        .flatten();
    git_cache_pid_probe_proves_dead(result, errno)
}

/// A changed record, even with a recycled inode, must not be removed.
#[cfg(unix)]
fn git_cache_record_generation_unchanged(before: &libc::stat, after: &libc::stat) -> bool {
    (before.st_ctime, before.st_ctime_nsec, before.st_size)
        == (after.st_ctime, after.st_ctime_nsec, after.st_size)
}

/// Logs a fixed-vocabulary WARN at most once per process per category; the
/// statusline is stdout-only, so a failing cache would otherwise be invisible.
#[cfg(unix)]
fn warn_git_cache_once(flag: &std::sync::atomic::AtomicBool, error_kind: &'static str) -> bool {
    let first = !flag.swap(true, std::sync::atomic::Ordering::Relaxed);
    if first {
        tracing::warn!(error_kind, "git cache could not be written or swept");
    }
    first
}

/// Once-per-process WARN for a sweep failure; one latch per fixed tag.
#[cfg(unix)]
fn warn_git_cache_sweep_once(error_kind: &'static str) {
    use std::sync::atomic::AtomicBool;
    static ROOT_WARNED: AtomicBool = AtomicBool::new(false);
    static LIST_WARNED: AtomicBool = AtomicBool::new(false);
    static STAT_WARNED: AtomicBool = AtomicBool::new(false);
    static REMOVE_WARNED: AtomicBool = AtomicBool::new(false);
    static READ_WARNED: AtomicBool = AtomicBool::new(false);
    let flag = match error_kind {
        "git_cache_sweep_root" => &ROOT_WARNED,
        "git_cache_sweep_list" => &LIST_WARNED,
        "git_cache_sweep_stat" => &STAT_WARNED,
        "git_cache_sweep_remove" => &REMOVE_WARNED,
        _ => &READ_WARNED,
    };
    warn_git_cache_once(flag, error_kind);
}

/// Address of this thread's `errno`, to tell end-of-directory from a failed read.
#[cfg(target_os = "macos")]
fn git_cache_errno() -> *mut libc::c_int {
    // SAFETY: `__error` returns the calling thread's errno slot and has no preconditions.
    unsafe { libc::__error() }
}
#[cfg(all(unix, not(target_os = "macos")))]
fn git_cache_errno() -> *mut libc::c_int {
    // SAFETY: `__errno_location` returns the calling thread's errno slot and has no preconditions.
    unsafe { libc::__errno_location() }
}

/// A regular, euid-owned, mode-0600, single-link file.
#[cfg(unix)]
fn git_cache_private_stat(st: &libc::stat, euid: libc::uid_t) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFREG
        && st.st_uid == euid
        && st.st_mode & 0o7777 == 0o600
        && st.st_nlink == 1
}

/// Whether the entry's mtime is older than `GIT_CACHE_STALE` at `now`; an
/// unrepresentable or future mtime is not stale.
#[cfg(unix)]
fn git_cache_mtime_stale(st: &libc::stat, now: std::time::SystemTime) -> bool {
    u64::try_from(st.st_mtime).ok().is_some_and(|secs| {
        let modified = std::time::UNIX_EPOCH
            + std::time::Duration::new(secs, u32::try_from(st.st_mtime_nsec).unwrap_or(0));
        now.duration_since(modified)
            .is_ok_and(|age| age > GIT_CACHE_STALE)
    })
}

/// The reclaim predicate for a tmp file: private (see `git_cache_private_stat`)
/// AND stale by mtime.
#[cfg(unix)]
fn git_cache_reclaimable(st: &libc::stat, euid: libc::uid_t, now: std::time::SystemTime) -> bool {
    git_cache_private_stat(st, euid) && git_cache_mtime_stale(st, now)
}

/// What reading a cache record for the sweep yielded.
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
enum RecordRead {
    /// Parsed; carries `observed_ms`.
    Observed(u64),
    /// Read without error, but more than `GIT_CACHE_MAX_BYTES` or not a valid
    /// record: mtime decides.
    Unparseable,
    /// Could not be opened (other than ENOENT) or read (EMFILE, EIO, ...):
    /// the entry is KEPT.
    Unreadable,
    /// Removed before it was opened (a concurrent sweep or other unlink; a
    /// writer's rename never removes the name): skipped, nothing to do.
    Gone,
}

/// Reads the record named `name` under `dir_fd` through an
/// `openat(O_NOFOLLOW)`, bounded to `GIT_CACHE_MAX_BYTES`.
#[cfg(unix)]
fn git_cache_record_observed(dir_fd: std::os::fd::RawFd, name: &std::ffi::CStr) -> RecordRead {
    use std::os::fd::FromRawFd;
    // SAFETY: `dir_fd` is the live held root; `name` is NUL-terminated; the
    // returned fd is owned and wrapped immediately.
    let fd = unsafe {
        libc::openat(
            dir_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            RecordRead::Gone
        } else {
            RecordRead::Unreadable
        };
    }
    // SAFETY: `fd` is fresh from openat and owned by nothing else.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut bytes = Vec::new();
    if (&file)
        .take(GIT_CACHE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return RecordRead::Unreadable;
    }
    if bytes.len() as u64 > GIT_CACHE_MAX_BYTES {
        return RecordRead::Unparseable;
    }
    serde_json::from_slice::<GitCacheRecord>(&bytes).map_or(RecordRead::Unparseable, |r| {
        RecordRead::Observed(r.observed_ms)
    })
}

/// Reclaims stale cache entries: tmp files left by killed writers and records
/// past the TTL. Best-effort; never fails the render.
///
/// Self-guarding on the root: it opens the directory `O_NOFOLLOW|O_DIRECTORY`,
/// requires THAT fd to be a private (euid, 0700) directory, and then lists,
/// stats (`fstatat`, no-follow) and removes (`unlinkat`) strictly relative to
/// the held fd, so a root swapped after the check cannot redirect a delete.
/// An entry is removed only if it is a regular file, euid-owned, mode 0600,
/// single-link and stale as observed by `fstatat`. Immediately before unlink,
/// identity and privacy are checked again; records must also retain ctime
/// (seconds and nanoseconds) and size, while tmp files must remain stale with
/// a provably dead writer PID. Staleness of a `.json`
/// record comes from `observed_ms`: observations more than five minutes ahead
/// of `now` are stale irrespective of mtime; nearer future observations are
/// kept, and past observations use GIT_CACHE_STALE. Mtime is a fallback only
/// for a record that was read
/// up to the `GIT_CACHE_MAX_BYTES + 1` cap without error but is oversize or
/// invalid; a record that cannot be opened (other than ENOENT, which is
/// skipped) or read is KEPT (WARN `git_cache_sweep_read`). Record reads have
/// an independent 64-attempt cap. Tmp files use mtime plus writer liveness. `keep`
/// names an entry that is never a candidate.
/// POSIX has no inode-conditional unlink, so a record renamed onto the same
/// name between the re-check and the unlink is removed too. That window has no
/// enforced duration (the process can be preempted there), and inode numbers
/// can be recycled; matching ctime and size tighten that record exposure but
/// cannot provide an atomic conditional unlink. Tmp liveness checks keep a
/// live writer even if it has been paused longer than the age bound.
/// Whatever its length, the cost is one cache miss per removed record and no
/// data loss (the cache is display-only and re-probed).
/// Any other unreadable entry is also kept. Returns the number of entries
/// examined.
#[cfg(unix)]
fn sweep_git_cache_tmp(
    root: &Path,
    now: std::time::SystemTime,
    keep: Option<&std::ffi::OsStr>,
) -> usize {
    sweep_git_cache_entries(
        root,
        now,
        keep,
        &git_cache_record_observed,
        &|_| {},
        &warn_git_cache_sweep_once,
    )
}

/// `sweep_git_cache_tmp` with its three seams: `read_record` (how a record is
/// read), `before_recheck` (called between the staleness decision and the
/// identity re-check) and `report` (called with a fixed `git_cache_sweep_*`
/// tag on EVERY sweep failure; production latches it to one WARN per process),
/// so tests can force the failure and race paths and observe the reports.
#[cfg(unix)]
fn sweep_git_cache_entries(
    root: &Path,
    now: std::time::SystemTime,
    keep: Option<&std::ffi::OsStr>,
    read_record: &dyn Fn(std::os::fd::RawFd, &std::ffi::CStr) -> RecordRead,
    before_recheck: &dyn Fn(&std::ffi::CStr),
    report: &dyn Fn(&'static str),
) -> usize {
    use std::ffi::CStr;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::OpenOptionsExt;

    let Ok(dir) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(root)
    else {
        report("git_cache_sweep_root");
        return 0;
    };
    match dir.metadata() {
        Ok(meta) if git_cache_private(&meta, true) => {}
        _ => {
            report("git_cache_sweep_root");
            return 0;
        }
    }
    // fdopendir takes ownership of the fd it is given, so give it a duplicate.
    // SAFETY: `dir` is a live fd; dup has no other preconditions.
    let dup = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        report("git_cache_sweep_list");
        return 0;
    }
    // SAFETY: `dup` is a fresh directory fd owned here; on success the DIR*
    // owns it and closedir below releases it, on failure we close it.
    let stream = unsafe { libc::fdopendir(dup) };
    if stream.is_null() {
        // SAFETY: fdopendir failed, so `dup` is still ours to close.
        unsafe { libc::close(dup) };
        report("git_cache_sweep_list");
        return 0;
    }
    let mut names: Vec<std::ffi::CString> = Vec::new();
    let mut examined = 0;
    loop {
        if examined >= GIT_CACHE_SWEEP_SCAN_CAP {
            break;
        }
        // SAFETY: `stream` is a live DIR*; errno is cleared to tell end from error.
        let entry = unsafe {
            *git_cache_errno() = 0;
            libc::readdir(stream)
        };
        if entry.is_null() {
            if std::io::Error::last_os_error().raw_os_error().unwrap_or(0) != 0 {
                report("git_cache_sweep_list");
            }
            break;
        }
        examined += 1;
        // SAFETY: readdir returned a valid dirent whose d_name is NUL-terminated.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_str().is_ok_and(is_git_cache_entry_name)
            && keep.is_none_or(|k| k.as_bytes() != name.to_bytes())
        {
            names.push(name.to_owned());
        }
    }
    // SAFETY: `stream` is live and not used after this; it closes `dup`.
    unsafe { libc::closedir(stream) };

    let mut removed = 0;
    let mut record_reads = 0;
    for name in names {
        if removed >= GIT_CACHE_SWEEP_REMOVE_CAP {
            break;
        }
        // SAFETY: zeroed stat is a valid out-parameter; fd and name are live.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::NotFound {
                report("git_cache_sweep_stat");
            }
            continue;
        }
        // SAFETY: geteuid has no preconditions and changes no process state.
        let euid = unsafe { libc::geteuid() };
        if !git_cache_private_stat(&st, euid) {
            continue;
        }
        let is_record = name.to_bytes().ends_with(b".json");
        let reclaimable = if is_record {
            if record_reads >= GIT_CACHE_SWEEP_RECORD_READ_CAP {
                continue;
            }
            record_reads += 1;
            match read_record(dir.as_raw_fd(), &name) {
                RecordRead::Unreadable => {
                    report("git_cache_sweep_read");
                    continue;
                }
                RecordRead::Gone => continue,
                RecordRead::Observed(observed_ms) => {
                    let now_ms = now
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_millis());
                    u128::from(observed_ms) > now_ms.saturating_add(GIT_CACHE_FUTURE_GRACE_MS)
                        || now_ms.saturating_sub(u128::from(observed_ms))
                            > GIT_CACHE_STALE.as_millis()
                }
                RecordRead::Unparseable => git_cache_mtime_stale(&st, now),
            }
        } else {
            git_cache_reclaimable(&st, euid, now) && git_cache_tmp_writer_dead(&name)
        };
        if !reclaimable {
            continue;
        }
        before_recheck(&name);
        // Re-check identity/privacy plus record ctime/size, or tmp age and
        // writer liveness, immediately before unlinking.
        // SAFETY: as above.
        let mut again: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                &mut again,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::NotFound {
                report("git_cache_sweep_stat");
            }
            continue;
        }
        if (again.st_dev, again.st_ino) != (st.st_dev, st.st_ino)
            || !git_cache_private_stat(&again, euid)
            || (is_record && !git_cache_record_generation_unchanged(&st, &again))
            || (!is_record
                && (!git_cache_mtime_stale(&again, now) || !git_cache_tmp_writer_dead(&name)))
        {
            continue;
        }
        // SAFETY: fd is the held, verified root; unlinkat removes the entry
        // itself and never follows a symlink.
        if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } == 0 {
            removed += 1;
        } else if std::io::Error::last_os_error().kind() != std::io::ErrorKind::NotFound {
            report("git_cache_sweep_remove");
        }
    }
    examined
}

/// Why the repository probe could not be made, when it could not be made.
enum GitProbeMiss {
    /// git ran to completion and exited with a code — 128 for "not a
    /// repository", 126/127/129 for exec/usage refusals. Every non-zero code
    /// is git HAVING ANSWERED (with a refusal): a MEASUREMENT. The specific
    /// refusal is not distinguished because every caller renders both misses
    /// identically, and this predicate is not the place to guess which code
    /// means what (review R1 LOW-3).
    GitAnswered,
    /// No answer was obtained: the spawn failed, or git was killed before it
    /// could exit — the ABSENCE of a measurement. On Unix, a signal-killed
    /// git is exactly `code() == None`; on Windows `code()` is always Some,
    /// so an externally killed git lands in `GitAnswered` there instead —
    /// not distinguished (review R2 LOW-3). an internal ticket: the two collapsed
    /// into one `None`, so a git killed under load was indistinguishable
    /// from a plain non-repo at every caller.
    Unmeasured,
}

/// Probe whether `workdir` is inside a git repository, keeping "measured no"
/// distinct from "could not measure". Both render as `None` through
/// `git_status_uncached` (the display question is unchanged), but the reason
/// stays nameable at each assertion site.
fn git_repo_probe(workdir: &Path) -> Result<(), GitProbeMiss> {
    match Command::new("git")
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(workdir)
        .arg("rev-parse")
        .arg("--git-dir")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Err(_) => Err(GitProbeMiss::Unmeasured),
        Ok(status) => match status.code() {
            Some(0) => Ok(()),
            // Any non-zero exit is git having ANSWERED (128 for a non-repo).
            Some(_) => Err(GitProbeMiss::GitAnswered),
            // On Unix, `code()` is None exactly when a signal terminated
            // git. On Windows `code()` is always Some, so an externally
            // killed git reads as GitAnswered there — not distinguished
            // (review R2 LOW-3).
            None => Err(GitProbeMiss::Unmeasured),
        },
    }
}

/// Four best-effort Git commands; failures preserve dirty's unknown state.
fn git_status_uncached(workdir: &Path) -> Option<GitStatus> {
    if !workdir.is_dir() {
        return None;
    }

    // Stage 1: is this a git repo at all? The miss REASON is preserved (see
    // `git_repo_probe`) so an assertion site can tell a measured "not a repo"
    // from a spawn failure or a git killed before it could answer — issue
    // an internal ticket: under load a killed git read exactly like an ordinary non-repo.
    if git_repo_probe(workdir).is_err() {
        return None;
    }

    // Stage 2: current branch. Empty stdout on detached HEAD — but "detached"
    // is only a MEASUREMENT when git actually ran and answered; a spawn
    // failure or a git killed under load must stay unmeasured (None). This is
    // the same collapse stage 3 was fixed for, one command over — and an internal ticket's
    // owner diagnosis names these earlier probe paths as the outer `None`
    // source: a killed `branch --show-current` prints nothing, and reading
    // that empty stdout as a factual `detached` is a confident wrong answer
    // from an unmeasured command.
    let branch_out = Command::new("git")
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(workdir)
        .arg("branch")
        .arg("--show-current")
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !branch_out.status.success() {
        return None;
    }
    let branch_raw = String::from_utf8_lossy(&branch_out.stdout)
        .trim()
        .to_string();
    let branch = if branch_raw.is_empty() {
        "detached".to_string()
    } else {
        branch_raw
    };

    // Stage 3: dirty? `git diff --quiet` returns 0 clean, 1 dirty.
    // THREE outcomes, not two: `Some(false)` (clean), `Some(true)`
    // (dirty), or `None` when git could not answer at all — spawn
    // failure, or any exit that is neither 0 nor 1. That last case
    // covers a missing binary, an aborted diff (exit 128), AND a
    // signal-killed git process (`ExitStatus::code()` returns `None`
    // on Unix) — the collapse that made this function report a
    // confident `dirty: false` for a killed-under-load git process,
    // indistinguishable from a genuinely clean repo (an internal ticket).
    // `None` is NOT inferred to be clean here; only the render site
    // in `quota::format::rich_statusline` decides how to DISPLAY an
    // unmeasured repo, and it deliberately renders `None` the same as
    // clean — see that function's doc for why display and knowledge
    // are different questions.
    let diff_dirty = |status: std::io::Result<std::process::ExitStatus>| -> Option<bool> {
        match status.ok().and_then(|s| s.code()) {
            Some(0) => Some(false),
            Some(1) => Some(true),
            _ => None,
        }
    };
    let worktree_dirty = diff_dirty(
        Command::new("git")
            .arg("--no-optional-locks")
            .arg("-C")
            .arg(workdir)
            .arg("diff")
            .arg("--quiet")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    );
    let index_dirty = diff_dirty(
        Command::new("git")
            .arg("--no-optional-locks")
            .arg("-C")
            .arg(workdir)
            .arg("diff")
            .arg("--cached")
            .arg("--quiet")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    );
    // A confirmed dirty from EITHER side wins even if the other side
    // could not be measured — dirty is dirty. Only when neither side
    // confirms dirty AND at least one side is unmeasured does the
    // combined result become `None` rather than a confident `false`.
    let dirty = match (worktree_dirty, index_dirty) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        _ => None,
    };

    Some(GitStatus { branch, dirty })
}

#[cfg(all(test, unix))]
#[path = "statusline_git_cache_tests.rs"]
mod git_cache_tests;

#[cfg(test)]
mod tests {

    #[test]
    fn message_segment_counts_and_distinguishes_absence_from_failure() {
        assert_eq!(message_status(Ok(None)), None);
        let c = |pending, unreadable| {
            Ok(Some(PendingCount {
                pending,
                queued: pending,
                unreadable,
            }))
        };
        assert_eq!(message_status(c(0, 0)), None);
        assert_eq!(message_status(c(1, 0)).as_deref(), Some("[1 message]"));
        assert_eq!(message_status(c(3, 0)).as_deref(), Some("[3 messages]"));
        assert_eq!(
            message_status(c(2, 1)).as_deref(),
            Some("[2 messages, 1 unreadable]")
        );
        assert_eq!(
            message_status(c(0, 2)).as_deref(),
            Some("[messages: 2 unreadable]")
        );
        assert_eq!(message_status(Err(())).as_deref(), Some("[messages: ?]"));
    }

    #[test]
    fn directive_notice_absent_when_nothing_pending_and_truncates_long_summaries() {
        use csq_core::sessions::directives::PendingInfo;
        let none = PendingInfo {
            pending: 0,
            last_directive_at: None,
            first_summary: None,
        };
        assert_eq!(directive_notice(&none), None);
        let one = PendingInfo {
            pending: 1,
            last_directive_at: Some(1),
            first_summary: Some("Free disk".into()),
        };
        assert_eq!(
            directive_notice(&one).as_deref(),
            Some("[1 directive: Free disk]")
        );
        let long = PendingInfo {
            pending: 2,
            last_directive_at: Some(1),
            first_summary: Some("x".repeat(80)),
        };
        let n = directive_notice(&long).unwrap();
        assert!(n.starts_with("[2 directives: "), "{n}");
        assert!(n.ends_with("…]"), "{n}");
        assert_eq!(n.chars().filter(|c| *c == 'x').count(), 60);
    }

    #[test]
    fn directive_notice_drops_hidden_character_classes_from_the_summary() {
        use csq_core::sessions::directives::PendingInfo;
        for (class, ch) in [
            ("Cc", '\u{1b}'),
            ("Cf bidi", '\u{202E}'),
            ("Cf zero-width", '\u{200B}'),
            ("Cf BOM", '\u{FEFF}'),
            ("Cf tag", '\u{E0041}'),
            ("Zl", '\u{2028}'),
            ("Zp", '\u{2029}'),
            ("Co", '\u{E000}'),
            ("Cn", '\u{0378}'),
            ("variation selector", '\u{FE0F}'),
            ("variation selector supplement", '\u{E0100}'),
            ("CGJ", '\u{034F}'),
            ("Mongolian selector", '\u{180B}'),
            ("Khmer inherent vowel", '\u{17B4}'),
            ("Hangul filler", '\u{115F}'),
            ("Hangul filler 3164", '\u{3164}'),
            ("halfwidth Hangul filler", '\u{FFA0}'),
            ("braille blank", '\u{2800}'),
            // combining marks are accepted in directive text but would stack over the
            // character before them on the statusline line
            ("Mn combining acute", '\u{0301}'),
            ("Me combining enclosing circle", '\u{20DD}'),
        ] {
            let p = PendingInfo {
                pending: 1,
                last_directive_at: Some(1),
                first_summary: Some(format!("Free{ch} disk")),
            };
            assert_eq!(
                directive_notice(&p).as_deref(),
                Some("[1 directive: Free disk]"),
                "{class}"
            );
        }
    }

    #[test]
    fn unreadable_store_shows_a_question_mark_and_absence_shows_nothing() {
        use csq_core::sessions::directives::{DirectiveError, PendingInfo};
        assert_eq!(directive_status(Ok(None)), None);
        let quiet = PendingInfo {
            pending: 0,
            last_directive_at: None,
            first_summary: None,
        };
        assert_eq!(directive_status(Ok(Some(quiet))), None);
        let e = DirectiveError {
            code: csq_core::sdk::SdkErrorCode::Undetermined,
            message: "x".into(),
            next_allowed_at: None,
            cause: None,
            attempts: None,
        };
        assert_eq!(directive_status(Err(e)).as_deref(), Some("[directives: ?]"));
    }

    #[test]
    fn model_manifest_statusline_context_reads_updates_and_rejects_invalid_data() {
        use csq_core::providers::model_manifest::{manifest_path, ModelManifest};
        let base = tempfile::TempDir::new().unwrap();
        assert_eq!(
            super::model_context_window(base.path(), "deepseek-flash[1m]").unwrap(),
            Some(1_000_000)
        );
        let mut manifest = ModelManifest::bundled();
        manifest
            .models
            .iter_mut()
            .find(|m| m.id == "deepseek-flash")
            .unwrap()
            .context_window = Some(2_000_000);
        let path = manifest_path(base.path());
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert_eq!(
            super::model_context_window(base.path(), "deepseek-flash[1m]").unwrap(),
            Some(2_000_000)
        );
        std::fs::write(path, b"invalid").unwrap();
        assert!(super::model_context_window(base.path(), "deepseek-flash[1m]").is_err());
    }

    use super::*;
    use tempfile::TempDir;

    /// Serialises tests that mutate `CLAUDE_CONFIG_DIR`.
    ///
    /// `std::env::set_var` is process-wide; running two env-mutating
    /// tests in parallel produces a read/write race where one test
    /// sees the other's value.
    ///
    /// MUST acquire the WORKSPACE-WIDE mutex
    /// (`csq_core::platform::test_env::lock()`), not a module-local
    /// one, per `testing.md` MUST Rule 6. A module-local `Mutex` only
    /// serialized statusline's own env tests — it did NOT serialize
    /// against `swap.rs`'s `detect_source_handle` tests, which mutate
    /// the SAME `CLAUDE_CONFIG_DIR` under the canonical lock. The two
    /// locks were disjoint, so the suites raced cross-module: a
    /// statusline test rewriting `CLAUDE_CONFIG_DIR` between a swap
    /// test's `EnvVarGuard::set` and its `detect_source_handle` call
    /// made the swap test observe statusline's value and return the
    /// wrong error variant. macOS-only by CI thread-scheduling luck
    /// (green on an internal ticket macOS + an internal ticket ubuntu/windows, red on an internal ticket
    /// macOS). Root-caused + fixed per `zero-tolerance.md` Rule 1
    /// during the v2.8.0-rc.1 cut; see an internal journal entry
    struct GitEnvironmentGuard {
        previous: Vec<(std::ffi::OsString, std::ffi::OsString)>,
        home: TempDir,
        _lock: csq_core::platform::test_env::EnvTestGuard,
    }

    impl Drop for GitEnvironmentGuard {
        fn drop(&mut self) {
            // Restore while the shared lock and sandbox are still alive, on
            // success and unwind alike. Remove test-added Git overrides too.
            for (key, _) in
                std::env::vars_os().filter(|(key, _)| key.to_string_lossy().starts_with("GIT_"))
            {
                unsafe { std::env::remove_var(key) };
            }
            for key in ["HOME", "USERPROFILE", "XDG_CONFIG_HOME"] {
                unsafe { std::env::remove_var(key) };
            }
            for (key, value) in &self.previous {
                unsafe { std::env::set_var(key, value) };
            }
        }
    }

    fn env_guard() -> GitEnvironmentGuard {
        let lock = csq_core::platform::test_env::lock();
        let home = TempDir::new().expect("production Git probe sandbox home");
        let previous = std::env::vars_os()
            .filter(|(key, _)| {
                key.to_string_lossy().starts_with("GIT_")
                    || ["HOME", "USERPROFILE", "XDG_CONFIG_HOME"]
                        .iter()
                        .any(|name| key == std::ffi::OsStr::new(name))
            })
            .collect();
        let guard = GitEnvironmentGuard {
            previous,
            home,
            _lock: lock,
        };
        for (key, _) in
            std::env::vars_os().filter(|(key, _)| key.to_string_lossy().starts_with("GIT_"))
        {
            unsafe { std::env::remove_var(key) };
        }
        assert!(!std::env::vars_os().any(|(key, _)| key.to_string_lossy().starts_with("GIT_")));
        // The production readers retain their normal environment semantics;
        // these test callers provide only owned configuration and home paths.
        let config = guard.home.path().join("empty-gitconfig");
        std::fs::write(&config, b"").expect("empty probe Git config");
        unsafe {
            std::env::set_var("GIT_CONFIG_NOSYSTEM", "1");
            std::env::set_var("GIT_CONFIG_GLOBAL", config);
            for key in ["HOME", "USERPROFILE", "XDG_CONFIG_HOME"] {
                std::env::set_var(key, guard.home.path());
            }
        }
        guard
    }

    fn run_git(dir: &Path, args: &[&str]) {
        let home = TempDir::new().expect("sandbox Git home");
        let status = csq_core::platform::test_git::command(dir, home.path())
            .expect("sandbox Git command")
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("git not available on PATH — tests require git");
        assert!(status.success(), "git {:?} failed", args);
    }

    /// Panic naming the probe's own reason when git_status could not measure
    /// the fixture. The re-probe exists ONLY to annotate the failure — it never
    /// changes the verdict (an internal ticket: a load-killed git surfaced as a bare
    /// `None` panic, indistinguishable from a git_status defect).
    fn expect_measured(g: Option<GitStatus>, dir: &Path) -> GitStatus {
        g.unwrap_or_else(|| {
            panic!(
                "git_status could not measure {}: {}",
                dir.display(),
                match git_repo_probe(dir) {
                    Ok(()) => "the repo probe succeeded on the failure re-run — a LATER stage failed (e.g. the branch probe exited non-zero, as on git < 2.22 with no --show-current), or the failure was transient (resource exhaustion under load)",
                    Err(GitProbeMiss::GitAnswered) => "git ANSWERED with a non-zero code (128: not a repository; other codes: git refusing) — fixture or git_status defect",
                    Err(GitProbeMiss::Unmeasured) => "git could not be measured (spawn failed or killed — resource exhaustion under load)",
                }
            )
        })
    }

    #[cfg(unix)]
    #[test]
    fn git_probe_names_a_killed_git_as_unmeasured() {
        // an internal ticket: under a loaded host a spawned git can die before it answers.
        // The probe must report that as Unmeasured — never as a measured "not
        // a repository" — or a resource kill reads as a git_status defect.
        // Same PATH-under-the-workspace-lock discipline as the sibling tests.
        let _guard = env_guard();
        use std::os::unix::fs::PermissionsExt;

        // A real non-repo dir answered by REAL git is a MEASUREMENT.
        let tmp = TempDir::new().unwrap();
        struct RestoreCeiling(Option<std::ffi::OsString>);
        impl Drop for RestoreCeiling {
            fn drop(&mut self) {
                match &self.0 {
                    Some(value) => unsafe { std::env::set_var("GIT_CEILING_DIRECTORIES", value) },
                    None => unsafe { std::env::remove_var("GIT_CEILING_DIRECTORIES") },
                }
            }
        }
        let _ceiling = RestoreCeiling(std::env::var_os("GIT_CEILING_DIRECTORIES"));
        let ceiling = tmp.path().parent().unwrap().canonicalize().unwrap();
        unsafe { std::env::set_var("GIT_CEILING_DIRECTORIES", ceiling) };
        assert!(matches!(
            git_repo_probe(tmp.path()),
            Err(GitProbeMiss::GitAnswered)
        ));

        // A `git` that kills itself before printing anything is UNMEASURED —
        // even though the directory is likewise not a repository.
        let stub = tmp.path().join("bin");
        std::fs::create_dir(&stub).unwrap();
        let git = stub.join("git");
        std::fs::write(&git, "#!/bin/sh\nkill -9 $$\n").unwrap();
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
        struct RestorePath(Option<std::ffi::OsString>);
        impl Drop for RestorePath {
            fn drop(&mut self) {
                match &self.0 {
                    Some(value) => unsafe { std::env::set_var("PATH", value) },
                    None => unsafe { std::env::remove_var("PATH") },
                }
            }
        }
        let _path = RestorePath(std::env::var_os("PATH"));
        unsafe { std::env::set_var("PATH", &stub) };
        assert!(matches!(
            git_repo_probe(tmp.path()),
            Err(GitProbeMiss::Unmeasured)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn git_status_stays_unmeasured_when_a_probe_command_is_killed() {
        // an internal ticket, the fail-open half. A `git branch --show-current` killed
        // before it answers prints NOTHING, and the old code read that empty
        // stdout as a factual `detached` — a confident wrong answer from an
        // unmeasured command (the outer-`None` diagnosis's "branch probe
        // path"). A killed probe command must leave the whole status
        // unmeasured: None, never a fabricated branch or dirty flag.
        let _guard = env_guard();
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let stub = tmp.path().join("bin");
        std::fs::create_dir(&stub).unwrap();
        let git = stub.join("git");
        // Answers everything with exit 0 (so the repo probe passes) except a
        // `branch` invocation, where it dies on SIGKILL mid-answer.
        std::fs::write(
            &git,
            "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = \"branch\" ] && kill -9 $$; done\nexit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
        struct RestorePath(Option<std::ffi::OsString>);
        impl Drop for RestorePath {
            fn drop(&mut self) {
                match &self.0 {
                    Some(value) => unsafe { std::env::set_var("PATH", value) },
                    None => unsafe { std::env::remove_var("PATH") },
                }
            }
        }
        let _path = RestorePath(std::env::var_os("PATH"));
        unsafe { std::env::set_var("PATH", &stub) };
        assert!(
            git_status_uncached(tmp.path()).is_none(),
            "a killed branch probe must yield None, never a fabricated `detached` status"
        );
    }

    #[test]
    fn git_status_none_outside_repo() {
        // MUST hold the WORKSPACE-WIDE lock: this test spawns `git`, which is
        // resolved through the process-global PATH, and sibling tests in this
        // same `csq --lib` binary set `PATH` to "" and to a fixture dir
        // (`csq/src/desktop/commands/mod.rs`) under that same lock. A reader
        // that skips it races a mid-flight mutation, `Command::new("git")`
        // fails to spawn, `git_status` returns None via `.ok()?`, and the
        // assertion below reads as "not in a repo". Reader side of
        // `test-hermeticity.md` MUST-1b/1c — mutating nothing is not the same
        // as not participating in the race.
        let _guard = env_guard();
        // A non-existent dir shouldn't be probed.
        assert!(git_status("/definitely/not/a/real/path/12345").is_none());

        // TempDir may live under the checkout's isolated TMPDIR. Bound Git's
        // parent discovery so this fixture cannot inherit the enclosing repo.
        let tmp = TempDir::new().unwrap();
        struct RestoreCeiling(Option<std::ffi::OsString>);
        impl Drop for RestoreCeiling {
            fn drop(&mut self) {
                match &self.0 {
                    Some(value) => unsafe { std::env::set_var("GIT_CEILING_DIRECTORIES", value) },
                    None => unsafe { std::env::remove_var("GIT_CEILING_DIRECTORIES") },
                }
            }
        }
        let _restore = RestoreCeiling(std::env::var_os("GIT_CEILING_DIRECTORIES"));
        let ceiling = tmp.path().parent().unwrap().canonicalize().unwrap();
        unsafe { std::env::set_var("GIT_CEILING_DIRECTORIES", ceiling) };
        assert!(git_status_at(tmp.path(), None, std::time::SystemTime::now()).is_none());
    }

    #[test]
    fn git_status_clean_repo_reports_branch_not_dirty() {
        // MUST hold the WORKSPACE-WIDE lock: this test spawns `git`, which is
        // resolved through the process-global PATH, and sibling tests in this
        // same `csq --lib` binary set `PATH` to "" and to a fixture dir
        // (`csq/src/desktop/commands/mod.rs`) under that same lock. A reader
        // that skips it races a mid-flight mutation, `Command::new("git")`
        // fails to spawn, `git_status` returns None via `.ok()?`, and the
        // assertion below reads as "not in a repo". Reader side of
        // `test-hermeticity.md` MUST-1b/1c — mutating nothing is not the same
        // as not participating in the race.
        let _guard = env_guard();
        let tmp = TempDir::new().unwrap();
        run_git(tmp.path(), &["init", "-q", "--initial-branch=main"]);
        // Fresh repo with no commits is still considered "in a repo".
        // Create an initial commit so `--show-current` returns `main`.
        std::fs::write(tmp.path().join("README"), "hello").unwrap();
        run_git(tmp.path(), &["add", "README"]);
        run_git(tmp.path(), &["commit", "-q", "-m", "init"]);

        let g = expect_measured(
            git_status_at(tmp.path(), None, std::time::SystemTime::now()),
            tmp.path(),
        );
        assert_eq!(g.branch, "main");
        assert_eq!(
            g.dirty,
            Some(false),
            "freshly-committed repo should be clean"
        );
    }

    #[test]
    fn git_status_real_detached_head_reports_detached() {
        // Review R1 MED-3: `git branch --show-current` on a REAL detached HEAD
        // exits 0 with EMPTY stdout — a MEASUREMENT of detachment that must
        // still render `detached`. A stage 2 that returned None on empty stdout,
        // or on every result, would pass every other test in this module; the
        // killed-probe test above only covers the no-answer direction, so
        // without this leg the honest path has no non-vacuity witness.
        // Same workspace-lock discipline as the sibling tests (spawns `git`
        // through the process-global PATH).
        let _guard = env_guard();
        let tmp = TempDir::new().unwrap();
        run_git(tmp.path(), &["init", "-q", "--initial-branch=main"]);
        std::fs::write(tmp.path().join("README"), "hello").unwrap();
        run_git(tmp.path(), &["add", "README"]);
        run_git(tmp.path(), &["commit", "-q", "-m", "init"]);
        run_git(tmp.path(), &["checkout", "-q", "--detach", "HEAD"]);

        let g = expect_measured(
            git_status_at(tmp.path(), None, std::time::SystemTime::now()),
            tmp.path(),
        );
        assert_eq!(
            g.branch, "detached",
            "a real detached HEAD answers exit 0 with empty stdout — a measurement, not an unmeasured miss"
        );
    }

    #[test]
    fn git_status_reports_worktree_dirty() {
        // MUST hold the WORKSPACE-WIDE lock: this test spawns `git`, which is
        // resolved through the process-global PATH, and sibling tests in this
        // same `csq --lib` binary set `PATH` to "" and to a fixture dir
        // (`csq/src/desktop/commands/mod.rs`) under that same lock. A reader
        // that skips it races a mid-flight mutation, `Command::new("git")`
        // fails to spawn, `git_status` returns None via `.ok()?`, and the
        // assertion below reads as "not in a repo". Reader side of
        // `test-hermeticity.md` MUST-1b/1c — mutating nothing is not the same
        // as not participating in the race.
        let _guard = env_guard();
        let tmp = TempDir::new().unwrap();
        run_git(tmp.path(), &["init", "-q", "--initial-branch=main"]);
        std::fs::write(tmp.path().join("README"), "hello").unwrap();
        run_git(tmp.path(), &["add", "README"]);
        run_git(tmp.path(), &["commit", "-q", "-m", "init"]);
        // Touch the committed file — worktree now diverges from index.
        std::fs::write(tmp.path().join("README"), "hello + new").unwrap();

        let g = expect_measured(
            git_status_at(tmp.path(), None, std::time::SystemTime::now()),
            tmp.path(),
        );
        assert_eq!(g.dirty, Some(true), "worktree edit should flip dirty=true");
    }

    #[test]
    fn git_status_reports_staged_dirty() {
        // MUST hold the WORKSPACE-WIDE lock: this test spawns `git`, which is
        // resolved through the process-global PATH, and sibling tests in this
        // same `csq --lib` binary set `PATH` to "" and to a fixture dir
        // (`csq/src/desktop/commands/mod.rs`) under that same lock. A reader
        // that skips it races a mid-flight mutation, `Command::new("git")`
        // fails to spawn, `git_status` returns None via `.ok()?`, and the
        // assertion below reads as "not in a repo". Reader side of
        // `test-hermeticity.md` MUST-1b/1c — mutating nothing is not the same
        // as not participating in the race.
        let _guard = env_guard();
        let tmp = TempDir::new().unwrap();
        run_git(tmp.path(), &["init", "-q", "--initial-branch=main"]);
        std::fs::write(tmp.path().join("README"), "hello").unwrap();
        run_git(tmp.path(), &["add", "README"]);
        run_git(tmp.path(), &["commit", "-q", "-m", "init"]);
        // Stage a new file but don't commit — index diverges from HEAD.
        std::fs::write(tmp.path().join("NEW"), "x").unwrap();
        run_git(tmp.path(), &["add", "NEW"]);

        let g = expect_measured(
            git_status_at(tmp.path(), None, std::time::SystemTime::now()),
            tmp.path(),
        );
        assert_eq!(g.dirty, Some(true), "staged file should flip dirty=true");
    }

    /// an internal ticket / an internal ticket row 18 regression guard: `git diff --quiet` can exit with
    /// something other than 0 or 1 — on Unix a signal-killed git process makes
    /// `ExitStatus::code()` return `None`; a repo whose index git cannot parse
    /// (this test's reproduction) makes it exit 128. Both must land on
    /// `dirty: None` ("could not measure"), never on the same `Some(false)` a
    /// genuinely clean repo reports. Without this case the suite cannot tell
    /// `Option<bool>` apart from a `bool` that happens to be right today —
    /// deleting the `None` arm and collapsing it into `Some(false)` must RED
    /// this test (proven by mutation, not asserted).
    ///
    /// WHY A CORRUPT INDEX AND NOT AN UNREADABLE FILE. The first version of
    /// this test chmod'd a tracked file to `0o000`. That is NOT portable and
    /// shipped red: macOS git cannot hash the file and exits 128, but Linux
    /// git treats it as modified and exits 1, so the assertion read
    /// `Some(true)` on ubuntu and enterprise CI while passing locally. An
    /// unparseable index is a fatal in git's index-reading path on every
    /// platform, needs no permission semantics, and therefore also needs no
    /// root guard — root parses a corrupt index exactly as badly as anyone
    /// else, whereas `0o000` is bypassed by DAC_OVERRIDE.
    ///
    /// Stages 1 and 2 of `git_status` still succeed: `rev-parse --git-dir`
    /// and `branch --show-current` read HEAD and the gitdir, never the index.
    /// Only stage 3 fails, which is precisely the arm under test.
    #[test]
    fn git_status_reports_none_when_diff_cannot_measure() {
        // MUST hold the WORKSPACE-WIDE lock: this test spawns `git`, which is
        // resolved through the process-global PATH, and sibling tests in this
        // same `csq --lib` binary set `PATH` to "" and to a fixture dir
        // (`csq/src/desktop/commands/mod.rs`) under that same lock. A reader
        // that skips it races a mid-flight mutation, `Command::new("git")`
        // fails to spawn, `git_status` returns None via `.ok()?`, and the
        // assertion below reads as "not in a repo". Reader side of
        // `test-hermeticity.md` MUST-1b/1c — mutating nothing is not the same
        // as not participating in the race.
        let _guard = env_guard();
        let tmp = TempDir::new().unwrap();
        run_git(tmp.path(), &["init", "-q", "--initial-branch=main"]);
        let readme = tmp.path().join("README");
        std::fs::write(&readme, "hello").unwrap();
        run_git(tmp.path(), &["add", "README"]);
        run_git(tmp.path(), &["commit", "-q", "-m", "init"]);

        // Replace the index with bytes git cannot parse. `git diff --quiet`
        // then exits 128 ("bad index file") — neither 0 (clean) nor 1
        // (dirty) — reproducing the same "git ran but could not answer"
        // shape a signal-killed process produces, deterministically and
        // without depending on filesystem permission semantics.
        std::fs::write(tmp.path().join(".git").join("index"), b"NOT-A-GIT-INDEX").unwrap();

        let g = git_status_at(tmp.path(), None, std::time::SystemTime::now())
            .expect("in a repo → Some, even when diff could not measure");
        assert_eq!(
            g.dirty, None,
            "git diff exited non-0/1 on an unparseable index — must report \
             None (could not measure), not a confident Some(false) \
             indistinguishable from clean, nor Some(true)"
        );
    }

    #[test]
    fn is_csq_managed_terminal_matches_subdirectory() {
        let _guard = env_guard();
        let base = TempDir::new().unwrap();
        let term_dir = base.path().join("term-12345");
        std::fs::create_dir_all(&term_dir).unwrap();

        let prev = std::env::var_os("CLAUDE_CONFIG_DIR");
        unsafe { std::env::set_var("CLAUDE_CONFIG_DIR", &term_dir) };
        let result = is_csq_managed_terminal(base.path());
        if let Some(p) = prev {
            unsafe { std::env::set_var("CLAUDE_CONFIG_DIR", p) };
        } else {
            unsafe { std::env::remove_var("CLAUDE_CONFIG_DIR") };
        }

        assert!(result, "handle dir under base_dir must be recognized");
    }

    #[test]
    fn is_csq_managed_terminal_rejects_unrelated_path() {
        let _guard = env_guard();
        let base = TempDir::new().unwrap();
        let other = TempDir::new().unwrap();

        let prev = std::env::var_os("CLAUDE_CONFIG_DIR");
        unsafe { std::env::set_var("CLAUDE_CONFIG_DIR", other.path()) };
        let result = is_csq_managed_terminal(base.path());
        if let Some(p) = prev {
            unsafe { std::env::set_var("CLAUDE_CONFIG_DIR", p) };
        } else {
            unsafe { std::env::remove_var("CLAUDE_CONFIG_DIR") };
        }

        assert!(!result);
    }

    /// Finding 7: the cost gate uses the config dir `handle()` already resolved. A
    /// re-read of `CLAUDE_CONFIG_DIR` that came back unset used to skip the cost
    /// block and render CC's Anthropic-priced number for a third-party slot.
    #[test]
    fn build_rich_line_uses_the_resolved_config_dir_not_the_environment() {
        let _guard = env_guard();
        let base = TempDir::new().unwrap();
        let cfg = base.path().join("term-1");
        std::fs::create_dir_all(&cfg).unwrap();
        let slot_dir = base.path().join("config-7");
        std::fs::create_dir_all(&slot_dir).unwrap();
        std::fs::write(
            slot_dir.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.deepseek.com/anthropic"}}"#,
        )
        .unwrap();
        let prev = std::env::var_os("CLAUDE_CONFIG_DIR");
        unsafe { std::env::remove_var("CLAUDE_CONFIG_DIR") };
        let stdin = r#"{"context_window":{"current_usage":{"input_tokens":45000}},"cost":{"total_cost_usd":9.99}}"#;
        let line = build_rich_line(
            stdin,
            base.path(),
            &cfg,
            AccountNum::try_from(7u16).unwrap(),
            "x",
            None,
            false,
        );
        if let Some(p) = prev {
            unsafe { std::env::set_var("CLAUDE_CONFIG_DIR", p) };
        }
        let line = line.expect("rich line");
        assert!(line.contains("| $?"), "{line}");
        assert!(!line.contains("9.99"), "{line}");
    }
}
