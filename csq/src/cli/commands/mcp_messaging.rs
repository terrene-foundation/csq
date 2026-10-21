//! `csq mcp-messaging` — the stdio MCP server for cross-CLI messaging (spec 32 §4.2).
//!
//! Started by Claude Code or Codex as a child of the CLI process, so its parent chain
//! contains that CLI and the §2.2 caller proof holds. The protocol and the tools live in
//! `csq_core::messaging::mcp`; this module only wires the real process table, clock and
//! stdio to it. Its image context is immutable, it opens no socket, and stdout carries only
//! JSON-RPC lines: stdout is the protocol channel, so a stray byte there would corrupt it.

use super::mcp_messaging_reload::Reload;
#[cfg(not(unix))]
use std::io::BufReader;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use csq_core::messaging::mcp::{self, Backend, SessionEntry, SessionList};
use csq_core::messaging::model::Recipient;
use csq_core::messaging::model::VerifiedSession;
use csq_core::messaging::registry;
use csq_core::messaging::wake::Delivery;
use csq_core::sdk::SdkErrorCode;
use csq_core::sessions::directives::{real_fs, DirectiveError};

use super::sessions_messages::{
    now_secs, real_exact_of, real_liveness, real_wake, resolve_target_exact, resolve_verified,
};

fn err(code: SdkErrorCode, message: &str) -> DirectiveError {
    DirectiveError {
        code,
        message: message.to_string(),
        cause: None,
        attempts: None,
        next_allowed_at: None,
    }
}

/// Adapt the CLI's typed wake outcome to the wire string the MCP backend reports. The wake
/// itself is the CLI's own `real_wake`: one implementation of target validation, thread-id
/// resolution and the bounded `codex queue` spawn for both surfaces.
fn delivery_wake<'a>(
    wake: &'a dyn Fn(&Recipient) -> Delivery,
) -> impl Fn(&Recipient) -> &'static str + 'a {
    move |r| wake(r).tagged()
}

fn list_sessions(base_dir: &Path) -> Result<SessionList, DirectiveError> {
    let home = csq_core::platform::home::home_dir()
        .ok_or_else(|| err(SdkErrorCode::Undetermined, "home directory unknown"))?;
    let listing = csq_core::sessions::list_rows_for_names(base_dir, &home).ok_or_else(|| {
        err(
            SdkErrorCode::Undetermined,
            "the process table could not be read",
        )
    })?;
    if listing.restricted {
        return Err(err(
            SdkErrorCode::Undetermined,
            "process information is restricted for this caller",
        ));
    }
    let budget = registry::LookupBudget::new(registry::LISTING_LOOKUP_BUDGET);
    // A row whose repo lookup fell back carries a label that may not be the session's real
    // default label: it is flagged per row (`label_fallback`), and only a default-shaped name
    // for that session resolves `undetermined` (spec 32a 4.3).
    let entries = listing
        .rows
        .iter()
        .filter_map(|r| registry::candidate_for_row_keyed(r, budget).map(|(c, _, key)| (r, c, key)))
        .map(|(r, c, key)| SessionEntry {
            repo_key: key,
            pid: r.pid,
            started_at: r.started_at,
            surface: r.surface,
            name: r.name.clone(),
            label: Some(c.name),
            label_source: c.name_source,
            repo: c.repo,
            branch: c.branch,
            cwd: r.cwd.to_string_lossy().into_owned(),
            label_fallback: c.label_fallback,
        })
        .collect();
    let complete = listing.is_complete();
    Ok(SessionList { entries, complete })
}

/// Store or remove the OWN name of the proven caller, in the handle dir that proof returned.
fn set_own_name(who: &VerifiedSession, name: Option<&str>) -> Result<(), DirectiveError> {
    let r = match name {
        Some(n) => registry::write_own_name(who.handle_dir(), n),
        None => registry::clear_own_name(who.handle_dir()),
    };
    r.map_err(|e| {
        let code = match e {
            registry::NameError::Invalid | registry::NameError::Reserved => {
                SdkErrorCode::InvalidInput
            }
            registry::NameError::Io => SdkErrorCode::Undetermined,
        };
        err(code, &e.to_string())
    })
}

/// Serve the MCP protocol on this process's stdin and stdout until stdin closes.
pub fn run(base_dir: &Path) -> Result<()> {
    let image = super::mcp_image::capture();
    let fs = real_fs();
    let resolve = |p: u32, s: u64| {
        resolve_target_exact(
            p,
            s,
            &csq_core::sessions::session_info_for_pid_kind,
            &real_exact_of,
        )
    };
    let sessions = || list_sessions(base_dir);
    // Same wake as `csq sessions send` (spec 32 section 5.1), so the MCP receipt's `delivery`
    // is what the CLI would have reported for the same recipient.
    let real = |r: &Recipient| real_wake(base_dir, r);
    let wake = delivery_wake(&real);
    let be = Backend {
        base_dir,
        now: &now_secs,
        fs: &fs,
        live: &real_liveness,
        caller: &resolve_verified,
        resolve: &resolve,
        sessions: &sessions,
        set_name: &set_own_name,
        wake: &wake,
    };
    #[cfg(unix)]
    let mut input = super::mcp_messaging_reload::raw_stdin().context("mcp-messaging stdin")?;
    #[cfg(not(unix))]
    let stdin = std::io::stdin();
    #[cfg(not(unix))]
    let mut input = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    // Each write locks stdout only for that write; no Rust stdout lock is held
    // across exec. The callback flushes the completed response before checking.
    let mut output = stdout;
    let mut reload = super::mcp_messaging_reload::reload_or_warn(Reload::new);
    if reload.as_mut().is_some_and(Reload::take_notification) {
        serde_json::to_writer(&mut output, &mcp::tools_list_changed_notification())?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    let mut boundary = |output: &mut std::io::Stdout| -> std::io::Result<()> {
        output.flush()?;
        if let Some(reload) = &mut reload {
            if reload.boundary().is_err() {
                tracing::warn!(
                    error_kind = "mcp_reload_refused",
                    "MCP executable update refused"
                );
            }
        }
        Ok(())
    };
    mcp::serve_with_lifecycle_and_image_report(
        &mut input,
        &mut output,
        &be,
        &mut boundary,
        image.as_ref(),
    )
    .context("mcp-messaging stdio")?;
    output.flush().context("mcp-messaging stdio")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// G1: the MCP wake is the CLI's wake behind a string adapter. Falsifier: a constant
    /// "queued_only" closure (the pre-wiring state) fails the `codex_woken` assertions.
    #[test]
    fn delivery_adapter_carries_the_wake_outcome_for_every_variant() {
        let r = Recipient {
            pid: 7,
            started_at: 5_000,
            surface: csq_core::messaging::model::Surface::Codex,
            started_exact: None,
        };
        // The denominator comes from the canonical inventory; the exhaustive match
        // pins independent wire expectations and rejects newly added variants at build.
        for d in Delivery::ALL {
            let d = *d;
            let want = match d {
                Delivery::QueuedOnly => "queued_only",
                Delivery::CodexWoken => "codex_woken",
                Delivery::CodexWakeFailed => "codex_wake_failed",
                Delivery::ClaudeWoken => "claude_woken",
                Delivery::ClaudeWakeFailed => "claude_wake_failed",
                Delivery::ClaudeWakeContended => "queued_only:wake_contended",
                Delivery::ClaudeWakePending => "claude_wake_pending",
                Delivery::ClaudeWakeRateLimited => "claude_wake_rate_limited",
                Delivery::CodexQueued => "codex_queued",
                Delivery::CodexQueuedUnverified => "codex_queued_unverified",
                Delivery::CodexWakeDeferred => "codex_wake_pending",
                Delivery::CodexWakePending => "codex_queued:wake_pending",
                Delivery::CodexWakeInFlight => "queued_only:wake_in_flight",
                Delivery::CodexRowNeverSeen => "codex_queued_unverified:row_never_seen",
                Delivery::CodexNoTurnYet => "queued_only:codex_no_turn_yet",
                Delivery::StoredNoWake => "stored_no_wake",
            };
            let f = move |_: &Recipient| d;
            assert_eq!(delivery_wake(&f)(&r), want);
        }
    }

    /// The glue this module used to duplicate is gone: the shared functions are the only
    /// definitions, so a fix there reaches both surfaces.
    #[test]
    fn the_glue_is_not_redefined_here() {
        let src = include_str!("mcp_messaging.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        for dup in [
            "fn resolve_target(",
            "fn liveness(",
            "fn resolve_caller(",
            "fn now_secs(",
        ] {
            assert!(
                !prod.contains(dup),
                "{dup} must come from sessions_messages"
            );
        }
    }
}
