//! Formatting helpers for statusline output.

use super::AccountQuota;
use crate::accounts::markers;
use crate::accounts::profiles;
use crate::types::AccountNum;
use serde::Deserialize;
use std::path::Path;

/// Maximum age of a broker-failed flag before it's auto-cleared (24 hours).
pub const BROKER_FLAG_STALE_SECS: u64 = 24 * 3600;

/// Formats a duration in seconds as a compact string.
///
/// Examples: "now", "5m", "2h", "1d"
pub fn fmt_time(secs: u64) -> String {
    if secs < 60 {
        "now".to_string()
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// Formats a token count as a compact string.
///
/// Examples: 500 → "500", 1200 → "1k", 1500000 → "1.5M"
pub fn fmt_tokens(n: u64) -> String {
    if n < 1_000 {
        n.to_string()
    } else if n < 1_000_000 {
        let k = n as f64 / 1_000.0;
        if k >= 10.0 {
            format!("{}k", k.round() as u64)
        } else {
            format!("{:.1}k", k)
        }
    } else {
        let m = n as f64 / 1_000_000.0;
        if m >= 10.0 {
            format!("{}M", m.round() as u64)
        } else {
            format!("{:.1}M", m)
        }
    }
}

/// Formats the statusline string for an account.
///
/// Format: `#N:label 5h:X% 7d:Y%`
/// With indicators:
///   - `#N!:label` if swap is stuck
///   - `LOGIN-NEEDED #N:label 5h:X% 7d:Y%` if broker failed
pub fn statusline_str(
    account: AccountNum,
    label: &str,
    quota: Option<&AccountQuota>,
    stuck_swap: bool,
    broker_failed: bool,
) -> String {
    let stuck = if stuck_swap { "!" } else { "" };
    let prefix = if broker_failed { "LOGIN-NEEDED " } else { "" };

    match quota {
        Some(q) => {
            format!(
                "{}#{}{}:{} 5h:{:.0}% 7d:{:.0}%",
                prefix,
                account,
                stuck,
                label,
                q.five_hour_pct(),
                q.seven_day_pct()
            )
        }
        None => {
            format!("{}#{}{}:{} no data", prefix, account, stuck, label)
        }
    }
}

/// Resolves the display label for an account from profiles.json.
///
/// Falls back to "account-N" if no profile exists.
pub fn account_label(base_dir: &Path, account: AccountNum) -> String {
    let profiles_path = profiles::profiles_path(base_dir);
    match profiles::load(&profiles_path) {
        Ok(p) => p
            .get_email(account.get())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("account-{}", account)),
        Err(_) => format!("account-{}", account),
    }
}

/// Checks if a broker-failed flag is stale (older than 24h) and should be ignored.
///
/// Returns true if the flag should be treated as cleared.
pub fn is_broker_flag_stale(base_dir: &Path, account: AccountNum) -> bool {
    let path = base_dir
        .join("credentials")
        .join(format!("{}.broker-failed", account));

    match std::fs::metadata(&path) {
        Ok(metadata) => {
            if let Ok(modified) = metadata.modified() {
                if let Ok(age) = modified.elapsed() {
                    return age.as_secs() > BROKER_FLAG_STALE_SECS;
                }
            }
            false
        }
        Err(_) => true, // No flag = treat as stale (cleared)
    }
}

/// Self-healing check: returns true if broker-failed flag should be reported.
/// Auto-clears stale flags (>24h old).
pub fn should_report_broker_failed(base_dir: &Path, account: AccountNum) -> bool {
    let path = base_dir
        .join("credentials")
        .join(format!("{}.broker-failed", account));

    if !path.exists() {
        return false;
    }

    if is_broker_flag_stale(base_dir, account) {
        let _ = std::fs::remove_file(&path);
        return false;
    }

    true
}

/// Context the CLI supplies to [`rich_statusline`] after parsing
/// Claude Code's stdin JSON. Every field is optional — missing
/// fields are dropped from the rendered line rather than aborting.
#[derive(Debug, Default, Clone)]
pub struct StatuslineContext {
    /// `model.display_name` from the CC JSON (e.g. "Claude Opus 4.7").
    pub model_name: Option<String>,
    /// Last path component of `workspace.current_dir` — the project
    /// the user is working in, displayed with a folder glyph.
    pub project_name: Option<String>,
    /// Sum of input + output + cache_creation + cache_read tokens
    /// from `context_window.current_usage`. Formatted with
    /// [`fmt_tokens`] for compact display.
    pub ctx_total_tokens: Option<u64>,
    /// `context_window.used_percentage`.
    pub ctx_used_pct: Option<f64>,
    /// `cost.total_cost_usd`. Rendered as `$0.12` alongside the
    /// context tokens.
    pub session_cost_usd: Option<f64>,
    /// Git branch + dirty flag resolved in `workspace.current_dir`.
    /// `None` when the project isn't under version control or the
    /// git probe fails.
    pub git: Option<GitStatus>,
    /// True when the caller detected that this terminal is running
    /// under csq (CLAUDE_CONFIG_DIR points inside the csq base dir).
    /// Flips the `⚡csq ` prefix on/off.
    pub is_csq_terminal: bool,
}

/// Git state at the moment the statusline rendered. `dirty` means
/// `git diff --quiet` OR `git diff --cached --quiet` returned
/// non-zero (worktree or index has uncommitted changes).
#[derive(Debug, Clone)]
pub struct GitStatus {
    pub branch: String,
    pub dirty: bool,
}

/// Composes the full statusline — account/quota + model + project +
/// context window + cost + git — separated by ` | `.
///
/// Format (all segments optional, joined by ` | `):
///
/// ```text
/// ⚡csq #1:user@example.com 5h:10% 7d:15% | ctx:45k 30% | $0.12 | 🤖Claude Opus 4.7 | 📁my-project | git:main●
/// ```
///
/// The account/quota prefix is always present (delegates to
/// [`statusline_str`]). Everything else is driven by the fields the
/// CLI was able to extract from CC's stdin payload.
pub fn rich_statusline(
    account: AccountNum,
    label: &str,
    quota: Option<&AccountQuota>,
    stuck_swap: bool,
    broker_failed: bool,
    ctx: &StatuslineContext,
) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(6);

    let core = statusline_str(account, label, quota, stuck_swap, broker_failed);
    if ctx.is_csq_terminal {
        parts.push(format!("⚡csq {core}"));
    } else {
        parts.push(core);
    }

    // Context tokens + session cost. Gated on a non-zero token count
    // so brand-new sessions (where CC hasn't attached any usage data)
    // don't render a stub "ctx:0 0%" segment.
    if let Some(total) = ctx.ctx_total_tokens {
        if total > 0 {
            let pct = ctx.ctx_used_pct.unwrap_or(0.0);
            let cost = ctx.session_cost_usd.unwrap_or(0.0);
            parts.push(format!(
                "ctx:{} {:.0}% | ${:.2}",
                fmt_tokens(total),
                pct,
                cost
            ));
        }
    }

    if let Some(model) = ctx.model_name.as_deref() {
        if !model.is_empty() {
            parts.push(format!("🤖{}", model));
        }
    }

    if let Some(project) = ctx.project_name.as_deref() {
        if !project.is_empty() {
            parts.push(format!("📁{}", project));
        }
    }

    if let Some(g) = &ctx.git {
        let dirty_glyph = if g.dirty { "●" } else { "" };
        parts.push(format!("git:{}{}", g.branch, dirty_glyph));
    }

    parts.join(" | ")
}

/// Parses Claude Code's statusline stdin JSON into a
/// [`StatuslineContext`] the CLI can pass to [`rich_statusline`].
///
/// Tolerant on every axis: an empty input, invalid JSON, or an
/// object missing any / all of these keys returns a default context
/// with every field `None`. The rich renderer then degrades to the
/// account+quota-only line.
///
/// Returns a partial context even when `workspace.current_dir` is
/// present — extracting the last path component as `project_name`.
/// The caller is responsible for running the git probe (IO) using
/// that `workspace.current_dir`.
pub fn parse_cc_stdin(raw: &str) -> StatuslineContext {
    #[derive(Deserialize, Default)]
    struct Input {
        #[serde(default)]
        model: Option<Model>,
        #[serde(default)]
        workspace: Option<Workspace>,
        #[serde(default)]
        context_window: Option<ContextWindow>,
        #[serde(default)]
        cost: Option<Cost>,
    }

    #[derive(Deserialize, Default)]
    struct Model {
        display_name: Option<String>,
    }

    #[derive(Deserialize, Default)]
    struct Workspace {
        current_dir: Option<String>,
    }

    #[derive(Deserialize, Default)]
    struct ContextWindow {
        current_usage: Option<CtxUsage>,
        used_percentage: Option<f64>,
    }

    #[derive(Deserialize, Default)]
    struct CtxUsage {
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
        cache_creation_input_tokens: Option<u64>,
        cache_read_input_tokens: Option<u64>,
    }

    #[derive(Deserialize, Default)]
    struct Cost {
        total_cost_usd: Option<f64>,
    }

    let parsed: Input = serde_json::from_str(raw).unwrap_or_default();

    let ctx_total = parsed.context_window.as_ref().and_then(|w| {
        w.current_usage.as_ref().map(|u| {
            u.input_tokens.unwrap_or(0)
                + u.output_tokens.unwrap_or(0)
                + u.cache_creation_input_tokens.unwrap_or(0)
                + u.cache_read_input_tokens.unwrap_or(0)
        })
    });

    let project_name = parsed
        .workspace
        .as_ref()
        .and_then(|w| w.current_dir.as_deref())
        .and_then(|p| Path::new(p).file_name())
        .and_then(|n| n.to_str())
        .map(|s| s.to_string());

    StatuslineContext {
        model_name: parsed.model.and_then(|m| m.display_name),
        project_name,
        ctx_total_tokens: ctx_total,
        ctx_used_pct: parsed
            .context_window
            .as_ref()
            .and_then(|w| w.used_percentage),
        session_cost_usd: parsed.cost.and_then(|c| c.total_cost_usd),
        git: None,
        is_csq_terminal: false,
    }
}

/// Convenience companion to [`parse_cc_stdin`] that extracts
/// `workspace.current_dir` so the CLI can run its git probe in that
/// directory. Returns `None` when the JSON has no workspace or the
/// field is missing.
pub fn parse_workspace_dir(raw: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Input {
        workspace: Option<Workspace>,
    }
    #[derive(Deserialize)]
    struct Workspace {
        current_dir: Option<String>,
    }
    serde_json::from_str::<Input>(raw)
        .ok()?
        .workspace?
        .current_dir
}

/// Checks whether a swap is stuck — the live access token differs from
/// what we most recently wrote. Used as a swap verification indicator.
pub fn is_swap_stuck(config_dir: &Path, base_dir: &Path) -> bool {
    let Some(account) = markers::read_csq_account(config_dir) else {
        return false;
    };

    let live_path = config_dir.join(".credentials.json");
    let Ok(live) = crate::credentials::load(&live_path) else {
        return false;
    };

    let canonical_path = crate::credentials::file::canonical_path(base_dir, account);
    let Ok(canonical) = crate::credentials::load(&canonical_path) else {
        return false;
    };

    live.claude_ai_oauth.access_token.expose_secret()
        != canonical.claude_ai_oauth.access_token.expose_secret()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quota::UsageWindow;

    #[test]
    fn fmt_time_edge_cases() {
        assert_eq!(fmt_time(0), "now");
        assert_eq!(fmt_time(59), "now");
        assert_eq!(fmt_time(60), "1m");
        assert_eq!(fmt_time(3599), "59m");
        assert_eq!(fmt_time(3600), "1h");
        assert_eq!(fmt_time(86399), "23h");
        assert_eq!(fmt_time(86400), "1d");
        assert_eq!(fmt_time(172800), "2d");
    }

    #[test]
    fn fmt_tokens_edge_cases() {
        assert_eq!(fmt_tokens(0), "0");
        assert_eq!(fmt_tokens(500), "500");
        assert_eq!(fmt_tokens(999), "999");
        assert_eq!(fmt_tokens(1000), "1.0k");
        assert_eq!(fmt_tokens(1200), "1.2k");
        assert_eq!(fmt_tokens(9999), "10.0k");
        assert_eq!(fmt_tokens(10000), "10k");
        assert_eq!(fmt_tokens(1_000_000), "1.0M");
        assert_eq!(fmt_tokens(1_500_000), "1.5M");
        assert_eq!(fmt_tokens(10_000_000), "10M");
    }

    #[test]
    fn statusline_normal() {
        let quota = AccountQuota {
            five_hour: Some(UsageWindow {
                used_percentage: 42.0,
                resets_at: 9999999999,
            }),
            seven_day: Some(UsageWindow {
                used_percentage: 15.0,
                resets_at: 9999999999,
            }),
            ..Default::default()
        };
        let s = statusline_str(
            AccountNum::try_from(3u16).unwrap(),
            "user@test.com",
            Some(&quota),
            false,
            false,
        );
        assert_eq!(s, "#3:user@test.com 5h:42% 7d:15%");
    }

    #[test]
    fn statusline_stuck_swap() {
        let quota = AccountQuota {
            five_hour: Some(UsageWindow {
                used_percentage: 0.0,
                resets_at: 9999999999,
            }),
            ..Default::default()
        };
        let s = statusline_str(
            AccountNum::try_from(1u16).unwrap(),
            "user",
            Some(&quota),
            true,
            false,
        );
        assert_eq!(s, "#1!:user 5h:0% 7d:0%");
    }

    #[test]
    fn statusline_broker_failed() {
        let s = statusline_str(
            AccountNum::try_from(2u16).unwrap(),
            "user",
            None,
            false,
            true,
        );
        assert!(s.starts_with("LOGIN-NEEDED"));
        assert!(s.contains("#2:user"));
    }

    #[test]
    fn statusline_no_data() {
        let s = statusline_str(
            AccountNum::try_from(5u16).unwrap(),
            "user",
            None,
            false,
            false,
        );
        assert_eq!(s, "#5:user no data");
    }

    #[test]
    fn is_broker_flag_stale_missing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(1u16).unwrap();
        assert!(is_broker_flag_stale(dir.path(), account));
    }

    #[test]
    fn should_report_broker_failed_no_flag() {
        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(1u16).unwrap();
        assert!(!should_report_broker_failed(dir.path(), account));
    }

    #[test]
    fn should_report_broker_failed_fresh_flag() {
        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(2u16).unwrap();
        crate::broker::fanout::set_broker_failed(dir.path(), account, "test").unwrap();
        // Fresh flag should be reported
        assert!(should_report_broker_failed(dir.path(), account));
    }

    // ── rich_statusline + parse_cc_stdin ─────────────────────

    fn demo_quota() -> AccountQuota {
        AccountQuota {
            five_hour: Some(UsageWindow {
                used_percentage: 10.0,
                resets_at: 9999999999,
            }),
            seven_day: Some(UsageWindow {
                used_percentage: 15.0,
                resets_at: 9999999999,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn rich_statusline_full_context() {
        let quota = demo_quota();
        let ctx = StatuslineContext {
            model_name: Some("Claude Opus 4.7".into()),
            project_name: Some("csq".into()),
            ctx_total_tokens: Some(45_000),
            ctx_used_pct: Some(30.0),
            session_cost_usd: Some(0.1234),
            git: Some(GitStatus {
                branch: "main".into(),
                dirty: true,
            }),
            is_csq_terminal: true,
        };
        let s = rich_statusline(
            AccountNum::try_from(1u16).unwrap(),
            "user@test.com",
            Some(&quota),
            false,
            false,
            &ctx,
        );
        assert_eq!(
            s,
            "⚡csq #1:user@test.com 5h:10% 7d:15% | ctx:45k 30% | $0.12 | 🤖Claude Opus 4.7 | 📁csq | git:main●"
        );
    }

    #[test]
    fn rich_statusline_skips_segments_when_missing() {
        // Only the account+quota core should render; everything else is None.
        let quota = demo_quota();
        let ctx = StatuslineContext::default();
        let s = rich_statusline(
            AccountNum::try_from(4u16).unwrap(),
            "u@e",
            Some(&quota),
            false,
            false,
            &ctx,
        );
        assert_eq!(s, "#4:u@e 5h:10% 7d:15%");
    }

    #[test]
    fn rich_statusline_drops_zero_ctx_segment() {
        // Brand-new session: tokens reported as 0. The ctx segment
        // must NOT appear ("ctx:0 0% | $0.00" would be noise).
        let quota = demo_quota();
        let ctx = StatuslineContext {
            ctx_total_tokens: Some(0),
            ctx_used_pct: Some(0.0),
            session_cost_usd: Some(0.0),
            is_csq_terminal: true,
            ..Default::default()
        };
        let s = rich_statusline(
            AccountNum::try_from(1u16).unwrap(),
            "u",
            Some(&quota),
            false,
            false,
            &ctx,
        );
        assert!(!s.contains("ctx:"), "got: {s}");
        assert!(!s.contains("$"), "got: {s}");
    }

    #[test]
    fn rich_statusline_clean_git_has_no_dot() {
        let quota = demo_quota();
        let ctx = StatuslineContext {
            git: Some(GitStatus {
                branch: "main".into(),
                dirty: false,
            }),
            ..Default::default()
        };
        let s = rich_statusline(
            AccountNum::try_from(1u16).unwrap(),
            "u",
            Some(&quota),
            false,
            false,
            &ctx,
        );
        assert!(s.contains("git:main"));
        assert!(!s.contains("git:main●"));
    }

    #[test]
    fn rich_statusline_prefixes_csq_only_when_csq_terminal() {
        let quota = demo_quota();
        let vanilla = StatuslineContext {
            is_csq_terminal: false,
            ..Default::default()
        };
        let s_vanilla = rich_statusline(
            AccountNum::try_from(1u16).unwrap(),
            "u",
            Some(&quota),
            false,
            false,
            &vanilla,
        );
        assert!(!s_vanilla.contains("⚡csq"));

        let csq = StatuslineContext {
            is_csq_terminal: true,
            ..Default::default()
        };
        let s_csq = rich_statusline(
            AccountNum::try_from(1u16).unwrap(),
            "u",
            Some(&quota),
            false,
            false,
            &csq,
        );
        assert!(s_csq.starts_with("⚡csq "));
    }

    #[test]
    fn parse_cc_stdin_full_payload() {
        let raw = r#"{
            "model": { "display_name": "Claude Opus 4.7" },
            "workspace": { "current_dir": "/Users/esperie/repos/terrene/contrib/csq" },
            "context_window": {
                "current_usage": {
                    "input_tokens": 10000,
                    "output_tokens": 5000,
                    "cache_creation_input_tokens": 2000,
                    "cache_read_input_tokens": 3000
                },
                "used_percentage": 12.5
            },
            "cost": { "total_cost_usd": 0.4321 }
        }"#;
        let ctx = parse_cc_stdin(raw);
        assert_eq!(ctx.model_name.as_deref(), Some("Claude Opus 4.7"));
        assert_eq!(ctx.project_name.as_deref(), Some("csq"));
        assert_eq!(ctx.ctx_total_tokens, Some(20_000));
        assert_eq!(ctx.ctx_used_pct, Some(12.5));
        assert_eq!(ctx.session_cost_usd, Some(0.4321));
        assert!(ctx.git.is_none(), "git is populated by the CLI, not parse");
    }

    #[test]
    fn parse_cc_stdin_empty_string_is_default() {
        let ctx = parse_cc_stdin("");
        assert!(ctx.model_name.is_none());
        assert!(ctx.ctx_total_tokens.is_none());
        assert!(ctx.session_cost_usd.is_none());
    }

    #[test]
    fn parse_cc_stdin_malformed_json_is_default() {
        let ctx = parse_cc_stdin("{ not valid");
        assert!(ctx.model_name.is_none());
        assert!(ctx.ctx_total_tokens.is_none());
    }

    #[test]
    fn parse_cc_stdin_partial_object() {
        let raw = r#"{"workspace":{"current_dir":"/tmp/foo"}}"#;
        let ctx = parse_cc_stdin(raw);
        assert_eq!(ctx.project_name.as_deref(), Some("foo"));
        assert!(ctx.model_name.is_none());
        assert!(ctx.ctx_total_tokens.is_none());
    }

    #[test]
    fn parse_cc_stdin_omits_zero_cache_fields() {
        // CC payloads sometimes omit cache_* fields entirely. Parser
        // must treat missing as 0, not reject.
        let raw = r#"{
            "context_window": {
                "current_usage": { "input_tokens": 100, "output_tokens": 50 }
            }
        }"#;
        let ctx = parse_cc_stdin(raw);
        assert_eq!(ctx.ctx_total_tokens, Some(150));
    }

    #[test]
    fn parse_workspace_dir_extracts_path() {
        let raw = r#"{"workspace":{"current_dir":"/a/b/c"}}"#;
        assert_eq!(parse_workspace_dir(raw).as_deref(), Some("/a/b/c"));
    }

    #[test]
    fn parse_workspace_dir_none_on_missing() {
        assert!(parse_workspace_dir("{}").is_none());
        assert!(parse_workspace_dir("").is_none());
    }
}
