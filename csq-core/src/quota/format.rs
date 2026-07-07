//! Formatting helpers for statusline output.

use super::AccountQuota;
use crate::accounts::profiles;
use crate::types::AccountNum;
use serde::Deserialize;
use std::path::Path;

/// Strips control characters (bytes < 0x20) from a label string to prevent
/// ANSI escape injection when the label is written to a terminal.
///
/// Pre-RN1-D3 csq versions wrote `accounts[N].email` without validation.
/// A malicious or corrupted value could contain ANSI escape sequences that
/// rewrite the terminal display or move the cursor. This sanitizer is applied
/// at every label render site (statusline, doctor warning).
///
/// Returns the original string unchanged if no control characters are found
/// (the common case). Returns a new `String` with control chars stripped if
/// any are found.
pub fn sanitize_for_display(label: &str) -> std::borrow::Cow<'_, str> {
    if label.bytes().any(|b| b < 0x20) {
        std::borrow::Cow::Owned(label.chars().filter(|c| *c as u32 >= 0x20).collect())
    } else {
        std::borrow::Cow::Borrowed(label)
    }
}

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

/// Formats a "resets in" duration for the `csq status` table — finer-grained
/// than [`fmt_time`] (which the space-constrained statusline uses).
///
/// Keeps a two-unit resolution so an operator can tell `3h12m` from `3h58m`
/// when deciding whether to wait out a 5-hour window, and `1d9h` from `6d1h`
/// for the weekly window. Max width is 6 (`23h59m`).
///
/// Examples: `now`, `31m`, `3h12m`, `4h` (zero minutes elide), `1d9h`, `6d`.
pub fn fmt_reset(secs: u64) -> String {
    if secs < 60 {
        "now".to_string()
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        if m == 0 {
            format!("{}h", h)
        } else {
            format!("{}h{:02}m", h, m)
        }
    } else {
        let d = secs / 86_400;
        let h = (secs % 86_400) / 3600;
        if h == 0 {
            format!("{}d", d)
        } else {
            format!("{}d{}h", d, h)
        }
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
/// With `LOGIN-NEEDED` prefix when `broker_failed` is set.
pub fn statusline_str(
    account: AccountNum,
    label: &str,
    quota: Option<&AccountQuota>,
    broker_failed: bool,
) -> String {
    let prefix = if broker_failed { "LOGIN-NEEDED " } else { "" };

    match quota {
        // Balance-metered providers (DeepSeek) carry a $-balance, not 5h/7d
        // windows. Detect them by the record's own `kind` ("balance", written
        // by the poller atomically with the balance) OR a present balance, so a
        // balance slot NEVER falls through to the 5h/7d arm and renders the
        // spurious `5h:0% 7d:0%` that #52 set out to kill.
        Some(q) if q.kind == "balance" || q.balance.is_some() => {
            let body = match q.balance.as_ref() {
                Some(b) => fmt_balance(b),
                // kind=balance but no successful poll yet — show a pending
                // marker rather than a fabricated 0% window.
                None => "balance n/a".to_string(),
            };
            format!("{}#{}:{} {}", prefix, account, label, body)
        }
        Some(q) => {
            format!(
                "{}#{}:{} 5h:{:.0}% 7d:{:.0}%",
                prefix,
                account,
                label,
                q.five_hour_pct(),
                q.seven_day_pct()
            )
        }
        None => {
            format!("{}#{}:{} no data", prefix, account, label)
        }
    }
}

/// Formats a [`BalanceInfo`](crate::quota::BalanceInfo) for display: `$196.42` for USD, else
/// `196.42 EUR`. Shared by the CC statusline and the desktop IPC view
/// (`get_accounts` → `AccountView::balance_display`) so currency
/// formatting has a single source of truth.
///
/// The `currency` string originates from a remote provider API
/// (`/user/balance`), so on the non-USD path it is control-char-stripped
/// via [`sanitize_for_display`] and length-bounded before rendering —
/// the same defense the account label already gets. Without it a hostile
/// or garbled API response (e.g. `"USD\x1b[2J"`, an embedded newline)
/// would render verbatim to the operator's terminal via the statusline's
/// `println!`, rewriting the display. Real ISO currency codes are 3 chars;
/// the 12-char cap leaves slack for symbols while bounding the sink.
pub fn fmt_balance(b: &crate::quota::BalanceInfo) -> String {
    if b.currency == "USD" {
        format!("${:.2}", b.remaining)
    } else {
        let cur = sanitize_for_display(&b.currency);
        let cur: String = cur.chars().take(12).collect();
        format!("{:.2} {}", b.remaining, cur)
    }
}

/// Resolves the display label for an account from profiles.json.
///
/// Falls back to "account-N" if no profile exists.
///
/// H2 (security review): applies [`sanitize_for_display`] to strip
/// control characters from labels written by pre-RN1-D3 csq versions.
/// A label with ANSI escapes written directly to a terminal could
/// rewrite display or move the cursor.
pub fn account_label(base_dir: &Path, account: AccountNum) -> String {
    let profiles_path = profiles::profiles_path(base_dir);
    match profiles::load(&profiles_path) {
        Ok(p) => p
            .get_email(account.get())
            .map(|s| sanitize_for_display(s).into_owned())
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
    /// `context_window.used_percentage` — CC's OWN percentage, computed against
    /// the window CC assumes for the model (~200k for the Anthropic-compatible
    /// endpoint). Trusted only when `ctx_window_true` is None.
    pub ctx_used_pct: Option<f64>,
    /// The model's TRUE context window from csq's catalog (e.g. 1M for
    /// deepseek-v4-pro), resolved by the CLI from the slot's settings.json
    /// model id (`providers::settings::model_id_for_slot`). When set,
    /// the context % is RECOMPUTED as `ctx_total_tokens / ctx_window_true` — CC
    /// mis-computes it against its own ~200k assumption for 3P models with a
    /// larger real window (deepseek/minimax/glm = 1M). Origin: #52 / models.rs
    /// deepseek-v4-pro note (the deferred recompute shard).
    pub ctx_window_true: Option<u64>,
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
    broker_failed: bool,
    ctx: &StatuslineContext,
) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(6);

    let core = statusline_str(account, label, quota, broker_failed);
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
            // Recompute the context % against the model's TRUE window when csq
            // knows it (3P models where CC assumes ~200k — deepseek/minimax/glm
            // are 1M). Otherwise trust CC's own used_percentage.
            let pct = match ctx.ctx_window_true {
                // Clamp to 100%: a session can't hold more tokens than the
                // window. For a model whose TRUE window is SMALLER than CC's
                // ~200k assumption (e.g. deepseek-v4-flash = 128k), a large
                // context makes the recompute exceed 100% — cap it so the
                // statusline never renders a nonsensical ">100%".
                Some(w) if w > 0 => ((total as f64 / w as f64) * 100.0).min(100.0),
                _ => ctx.ctx_used_pct.unwrap_or(0.0),
            };
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
        // Populated by the CLI (statusline.rs) from the slot's settings.json
        // model id — the stdin JSON carries no true-window signal, so
        // parse_cc_stdin leaves it None.
        ctx_window_true: None,
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

// M3-7 fix-wave R1 M2-DA: `is_swap_stuck` is retired. Pre-M3-7 it compared
// `config_dir/.credentials.json` (live mirror, then a credential reader) to
// `credentials/N.json` (canonical) and rendered a `!` glyph in the statusline
// when they diverged. Post-M3-7 the live mirror is no longer a credential
// reader — handle dirs symlink `.credentials.json` to
// `identities/<UUID>/credentials.json` and the daemon writes that path on
// every refresh. The "stuck" semantic has no production meaning under the
// handle-dir model. Per zero-tolerance Rule 5, retired rather than
// silently-returns-false.

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
    fn fmt_reset_edge_cases() {
        assert_eq!(fmt_reset(0), "now");
        assert_eq!(fmt_reset(59), "now");
        assert_eq!(fmt_reset(60), "1m");
        assert_eq!(fmt_reset(1860), "31m");
        assert_eq!(fmt_reset(3600), "1h"); // zero minutes elide
        assert_eq!(fmt_reset(11_520), "3h12m");
        assert_eq!(fmt_reset(86_340), "23h59m"); // max h-case width = 6
        assert_eq!(fmt_reset(86_400), "1d"); // zero hours elide
        assert_eq!(fmt_reset(118_800), "1d9h");
        assert_eq!(fmt_reset(531_360), "6d3h");
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
        );
        assert_eq!(s, "#3:user@test.com 5h:42% 7d:15%");
    }

    // M3-7 fix-wave R1 M2-DA: `statusline_stuck_swap` test retired together
    // with `is_swap_stuck` (no production "stuck" semantic under handle-dir
    // model; see comment near `is_swap_stuck`'s retirement marker above).

    #[test]
    fn statusline_broker_failed() {
        let s = statusline_str(AccountNum::try_from(2u16).unwrap(), "user", None, true);
        assert!(s.starts_with("LOGIN-NEEDED"));
        assert!(s.contains("#2:user"));
    }

    #[test]
    fn statusline_no_data() {
        let s = statusline_str(AccountNum::try_from(5u16).unwrap(), "user", None, false);
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
        crate::refresh::sentinel::set_broker_failed(dir.path(), account, "test").unwrap();
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
            ctx_window_true: None,
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
            &ctx,
        );
        assert_eq!(
            s,
            "⚡csq #1:user@test.com 5h:10% 7d:15% | ctx:45k 30% | $0.12 | 🤖Claude Opus 4.7 | 📁csq | git:main●"
        );
    }

    #[test]
    fn rich_statusline_recomputes_ctx_against_true_window() {
        // #52: 180k tokens against CC's ~200k assumption reads 89%; against the
        // model's TRUE 1M window (ctx_window_true) it is ~18%. The recompute wins.
        let quota = demo_quota();
        let ctx = StatuslineContext {
            ctx_total_tokens: Some(180_000),
            ctx_used_pct: Some(89.0), // CC's wrong number — must be ignored
            ctx_window_true: Some(1_000_000),
            session_cost_usd: Some(0.0),
            ..Default::default()
        };
        let s = rich_statusline(
            AccountNum::try_from(11u16).unwrap(),
            "DeepSeek",
            Some(&quota),
            false,
            &ctx,
        );
        // 180000 / 1_000_000 = 18%, NOT 89%.
        assert!(
            s.contains("ctx:180k 18%"),
            "expected 18% recompute, got: {s}"
        );
        assert!(!s.contains("89%"), "must not show CC's 89%: {s}");
    }

    #[test]
    fn statusline_str_renders_balance_for_balance_quota() {
        let q = AccountQuota {
            balance: Some(crate::quota::BalanceInfo {
                currency: "USD".into(),
                remaining: 196.42,
            }),
            ..Default::default()
        };
        let s = statusline_str(
            AccountNum::try_from(11u16).unwrap(),
            "DeepSeek",
            Some(&q),
            false,
        );
        assert_eq!(s, "#11:DeepSeek $196.42");
    }

    #[test]
    fn statusline_str_balance_kind_without_balance_shows_pending_not_5h7d() {
        // #984 redteam (intermediate M1): a balance-kind record whose balance
        // hasn't been polled yet must NOT fall through to the 5h/7d arm and
        // render the spurious `5h:0% 7d:0%`. It shows a pending marker instead.
        let q = AccountQuota {
            kind: "balance".into(),
            balance: None,
            ..Default::default()
        };
        let s = statusline_str(
            AccountNum::try_from(11u16).unwrap(),
            "DeepSeek",
            Some(&q),
            false,
        );
        assert_eq!(s, "#11:DeepSeek balance n/a");
        assert!(!s.contains("5h:"), "must not render a 5h/7d window: {s}");
    }

    #[test]
    fn fmt_balance_strips_control_chars_in_currency() {
        // #984 redteam (security M1): the currency string comes from a remote
        // API and must be control-char-stripped on the terminal render path.
        let b = crate::quota::BalanceInfo {
            currency: "CNY\x1b[2J\n".into(),
            remaining: 1400.50,
        };
        let s = fmt_balance(&b);
        // The ESC (0x1b) that initiates an ANSI sequence and the newline are
        // removed; the printable residual ("[2J") is inert without a leading ESC.
        assert!(
            !s.bytes().any(|c| c < 0x20),
            "no control bytes may reach the terminal: {s:?}"
        );
        assert_eq!(s, "1400.50 CNY[2J");
    }

    #[test]
    fn fmt_balance_bounds_currency_length() {
        // The 12-char cap bounds a hostile over-long currency string.
        let b = crate::quota::BalanceInfo {
            currency: "ABCDEFGHIJKLMNOPQRSTUVWXYZ".into(),
            remaining: 1.0,
        };
        let s = fmt_balance(&b);
        assert_eq!(s, "1.00 ABCDEFGHIJKL", "currency capped at 12 chars: {s:?}");
    }

    #[test]
    fn rich_statusline_clamps_ctx_recompute_at_100pct() {
        // #984 redteam (deep-analyst F3): for a model whose TRUE window is
        // SMALLER than CC's ~200k assumption (deepseek-v4-flash = 128k), a
        // large context makes tokens/window exceed 100% — it must clamp, not
        // render ">100%".
        let quota = demo_quota();
        let ctx = StatuslineContext {
            ctx_total_tokens: Some(200_000),
            ctx_used_pct: Some(75.0), // CC's number against 200k — ignored
            ctx_window_true: Some(128_000), // 200k/128k = 156% before clamp
            session_cost_usd: Some(0.0),
            ..Default::default()
        };
        let s = rich_statusline(
            AccountNum::try_from(11u16).unwrap(),
            "DeepSeek",
            Some(&quota),
            false,
            &ctx,
        );
        assert!(
            s.contains("ctx:200k 100%"),
            "expected clamp to 100%, got: {s}"
        );
        assert!(!s.contains("156%"), "must not render >100%: {s}");
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
            ctx_window_true: None,
            session_cost_usd: Some(0.0),
            is_csq_terminal: true,
            ..Default::default()
        };
        let s = rich_statusline(
            AccountNum::try_from(1u16).unwrap(),
            "u",
            Some(&quota),
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
            &csq,
        );
        assert!(s_csq.starts_with("⚡csq "));
    }

    #[test]
    fn parse_cc_stdin_full_payload() {
        let raw = r#"{
            "model": { "display_name": "Claude Opus 4.7" },
            "workspace": { "current_dir": "/Users/example/repos/csq" },
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

    /// H2 (security review): labels containing ANSI escape sequences or other
    /// control characters (bytes < 0x20) written by pre-RN1-D3 csq versions
    /// MUST NOT render verbatim to the terminal. `sanitize_for_display` strips
    /// them; this test verifies the strip is applied in the label pipeline.
    #[test]
    fn legacy_label_with_control_chars_sanitized_at_render() {
        // Arrange: a label with an ANSI escape sequence (ESC[31m = red foreground)
        // and a newline — two distinct control-char classes.
        let malicious_label = "alice\x1b[31mhacked\x0a@example.com";

        // Act: sanitize_for_display strips bytes < 0x20.
        let sanitized = sanitize_for_display(malicious_label);

        // Assert: the output contains none of the control bytes.
        assert!(
            !sanitized.bytes().any(|b| b < 0x20),
            "sanitize_for_display must strip all control characters (bytes < 0x20)"
        );
        // Assert: the printable content is preserved.
        assert!(
            sanitized.contains("alice"),
            "sanitize_for_display must preserve printable characters"
        );
        // Assert: the ESC byte is gone (would trigger terminal rewrite if rendered).
        assert!(
            !sanitized.contains('\x1b'),
            "sanitize_for_display must strip ESC (0x1b)"
        );
        // Assert: the newline is gone (would break statusline formatting if rendered).
        assert!(
            !sanitized.contains('\n'),
            "sanitize_for_display must strip newline (0x0a)"
        );

        // Verify the sanitized label renders correctly through statusline_str
        // without any control bytes leaking to the output.
        let account = AccountNum::try_from(1u16).unwrap();
        let rendered = statusline_str(account, &sanitized, None, false);
        assert!(
            !rendered.bytes().any(|b| b < 0x20),
            "statusline output must contain no control chars after sanitization"
        );
    }
}
