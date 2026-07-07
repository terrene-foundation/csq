//! Multi-account status display for `csq status` command.

use super::format::{account_label, fmt_reset, fmt_time};
use super::state;
use crate::accounts::{discovery, AccountInfo, AccountSource};
use crate::providers::catalog::Surface;
use crate::quota::BalanceInfo;
use crate::types::AccountNum;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Column widths for the `csq status` table. The 5h and 7d blocks share the
/// same `BAR(4) PCT(4) RESET(6)` shape so the header and data rows align by
/// construction.
const BAR_W: usize = 4;
const PCT_W: usize = 4; // "  2%" .. "100%"
const RST_W: usize = 6; // "now" .. "23h59m"

/// Renders a proportional usage bar `width` cells wide, with eighth-block
/// sub-cell resolution (`█` full, `▏▎▍▌▋▊▉` partial, `░` empty). A non-zero
/// percentage always shows at least one eighth so "tiny but used" is visually
/// distinct from "idle". Every glyph is display-width 1.
fn usage_bar(pct: f64, width: usize) -> String {
    const PARTIALS: [char; 7] = ['▏', '▎', '▍', '▌', '▋', '▊', '▉'];
    let p = pct.clamp(0.0, 100.0);
    let mut eighths = (p / 100.0 * width as f64 * 8.0).round() as usize;
    if p > 0.0 {
        eighths = eighths.max(1);
    }
    let full = (eighths / 8).min(width);
    let rem = eighths % 8;
    let mut s = String::with_capacity(width * 3);
    let mut used = 0;
    for _ in 0..full {
        s.push('█');
        used += 1;
    }
    if used < width && rem > 0 {
        s.push(PARTIALS[rem - 1]);
        used += 1;
    }
    for _ in used..width {
        s.push('░');
    }
    s
}

/// Status entry for a single account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStatus {
    pub id: u16,
    pub label: String,
    pub is_active: bool,
    pub five_hour_pct: Option<f64>,
    pub five_hour_resets_in: Option<u64>,
    pub seven_day_pct: Option<f64>,
    pub seven_day_resets_in: Option<u64>,
    /// Account source (Anthropic OAuth, Codex OAuth, third-party API
    /// key, manual). Older JSON without this field deserialises to
    /// `AccountSource::Anthropic` via the default.
    #[serde(default = "default_source")]
    pub source: AccountSource,
    /// Upstream surface (`claude-code` or `codex`). Defaults to
    /// `ClaudeCode` for backwards compatibility with snapshots that
    /// predate this field.
    #[serde(default)]
    pub surface: Surface,
    /// Auth method tag from `AccountInfo.method` —
    /// `oauth` / `api_key` / `code_assist_oauth` / `vertex_sa`.
    /// Used by [`AccountStatus::format_line`] to render the trailing
    /// `(api-key)` / `(oauth)` / `(vertex-sa)` suffix on non-polled
    /// rows. Defaults to empty for snapshots that predate this field.
    #[serde(default)]
    pub method: String,
    /// Remaining account balance for pay-per-token providers (e.g. DeepSeek).
    /// `None` for subscription-based or rate-limited providers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance: Option<BalanceInfo>,
}

fn default_source() -> AccountSource {
    AccountSource::Anthropic
}

impl AccountStatus {
    /// Returns the icon for 5-hour usage:
    /// - `●` (bullet) for <80%
    /// - `◐` (half) for 80-99%
    /// - `○` (circle) for 100%
    /// - `·` (middle dot) for no data
    pub fn five_hour_icon(&self) -> &'static str {
        match self.five_hour_pct {
            None => "·",
            Some(p) if p < 80.0 => "●",
            Some(p) if p < 100.0 => "◐",
            Some(_) => "○",
        }
    }

    /// Surface tag shown after the label, e.g. ` [codex]`,
    /// ` [gemini]`, or ` [minimax]`. Empty for vanilla Anthropic
    /// OAuth rows so existing output is byte-identical for
    /// Anthropic-only setups.
    fn surface_tag(&self) -> String {
        match (&self.surface, &self.source) {
            (Surface::Codex, _) => " [codex]".to_string(),
            (Surface::Gemini, _) => " [gemini]".to_string(),
            (_, AccountSource::ThirdParty { provider }) => {
                format!(" [{}]", provider.to_ascii_lowercase())
            }
            (_, AccountSource::Manual) => " [manual]".to_string(),
            _ => String::new(),
        }
    }

    /// Formats the status line for this account.
    ///
    /// Anthropic OAuth and Codex rows include 5h/7d quota fields when
    /// the poller has data (Codex quota lands alongside Anthropic per
    /// spec 07 §7.4). Third-party and manual rows omit the quota
    /// suffix — csq does not poll those providers' quotas today.
    pub fn format_line(&self) -> String {
        let marker = if self.is_active { "*" } else { " " };
        let icon = self.five_hour_icon();
        let tag = self.surface_tag();

        // Third-party / manual slots: no quota polling, render a
        // bound-state suffix instead of "5h:— 7d:—" so the user can
        // tell "no data yet" from "no polling".
        let polled = matches!(self.source, AccountSource::Anthropic | AccountSource::Codex);
        if !polled {
            let suffix = if self.has_any_quota_data() {
                self.quota_suffix()
            } else {
                self.bound_state_suffix().to_string()
            };
            return format!(
                "{} #{} {} {}{}  {}",
                marker, self.id, icon, self.label, tag, suffix
            );
        }

        let suffix = self.quota_suffix();
        format!(
            "{} #{} {} {}{}  {}",
            marker, self.id, icon, self.label, tag, suffix
        )
    }

    fn has_any_quota_data(&self) -> bool {
        self.five_hour_pct.is_some() || self.seven_day_pct.is_some() || self.balance.is_some()
    }

    /// Suffix shown on non-polled rows when no quota is recorded yet.
    /// Distinguishes the auth method so OAuth-mode Gemini (token-bearing)
    /// is not mislabelled as `(api-key)` (a real material misread —
    /// users with both API-key and OAuth slots cannot tell them apart
    /// from the dashboard otherwise).
    fn bound_state_suffix(&self) -> &'static str {
        match self.method.as_str() {
            "code_assist_oauth" | "oauth" | "oauth-personal" => "(oauth)",
            "vertex_sa" => "(vertex-sa)",
            // `api_key` and the empty-string default both render
            // `(api-key)` — preserves byte-for-byte output for the
            // 3P bearer slots (DeepSeek/MiniMax/Z.AI/Ollama) that
            // existed before this field landed.
            _ => "(api-key)",
        }
    }

    fn quota_suffix(&self) -> String {
        // Balance-carrying rows (pay-per-token, e.g. DeepSeek) render the
        // balance in place of the usage windows.
        if let Some(ref b) = self.balance {
            return format_balance(b);
        }
        let usage = match self.five_hour_pct {
            Some(p) => {
                let resets = self
                    .five_hour_resets_in
                    .map(fmt_time)
                    .unwrap_or_else(|| "?".into());
                format!("5h:{:.0}% ({}) ", p, resets)
            }
            None => "5h:— ".to_string(),
        };
        let weekly = match self.seven_day_pct {
            Some(p) => format!("7d:{:.0}%", p),
            None => "7d:—".to_string(),
        };
        format!("{}{}", usage, weekly)
    }

    // ── Table renderer (csq status) ──────────────────────────────────

    /// True when this row carries quota data csq can render — a polled
    /// surface (Anthropic / Codex), a third-party slot that reports usage
    /// (e.g. Z.AI 7-day window), or a balance-carrying pay-per-token slot.
    fn shows_quota(&self) -> bool {
        matches!(self.source, AccountSource::Anthropic | AccountSource::Codex)
            || self.has_any_quota_data()
    }

    /// Surface tag without the leading space [`surface_tag`] adds, e.g.
    /// `[codex]`. Empty for vanilla Anthropic.
    fn tag_bare(&self) -> String {
        self.surface_tag().trim_start().to_string()
    }

    /// The non-polled bound-state line shown in place of the quota columns,
    /// e.g. `oauth — not quota-polled`. Distinguishes auth method so an
    /// OAuth Gemini slot is not mislabelled as an api-key slot.
    fn bound_state_line(&self) -> String {
        let word = match self.method.as_str() {
            "code_assist_oauth" | "oauth" | "oauth-personal" => "oauth",
            "vertex_sa" => "vertex-sa",
            _ => "api-key",
        };
        format!("{word} — not quota-polled")
    }

    /// Weekly-cap flag: `⛔` at 100%, `⚠` above 80%, empty otherwise. The
    /// single signal that tells an operator "this account is weekly-limited"
    /// at a glance.
    fn weekly_flag(&self) -> &'static str {
        match self.seven_day_pct {
            Some(p) if p >= 100.0 => "⛔",
            Some(p) if p >= 80.0 => "⚠",
            _ => "",
        }
    }

    /// Renders one quota block — `bar pct reset` — to a fixed 16-column width
    /// so the 5h and 7d columns align. `empty_label` (`idle` / `—`) fills the
    /// block when the window has no data.
    fn quota_block(pct: Option<f64>, resets_in: Option<u64>, empty_label: &str) -> String {
        let block_w = BAR_W + 1 + PCT_W + 1 + RST_W; // 16
        match pct {
            Some(p) => {
                let bar = usage_bar(p, BAR_W);
                let reset = resets_in.map(fmt_reset).unwrap_or_else(|| "?".into());
                format!("{bar} {p:>3.0}% {reset:<RST_W$}")
            }
            None => format!("{empty_label:<block_w$}"),
        }
    }
}

/// Formats a balance for display.
///
/// USD renders as `$197.15`; other currencies render as `197.15 EUR`.
fn format_balance(b: &BalanceInfo) -> String {
    if b.currency == "USD" {
        format!("${:.2}", b.remaining)
    } else {
        format!("{:.2} {}", b.remaining, b.currency)
    }
}

/// Renders the full `csq status` table: header summary, aligned account rows
/// with per-window usage bars + reset countdowns + weekly-cap flags, and a
/// legend footer when any account is capped.
///
/// Pure (takes a pre-formatted `clock` string) so the layout is golden-tested
/// without a wall-clock dependency. The CLI passes `chrono::Local::now()`.
pub fn render_status_table(
    accounts: &[AccountStatus],
    active: Option<AccountNum>,
    clock: &str,
) -> String {
    let active_id = active.map(|a| a.get());

    // Column widths derived from the data so labels + tags align.
    let id_w = accounts
        .iter()
        .map(|a| a.id.to_string().len())
        .max()
        .unwrap_or(1)
        .max(1);
    let acct_w = accounts
        .iter()
        .map(|a| {
            let label = a.label.chars().count();
            let tag = a.tag_bare().chars().count();
            if tag == 0 {
                label
            } else {
                label + 1 + tag
            }
        })
        .max()
        .unwrap_or(7)
        .max("ACCOUNT".len());

    let mut out = String::new();

    // Header summary.
    let n = accounts.len();
    let active_str = active_id
        .map(|id| format!("#{id} active"))
        .unwrap_or_else(|| "no active slot".to_string());
    out.push_str(&format!("\n  csq · {n} slots · {active_str} · {clock}\n\n"));

    // Column header (each window block shares the BAR/PCT/RESET widths used by
    // the data rows, so they align by construction).
    let head5 = format!("{:<BAR_W$} {:>PCT_W$} {:<RST_W$}", "5H", "USED", "RESET");
    let head7 = format!("{:<BAR_W$} {:>PCT_W$} {:<RST_W$}", "7D", "USED", "RESET");
    let header = format!(
        "  {marker} {hash:>id_w$}  {acct:<acct_w$}  {head5}  {head7}",
        marker = " ",
        hash = "#",
        acct = "ACCOUNT",
    );
    out.push_str(header.trim_end());
    out.push('\n');

    let mut any_flag = false;
    for a in accounts {
        let marker = if active_id == Some(a.id) { "▸" } else { " " };

        // Account field: label left, tag right-aligned to the column edge.
        let tag = a.tag_bare();
        let label_w = a.label.chars().count();
        let acct_field = if tag.is_empty() {
            format!("{:<acct_w$}", a.label)
        } else {
            let pad = acct_w.saturating_sub(label_w + tag.chars().count());
            format!("{}{}{}", a.label, " ".repeat(pad), tag)
        };

        let body = if let Some(ref b) = a.balance {
            // Pay-per-token slot with a polled balance — render in place of
            // the usage bars so the operator sees the remaining credit.
            format!("{} balance", format_balance(b))
        } else if a.shows_quota() {
            let five = AccountStatus::quota_block(a.five_hour_pct, a.five_hour_resets_in, "idle");
            let seven = AccountStatus::quota_block(a.seven_day_pct, a.seven_day_resets_in, "—");
            let flag = a.weekly_flag();
            if !flag.is_empty() {
                any_flag = true;
            }
            let flag_part = if flag.is_empty() {
                String::new()
            } else {
                format!(" {flag}")
            };
            format!("{five}  {seven}{flag_part}")
        } else {
            a.bound_state_line()
        };

        let line = format!("  {marker} {id:>id_w$}  {acct_field}  {body}", id = a.id);
        out.push_str(line.trim_end());
        out.push('\n');
    }

    if any_flag {
        out.push_str("\n  ⛔ weekly cap reached    ⚠ weekly >80%\n");
    }

    out
}

/// Returns the status of all discovered accounts.
///
/// Convenience wrapper for the direct (non-daemon) path: runs
/// [`discovery::discover_all`] and hands the result to
/// [`compose_status`]. The daemon-delegated path calls
/// [`compose_status`] directly with accounts parsed from
/// `/api/accounts`.
///
/// Before alpha.N this function called `discover_anthropic`, which
/// silently dropped Codex + third-party (MiniMax/Z.AI/Ollama) + manual
/// slots. `discover_all` composes every source in priority order so
/// `csq status` now renders the full configured set.
pub fn show_status(base_dir: &Path, active: Option<AccountNum>) -> Vec<AccountStatus> {
    let accounts = discovery::discover_all(base_dir);
    compose_status(base_dir, accounts, active)
}

/// Composes status entries from a pre-discovered account list.
///
/// Joins the account list with the local quota file and produces
/// the filtered, sorted [`AccountStatus`] entries the CLI displays.
/// The quota file is a local read in both paths — the daemon does
/// not currently expose quota over HTTP.
///
/// Used by both the direct path (via [`show_status`]) and the
/// daemon-delegated path (`csq status` after parsing
/// `/api/accounts`), so the two paths are guaranteed to produce
/// identical output for the same `(accounts, quota)` pair.
pub fn compose_status(
    base_dir: &Path,
    accounts: Vec<AccountInfo>,
    active: Option<AccountNum>,
) -> Vec<AccountStatus> {
    let quota = state::load_state(base_dir).unwrap_or_else(|_| super::QuotaFile::empty());

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    accounts
        .into_iter()
        .filter(|a| a.has_credentials)
        .map(|a| {
            let q = quota.get(a.id);
            let account_num = AccountNum::try_from(a.id).ok();
            let label = if a.label == "unknown" {
                account_num
                    .map(|n| account_label(base_dir, n))
                    .unwrap_or_else(|| a.label.clone())
            } else {
                a.label.clone()
            };

            AccountStatus {
                id: a.id,
                label,
                is_active: active.map(|c| c.get() == a.id).unwrap_or(false),
                five_hour_pct: q
                    .map(|q| q.five_hour_pct())
                    .filter(|p| *p > 0.0 || q.is_some_and(|q| q.five_hour.is_some())),
                five_hour_resets_in: q.and_then(|q| {
                    q.five_hour
                        .as_ref()
                        .map(|w| w.resets_at.saturating_sub(now_secs))
                }),
                seven_day_pct: q
                    .map(|q| q.seven_day_pct())
                    .filter(|p| *p > 0.0 || q.is_some_and(|q| q.seven_day.is_some())),
                seven_day_resets_in: q.and_then(|q| {
                    q.seven_day
                        .as_ref()
                        .map(|w| w.resets_at.saturating_sub(now_secs))
                }),
                source: a.source,
                surface: a.surface,
                method: a.method,
                balance: q.and_then(|q| q.balance.clone()),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::BillingMode;
    use crate::credentials::{self, AnthropicCredentialFile, CredentialFile, OAuthPayload};
    use crate::quota::{AccountQuota, QuotaFile, UsageWindow};
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn setup(base: &Path, account: u16, pct: f64) {
        let target = AccountNum::try_from(account).unwrap();
        let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new(format!("at-{account}")),
                refresh_token: RefreshToken::new(format!("rt-{account}")),
                expires_at: 9999999999999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        });
        credentials::save(&credentials::file::canonical_path(base, target), &creds).unwrap();

        let mut quota = state::load_state(base).unwrap_or_else(|_| QuotaFile::empty());
        quota.set(
            account,
            AccountQuota {
                five_hour: Some(UsageWindow {
                    used_percentage: pct,
                    resets_at: 9999999999,
                }),
                ..Default::default()
            },
        );
        state::save_state(base, &quota).unwrap();
    }

    #[test]
    fn show_status_returns_all_accounts() {
        let dir = TempDir::new().unwrap();
        setup(dir.path(), 1, 20.0);
        setup(dir.path(), 2, 85.0);
        setup(dir.path(), 3, 100.0);

        let active = AccountNum::try_from(2u16).unwrap();
        let status = show_status(dir.path(), Some(active));

        assert_eq!(status.len(), 3);
        assert!(status.iter().find(|s| s.id == 2).unwrap().is_active);
        assert!(!status.iter().find(|s| s.id == 1).unwrap().is_active);
    }

    fn anthropic_status(id: u16) -> AccountStatus {
        AccountStatus {
            id,
            label: "x".into(),
            is_active: false,
            five_hour_pct: Some(20.0),
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::Anthropic,
            surface: Surface::ClaudeCode,
            method: "oauth".into(),
            balance: None,
        }
    }

    #[test]
    fn status_icons_by_usage() {
        let s_low = anthropic_status(1);
        assert_eq!(s_low.five_hour_icon(), "●");

        let s_high = AccountStatus {
            five_hour_pct: Some(90.0),
            ..s_low.clone()
        };
        assert_eq!(s_high.five_hour_icon(), "◐");

        let s_full = AccountStatus {
            five_hour_pct: Some(100.0),
            ..s_low.clone()
        };
        assert_eq!(s_full.five_hour_icon(), "○");

        let s_none = AccountStatus {
            five_hour_pct: None,
            ..s_low
        };
        assert_eq!(s_none.five_hour_icon(), "·");
    }

    #[test]
    fn format_line_active_marker() {
        let s = AccountStatus {
            id: 3,
            label: "test@example.com".into(),
            is_active: true,
            five_hour_pct: Some(42.0),
            five_hour_resets_in: Some(3600),
            seven_day_pct: Some(15.0),
            seven_day_resets_in: Some(86400),
            source: AccountSource::Anthropic,
            surface: Surface::ClaudeCode,
            method: "oauth".into(),
            balance: None,
        };
        let line = s.format_line();
        assert!(line.starts_with("* #3"));
        assert!(line.contains("test@example.com"));
        assert!(line.contains("42%"));
        assert!(line.contains("15%"));
        // Anthropic rows carry no surface tag — keeps existing output byte-identical.
        assert!(!line.contains("["));
    }

    #[test]
    fn format_line_third_party_minimax_shows_tag_and_api_key_suffix() {
        let s = AccountStatus {
            id: 9,
            label: "MiniMax".into(),
            is_active: false,
            five_hour_pct: None,
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::ThirdParty {
                provider: "MiniMax".into(),
            },
            surface: Surface::ClaudeCode,
            method: "api_key".into(),
            balance: None,
        };
        let line = s.format_line();
        assert!(line.contains("#9"), "missing id: {line}");
        assert!(line.contains("[minimax]"), "missing provider tag: {line}");
        assert!(line.contains("(api-key)"), "missing api-key suffix: {line}");
        // 3P rows must NOT render quota placeholders — quota isn't
        // polled for MiniMax/Z.AI/Ollama today, so `5h:—` would imply
        // "no data yet" which is misleading.
        assert!(!line.contains("5h:"), "unexpected quota suffix: {line}");
        assert!(!line.contains("7d:"), "unexpected quota suffix: {line}");
    }

    #[test]
    fn format_line_gemini_oauth_shows_gemini_tag_and_oauth_suffix() {
        let s = AccountStatus {
            id: 13,
            label: "gemini-13".into(),
            is_active: false,
            five_hour_pct: None,
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::Gemini,
            surface: Surface::Gemini,
            method: "code_assist_oauth".into(),
            balance: None,
        };
        let line = s.format_line();
        assert!(line.contains("[gemini]"), "missing gemini tag: {line}");
        assert!(line.contains("#13"), "missing slot id: {line}");
        assert!(
            line.contains("(oauth)"),
            "OAuth slot rendered as api-key: {line}"
        );
        assert!(
            !line.contains("(api-key)"),
            "OAuth slot mislabelled: {line}"
        );
    }

    #[test]
    fn format_line_gemini_api_key_keeps_api_key_suffix() {
        let s = AccountStatus {
            id: 13,
            label: "gemini-13".into(),
            is_active: false,
            five_hour_pct: None,
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::Gemini,
            surface: Surface::Gemini,
            method: "api_key".into(),
            balance: None,
        };
        let line = s.format_line();
        assert!(
            line.contains("(api-key)"),
            "api-key slot mislabelled: {line}"
        );
    }

    #[test]
    fn format_line_gemini_vertex_sa_shows_vertex_sa_suffix() {
        let s = AccountStatus {
            id: 13,
            label: "gemini-13".into(),
            is_active: false,
            five_hour_pct: None,
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::Gemini,
            surface: Surface::Gemini,
            method: "vertex_sa".into(),
            balance: None,
        };
        let line = s.format_line();
        assert!(
            line.contains("(vertex-sa)"),
            "vertex-sa slot mislabelled: {line}"
        );
    }

    #[test]
    fn format_line_codex_shows_codex_tag_and_quota() {
        let s = AccountStatus {
            id: 4,
            label: "user@openai.test".into(),
            is_active: true,
            five_hour_pct: Some(12.0),
            five_hour_resets_in: Some(1800),
            seven_day_pct: Some(3.0),
            seven_day_resets_in: Some(86400),
            source: AccountSource::Codex,
            surface: Surface::Codex,
            method: "oauth".into(),
            balance: None,
        };
        let line = s.format_line();
        assert!(line.starts_with("* #4"), "line: {line}");
        assert!(line.contains("[codex]"), "missing codex tag: {line}");
        // Codex is a polled surface (spec 07 §7.4) so quota suffix
        // must render like Anthropic.
        assert!(line.contains("5h:12%"), "missing 5h quota: {line}");
        assert!(line.contains("7d:3%"), "missing 7d quota: {line}");
    }

    #[test]
    fn show_status_no_accounts() {
        let dir = TempDir::new().unwrap();
        let status = show_status(dir.path(), None);
        assert!(status.is_empty());
    }

    /// `compose_status` is the composition step used by both the
    /// direct path (via [`show_status`]) and the daemon-delegated
    /// path (via `csq status` after parsing `/api/accounts`).
    /// This test feeds it a synthetic account list mirroring the
    /// shape the daemon route returns — validating that the CLI's
    /// daemon path produces identical output to the direct path
    /// for the same `(accounts, quota)` pair.
    #[test]
    fn compose_status_with_daemon_shaped_accounts() {
        let dir = TempDir::new().unwrap();
        // Populate quota file + credentials so compose_status has
        // something to join against.
        setup(dir.path(), 1, 20.0);
        setup(dir.path(), 2, 85.0);

        // Synthetic AccountInfo list as if returned from
        // `GET /api/accounts`. Label is already resolved (daemon
        // hits profiles.json server-side), has_credentials=true.
        let accounts = vec![
            AccountInfo {
                id: 1,
                label: "alice@example.com".into(),
                oauth_email: None,
                source: AccountSource::Anthropic,
                surface: crate::providers::catalog::Surface::ClaudeCode,
                method: "oauth".into(),
                has_credentials: true,
                billing_mode: BillingMode::Subscription,
            },
            AccountInfo {
                id: 2,
                label: "bob@example.com".into(),
                oauth_email: None,
                source: AccountSource::Anthropic,
                surface: crate::providers::catalog::Surface::ClaudeCode,
                method: "oauth".into(),
                has_credentials: true,
                billing_mode: BillingMode::Subscription,
            },
        ];

        let active = AccountNum::try_from(2u16).unwrap();
        let status = compose_status(dir.path(), accounts, Some(active));

        assert_eq!(status.len(), 2);
        let first = status.iter().find(|s| s.id == 1).unwrap();
        assert_eq!(first.label, "alice@example.com");
        assert!(!first.is_active);
        let second = status.iter().find(|s| s.id == 2).unwrap();
        assert_eq!(second.label, "bob@example.com");
        assert!(second.is_active);
    }

    /// `compose_status` must filter out accounts with
    /// `has_credentials == false` — these are placeholders the
    /// daemon may list (e.g., after a failed credential parse).
    #[test]
    fn compose_status_filters_accounts_without_credentials() {
        let dir = TempDir::new().unwrap();
        setup(dir.path(), 1, 20.0);

        let accounts = vec![
            AccountInfo {
                id: 1,
                label: "real@example.com".into(),
                oauth_email: None,
                source: AccountSource::Anthropic,
                surface: Surface::ClaudeCode,
                method: "oauth".into(),
                has_credentials: true,
                billing_mode: BillingMode::Subscription,
            },
            AccountInfo {
                id: 7,
                label: "broken@example.com".into(),
                oauth_email: None,
                source: AccountSource::Anthropic,
                surface: Surface::ClaudeCode,
                method: "oauth".into(),
                has_credentials: false,
                billing_mode: BillingMode::Subscription,
            },
        ];

        let status = compose_status(dir.path(), accounts, None);
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].id, 1);
    }

    /// Multi-surface coverage: the same mix a real user sees —
    /// Anthropic OAuth on slot 1, Codex OAuth on slot 4, per-slot
    /// MiniMax binding on slot 9, and Ollama (local) on slot 10.
    /// `compose_status` must carry the surface/source through so
    /// `format_line` can render each correctly.
    #[test]
    fn compose_status_multi_surface_mix() {
        let dir = TempDir::new().unwrap();
        setup(dir.path(), 1, 25.0); // Anthropic quota only
        let accounts = vec![
            AccountInfo {
                id: 1,
                label: "anthro@example.com".into(),
                oauth_email: None,
                source: AccountSource::Anthropic,
                surface: Surface::ClaudeCode,
                method: "oauth".into(),
                has_credentials: true,
                billing_mode: BillingMode::Subscription,
            },
            AccountInfo {
                id: 4,
                label: "openai-user".into(),
                oauth_email: None,
                source: AccountSource::Codex,
                surface: Surface::Codex,
                method: "oauth".into(),
                has_credentials: true,
                billing_mode: BillingMode::Subscription,
            },
            AccountInfo {
                id: 9,
                label: "MiniMax".into(),
                oauth_email: None,
                source: AccountSource::ThirdParty {
                    provider: "MiniMax".into(),
                },
                surface: Surface::ClaudeCode,
                method: "api_key".into(),
                has_credentials: true,
                billing_mode: BillingMode::Subscription,
            },
            AccountInfo {
                id: 10,
                label: "Ollama".into(),
                oauth_email: None,
                source: AccountSource::ThirdParty {
                    provider: "Ollama".into(),
                },
                surface: Surface::ClaudeCode,
                method: "api_key".into(),
                has_credentials: true,
                billing_mode: BillingMode::Subscription,
            },
        ];

        let status = compose_status(dir.path(), accounts, None);
        assert_eq!(status.len(), 4, "all four slots must be composed");

        let anth = status.iter().find(|s| s.id == 1).unwrap();
        assert!(matches!(anth.source, AccountSource::Anthropic));
        assert_eq!(anth.surface, Surface::ClaudeCode);

        let codex = status.iter().find(|s| s.id == 4).unwrap();
        assert!(matches!(codex.source, AccountSource::Codex));
        assert_eq!(codex.surface, Surface::Codex);
        assert!(codex.format_line().contains("[codex]"));

        let mm = status.iter().find(|s| s.id == 9).unwrap();
        match &mm.source {
            AccountSource::ThirdParty { provider } => assert_eq!(provider, "MiniMax"),
            other => panic!("expected ThirdParty MiniMax, got {:?}", other),
        }
        assert!(mm.format_line().contains("[minimax]"));

        let ol = status.iter().find(|s| s.id == 10).unwrap();
        match &ol.source {
            AccountSource::ThirdParty { provider } => assert_eq!(provider, "Ollama"),
            other => panic!("expected ThirdParty Ollama, got {:?}", other),
        }
        assert!(ol.format_line().contains("[ollama]"));
    }

    /// Back-compat regression: an AccountStatus JSON written by an
    /// older csq (no `source`/`surface` fields) must deserialise.
    #[test]
    fn account_status_deserializes_without_new_fields() {
        let legacy = r#"{
            "id": 1,
            "label": "alice@example.com",
            "is_active": true,
            "five_hour_pct": 12.0,
            "five_hour_resets_in": 3600,
            "seven_day_pct": 3.0,
            "seven_day_resets_in": 86400
        }"#;
        let parsed: AccountStatus = serde_json::from_str(legacy).expect("legacy JSON parses");
        assert_eq!(parsed.id, 1);
        assert!(matches!(parsed.source, AccountSource::Anthropic));
        assert_eq!(parsed.surface, Surface::ClaudeCode);
    }

    // ── Table renderer ───────────────────────────────────────────────

    #[test]
    fn usage_bar_resolution() {
        assert_eq!(usage_bar(0.0, 4), "░░░░"); // idle
        assert_eq!(usage_bar(2.0, 4), "▏░░░"); // nonzero shows ≥1 eighth
        assert_eq!(usage_bar(50.0, 4), "██░░"); // round(0.5*32)=16 → 2 full
        assert_eq!(usage_bar(100.0, 4), "████");
        assert_eq!(usage_bar(150.0, 4), "████"); // clamps over 100
    }

    #[allow(clippy::too_many_arguments)]
    fn tbl_row(
        id: u16,
        label: &str,
        active: bool,
        fh: Option<f64>,
        fh_r: Option<u64>,
        sd: Option<f64>,
        sd_r: Option<u64>,
        source: AccountSource,
        surface: Surface,
        method: &str,
    ) -> AccountStatus {
        AccountStatus {
            id,
            label: label.into(),
            is_active: active,
            five_hour_pct: fh,
            five_hour_resets_in: fh_r,
            seven_day_pct: sd,
            seven_day_resets_in: sd_r,
            source,
            surface,
            method: method.into(),
            balance: None,
        }
    }

    #[test]
    fn render_table_shows_both_resets_aligns_and_flags() {
        let accts = vec![
            tbl_row(
                1,
                "a@x.com",
                false,
                Some(2.0),
                Some(11_520), // 3h12m
                Some(2.0),
                Some(446_400), // 5d4h
                AccountSource::Anthropic,
                Surface::ClaudeCode,
                "oauth",
            ),
            tbl_row(
                2,
                "bob@example.com",
                true,
                None, // idle 5h
                None,
                Some(100.0),
                Some(194_400), // 2d6h
                AccountSource::Anthropic,
                Surface::ClaudeCode,
                "oauth",
            ),
            tbl_row(
                10,
                "gemini-10",
                false,
                None,
                None,
                None,
                None,
                AccountSource::Gemini,
                Surface::Gemini,
                "oauth",
            ),
        ];
        let active = AccountNum::try_from(2u16).unwrap();
        let out = render_status_table(&accts, Some(active), "Mon 09:00");

        // Header summary.
        assert!(
            out.contains("csq · 3 slots · #2 active · Mon 09:00"),
            "{out}"
        );
        // BOTH windows now show a reset countdown — the gap this redesign closes
        // (the old format printed a 7d percentage with no reset time).
        assert!(out.contains("3h12m"), "5h reset missing: {out}");
        assert!(out.contains("5d4h"), "7d reset missing (the bug): {out}");
        assert!(out.contains("2d6h"), "capped row 7d reset: {out}");
        // Weekly-cap flag + idle 5h on the exhausted account.
        assert!(out.contains("⛔"), "cap flag: {out}");
        assert!(out.contains("idle"), "idle 5h cell: {out}");
        // Non-polled Gemini row renders bound state, not quota placeholders.
        assert!(out.contains("oauth — not quota-polled"), "{out}");
        // Footer legend appears because a row is capped.
        assert!(out.contains("⛔ weekly cap reached"), "{out}");

        // Active marker on slot 2 only.
        let active_line = out.lines().find(|l| l.contains("bob@example.com")).unwrap();
        assert!(
            active_line.trim_start().starts_with("▸"),
            "missing active marker: {active_line:?}"
        );
        let inactive_line = out.lines().find(|l| l.contains("a@x.com")).unwrap();
        assert!(
            !inactive_line.trim_start().starts_with("▸"),
            "unexpected active marker: {inactive_line:?}"
        );

        // Alignment: the "5H" column-header label and each polled row's usage
        // bar begin at the same character column.
        let header = out.lines().find(|l| l.contains("ACCOUNT")).unwrap();
        let col5 = header.chars().collect::<Vec<_>>();
        let h5 = col5
            .windows(2)
            .position(|w| w == ['5', 'H'])
            .expect("5H header");
        let row1 = out.lines().find(|l| l.contains("a@x.com")).unwrap();
        assert_eq!(
            row1.chars().nth(h5),
            Some('▏'),
            "5h bar misaligned with header: {row1:?}"
        );
    }

    #[test]
    fn render_table_no_flag_no_legend() {
        // No account above 80% weekly → no legend footer.
        let accts = vec![tbl_row(
            1,
            "a@x.com",
            true,
            Some(10.0),
            Some(3600),
            Some(20.0),
            Some(86_400),
            AccountSource::Anthropic,
            Surface::ClaudeCode,
            "oauth",
        )];
        let active = AccountNum::try_from(1u16).unwrap();
        let out = render_status_table(&accts, Some(active), "Tue 12:00");
        assert!(!out.contains("weekly cap reached"), "{out}");
        assert!(!out.contains("⛔"), "{out}");
        assert!(!out.contains('⚠'), "{out}");
    }

    // ── DeepSeek balance display tests ───────────────────────────────

    /// (c) A DeepSeek slot with a polled balance renders `$197.15` in the
    /// statusline suffix — not `(api-key)` or `not quota-polled`.
    #[test]
    fn format_line_deepseek_balance_renders_dollar_amount() {
        let s = AccountStatus {
            id: 7,
            label: "DeepSeek".into(),
            is_active: false,
            five_hour_pct: None,
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::ThirdParty {
                provider: "DeepSeek".into(),
            },
            surface: Surface::ClaudeCode,
            method: "api_key".into(),
            balance: Some(BalanceInfo {
                currency: "USD".into(),
                remaining: 197.15,
            }),
        };
        let line = s.format_line();
        assert!(
            line.contains("$197.15"),
            "balance missing from line: {line}"
        );
        // Must NOT fall back to the unpolled bound-state suffix.
        assert!(
            !line.contains("(api-key)"),
            "unexpected api-key suffix on balanced row: {line}"
        );
        assert!(
            !line.contains("not quota-polled"),
            "unexpected not-polled text: {line}"
        );
    }

    /// (c) A DeepSeek slot with NO balance yet renders the bound-state suffix.
    #[test]
    fn format_line_deepseek_no_balance_renders_bound_state() {
        let s = AccountStatus {
            id: 7,
            label: "DeepSeek".into(),
            is_active: false,
            five_hour_pct: None,
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::ThirdParty {
                provider: "DeepSeek".into(),
            },
            surface: Surface::ClaudeCode,
            method: "api_key".into(),
            balance: None,
        };
        let line = s.format_line();
        // No balance → fallback to bound-state.
        assert!(
            line.contains("(api-key)"),
            "expected api-key suffix: {line}"
        );
        assert!(
            !line.contains('$'),
            "unexpected dollar sign on unpolled row: {line}"
        );
    }

    /// (c) Table renderer renders `$197.15 balance` in the body column.
    #[test]
    fn render_table_deepseek_balance_in_body() {
        let s = AccountStatus {
            id: 7,
            label: "DeepSeek".into(),
            is_active: false,
            five_hour_pct: None,
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::ThirdParty {
                provider: "DeepSeek".into(),
            },
            surface: Surface::ClaudeCode,
            method: "api_key".into(),
            balance: Some(BalanceInfo {
                currency: "USD".into(),
                remaining: 197.15,
            }),
        };
        let out = render_status_table(&[s], None, "Mon 09:00");
        assert!(out.contains("$197.15 balance"), "table body: {out}");
        // Must not contain the unpolled text.
        assert!(
            !out.contains("not quota-polled"),
            "unexpected not-polled text: {out}"
        );
    }
}
