//! `csq statusline` — reads CC JSON from stdin, updates quota, outputs formatted statusline.

use anyhow::Result;
use csq_core::accounts::markers;
use csq_core::broker::fanout::is_broker_failed;
use csq_core::quota::{
    format::{account_label, is_swap_stuck, should_report_broker_failed, statusline_str},
    state,
};
use csq_core::types::AccountNum;
use std::io::Read;
use std::path::Path;

/// Maximum bytes of CC JSON we accept on stdin.
/// Real CC payloads are <16KB; 64KB is generous and prevents DoS.
const MAX_STDIN: u64 = 65_536;

pub fn handle(base_dir: &Path) -> Result<()> {
    let config_dir = super::current_config_dir();

    // Read CC's JSON from stdin with a hard size limit
    let mut stdin_json = String::new();
    let _ = std::io::stdin()
        .take(MAX_STDIN)
        .read_to_string(&mut stdin_json);

    // Determine active account
    let account: AccountNum = match config_dir
        .as_deref()
        .and_then(markers::read_current_account)
    {
        Some(a) => a,
        None => {
            println!("csq: no active account");
            return Ok(());
        }
    };

    let config_dir = config_dir.unwrap();

    // Update quota from CC's rate_limits payload (if present and parseable)
    if !stdin_json.trim().is_empty() {
        if let Ok(cc_payload) = serde_json::from_str::<serde_json::Value>(&stdin_json) {
            if let Some(rate_limits) = cc_payload.get("rate_limits") {
                // Best-effort — never block statusline render on quota errors
                let _ = state::update_quota(base_dir, &config_dir, account, rate_limits);
            }
        }
    }

    // Load state after (possibly) updating
    let quota = state::load_state(base_dir).unwrap_or_else(|_| csq_core::quota::QuotaFile::empty());
    let account_quota = quota.get(account.get());

    let label = account_label(base_dir, account);
    let stuck = is_swap_stuck(&config_dir, base_dir);
    let broker_failed =
        should_report_broker_failed(base_dir, account) || is_broker_failed(base_dir, account);

    let line = statusline_str(account, &label, account_quota, stuck, broker_failed);
    println!("{line}");
    Ok(())
}
