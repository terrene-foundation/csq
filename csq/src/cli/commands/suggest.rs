//! `csq suggest` — JSON output of the best account to switch to.

use anyhow::Result;
use csq_core::accounts::snapshot;
use csq_core::rotation;
use std::path::Path;

pub fn handle(base_dir: &Path) -> Result<()> {
    // Authority-first resolution (workspace an internal workspace):
    // route through snapshot_account so `csq suggest` sees the same
    // self-healed slot as the statusline, not a raw (drift-prone) cache read.
    let current = super::current_config_dir()
        .as_deref()
        .and_then(|cd| snapshot::snapshot_account(cd, base_dir));

    let suggestion = rotation::suggest(base_dir, current);
    println!("{}", serde_json::to_string(&suggestion)?);
    Ok(())
}
