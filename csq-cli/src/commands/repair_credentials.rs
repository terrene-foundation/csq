//! `csq repair-credentials` — detect and optionally repair
//! cross-slot refresh-token contamination.
//!
//! ### What contamination looks like
//!
//! When the fanout/rotation logic writes the same OAuth refresh
//! response to multiple slots, their `credentials/N.json` and
//! `config-N/.credentials.json` files end up sharing refresh
//! tokens. Each successful refresh rotates the token; only one
//! slot consumes the new value and the others now point at a
//! dead token that Anthropic rejects with `invalid_grant`.
//!
//! Symptoms: user sees "Expired — invalid token — re-login
//! needed" on multiple slots even though the daemon is running
//! and network is healthy. Logs show `broker_token_invalid`.
//!
//! ### Detection strategy
//!
//! For every pair of slots, compare:
//! - `credentials/{a}.json` refresh_token prefix
//! - `credentials/{b}.json` refresh_token prefix
//! - `config-{a}/.credentials.json` refresh_token prefix
//! - `config-{b}/.credentials.json` refresh_token prefix
//!
//! Any two slots with matching prefixes in any of these files
//! are contaminated. A slot whose canonical and live files point
//! at different tokens is also flagged (likely a fanout miss).
//!
//! ### Repair strategy
//!
//! By default, dry-run: just report the affected slots. With
//! `--apply`, deletes the contaminated `credentials/N.json` so
//! the next use triggers a fresh login via the Add Account flow.
//! Never deletes the live `config-N/.credentials.json` — those
//! are what CC itself is holding and blowing them away would
//! break active sessions.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A slot whose credentials need attention.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    slot: u16,
    canonical_prefix: Option<String>,
    live_prefix: Option<String>,
    kind: FindingKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FindingKind {
    /// Canonical and live disagree on refresh token — fanout miss.
    CanonicalLiveMismatch,
    /// Canonical token is shared with another slot.
    CanonicalSharedWith { other_slot: u16 },
    /// Live token is shared with another slot.
    LiveSharedWith { other_slot: u16 },
}

/// Public entry point. `apply = false` is a dry run.
pub fn handle(base_dir: &Path, apply: bool) -> Result<()> {
    let findings = scan(base_dir).context("scan failed")?;

    if findings.is_empty() {
        println!("✓ No credential contamination detected.");
        return Ok(());
    }

    println!("Detected {} credential issue(s):", findings.len());
    for f in &findings {
        let kind_desc = match &f.kind {
            FindingKind::CanonicalLiveMismatch => "canonical ≠ live (fanout miss)".to_string(),
            FindingKind::CanonicalSharedWith { other_slot } => {
                format!("canonical shared with slot {other_slot}")
            }
            FindingKind::LiveSharedWith { other_slot } => {
                format!("live shared with slot {other_slot}")
            }
        };
        println!(
            "  slot {:>3}  {:<35}  canonical={:<12}  live={:<12}",
            f.slot,
            kind_desc,
            f.canonical_prefix.as_deref().unwrap_or("(none)"),
            f.live_prefix.as_deref().unwrap_or("(none)"),
        );
    }

    if !apply {
        println!();
        println!("Dry run — no files modified. Re-run with `--apply` to delete");
        println!("the affected canonical `credentials/N.json` files and force");
        println!("re-login on next use.");
        return Ok(());
    }

    // Apply: delete contaminated canonical files. Never touch
    // live files — CC may be holding them.
    let mut removed = 0usize;
    for f in &findings {
        let path = base_dir
            .join("credentials")
            .join(format!("{}.json", f.slot));
        match std::fs::remove_file(&path) {
            Ok(()) => {
                println!("  removed {}", path.display());
                removed += 1;
            }
            Err(e) => {
                eprintln!("  failed to remove {}: {e}", path.display());
            }
        }
    }
    println!();
    println!(
        "Removed {removed}/{} contaminated canonical credential(s).",
        findings.len()
    );
    println!("Run the Add Account flow in the desktop app (or `csq login N`)");
    println!("to re-authenticate the affected slot(s).");
    Ok(())
}

/// Scans `base_dir` for contamination findings. Separated from
/// `handle` for unit testability.
fn scan(base_dir: &Path) -> Result<Vec<Finding>> {
    // Load each slot's canonical + live refresh token prefix.
    // Prefix-only so we never hold full tokens in memory.
    let mut per_slot: HashMap<u16, (Option<String>, Option<String>)> = HashMap::new();
    for slot in 1u16..=999 {
        let canonical = base_dir.join("credentials").join(format!("{slot}.json"));
        let live = base_dir
            .join(format!("config-{slot}"))
            .join(".credentials.json");
        let canon_prefix = read_rt_prefix(&canonical);
        let live_prefix = read_rt_prefix(&live);
        if canon_prefix.is_none() && live_prefix.is_none() {
            continue;
        }
        per_slot.insert(slot, (canon_prefix, live_prefix));
    }

    let mut findings = Vec::new();

    // Pass 1: canonical ≠ live for any slot → fanout miss.
    for (&slot, (canon, live)) in &per_slot {
        if let (Some(c), Some(l)) = (canon, live) {
            if c != l {
                findings.push(Finding {
                    slot,
                    canonical_prefix: Some(c.clone()),
                    live_prefix: Some(l.clone()),
                    kind: FindingKind::CanonicalLiveMismatch,
                });
            }
        }
    }

    // Pass 2: canonical tokens shared across slots.
    let mut canon_by_token: HashMap<String, Vec<u16>> = HashMap::new();
    for (&slot, (canon, _)) in &per_slot {
        if let Some(c) = canon {
            canon_by_token.entry(c.clone()).or_default().push(slot);
        }
    }
    for (_, slots) in canon_by_token.iter() {
        if slots.len() < 2 {
            continue;
        }
        let mut sorted = slots.clone();
        sorted.sort();
        for (i, &slot) in sorted.iter().enumerate() {
            let other = sorted[if i == 0 { 1 } else { 0 }];
            findings.push(Finding {
                slot,
                canonical_prefix: per_slot[&slot].0.clone(),
                live_prefix: per_slot[&slot].1.clone(),
                kind: FindingKind::CanonicalSharedWith { other_slot: other },
            });
        }
    }

    // Pass 3: live tokens shared across slots.
    let mut live_by_token: HashMap<String, Vec<u16>> = HashMap::new();
    for (&slot, (_, live)) in &per_slot {
        if let Some(l) = live {
            live_by_token.entry(l.clone()).or_default().push(slot);
        }
    }
    for (_, slots) in live_by_token.iter() {
        if slots.len() < 2 {
            continue;
        }
        let mut sorted = slots.clone();
        sorted.sort();
        for (i, &slot) in sorted.iter().enumerate() {
            let other = sorted[if i == 0 { 1 } else { 0 }];
            findings.push(Finding {
                slot,
                canonical_prefix: per_slot[&slot].0.clone(),
                live_prefix: per_slot[&slot].1.clone(),
                kind: FindingKind::LiveSharedWith { other_slot: other },
            });
        }
    }

    // Stable ordering for deterministic output.
    findings.sort_by_key(|f| (f.slot, format!("{:?}", f.kind)));
    findings.dedup();
    Ok(findings)
}

/// Reads the first 24 characters of the `claudeAiOauth.refreshToken`
/// field in a credential file. Used as a stable, safe identity for
/// cross-slot comparison — short enough to not hold a full token
/// in memory, long enough to detect any realistic collision.
///
/// Returns `None` if the file doesn't exist, is unreadable, or
/// doesn't have the expected shape.
fn read_rt_prefix(path: &PathBuf) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    let rt = json.get("claudeAiOauth")?.get("refreshToken")?.as_str()?;
    Some(rt.chars().take(24).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Writes a credential file with the given refresh token.
    fn write_creds(base: &Path, slot: u16, refresh_token: &str, live: bool) {
        let path = if live {
            let dir = base.join(format!("config-{slot}"));
            std::fs::create_dir_all(&dir).unwrap();
            dir.join(".credentials.json")
        } else {
            let dir = base.join("credentials");
            std::fs::create_dir_all(&dir).unwrap();
            dir.join(format!("{slot}.json"))
        };
        let json = format!(
            r#"{{"claudeAiOauth":{{"accessToken":"sk-ant-oat01-x","refreshToken":"{refresh_token}","expiresAt":1000}}}}"#
        );
        std::fs::write(path, json).unwrap();
    }

    #[test]
    fn scan_clean_state_returns_no_findings() {
        let dir = TempDir::new().unwrap();
        write_creds(dir.path(), 1, "sk-ant-ort01-aaaaaaaaaaaa", false);
        write_creds(dir.path(), 1, "sk-ant-ort01-aaaaaaaaaaaa", true);
        write_creds(dir.path(), 2, "sk-ant-ort01-bbbbbbbbbbbb", false);
        write_creds(dir.path(), 2, "sk-ant-ort01-bbbbbbbbbbbb", true);

        let findings = scan(dir.path()).unwrap();
        assert!(findings.is_empty(), "clean state should have no findings");
    }

    #[test]
    fn scan_detects_canonical_live_mismatch() {
        let dir = TempDir::new().unwrap();
        write_creds(dir.path(), 5, "sk-ant-ort01-canonical-one", false);
        write_creds(dir.path(), 5, "sk-ant-ort01-live-one", true);

        let findings = scan(dir.path()).unwrap();
        assert!(findings
            .iter()
            .any(|f| f.slot == 5 && f.kind == FindingKind::CanonicalLiveMismatch));
    }

    #[test]
    fn scan_detects_canonical_shared_across_slots() {
        let dir = TempDir::new().unwrap();
        // Slots 3 and 8 both have the same canonical refresh token.
        write_creds(dir.path(), 3, "sk-ant-ort01-SNK8-mdPlJU-shared", false);
        write_creds(dir.path(), 8, "sk-ant-ort01-SNK8-mdPlJU-shared", false);

        let findings = scan(dir.path()).unwrap();
        assert!(findings
            .iter()
            .any(|f| f.slot == 3
                && matches!(f.kind, FindingKind::CanonicalSharedWith { other_slot: 8 })));
        assert!(findings
            .iter()
            .any(|f| f.slot == 8
                && matches!(f.kind, FindingKind::CanonicalSharedWith { other_slot: 3 })));
    }

    #[test]
    fn scan_detects_live_shared_across_slots() {
        let dir = TempDir::new().unwrap();
        write_creds(dir.path(), 2, "sk-ant-ort01-different-canon", false);
        write_creds(dir.path(), 3, "sk-ant-ort01-different-canon2", false);
        // Both live files point at the same token (CC rotated
        // and wrote to multiple live paths somehow).
        write_creds(dir.path(), 2, "sk-ant-ort01-shared-live-token", true);
        write_creds(dir.path(), 3, "sk-ant-ort01-shared-live-token", true);

        let findings = scan(dir.path()).unwrap();
        assert!(findings.iter().any(
            |f| f.slot == 2 && matches!(f.kind, FindingKind::LiveSharedWith { other_slot: 3 })
        ));
    }

    #[test]
    fn scan_skips_slots_with_no_credentials() {
        let dir = TempDir::new().unwrap();
        // No files for any slot.
        let findings = scan(dir.path()).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn read_rt_prefix_caps_at_24_chars() {
        let dir = TempDir::new().unwrap();
        write_creds(
            dir.path(),
            9,
            "sk-ant-ort01-this-is-a-very-long-token-that-should-be-capped",
            false,
        );
        let prefix = read_rt_prefix(&dir.path().join("credentials/9.json")).unwrap();
        assert_eq!(prefix.len(), 24);
    }

    #[test]
    fn read_rt_prefix_returns_none_on_missing() {
        let dir = TempDir::new().unwrap();
        let result = read_rt_prefix(&dir.path().join("nonexistent"));
        assert!(result.is_none());
    }

    #[test]
    fn read_rt_prefix_returns_none_on_malformed_json() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json at all").unwrap();
        assert!(read_rt_prefix(&path).is_none());
    }
}
