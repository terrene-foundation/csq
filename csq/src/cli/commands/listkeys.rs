//! `csq listkeys` — list configured provider keys.

use anyhow::Result;
use csq_core::providers;
use csq_core::sdk::{self, Envelope, SCHEMA_LISTKEYS_V1};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
struct KeyEntry {
    provider_id: String,
    name: String,
    fingerprint: String,
    model: String,
    /// Settings filename (basename only — e.g. `settings-mm.json`).
    /// Stored as basename per `rules/operator-surface-verification.md`
    /// to avoid leaking the operator's `$HOME` prefix in stdout / `--json`
    /// output that may be shared in issue threads or screen captures.
    settings_filename: String,
}

/// `csq.listkeys.v1` payload (an internal ticket Track B). **R1** — hand-authored,
/// explicit field: `data` carries the pre-existing `Vec<KeyEntry>` rows UNCHANGED
/// (fingerprints stay fingerprints — `security.md` MUST-2 / `tauri-commands.md`
/// MUST-3; no raw key material was ever in `KeyEntry`, and the envelope adds
/// nothing that widens that surface). Migration for an existing consumer is a
/// one-line jq change: `.[0].provider_id` -> `.data[0].provider_id` (workspace
/// `sdk-surface` LAUNCH-LEDGER 2026-08-09-wave3 Track B).
#[derive(Debug, Serialize)]
struct ListkeysPayload {
    data: Vec<KeyEntry>,
}

pub fn handle(base_dir: &Path, json: bool) -> Result<()> {
    let configured = providers::settings::list_configured(base_dir);

    let entries: Vec<KeyEntry> = configured
        .iter()
        .map(|s| {
            let provider = providers::get_provider(&s.provider_id);
            KeyEntry {
                provider_id: s.provider_id.clone(),
                name: provider
                    .map(|p| p.name)
                    .unwrap_or(&s.provider_id)
                    .to_string(),
                fingerprint: s.key_fingerprint(),
                model: s.get_model().unwrap_or("(default)").to_string(),
                settings_filename: provider
                    .map(|p| p.settings_filename.to_string())
                    .unwrap_or_else(|| "(unknown)".into()),
            }
        })
        .collect();

    if json {
        // R3: emit() is the only stdout writer for the enveloped surface.
        sdk::emit(&Envelope::success(
            SCHEMA_LISTKEYS_V1,
            None,
            ListkeysPayload { data: entries },
        ))?;
        return Ok(());
    }

    if entries.is_empty() {
        println!("No provider keys configured.");
        println!();
        println!("Run `csq setkey mm --key <KEY>` to add a MiniMax key, for example.");
        return Ok(());
    }

    println!();
    println!("Configured provider keys:");
    println!();

    for e in &entries {
        println!("  {} ({})", e.name, e.provider_id);
        println!("    Key:      {}", e.fingerprint);
        println!("    Model:    {}", e.model);
        println!("    Settings: {}", e.settings_filename);
        println!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_row() -> KeyEntry {
        KeyEntry {
            provider_id: "deepseek".into(),
            name: "DeepSeek".into(),
            fingerprint: "sk-1db…07bb".into(),
            model: "deepseek-chat".into(),
            settings_filename: "settings-deepseek.json".into(),
        }
    }

    /// Golden fixture (an internal ticket Track B): every pre-existing `KeyEntry` row
    /// field, unchanged, now lives at `data[N].<field>` under the
    /// `csq.listkeys.v1` envelope. A rename or retype of ANY field asserted here
    /// REDS this test — verified by hand: renaming `ListkeysPayload.data` to
    /// `.keys` fails this test at `v["data"][0]` (returns `Value::Null`, so every
    /// subsequent field assertion fails).
    #[test]
    fn listkeys_json_envelope_matches_golden_shape() {
        let payload = ListkeysPayload {
            data: vec![sample_row()],
        };
        let env = Envelope::success(SCHEMA_LISTKEYS_V1, None, payload);
        let line = env.to_line().unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();

        assert_eq!(v["schema"], "csq.listkeys.v1");
        assert_eq!(v["ok"], true);
        assert!(
            v.get("error").is_none(),
            "success envelope carries no error"
        );

        let row = &v["data"][0];
        assert_eq!(row["provider_id"], "deepseek");
        assert_eq!(row["name"], "DeepSeek");
        assert_eq!(row["fingerprint"], "sk-1db…07bb");
        assert_eq!(row["model"], "deepseek-chat");
        assert_eq!(row["settings_filename"], "settings-deepseek.json");
    }

    /// Fingerprints stay fingerprints — no raw key material reaches the
    /// envelope (security.md MUST-2 / tauri-commands.md MUST-3).
    #[test]
    fn listkeys_json_envelope_never_carries_a_raw_key() {
        let payload = ListkeysPayload {
            data: vec![sample_row()],
        };
        let env = Envelope::success(SCHEMA_LISTKEYS_V1, None, payload);
        let line = env.to_line().unwrap();
        assert!(
            !line.contains("sk-1db-REAL-SECRET-VALUE"),
            "fixture sanity: fingerprint format, not a raw key, is asserted above"
        );
        assert!(
            line.contains('…'),
            "fingerprint is truncated with an ellipsis"
        );
    }
}
