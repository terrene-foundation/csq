//! `csq probe` — operator-run live-wire `(provider × auth-mode)`
//! contract verification.
//!
//! Authoritative spec: `specs/11-probe-driven-verification.md`.
//!
//! Probes are operator-only. They MUST NOT run in CI per
//! `.claude/rules/ci-real-oauth-prohibition.md`.

use anyhow::{anyhow, Context, Result};
use csq_core::accounts::discovery;
use csq_core::cli_deps::sanitize::redact_path;
use csq_core::probe::{self, ProbeRecord, ProbeStatus};
use csq_core::types::AccountNum;
use std::path::Path;

/// Run probes. If `slot` is `Some(N)`, probe just that slot. If `None`,
/// `--all` was passed: discover every provisioned slot and probe each.
pub fn handle(base_dir: &Path, slot: Option<u16>, json: bool) -> Result<()> {
    // Round-1 redteam L1-sec: defense-in-depth against accidental CI
    // invocation. The CI prohibition is enforced primarily by the
    // absence of credentials in CI runners, but a Makefile target
    // shared between local + CI could still spawn `csq probe` with
    // an operator's credentials in the runner image. Refuse early.
    if std::env::var_os("CI").is_some() || std::env::var_os("GITHUB_ACTIONS").is_some() {
        return Err(anyhow!(
            "csq probe is operator-only — `.claude/rules/ci-real-oauth-prohibition.md`. \
             Refusing to run with CI=true / GITHUB_ACTIONS=true set."
        ));
    }
    // Round-2 redteam C7 — HOME is required: Cell 09 (Gemini Code Assist
    // OAuth) reads `~/.gemini/oauth_creds.json` (gemini-cli's
    // authoritative per-user state file, which csq does NOT relocate
    // — see an internal journal entry + an internal journal entry FD-1). With `unwrap_or_default()`
    // an unset $HOME silently became `PathBuf::new()`, which then
    // resolves that path CWD-relative — an information-disclosure
    // footgun if the operator runs probe from inside a directory that
    // happens to contain `.gemini/`. Fail loud instead.
    //
    // Post-an internal ticket: Codex no longer requires HOME — the codex probe now
    // reads per-identity creds at `identities/<UUID>/credentials-codex.json`
    // (or legacy `credentials/codex-<N>.json` fallback), via the SAME
    // channel the daemon's production paths use
    // (`account-terminal-separation.md` MUST Rule 4 diagnostic-daemon
    // parity). The probe never reads `~/.codex/auth.json`.
    let home = dirs::home_dir().ok_or_else(|| {
        anyhow!(
            "HOME not set; csq probe needs the home directory to find \
             ~/.gemini/oauth_creds.json (Gemini Code Assist OAuth)"
        )
    })?;
    let records = match slot {
        Some(n) => {
            let account = AccountNum::try_from(n)
                .map_err(|_| anyhow!("slot {n} is out of range (1..=999)"))?;
            vec![probe::probe_slot(base_dir, &home, account)]
        }
        None => probe_all_slots(base_dir, &home)?,
    };

    if json {
        for r in &records {
            println!(
                "{}",
                serde_json::to_string(r).context("serializing probe record")?
            );
        }
    } else {
        for r in &records {
            print_text(r);
        }
    }

    let code = probe::exit_code_for(&records);
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

/// Discover every provisioned slot and return one [`ProbeRecord`] per slot.
///
/// The returned set is the union of three sources (issues an internal ticket, an internal ticket, an internal ticket):
///
/// 1. **`discover_all`** — Anthropic OAuth slots + healthy Codex/Gemini/3P
///    slots whose credential files parse correctly.
/// 2. **`is_gemini_corrupt_bound` scan** (issues an internal ticket) — corrupt Gemini
///    credential files whose parse fails; `discover_gemini` drops them, so
///    this scan is their only channel into `probe --all` output. LOAD-BEARING.
/// 3. **`is_codex_corrupt_bound` scan** (an internal ticket) — corrupt Codex credential
///    files. `discover_codex` emits these via its `Err` branch
///    (`has_credentials=false`), so this scan is idempotent with
///    `discover_all`; it is belt-and-braces.
/// 4. **`is_codex_wrong_variant_bound` scan** (an internal ticket) — Codex credential
///    files that parse successfully but carry the Anthropic variant instead
///    of the Codex variant (operator pasted `claudeAiOauth` payload at a
///    `codex-<N>.json` path). `discover_codex` **`continue`s** wrong-variant
///    slots (`discovery.rs:539`), so this scan is the **ONLY channel** by
///    which wrong-variant slots appear in `probe --all` output. LOAD-BEARING.
///    Removing this scan silently un-fixes an internal ticket; pinned by AC-6.
///
/// The `BTreeSet<u16>` union deduplicates slot ids from all sources, so each
/// slot is probed exactly once regardless of how many scans match it.
fn probe_all_slots(base_dir: &Path, home: &Path) -> Result<Vec<ProbeRecord>> {
    let entries = discovery::discover_all(base_dir);

    // Collect corrupt-Gemini slot ids to merge into the main id set.
    // `discover_gemini` drops corrupt markers (valid-entries-only contract);
    // this scan recovers them so they appear in the probe report (FM-2, an internal ticket).
    // Mutual exclusivity of Ok/Err is proven — a slot is in `discover_all`
    // only if `read_binding == Ok`; in the corrupt scan only if `Err`.
    // The merged `all_ids` BTreeSet dedups any Anthropic-shadows-corrupt-
    // Gemini same-id collision: the id is probed once, and per-slot C2
    // then FAILs it `ambiguous-binding`.
    let corrupt_gemini_slot_ids: std::collections::BTreeSet<u16> = (1
        ..=csq_core::types::MAX_ACCOUNTS)
        .filter_map(|n| AccountNum::try_from(n).ok())
        .filter(|&s| {
            csq_core::providers::gemini::provisioning::is_gemini_corrupt_bound(base_dir, s)
        })
        .map(|s| s.get())
        .collect();

    // an internal ticket: same defensive shape as the Gemini corrupt scan above. Today
    // `discover_codex` already emits corrupt slots with `has_credentials=false`,
    // so this scan is structurally idempotent with discover_all; it is
    // load-bearing only if `discover_codex`'s emission contract ever
    // tightens (e.g., drops `has_credentials=false` rows). AC-6b pin.
    let corrupt_codex_slot_ids: std::collections::BTreeSet<u16> = (1
        ..=csq_core::types::MAX_ACCOUNTS)
        .filter_map(|n| AccountNum::try_from(n).ok())
        .filter(|&s| csq_core::providers::codex::provisioning::is_codex_corrupt_bound(base_dir, s))
        .map(|s| s.get())
        .collect();

    // an internal ticket LOAD-BEARING: `discover_codex` `continue`s wrong-variant slots
    // (`discovery.rs:539`), so this scan is the ONLY channel by which they
    // appear in `probe --all` output. Removing this scan silently un-fixes
    // an internal ticket. Pinned by AC-6 (`probe_all_includes_wrong_variant_codex_slot_via_scan_only`).
    let wrong_variant_codex_slot_ids: std::collections::BTreeSet<u16> = (1
        ..=csq_core::types::MAX_ACCOUNTS)
        .filter_map(|n| AccountNum::try_from(n).ok())
        .filter(|&s| {
            csq_core::providers::codex::provisioning::is_codex_wrong_variant_bound(base_dir, s)
        })
        .map(|s| s.get())
        .collect();

    // Build the merged id set from discover_all entries + corrupt-Gemini ids
    // + corrupt-Codex ids + wrong-variant-Codex ids.
    // Sorted ascending per spec 11 §11.3 default-output ordering.
    let mut all_ids: std::collections::BTreeSet<u16> = entries.iter().map(|e| e.id).collect();
    all_ids.extend(corrupt_gemini_slot_ids);
    all_ids.extend(corrupt_codex_slot_ids); // an internal ticket
    all_ids.extend(wrong_variant_codex_slot_ids); // an internal ticket — load-bearing (only channel)

    if all_ids.is_empty() {
        return Err(anyhow!(
            "no provisioned slots found under {}",
            redact_path(base_dir)
        ));
    }

    let mut out = Vec::new();
    for id in all_ids {
        let Ok(account) = AccountNum::try_from(id) else {
            continue;
        };
        out.push(probe::probe_slot(base_dir, home, account));
    }
    Ok(out)
}

fn print_text(r: &ProbeRecord) {
    let symbol = match r.status {
        ProbeStatus::Ok => "✓",
        ProbeStatus::Fail => "✗",
        ProbeStatus::Skipped => "·",
    };
    let summary = match r.status {
        ProbeStatus::Ok => format!("{}/{} OK", r.assertions_passed, r.assertions_total),
        ProbeStatus::Fail => format!("FAIL {}/{}", r.assertions_passed, r.assertions_total),
        ProbeStatus::Skipped => "SKIPPED".to_string(),
    };
    println!(
        "{symbol} slot {slot:<3} ({cell:<22}) {endpoint:<60} {summary:<12} ({elapsed} ms)",
        slot = r.slot,
        cell = r.cell,
        endpoint = shorten(&r.endpoint),
        elapsed = r.elapsed_ms,
    );
    if let Some(d) = &r.diagnostic {
        println!("    failed: {}", d.failed_assertion);
        println!("    hint:   {}", d.hint);
        println!("    spec:   {}", r.spec_anchor);
        if let Some(excerpt) = &r.redacted_response_excerpt {
            println!("    body:   {}", excerpt);
        }
    }
}

fn shorten(url: &str) -> String {
    if url.len() <= 60 {
        url.to_string()
    } else {
        format!("…{}", &url[url.len() - 59..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use csq_core::probe::ProbeStatus;

    /// Seed profiles.json::by_slot[slot_n] = UUID and write Anthropic OAuth
    /// credentials at the UUID-keyed identity path.
    fn stage_valid_anthropic_identity(base: &std::path::Path, slot_n: u16) {
        let uuid = csq_core::testing::identity_fixtures::fixture_uuid_for_slot(slot_n);
        let profiles_path = csq_core::accounts::profiles::profiles_path(base);
        let mut profiles = csq_core::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert(slot_n.to_string(), uuid);
        csq_core::accounts::profiles::save(&profiles_path, &profiles).unwrap();
        let cred_path = csq_core::accounts::identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
        std::fs::write(
            &cred_path,
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-VALID-TOKEN","refreshToken":"rt","expiresAt":99999999999999,"scopes":["user:inference"]}}"#,
        )
        .unwrap();
    }

    /// AC-6: `probe_all_slots` includes corrupt Gemini slots in --all output.
    ///
    /// A base dir with 1 healthy Anthropic slot plus 1 corrupt Gemini marker
    /// must produce a record set where the corrupt slot appears exactly once
    /// classified as `gemini-corrupt-binding` (no double-listing).
    #[test]
    fn probe_all_includes_corrupt_gemini_slot() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();

        // Healthy Anthropic slot 1.
        stage_valid_anthropic_identity(base.path(), 1);

        // Corrupt Gemini marker slot 2 (present but unparseable JSON).
        let creds = base.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("gemini-2.json"), b"{ not valid json").unwrap();

        let records = probe_all_slots(base.path(), home.path()).unwrap();

        // The corrupt Gemini slot must appear in the result.
        let corrupt_records: Vec<_> = records
            .iter()
            .filter(|r| r.slot == 2 && r.cell == "gemini-corrupt-binding")
            .collect();
        assert_eq!(
            corrupt_records.len(),
            1,
            "corrupt Gemini slot must appear exactly once in --all output, got: {:?}",
            records.iter().map(|r| (r.slot, r.cell)).collect::<Vec<_>>()
        );

        // Must be Skipped with exit 64.
        let r = corrupt_records[0];
        assert_eq!(r.status, ProbeStatus::Skipped);
        assert_eq!(csq_core::probe::exit_code_for(std::slice::from_ref(r)), 64);

        // Slot 1 (Anthropic) must also appear.
        assert!(
            records.iter().any(|r| r.slot == 1),
            "Anthropic slot 1 must also appear in --all output"
        );

        // Slot 2 must appear exactly once (no double-listing).
        let slot2_count = records.iter().filter(|r| r.slot == 2).count();
        assert_eq!(
            slot2_count, 1,
            "slot 2 must appear exactly once (no double-listing); got {}",
            slot2_count
        );
    }

    /// AC-6a/6b: `probe_all_slots` includes corrupt Codex slots in --all output.
    ///
    /// A base dir with 1 healthy Anthropic slot plus 1 corrupt Codex marker
    /// must produce a record set where the corrupt slot appears exactly once
    /// classified as `codex-corrupt-binding` (no double-listing). (an internal ticket M4)
    #[test]
    fn probe_all_includes_corrupt_codex_slot() {
        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();

        // Healthy Anthropic slot 1.
        stage_valid_anthropic_identity(base.path(), 1);

        // Corrupt Codex marker slot 2 (present but unparseable JSON).
        let creds = base.path().join("credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("codex-2.json"), b"{ not valid json").unwrap();

        let records = probe_all_slots(base.path(), home.path()).unwrap();

        // The corrupt Codex slot must appear in the result.
        let corrupt_records: Vec<_> = records
            .iter()
            .filter(|r| r.slot == 2 && r.cell == "codex-corrupt-binding")
            .collect();
        assert_eq!(
            corrupt_records.len(),
            1,
            "corrupt Codex slot must appear exactly once in --all output, got: {:?}",
            records.iter().map(|r| (r.slot, r.cell)).collect::<Vec<_>>()
        );

        // Must be Skipped with exit 64.
        let r = corrupt_records[0];
        assert_eq!(r.status, ProbeStatus::Skipped);
        assert_eq!(csq_core::probe::exit_code_for(std::slice::from_ref(r)), 64);

        // Slot 1 (Anthropic) must also appear.
        assert!(
            records.iter().any(|r| r.slot == 1),
            "Anthropic slot 1 must also appear in --all output"
        );

        // Slot 2 must appear exactly once (AC-6b: BTreeSet union dedup).
        let slot2_count = records.iter().filter(|r| r.slot == 2).count();
        assert_eq!(
            slot2_count, 1,
            "slot 2 must appear exactly once (no double-listing); got {}",
            slot2_count
        );
    }

    /// AC-6 (an internal ticket): `probe_all_slots` includes wrong-variant Codex slots via
    /// the load-bearing `is_codex_wrong_variant_bound` scan.
    ///
    /// **Why this test is the structural regression pin:**
    /// `discover_codex` `continue`s wrong-variant slots (`discovery.rs:539`),
    /// so the `is_codex_wrong_variant_bound` scan added to `probe_all_slots`
    /// in M4 is the **ONLY channel** by which these slots appear in
    /// `probe --all` output. Unlike an internal ticket's `is_codex_corrupt_bound` scan
    /// (idempotent with `discover_all`, which already emits corrupt slots via
    /// its `Err` branch), this scan is truly load-bearing: remove it and
    /// wrong-variant slots silently disappear from probe output, un-fixing
    /// an internal ticket. This test pins that claim by asserting BOTH:
    ///   1. `discover_all` does NOT contain slot 7 (the wrong-variant slot),
    ///   2. `probe_all_slots` DOES contain exactly one record for slot 7
    ///      classified as `codex-wrong-variant-binding`.
    ///      A future PR that removes `is_codex_wrong_variant_bound` from the union
    ///      loop trips assertion (2), making the regression immediately visible.
    #[test]
    fn probe_all_includes_wrong_variant_codex_slot_via_scan_only() {
        // Per AC-6 (post-R1-deep-3): pins that the
        // is_codex_wrong_variant_bound scan is the LOAD-BEARING channel
        // (unlike an internal ticket where the scan was idempotent). A base-dir
        // containing ONLY a wrong-variant codex-7.json — no profiles.json
        // entry, no Gemini binding, no 3P settings — produces:
        //   - discover_all(): does NOT contain slot 7 (continue at
        //     discovery.rs:539)
        //   - probe_all_slots(): DOES contain exactly ONE record for slot 7
        //     with cell="codex-wrong-variant-binding"
        // A future PR that removes is_codex_wrong_variant_bound from the
        // union loop fails assertion (2).

        let base = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();

        // Write a wrong-variant codex-7.json: valid JSON, Anthropic shape
        // (claudeAiOauth key), but at a Codex-prefixed path. Synthetic-token
        // discipline per security.md §2.
        let creds_dir = base.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(
            creds_dir.join("codex-7.json"),
            br#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","refreshToken":"rt","expiresAt":4102444800000,"scopes":[]}}"#,
        )
        .unwrap();

        // ── Assertion 1: discover_all OMITS the wrong-variant slot ──────────
        // This is the silent-omission failure mode that an internal ticket closes. The slot
        // is absent from discover_all because discover_codex `continue`s it.
        let discovered = csq_core::accounts::discovery::discover_all(base.path());
        let slot_7_discovered: Vec<_> = discovered.iter().filter(|a| a.id == 7).collect();
        assert!(
            slot_7_discovered.is_empty(),
            "discover_all should omit wrong-variant slot per ADR-1 (no widening); \
             got {slot_7_discovered:?}"
        );

        // ── Assertion 2: probe_all_slots INCLUDES the slot via the scan ─────
        // probe_all_slots returns Err only when no slots are found. The wrong-
        // variant slot IS found via the scan, so unwrap is correct.
        let records = probe_all_slots(base.path(), home.path()).unwrap();
        let slot_7: Vec<_> = records.iter().filter(|r| r.slot == 7).collect();

        // BTreeSet dedup: exactly ONE record for slot 7 even though both
        // discover_all (absent) and the scan (present) are unioned.
        assert_eq!(
            slot_7.len(),
            1,
            "expected exactly one record for slot 7 (BTreeSet dedup); got {slot_7:?}"
        );

        assert_eq!(
            slot_7[0].cell, "codex-wrong-variant-binding",
            "wrong-variant slot must be classified as codex-wrong-variant-binding"
        );
        assert_eq!(
            slot_7[0].status,
            ProbeStatus::Skipped,
            "wrong-variant slot must have Skipped status (exit 64)"
        );
        assert_eq!(
            csq_core::probe::exit_code_for(std::slice::from_ref(slot_7[0])),
            64,
            "wrong-variant classification must produce exit code 64"
        );
    }
}
