//! `csq inspect coc` — read-only debug surface for `.coc/` content.
//!
//! Walks from CWD looking for `.coc/`, falls through to legacy chain per
//! spec 09 §9.3, and prints the resolved `CocSet`. Used by developers and
//! CI to verify what csq sees for a given working tree. Never writes
//! under `.coc/` per FR-FMT-06.
//!
//! Per `internal-design-docs` the first-pull trust gate
//! and per-artifact signing apparatus were retracted as wrong-layer;
//! `.coc/` is files in the user's repo (read like `.claude/`). No prompts.

use std::path::PathBuf;

use anyhow::{Context, Result};
use csq_core::coc::{load, types::CocSource};

#[derive(Default)]
pub struct InspectOptions {
    /// `--json` — emit a single JSON object instead of human-readable text.
    pub json: bool,
    /// `--show-unknowns` — include the per-artifact `unknowns` bucket
    /// (forward-compat fields csq does not yet understand).
    pub show_unknowns: bool,
    /// `--debug` — implies `--show-unknowns`; also surfaces full body.
    pub debug: bool,
    /// `--start <path>` — start the discovery walk from `<path>` instead
    /// of CWD. For tests + CI fixtures.
    pub start: Option<PathBuf>,
}

pub fn handle(base_dir: &std::path::Path, opts: InspectOptions) -> Result<()> {
    let start = opts
        .start
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .context("could not resolve starting directory for `csq inspect coc`")?;

    let outcome = match load(&start, base_dir) {
        Ok(o) => o,
        Err(e) => {
            if opts.json {
                let payload = serde_json::json!({
                    "ok": false,
                    "error": e.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&payload)?);
                return Ok(());
            }
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };

    if opts.json {
        let payload = serde_json::json!({
            "ok": true,
            "project_root": outcome.project_root,
            "set": outcome.set,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    let set = &outcome.set;
    println!("source: {}", set.source.as_log_value());
    if let CocSource::Coc { lock_sha256 } = &set.source {
        println!("  lock_sha256: {}", hex_short(lock_sha256));
    }
    println!(
        "version: {}.{}.{}",
        set.version.major, set.version.minor, set.version.patch
    );
    println!(
        "rules: {}  agents: {}  skills: {}  commands: {}",
        set.rules.len(),
        set.agents.len(),
        set.skills.len(),
        set.commands.len(),
    );

    let show_unknowns = opts.show_unknowns || opts.debug;
    if !set.rules.is_empty() {
        println!();
        println!("# rules");
        for rule in set.rules.values() {
            println!(
                "- {}  precedence={}  applies_to=[{}]",
                rule.id.as_str(),
                rule.precedence,
                rule.applies_to
                    .iter()
                    .map(|s| s.as_str().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            if show_unknowns && !rule.unknowns.is_empty() {
                for (k, v) in &rule.unknowns {
                    println!("    unknown:{k} = {v}");
                }
            }
        }
    }

    if !set.agents.is_empty() {
        println!();
        println!("# agents");
        for agent in set.agents.values() {
            println!("- {}  precedence={}", agent.id.as_str(), agent.precedence);
            if show_unknowns && !agent.unknowns.is_empty() {
                for (k, v) in &agent.unknowns {
                    println!("    unknown:{k} = {v}");
                }
            }
        }
    }

    Ok(())
}

fn hex_short(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in &bytes[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    s.push('…');
    s
}

#[derive(Default)]
pub struct TranslateOptions {
    /// Target Surface — accepts "cc" (alias of "claude-code"),
    /// "claude-code", "codex", or "gemini".
    pub surface: String,
    /// `--json` — emit the full SpawnPayload as JSON. Otherwise prints
    /// a human-readable summary.
    pub json: bool,
    pub start: Option<PathBuf>,
}

/// Translate the loaded `.coc/` set into a `SpawnPayload` for the target
/// Surface and print it (`--json` → full JSON, else a human summary). Backs
/// both `csq inspect translate` and the top-level `csq translate` (CU1a,
/// an internal ticket). Pure read: loads `.coc/` via `coc::load` and writes nothing
/// under the `.coc/` tree.
///
/// **`HostContext` is deliberately `None` here (CU1a / an internal ticket).** This is a
/// read-only conversion surface whose `--json` output is the contract the
/// neutral `coc-run` launcher and CU5's byte-parity golden consume, so it must
/// be stable and environment-independent.
///
/// CU1b resolved the live-vs-translate reconciliation (G1=UNIFY): the live
/// capability-layer scaffold stage renders through the shared
/// `coc::translate::flatten` module (single flatten — `flatten_artifacts` +
/// `render_sections`, NOT the `translate::translate` dispatch), and it too
/// uses `HostContext::None` because the DELIVERED TEXT is
/// host-context-independent on all three Surfaces — the flattener builds text
/// from `coc_set` + `surface` only. `HostContext`
/// affects solely Gemini's `host_isolation_warning` payload bit, which the
/// live spawn emits SEPARATELY (`run.rs::emit_host_isolation_warning_if_needed`
/// via its own `detect_host_context()`), not through the delivered text. So
/// the live-spawn text and this surface's text are byte-identical; the
/// `host_isolation_warning` field stays intentionally host-neutral here (CU1b
/// AC1 option b — spec 10 §10.4.6.2).
pub fn handle_translate(base_dir: &std::path::Path, opts: TranslateOptions) -> Result<()> {
    use csq_core::coc::translate;
    use csq_core::providers::catalog::Surface;

    let surface = match opts.surface.as_str() {
        "cc" | "claude-code" => Surface::ClaudeCode,
        "codex" => Surface::Codex,
        "gemini" => Surface::Gemini,
        other => anyhow::bail!("unknown surface `{other}`"),
    };

    let start = opts
        .start
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .context("could not resolve starting directory for `csq translate`")?;

    let outcome = csq_core::coc::load(&start, base_dir)?;
    let payload = translate::translate(&outcome.set, surface, &translate::HostContext::None);

    if opts.json {
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    print_payload_summary(&payload);
    Ok(())
}

fn print_payload_summary(payload: &csq_core::coc::translate::SpawnPayload) {
    use csq_core::coc::translate::SpawnPayload;
    match payload {
        SpawnPayload::ClaudeCode(p) => {
            println!("surface: claude-code");
            println!("contributing_ids: {}", p.contributing_ids.len());
            println!("permissions_allow: {}", p.permissions_allow.len());
            println!("settings_overlay keys: {}", p.settings_overlay.len());
            println!(
                "system_prompt_append ({} bytes):",
                p.system_prompt_append.len()
            );
            println!("---");
            println!("{}", p.system_prompt_append);
        }
        SpawnPayload::Codex(p) => {
            println!("surface: codex");
            println!("contributing_ids: {}", p.contributing_ids.len());
            println!("sandbox_mode: {}", p.sandbox_mode.as_str());
            println!("config_toml_overlay keys: {}", p.config_toml_overlay.len());
            println!("instructions ({} bytes):", p.instructions.len());
            println!("---");
            println!("{}", p.instructions);
        }
        SpawnPayload::Gemini(p) => {
            println!("surface: gemini");
            println!("contributing_ids: {}", p.contributing_ids.len());
            println!("approval_mode: {}", p.approval_mode.as_str());
            println!(
                "settings_json_overlay keys: {}",
                p.settings_json_overlay.len()
            );
            println!("host_isolation_warning: {}", p.host_isolation_warning);
            println!("system_instruction ({} bytes):", p.system_instruction.len());
            println!("---");
            println!("{}", p.system_instruction);
        }
    }
}
