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
    /// "claude-code", "codex", "gemini", "kimi", or "grok". Every Surface
    /// has its own translator (workspace hermes-parity an internal journal entry
    /// supersedes an internal journal entry's Codex-aliasing for kimi/grok).
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
        // Kimi/Grok each have their own translator (workspace hermes-parity
        // an internal journal entry supersedes an internal journal entry's Codex-aliasing).
        "kimi" => Surface::Kimi,
        "grok" => Surface::Grok,
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
        println!("{}", render_translate_json(surface, &payload)?);
        return Ok(());
    }

    print_payload_summary(surface, &payload);
    Ok(())
}

/// Serializes a `SpawnPayload` to the pretty-printed JSON `csq
/// translate --json` / `csq inspect translate --json` emits, injecting the
/// HIGH-D `"delivered": false` marker for Kimi/Grok. Extracted as a pure
/// function (no I/O) so the marker is unit-testable without capturing
/// stdout.
///
/// **Why the marker exists:** `launch_native`
/// (csq/src/cli/commands/run.rs) never calls `emit_kimi_native`/
/// `emit_grok_native` today — this payload is a pure library-computed
/// PREVIEW of what WOULD be written once the wiring shard lands, not a
/// claim about the currently-running slot's governance posture. Without
/// this flag, `sandbox_profile`, `permission_mode`, `hooks`,
/// `permission_rules` etc. read as delivered enforcement when none of it
/// reaches a live spawn yet — the worst possible misreading for a
/// governance product. Remove this block (or flip to `true`) the moment
/// `launch_native` actually materializes into the vendor home for these
/// surfaces.
/// # Why the `to_value` round-trip is Kimi/Grok-only (R2 live-path lens)
///
/// Serializing the payload DIRECTLY preserves struct field declaration
/// order; round-tripping through [`serde_json::Value`] does not. This
/// workspace does not enable serde_json's `preserve_order` feature
/// (`csq/Cargo.toml` requests only `raw_value`, and no `indexmap` appears
/// in the dependency graph), so `serde_json::Map` is a `BTreeMap` and a
/// round-trip **alphabetizes every key**.
///
/// Round-tripping unconditionally therefore silently reordered the
/// `--json` output of `cc`, `codex` and `gemini` — three surfaces this PR
/// has no business changing. For `CodexSpawnPayload` that is a real
/// reorder, not a cosmetic one: declaration order is
/// `config_toml_overlay, instructions, sandbox_mode, mcp_filter,
/// contributing_ids, output_schema_directive`.
///
/// No known consumer breaks (`coc-eval/lib/delivery.py::run_csq_translate`
/// parses with `json.loads()` into an order-independent dict), but an
/// operator-facing format is a contract, and gratuitously changing it for
/// surfaces outside this PR's scope is a regression regardless of whether
/// a consumer happens to survive it. The three wired surfaces keep their
/// byte-for-byte prior output; only Kimi/Grok — which had no prior output,
/// having never been their own `SpawnPayload` variant before this PR — pay
/// the reordering cost, and they pay it because the `delivered` marker
/// requires mutating the object.
fn render_translate_json(
    surface: csq_core::providers::catalog::Surface,
    payload: &csq_core::coc::translate::SpawnPayload,
) -> Result<String> {
    use csq_core::providers::catalog::Surface;

    if !matches!(surface, Surface::Kimi | Surface::Grok) {
        // Direct serialization — preserves declaration order.
        return Ok(serde_json::to_string_pretty(payload)?);
    }
    let mut value = serde_json::to_value(payload)?;
    match &mut value {
        serde_json::Value::Object(map) => {
            map.insert("delivered".to_string(), serde_json::Value::Bool(false));
        }
        // Fail LOUD, never silently. Dropping the marker leaves the preview
        // reading as delivered governance — precisely the misreading this
        // marker exists to block, and the failure would be invisible because
        // the command would still exit 0 with well-formed JSON.
        //
        // Unreachable today: `SpawnPayload` is
        // `#[serde(tag = "surface", rename_all = "kebab-case")]`, and an
        // internally-tagged enum over struct variants always serializes to an
        // Object. Dropping the enum's tag attribute, or admitting a newtype or
        // unit variant, would change that — so the arm guards a real future
        // edit rather than a hypothetical one, and it must not fail open.
        other => {
            anyhow::bail!(
                "internal: SpawnPayload for {surface} serialized to a JSON \
                 {kind}, not an object, so the not-delivered marker could not \
                 be attached. Refusing to emit a payload that would read as \
                 delivered governance.",
                kind = match other {
                    serde_json::Value::Null => "null",
                    serde_json::Value::Bool(_) => "bool",
                    serde_json::Value::Number(_) => "number",
                    serde_json::Value::String(_) => "string",
                    serde_json::Value::Array(_) => "array",
                    serde_json::Value::Object(_) => unreachable!("matched above"),
                }
            );
        }
    }
    Ok(serde_json::to_string_pretty(&value)?)
}

/// The HIGH-D not-yet-delivered banner printed for Kimi/Grok in the
/// human-readable summary.
///
/// Kept as a named constant for the same reason `render_translate_json`'s
/// `"delivered": false` key is test-pinned: dropping it is the worst possible
/// misreading for a governance product — the operator would read a PREVIEW of
/// an unenforced posture as a description of a live one. Tests assert against
/// this constant so a silent edit cannot pass.
pub(crate) const NOT_DELIVERED_BANNER: &str =
    "delivered: false (native materialization isn't wired into `csq run` \
     yet — this is a PREVIEW of what would be written; sandbox_profile / \
     permission_mode / hooks / permission_rules below do NOT reflect a \
     currently-enforced posture)";

/// Formats an `unscoped_path_rules` set for the human-readable summary —
/// LOW-1 (round-13 review): a bare count leaves the operator unable to tell
/// WHICH rules lost path scoping without re-running with `--json`. Rule ids
/// are bounded (`^[A-Z][A-Z0-9-]{1,32}$`, spec 09 §9.2.2) and the `BTreeSet`
/// is already sorted, so a comma-joined list is a safe, deterministic
/// one-liner.
///
/// The id CHARSET is bounded but the id COUNT is not, so the list is capped:
/// a `.coc/` with 500 path-scoped rules would otherwise emit a ~17 KB single
/// line into operator output. The count prefix always states the true total,
/// so the cap loses nothing an operator needs — matching every sibling
/// one-line emitter in this repo (round-4 redteam NIT).
fn format_unscoped_path_rules(ids: &std::collections::BTreeSet<String>) -> String {
    /// Ids shown inline before the list is elided. The full set is always
    /// available via `--json`.
    const MAX_SHOWN: usize = 20;

    if ids.is_empty() {
        return "0".to_string();
    }
    let total = ids.len();
    let shown: Vec<&str> = ids.iter().take(MAX_SHOWN).map(String::as_str).collect();
    if total > MAX_SHOWN {
        format!(
            "{total} [{}, … +{} more]",
            shown.join(", "),
            total - MAX_SHOWN
        )
    } else {
        format!("{total} [{}]", shown.join(", "))
    }
}

/// Renders the human-readable `csq translate` summary as a string.
///
/// Split out of the former `print_payload_summary` so the DEFAULT (non-`--json`)
/// operator output is assertable, exactly as `render_translate_json` makes the
/// `--json` output assertable. Before the split, the only test covering this
/// path asserted "does not error" and captured no stdout, so the governance
/// banner, the surface label, and the field ordering were all unpinned.
///
/// Each `SpawnPayload` variant is the Surface the caller actually requested —
/// Kimi/Grok no longer alias `SpawnPayload::Codex` (workspace hermes-parity
/// an internal journal entry), so there is no requested-vs-native Surface split to
/// reconcile here.
///
/// `surface` is used ONLY to decide whether to emit the HIGH-D
/// not-yet-delivered banner (Kimi/Grok) — see the `--json` branch's
/// `"delivered": false` key in [`render_translate_json`] for the JSON-mode
/// equivalent and the rationale.
fn render_payload_summary(
    surface: csq_core::providers::catalog::Surface,
    payload: &csq_core::coc::translate::SpawnPayload,
) -> String {
    use csq_core::coc::translate::SpawnPayload;
    use csq_core::providers::catalog::Surface;
    use std::fmt::Write as _;

    let mut out = String::new();

    if matches!(surface, Surface::Kimi | Surface::Grok) {
        let _ = writeln!(out, "{NOT_DELIVERED_BANNER}");
    }

    match payload {
        SpawnPayload::ClaudeCode(p) => {
            let _ = writeln!(out, "surface: claude-code");
            let _ = writeln!(out, "contributing_ids: {}", p.contributing_ids.len());
            let _ = writeln!(out, "permissions_allow: {}", p.permissions_allow.len());
            let _ = writeln!(out, "settings_overlay keys: {}", p.settings_overlay.len());
            let _ = writeln!(
                out,
                "system_prompt_append ({} bytes):",
                p.system_prompt_append.len()
            );
            let _ = writeln!(out, "---");
            let _ = writeln!(out, "{}", p.system_prompt_append);
        }
        SpawnPayload::Codex(p) => {
            let _ = writeln!(out, "surface: codex");
            let _ = writeln!(out, "contributing_ids: {}", p.contributing_ids.len());
            let _ = writeln!(out, "sandbox_mode: {}", p.sandbox_mode.as_str());
            let _ = writeln!(
                out,
                "config_toml_overlay keys: {}",
                p.config_toml_overlay.len()
            );
            // MED-2 (round-13 review): Codex flattens every in-scope rule
            // into ONE flat `instructions` block regardless of `paths` —
            // the same disclosure Grok already made, ported here so a
            // path-scoped rule's broadening is visible, not silent.
            let _ = writeln!(
                out,
                "unscoped_path_rules: {}",
                format_unscoped_path_rules(&p.unscoped_path_rules)
            );
            let _ = writeln!(out, "instructions ({} bytes):", p.instructions.len());
            let _ = writeln!(out, "---");
            let _ = writeln!(out, "{}", p.instructions);
        }
        SpawnPayload::Gemini(p) => {
            let _ = writeln!(out, "surface: gemini");
            let _ = writeln!(out, "contributing_ids: {}", p.contributing_ids.len());
            let _ = writeln!(out, "approval_mode: {}", p.approval_mode.as_str());
            let _ = writeln!(
                out,
                "settings_json_overlay keys: {}",
                p.settings_json_overlay.len()
            );
            let _ = writeln!(out, "host_isolation_warning: {}", p.host_isolation_warning);
            // MED-2 (round-13 review): same disclosure as Codex above —
            // Gemini also flattens every in-scope rule into one flat
            // `system_instruction` block regardless of `paths`.
            let _ = writeln!(
                out,
                "unscoped_path_rules: {}",
                format_unscoped_path_rules(&p.unscoped_path_rules)
            );
            let _ = writeln!(
                out,
                "system_instruction ({} bytes):",
                p.system_instruction.len()
            );
            let _ = writeln!(out, "---");
            let _ = writeln!(out, "{}", p.system_instruction);
        }
        SpawnPayload::Kimi(p) => {
            let _ = writeln!(out, "surface: kimi");
            let _ = writeln!(out, "contributing_ids: {}", p.contributing_ids.len());
            let _ = writeln!(out, "permission_rules: {}", p.permission_rules.len());
            let _ = writeln!(out, "hooks: {}", p.hooks.len());
            let _ = writeln!(
                out,
                "config_toml_overlay keys: {}",
                p.config_toml_overlay.len()
            );
            // MED-2 (round-13 review): Kimi's `AGENTS.md` channel silently
            // dropped this disclosure while Grok already made it for the
            // identical construct — see `KimiSpawnPayload::
            // unscoped_path_rules`'s doc comment.
            let _ = writeln!(
                out,
                "unscoped_path_rules: {}",
                format_unscoped_path_rules(&p.unscoped_path_rules)
            );
            let _ = writeln!(
                out,
                "agents_md ({} bytes, ADVISORY — see KimiSpawnPayload doc):",
                p.agents_md.len()
            );
            let _ = writeln!(out, "---");
            let _ = writeln!(out, "{}", p.agents_md);
        }
        SpawnPayload::Grok(p) => {
            let _ = writeln!(out, "surface: grok");
            let _ = writeln!(out, "contributing_ids: {}", p.contributing_ids.len());
            let _ = writeln!(out, "sandbox_profile: {}", p.sandbox_profile.as_str());
            let _ = writeln!(out, "permission_mode: {}", p.permission_mode.as_str());
            // MED-4 (round-13 review): hooks is a newly-reserved field
            // (report 14's own payload sketch had it; mirrors Kimi's
            // `hooks:` line above).
            let _ = writeln!(out, "hooks: {}", p.hooks.len());
            let _ = writeln!(
                out,
                "unscoped_path_rules: {}",
                format_unscoped_path_rules(&p.unscoped_path_rules)
            );
            let _ = writeln!(out, "agents_md ({} bytes):", p.agents_md.len());
            let _ = writeln!(out, "---");
            let _ = writeln!(out, "{}", p.agents_md);
        }
    }

    out
}

/// Prints the human-readable `csq translate` summary.
///
/// Thin wrapper over [`render_payload_summary`] — all content decisions live
/// there so they are unit-assertable.
fn print_payload_summary(
    surface: csq_core::providers::catalog::Surface,
    payload: &csq_core::coc::translate::SpawnPayload,
) {
    print!("{}", render_payload_summary(surface, payload));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// `csq translate --surface kimi` / `--surface grok` MUST be accepted,
    /// and each MUST produce its own `SpawnPayload` variant (not a
    /// `SpawnPayload::Codex` alias — an internal journal entry's aliasing is retired).
    #[test]
    fn handle_translate_accepts_kimi_and_grok_surface_strings() {
        for surface in ["kimi", "grok"] {
            let dir = TempDir::new().unwrap();
            let opts = TranslateOptions {
                surface: surface.to_string(),
                json: true,
                start: Some(dir.path().to_path_buf()),
            };
            handle_translate(dir.path(), opts)
                .unwrap_or_else(|e| panic!("--surface {surface} must be accepted, got: {e}"));
        }
    }

    /// Every OTHER unrecognized surface string must still be rejected — the
    /// allowlist covers exactly five surfaces, not "anything".
    #[test]
    fn handle_translate_rejects_unknown_surface_strings() {
        let dir = TempDir::new().unwrap();
        let opts = TranslateOptions {
            surface: "bogus".to_string(),
            json: true,
            start: Some(dir.path().to_path_buf()),
        };
        let err = handle_translate(dir.path(), opts).unwrap_err();
        assert!(err.to_string().contains("unknown surface"), "got: {err}");
    }

    /// Non-JSON `csq translate --surface kimi`/`grok` MUST reach
    /// `print_payload_summary`'s Kimi/Grok match arms without panicking —
    /// the ONLY way this compiles is if `SpawnPayload`'s match in
    /// `render_payload_summary` is exhaustive over all five variants.
    ///
    /// This asserts reachability ONLY. Content is pinned by the
    /// `non_json_summary_*` tests below, which assert against
    /// `render_payload_summary`'s returned string.
    #[test]
    fn handle_translate_non_json_summary_covers_kimi_and_grok() {
        for surface in ["kimi", "grok"] {
            let dir = TempDir::new().unwrap();
            let opts = TranslateOptions {
                surface: surface.to_string(),
                json: false,
                start: Some(dir.path().to_path_buf()),
            };
            handle_translate(dir.path(), opts)
                .unwrap_or_else(|e| panic!("--surface {surface} summary must succeed, got: {e}"));
        }
    }

    /// Builds the summary string the DEFAULT (non-`--json`) invocation prints.
    fn summary_for(surface: csq_core::providers::catalog::Surface) -> String {
        use csq_core::coc::translate;
        use csq_core::coc::types::CocSet;
        let empty = CocSet::empty();
        let payload = translate::translate(&empty, surface, &translate::HostContext::None);
        render_payload_summary(surface, &payload)
    }

    /// HIGH-D non-vacuity, accept boundary — the DEFAULT operator surface.
    ///
    /// `--json` has three tests pinning `"delivered": false`; the
    /// human-readable path is what an operator actually sees when they run
    /// `csq translate --surface kimi` with no flags, and it carries the
    /// identically-critical banner. Before this test it had zero content
    /// assertions: the only coverage asserted "does not error".
    #[test]
    fn non_json_summary_marks_kimi_and_grok_as_not_delivered() {
        use csq_core::providers::catalog::Surface;
        for surface in [Surface::Kimi, Surface::Grok] {
            let out = summary_for(surface);
            assert!(
                out.contains(NOT_DELIVERED_BANNER),
                "{surface:?} summary MUST carry the not-delivered banner; got:\n{out}"
            );
            // The banner is worthless if it does not lead — an operator who
            // reads the first line must see it before any posture field.
            assert!(
                out.starts_with(NOT_DELIVERED_BANNER),
                "{surface:?} banner MUST be the FIRST line, before any posture \
                 field; got:\n{out}"
            );
        }
    }

    /// HIGH-D non-vacuity, reject boundary: the three already-wired surfaces
    /// MUST NOT carry the banner. Without this, a mutation that emits the
    /// banner unconditionally would pass the accept-boundary test above.
    #[test]
    fn non_json_summary_does_not_mark_wired_surfaces_as_not_delivered() {
        use csq_core::providers::catalog::Surface;
        for surface in [Surface::ClaudeCode, Surface::Codex, Surface::Gemini] {
            let out = summary_for(surface);
            assert!(
                !out.contains("delivered: false"),
                "{surface:?} is wired and MUST NOT claim not-delivered; got:\n{out}"
            );
        }
    }

    /// Each surface labels itself correctly. Guards the mis-label failure
    /// mode: a copy-paste edit in one match arm that prints a sibling's
    /// surface name would otherwise be invisible — the operator would read a
    /// Grok posture as a Kimi one.
    #[test]
    fn non_json_summary_labels_every_surface_with_its_own_name() {
        use csq_core::providers::catalog::Surface;
        for (surface, label) in [
            (Surface::ClaudeCode, "claude-code"),
            (Surface::Codex, "codex"),
            (Surface::Gemini, "gemini"),
            (Surface::Kimi, "kimi"),
            (Surface::Grok, "grok"),
        ] {
            let out = summary_for(surface);
            assert!(
                out.contains(&format!("surface: {label}\n")),
                "{surface:?} MUST print `surface: {label}`; got:\n{out}"
            );
        }
    }

    /// The Kimi/Grok posture fields an operator reads off the preview MUST be
    /// present. These are exactly the fields the banner disclaims, so a
    /// silently-dropped field would leave the banner disclaiming nothing.
    #[test]
    fn non_json_summary_carries_the_posture_fields_the_banner_disclaims() {
        use csq_core::providers::catalog::Surface;
        for (surface, fields) in [
            (
                Surface::Kimi,
                vec!["contributing_ids:", "permission_rules:", "hooks:"],
            ),
            (
                Surface::Grok,
                vec![
                    "contributing_ids:",
                    "sandbox_profile:",
                    "permission_mode:",
                    "hooks:",
                    "unscoped_path_rules:",
                ],
            ),
        ] {
            let out = summary_for(surface);
            for field in fields {
                assert!(
                    out.contains(field),
                    "{surface:?} summary MUST carry `{field}` (the banner \
                     disclaims it by name); got:\n{out}"
                );
            }
        }
    }

    /// MED-2 (round-13 review) non-vacuity: every prose-flattening surface
    /// (codex/gemini/kimi/grok — cc is exempt, it materializes `paths`
    /// natively) MUST print `unscoped_path_rules:` in its summary. Before
    /// this fix, Kimi silently dropped the disclosure Grok already made for
    /// the identical construct — this pins that all four now share it via
    /// `flatten::is_real_path_restriction`.
    #[test]
    fn non_json_summary_carries_unscoped_path_rules_for_every_prose_flattening_surface() {
        use csq_core::providers::catalog::Surface;
        for surface in [
            Surface::Codex,
            Surface::Gemini,
            Surface::Kimi,
            Surface::Grok,
        ] {
            let out = summary_for(surface);
            assert!(
                out.contains("unscoped_path_rules:"),
                "{surface:?} summary MUST carry `unscoped_path_rules:`; got:\n{out}"
            );
        }
    }

    /// LOW-1 (round-13 review) non-vacuity: the summary MUST print the
    /// ACTUAL rule ids that lost path scoping, not just a bare count — an
    /// operator reading `unscoped_path_rules: 1` has no way to act on it
    /// without re-running with `--json`.
    #[test]
    fn format_unscoped_path_rules_lists_ids_not_just_count() {
        use std::collections::BTreeSet;
        assert_eq!(format_unscoped_path_rules(&BTreeSet::new()), "0");
        let mut ids = BTreeSet::new();
        ids.insert("RULE-SCOPED".to_string());
        assert_eq!(format_unscoped_path_rules(&ids), "1 [RULE-SCOPED]");
        ids.insert("RULE-OTHER".to_string());
        assert_eq!(
            format_unscoped_path_rules(&ids),
            "2 [RULE-OTHER, RULE-SCOPED]"
        );
    }

    /// End-to-end: a payload carrying a non-empty `unscoped_path_rules` set
    /// MUST surface the literal rule id in the rendered summary text.
    #[test]
    fn render_payload_summary_prints_unscoped_rule_ids_for_grok() {
        use csq_core::coc::translate::{GrokSpawnPayload, SpawnPayload};
        use csq_core::providers::catalog::Surface;
        let mut payload = GrokSpawnPayload::default();
        payload
            .unscoped_path_rules
            .insert("RULE-SCOPED".to_string());
        let out = render_payload_summary(Surface::Grok, &SpawnPayload::Grok(payload));
        assert!(
            out.contains("unscoped_path_rules: 1 [RULE-SCOPED]"),
            "summary must name the specific rule id, not just a count; got:\n{out}"
        );
    }

    /// HIGH-D non-vacuity, accept boundary: Kimi/Grok's `--json` output MUST
    /// carry `"delivered": false` — `launch_native` never materializes
    /// their governance payload into a live spawn yet.
    #[test]
    fn translate_json_marks_kimi_and_grok_as_not_delivered() {
        use csq_core::coc::translate;
        use csq_core::coc::types::CocSet;
        use csq_core::providers::catalog::Surface;

        let empty = CocSet::empty();
        for surface in [Surface::Kimi, Surface::Grok] {
            let payload = translate::translate(&empty, surface, &translate::HostContext::None);
            let json = render_translate_json(surface, &payload).unwrap();
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(
                value.get("delivered"),
                Some(&serde_json::Value::Bool(false)),
                "surface {surface:?} JSON must mark delivered:false until the \
                 launch_native wiring shard lands"
            );
        }
    }

    /// HIGH-D non-vacuity, reject boundary: the ALREADY-wired surfaces
    /// (cc/codex/gemini — `emit_cc_plugin`/`emit_codex_native`/
    /// `emit_gemini_native` are called from `launch_*` in run.rs today)
    /// MUST NOT carry the marker — it would be a false claim in the
    /// opposite direction (understating a surface that IS delivered).
    #[test]
    fn translate_json_does_not_mark_delivered_for_already_wired_surfaces() {
        use csq_core::coc::translate;
        use csq_core::coc::types::CocSet;
        use csq_core::providers::catalog::Surface;

        let empty = CocSet::empty();
        for surface in [Surface::ClaudeCode, Surface::Codex, Surface::Gemini] {
            let payload = translate::translate(&empty, surface, &translate::HostContext::None);
            let json = render_translate_json(surface, &payload).unwrap();
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert!(
                value.get("delivered").is_none(),
                "surface {surface:?} is already wired into launch_* in run.rs; \
                 must not carry the not-delivered marker"
            );
        }
    }

    /// R2 live-path lens: the already-wired surfaces MUST keep the exact
    /// `--json` bytes they emitted before this PR — a `serde_json::Value`
    /// round-trip alphabetizes keys (no `preserve_order` feature in this
    /// workspace), which would silently reorder an operator-facing format
    /// for three surfaces this PR does not otherwise touch.
    ///
    /// Pinned against DIRECT serialization rather than a hardcoded key
    /// list, so the test tracks the struct definition instead of restating
    /// it — a field added to `CodexSpawnPayload` keeps this green, while a
    /// re-introduced round-trip turns it red.
    #[test]
    fn translate_json_preserves_declaration_order_for_already_wired_surfaces() {
        use csq_core::coc::translate;
        use csq_core::coc::types::CocSet;
        use csq_core::providers::catalog::Surface;

        let empty = CocSet::empty();
        for surface in [Surface::ClaudeCode, Surface::Codex, Surface::Gemini] {
            let payload = translate::translate(&empty, surface, &translate::HostContext::None);
            let direct = serde_json::to_string_pretty(&payload).unwrap();
            let rendered = render_translate_json(surface, &payload).unwrap();
            assert_eq!(
                rendered, direct,
                "surface {surface:?}: `--json` must be byte-identical to direct \
                 serialization. A `serde_json::to_value` round-trip sorts keys \
                 alphabetically and would silently change this operator-facing \
                 format."
            );
        }
    }

    /// The Kimi/Grok counterpart: those two DO round-trip (the `delivered`
    /// marker requires mutating the object), so they are the only surfaces
    /// allowed to differ from direct serialization. Pinning this stops a
    /// future "simplification" from dropping the marker to restore
    /// byte-equality across all five.
    #[test]
    fn translate_json_marker_is_the_only_reason_kimi_grok_differ() {
        use csq_core::coc::translate;
        use csq_core::coc::types::CocSet;
        use csq_core::providers::catalog::Surface;

        let empty = CocSet::empty();
        for surface in [Surface::Kimi, Surface::Grok] {
            let payload = translate::translate(&empty, surface, &translate::HostContext::None);
            let rendered = render_translate_json(surface, &payload).unwrap();
            let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
            assert_eq!(
                value.get("delivered"),
                Some(&serde_json::Value::Bool(false)),
                "surface {surface:?} has no live spawn path; the marker must be present"
            );
        }
    }
}
