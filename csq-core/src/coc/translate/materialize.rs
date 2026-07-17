//! `.coc/` → native-artifact emitters (an internal ticket, item 2). Pure, deterministic
//! writers for each surface's Level-2 native materialization, exercised by the
//! `csq run` spawn-wiring in `run.rs`:
//!
//! - **[`emit_cc_plugin`]** (S2) — agents + skills + commands → a Claude Code
//!   *plugin* tree that `claude --plugin-dir <abs>` points at.
//! - **[`emit_coc_rules`]** (S2b) — rules → native `$CLAUDE_CONFIG_DIR/rules/`
//!   files with `paths:` scoping (CC-only; no other surface has a rule primitive).
//! - **[`emit_codex_native`]** (S3) — skills → `$CODEX_HOME/skills/<ID>/SKILL.md`
//!   (codex has native skills only; agents/commands/rules stay prose).
//! - **[`emit_gemini_native`]** (S4) — skills → `.gemini/skills/<ID>/SKILL.md`
//!   and commands → `.gemini/commands/<ID>.toml` (gemini has native skills and
//!   commands; agents/rules stay prose).
//!
//! Every emitter is a pure library writer — it changes NO spawn behavior itself;
//! the launch path decides WHICH surface's emitter to call and delivers whatever
//! is not materialized natively as Level-1 prose.
//!
//! ```text
//! <dest>/                         (the plugin root — S2 passes this to --plugin-dir)
//!   .claude-plugin/plugin.json    minimal fixed-field CC plugin manifest
//!   agents/<ID>.md                synthesized frontmatter (name+description) + full body
//!   skills/<ID>/SKILL.md          synthesized frontmatter (name+description) + full body
//!   commands/<ID>.md              synthesized frontmatter (description) + full body
//! ```
//!
//! ## Synthesized frontmatter (Task-invocability)
//!
//! `.coc/` agents/skills/commands carry only `id`/`applies_to` frontmatter, and
//! the parser strips it — so [`FlatArtifact`](super::flatten::FlatArtifact)
//! bodies are frontmatter-free. CC's plugin contract, however, needs
//! `name` + `description` on agents (to be Task-invocable as `<plugin>:<name>`)
//! and skills (to trigger). This emitter therefore SYNTHESIZES a minimal
//! frontmatter block: `name = <ID>` (matching the file / skill-dir name; omitted
//! for commands, which CC names by filename) and a `description` derived from the
//! body's first non-heading line (a stable generic when the body yields none).
//! The full body is preserved verbatim below the block.
//!
//! **Rules are NOT part of the PLUGIN tree** — a Claude Code plugin has no
//! `rules/` component (verified empirically: a `rules/` dir under `--plugin-dir`
//! is ignored). Rules instead materialize through [`emit_coc_rules`] into the
//! session handle dir's native `$CLAUDE_CONFIG_DIR/rules/` location (S2b), where
//! CC's own rules loader honors each rule's `paths:` file-scoping. CC
//! auto-discovers the `agents/`, `skills/`, and `commands/` subdirs from the
//! plugin root, so `plugin.json` carries only `{name, version, description}` and
//! never enumerates components (keeping it trivially deterministic).
//!
//! ## Determinism (spec 10 §10.3.5 — cross-process byte-identity)
//!
//! Same [`SurfaceArtifacts`] + same `dest` ⇒ byte-identical file tree AND
//! [`MaterializedManifest`]. There are NO timestamps, NO env reads, and NO
//! randomness anywhere in this module. The returned manifest is
//! `BTreeMap`-keyed by relative path so its iteration/serialization order is
//! stable (red-team R1 MED-2). `plugin.json` is a fixed-field serde struct
//! (declaration-order serialization) pinned to a constant version.
//!
//! ## Safety
//!
//! In production every `FlatArtifact.id` is a validated `RuleId`/`AgentId`/…
//! (`^[A-Z][A-Z0-9-]{1,32}$`, spec 09 §9.2.1) and is filesystem-safe. This
//! module does NOT trust that: [`emit_cc_plugin`] validates each id against a
//! conservative charset (rejecting path separators, `.`/`..`, and control
//! bytes → no directory traversal outside `dest`) and rejects
//! case-insensitive filename collisions (macOS/Windows default filesystems),
//! so a malformed or hostile `SurfaceArtifacts` fails closed with a
//! descriptive error rather than writing outside the tree or silently
//! clobbering a sibling artifact.

use std::collections::BTreeMap;
use std::path::Path;

use super::flatten::{FlatArtifact, SurfaceArtifacts};
use crate::platform::fs::secure_file;

/// Minimal Claude Code plugin name embedded in the emitted `plugin.json`.
const PLUGIN_NAME: &str = "csq-coc";
/// Version pinned to a constant (NOT a runtime value) so the manifest is
/// byte-identical across processes and csq builds.
const PLUGIN_VERSION: &str = "0.0.0";
/// Human-readable plugin description.
const PLUGIN_DESCRIPTION: &str =
    "csq capability-layer artifacts materialized from .coc/ for this session";

/// Which kind of artifact a materialized file holds. Recorded in the manifest
/// so a caller (S2 teardown / verification) can classify what was written
/// without re-parsing paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializedKind {
    /// `.claude-plugin/plugin.json`.
    PluginManifest,
    /// `agents/<ID>.md`.
    Agent,
    /// `skills/<ID>/SKILL.md`.
    Skill,
    /// `commands/<ID>.md`.
    Command,
    /// `rules/coc-<ID>.md` — native path-scoped rule (an internal ticket S2b).
    Rule,
}

/// Deterministic record of every file [`emit_cc_plugin`] wrote, keyed by path
/// RELATIVE to `dest`. `BTreeMap`-backed so iteration and any serialization is
/// byte-stable across processes (spec 10 §10.3.5). Relative (not absolute)
/// paths keep the manifest independent of where `dest` lives on disk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaterializedManifest {
    /// Relative path (POSIX `/` separators) → the kind it holds.
    pub files: BTreeMap<String, MaterializedKind>,
}

impl MaterializedManifest {
    /// Number of files recorded.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// True when no file was recorded (impossible from a successful
    /// [`emit_cc_plugin`] — it always writes `plugin.json`).
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// Errors from [`emit_cc_plugin`]. Every variant names the offending path or
/// id so a failure is self-describing.
#[derive(Debug, thiserror::Error)]
pub enum MaterializeError {
    /// A filesystem write / mkdir failed.
    #[error("io error writing {path}: {source}")]
    Io {
        /// The path being written when the error occurred.
        path: String,
        /// The underlying io error.
        #[source]
        source: std::io::Error,
    },
    /// Setting 0o600 permissions on a written file failed.
    #[error("securing permissions on {path}: {reason}")]
    Secure {
        /// The file whose permissions could not be set.
        path: String,
        /// Stringified platform error (avoids leaking the platform error type).
        reason: String,
    },
    /// An artifact id is not filesystem-safe (empty, `.`/`..`, or contains a
    /// path separator / control byte). Fails closed to prevent traversal.
    #[error("unsafe artifact id {id:?}: {reason}")]
    UnsafeId {
        /// The offending id.
        id: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// Two artifacts resolve to the same file after case-folding (the default
    /// macOS/Windows filesystems are case-insensitive).
    #[error("filename collision: {first:?} and {second:?} both map to {path:?}")]
    FilenameCollision {
        /// The relative path first claimed.
        first: String,
        /// The colliding relative path.
        second: String,
        /// The case-folded key they share.
        path: String,
    },
}

/// Fixed-field CC plugin manifest. Declaration-order serialization ⇒
/// deterministic bytes with no timestamp (red-team R1 MED-2). CC
/// auto-discovers `agents/`/`skills/`/`commands/`, so components are NOT
/// enumerated here.
#[derive(serde::Serialize)]
struct PluginManifest {
    name: &'static str,
    version: &'static str,
    description: &'static str,
}

/// Render the byte-deterministic `plugin.json` contents (trailing newline for
/// POSIX-clean files).
fn render_plugin_json() -> String {
    let manifest = PluginManifest {
        name: PLUGIN_NAME,
        version: PLUGIN_VERSION,
        description: PLUGIN_DESCRIPTION,
    };
    // to_string_pretty is deterministic for a fixed-field struct.
    let mut s = serde_json::to_string_pretty(&manifest)
        .expect("PluginManifest is a fixed struct of &str fields — serialization is infallible");
    s.push('\n');
    s
}

/// Cap for a synthesized `description` frontmatter value — keeps the emitted
/// frontmatter compact and the token cost bounded.
const DESCRIPTION_MAX_CHARS: usize = 200;

/// Derive a one-line `description` for a synthesized agent/skill/command
/// frontmatter from the artifact body: the first non-blank, non-ATX-heading
/// (`#…`) line, trimmed and length-capped. `.coc/` agents/skills/commands carry
/// NO `name`/`description` frontmatter (only `id`/`applies_to`; the parser
/// strips frontmatter so [`FlatArtifact::body`](super::flatten::FlatArtifact)
/// is body-only), so csq synthesizes the CC-required `description` here.
/// Deterministic: same body ⇒ same description.
fn derive_description(id: &str, kind_label: &str, body: &str) -> String {
    match body
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
    {
        Some(line) if line.chars().count() > DESCRIPTION_MAX_CHARS => {
            let mut d: String = line.chars().take(DESCRIPTION_MAX_CHARS).collect();
            d.push('…');
            d
        }
        Some(line) => line.to_string(),
        // Body is empty or heading-only → a stable generic.
        None => format!("csq capability-layer {kind_label} {id}"),
    }
}

/// Escape a string as a YAML double-quoted scalar, neutralizing EVERY byte that
/// could break out of the quoted scalar or the surrounding frontmatter block:
/// `\` and `"`, the line breaks `\n`/`\r`/`\t`, and any remaining C0/C1 control
/// character (as a `\xNN` escape). The input comes from an arbitrary `.coc/`
/// artifact body line, so the guarantee "the emitted scalar is a single
/// physical line with no raw control byte" MUST hold by construction — NOT by
/// trusting `str::lines()` + `str::trim()` (which leave interior lone `\r` /
/// ESC / NUL) plus a lenient downstream frontmatter parser. The synthesized
/// frontmatter can carry privilege-bearing keys (an injected `tools:` / `model:`
/// sibling would change agent capabilities), so this is the trust boundary
/// between repo content and CC's plugin manifest (red-team R1 MED — deep-analyst
/// + security-reviewer converged).
fn yaml_double_quoted(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Any other control char (C0 0x00–0x1F, DEL 0x7F, C1 0x80–0x9F —
            // all ≤ 0xFF) as a two-hex-digit YAML escape.
            c if c.is_control() => {
                let _ = write!(out, "\\x{:02X}", c as u32);
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Render a materialized component file: a synthesized CC frontmatter block
/// (`name` for agents/skills — CC derives the command name from the filename —
/// plus a derived `description`) followed by the full artifact body. The `name`
/// equals the validated `id` (which also names the file / skill dir), so CC's
/// `<plugin>:<name>` invocation and the on-disk layout agree.
///
/// A synthesized frontmatter is REQUIRED for Task-invocability (agents) and
/// skill triggering: `.coc/` bodies are frontmatter-stripped, and CC's plugin
/// contract needs `name`/`description` on agents + skills. Commands are
/// filename-named and take only a `description`.
fn render_component_file(id: &str, kind_label: &str, body: &str, include_name: bool) -> String {
    let desc = derive_description(id, kind_label, body);
    let mut out = String::from("---\n");
    if include_name {
        // Double-quote the name so it is ALWAYS a YAML string, never coerced to
        // a bool/null/number (an id like `true`/`null`/`123` is a valid
        // `[A-Za-z0-9._-]` id but a YAML plain scalar of those types). Belt-and-
        // suspenders with `validate_id`; the guarantee holds by construction, not
        // by trusting the id charset (red-team R2 LOW).
        out.push_str("name: ");
        out.push_str(&yaml_double_quoted(id));
        out.push('\n');
    }
    out.push_str("description: ");
    out.push_str(&yaml_double_quoted(&desc));
    out.push('\n');
    out.push_str("---\n\n");
    out.push_str(body);
    // POSIX-clean trailing newline (bodies may or may not carry one).
    if !body.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Escape a string as a TOML basic (single-line, double-quoted) string,
/// neutralizing every byte that could break out of the quoted scalar: `\` and
/// `"`, the line breaks `\n`/`\r`/`\t`, and any remaining control character (as a
/// `\uNNNN` escape — every control char is ≤ U+009F, so four hex digits always
/// suffice). Newlines are ALWAYS escaped to `\n` (single-line form), so a body
/// line can never terminate the string early or form a `"""` sequence. The input
/// is an arbitrary `.coc/` command body, so — exactly like [`yaml_double_quoted`]
/// for the CC/gemini SKILL.md frontmatter — this is the trust boundary between
/// repo content and the gemini command `.toml` the CLI parses (a body that
/// injected a `[section]` or a sibling key could otherwise change command
/// semantics).
fn toml_basic_quoted(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Any other control char (C0 0x00–0x1F, DEL 0x7F, C1 0x80–0x9F) as a
            // 4-hex-digit TOML unicode escape.
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Render a gemini custom-command `.toml` file: a `description` (derived, same
/// rule as agents/skills) plus a `prompt` carrying the full command body. Both
/// values are TOML-escaped via [`toml_basic_quoted`] so a hostile body cannot
/// break the file. gemini names the command by filename (`commands/<id>.toml` →
/// `/<id>`), so no name key is emitted. Deterministic: same id + body ⇒ same file.
fn render_gemini_command_toml(id: &str, body: &str) -> String {
    let desc = derive_description(id, "command", body);
    let mut out = String::new();
    out.push_str("description = ");
    out.push_str(&toml_basic_quoted(&desc));
    out.push('\n');
    out.push_str("prompt = ");
    out.push_str(&toml_basic_quoted(body));
    out.push('\n');
    out
}

/// Validate that `id` is safe to use as a single path component: non-empty,
/// not `.`/`..`, and composed only of `[A-Za-z0-9._-]` (no separators, no
/// control bytes). This is a superset of the spec 09 §9.2.1 id charset, so it
/// never rejects a production id, but it fails closed on a hostile or
/// malformed `SurfaceArtifacts` before any path join.
fn validate_id(id: &str) -> Result<(), MaterializeError> {
    if id.is_empty() {
        return Err(MaterializeError::UnsafeId {
            id: id.to_string(),
            reason: "empty id",
        });
    }
    if id == "." || id == ".." {
        return Err(MaterializeError::UnsafeId {
            id: id.to_string(),
            reason: "`.` / `..` are not valid filenames",
        });
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        return Err(MaterializeError::UnsafeId {
            id: id.to_string(),
            reason: "id contains a character outside [A-Za-z0-9._-]",
        });
    }
    Ok(())
}

/// Emit the Claude Code plugin tree for `arts` rooted at `dest`. `dest` is
/// treated as a fresh (or overwriteable) plugin root — existing files at the
/// same relative paths are overwritten; stale files from a prior emit that are
/// NOT in `arts` are left untouched (S2 owns the ephemeral-dir lifecycle).
///
/// Writes `agents/`, `skills/`, and `commands/` (rules are excluded — they
/// stay Level-1 prose). Returns the deterministic [`MaterializedManifest`].
///
/// Every written file is chmod `0o600` via [`secure_file`], matching the
/// existing per-spawn handle-dir materialization discipline.
///
/// # Caller contract (S2 owns the ephemeral-dir lifecycle)
///
/// - **Fresh, non-symlink `dest`.** The caller MUST pass a freshly-created
///   real directory it owns (the per-spawn `term-<pid>/coc-plugin/`). This
///   function joins `dest` with fixed relative components and never follows
///   `..`, but it does NOT defend against a pre-planted symlink at `dest` or a
///   subdir — `create_dir_all` + `fs::write` would follow it. Symlink/TOCTOU
///   hardening (a re-stat that the target is a regular file, mirroring
///   `run.rs`'s `verify_codex_handle_config_toml_is_regular_file`) belongs to
///   the S2 spawn-wiring, which owns the dir's creation and lifetime.
/// - **Partial failure leaves a partial tree.** On any [`MaterializeError`],
///   files written before the error remain on disk (there is no rollback). The
///   caller MUST treat an `Err` as "materialization failed" — fall back to
///   Level-1 prose AND tear down `dest` — rather than launch a CLI against a
///   half-populated plugin dir.
pub fn emit_cc_plugin(
    arts: &SurfaceArtifacts,
    dest: &Path,
) -> Result<MaterializedManifest, MaterializeError> {
    let mut manifest = MaterializedManifest::default();
    // Case-folded relative path → the original relative path, for collision
    // detection on case-insensitive filesystems.
    let mut seen: BTreeMap<String, String> = BTreeMap::new();

    write_file(
        dest,
        ".claude-plugin/plugin.json".to_string(),
        &render_plugin_json(),
        MaterializedKind::PluginManifest,
        &mut manifest,
        &mut seen,
    )?;

    for a in &arts.agents {
        validate_id(&a.id)?;
        // Agents need `name` + `description` frontmatter to be Task-invocable.
        let content = render_component_file(&a.id, "agent", &a.body, true);
        write_file(
            dest,
            format!("agents/{}.md", a.id),
            &content,
            MaterializedKind::Agent,
            &mut manifest,
            &mut seen,
        )?;
    }
    for s in &arts.skills {
        validate_id(&s.id)?;
        // Skills need `name` (matching the dir) + `description` frontmatter.
        let content = render_component_file(&s.id, "skill", &s.body, true);
        write_file(
            dest,
            format!("skills/{}/SKILL.md", s.id),
            &content,
            MaterializedKind::Skill,
            &mut manifest,
            &mut seen,
        )?;
    }
    for c in &arts.commands {
        validate_id(&c.id)?;
        // Commands are named by filename; only a `description` is synthesized.
        let content = render_component_file(&c.id, "command", &c.body, false);
        write_file(
            dest,
            format!("commands/{}.md", c.id),
            &content,
            MaterializedKind::Command,
            &mut manifest,
            &mut seen,
        )?;
    }

    Ok(manifest)
}

/// Render a native Claude Code rule file: a `paths:` frontmatter block (ONLY
/// when the rule is path-scoped) followed by the full rule body. CC natively
/// loads `$CLAUDE_CONFIG_DIR/rules/*.md` (an internal ticket S2b) — a path-scoped rule
/// (`paths:` present) activates only when Claude reads a matching file; an
/// unscoped rule (no `paths:`) loads always-on at launch. Each glob is
/// YAML-escaped so a hostile `.coc/` `paths` value cannot break the frontmatter.
fn render_rule_file(paths: &[String], body: &str) -> String {
    let mut out = String::new();
    if !paths.is_empty() {
        out.push_str("---\npaths:\n");
        for p in paths {
            out.push_str("  - ");
            out.push_str(&yaml_double_quoted(p));
            out.push('\n');
        }
        out.push_str("---\n\n");
    }
    out.push_str(body);
    // POSIX-clean trailing newline.
    if !body.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Emit each in-scope rule as a native Claude Code rule file `coc-<ID>.md` under
/// `dest` (the session handle dir's `rules/` directory). Path-scoped rules
/// (`FlatArtifact.paths` non-empty) get `paths:` frontmatter so CC activates
/// them on matching file reads; unscoped rules load always-on. Filenames are
/// `coc-`-prefixed to namespace against any user-global rule copied in
/// alongside. Every file is `validate_id`-checked, case-insensitive-collision
/// checked, and chmod 0o600 — the same discipline as [`emit_cc_plugin`].
///
/// **This is the ONLY channel that honors `.coc/` rule path-scoping** (spec 09
/// §9.2.2), resolving the `coc-native-materialization` an internal journal entry gap where
/// `paths` was parsed but consumed by no surface.
///
/// # Caller contract
///
/// On any [`MaterializeError`] the caller MUST treat the whole rule set as
/// un-materialized and fall back to delivering rules as Level-1 prose — there is
/// no rollback here (a partial `rules/` may remain; the caller owns the
/// ephemeral handle-dir lifecycle).
pub fn emit_coc_rules(
    rules: &[FlatArtifact],
    dest: &Path,
) -> Result<MaterializedManifest, MaterializeError> {
    let mut manifest = MaterializedManifest::default();
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for r in rules {
        validate_id(&r.id)?;
        write_file(
            dest,
            format!("coc-{}.md", r.id),
            &render_rule_file(&r.paths, &r.body),
            MaterializedKind::Rule,
            &mut manifest,
            &mut seen,
        )?;
    }
    Ok(manifest)
}

/// Emit the codex-native artifact tree for `arts` rooted at `dest` (`dest` is
/// `$CODEX_HOME` — the ephemeral `term-<pid>` handle dir per spec 07 §7.2.2).
/// an internal ticket S3.
///
/// **Only skills are materialized natively.** Per the plan-01 capability matrix
/// (codex-cli 0.144.4), codex has NATIVE `$CODEX_HOME/skills/<name>/SKILL.md`
/// discovery but NO subagent registry (agents stay prose) and its `prompts/`
/// commands are TUI-only / medium-confidence (commands stay prose pending a live
/// TUI confirm). Rules have no native codex primitive (they stay
/// `config.toml::instructions` prose). So this writes ONLY
/// `skills/<ID>/SKILL.md`, each with the same synthesized `name`+`description`
/// frontmatter + full body as the CC plugin skills, chmod 0o600, id-validated,
/// and case-collision checked. The caller delivers every non-skill kind (and
/// skills too, on any error here) as Level-1 prose.
///
/// # Caller contract
///
/// Same as [`emit_cc_plugin`]: `dest` MUST be a fresh, csq-owned, non-symlink
/// dir; on any [`MaterializeError`] the partial tree is left in place and the
/// caller MUST tear it down AND fall back to prose (no rollback here).
pub fn emit_codex_native(
    arts: &SurfaceArtifacts,
    dest: &Path,
) -> Result<MaterializedManifest, MaterializeError> {
    let mut manifest = MaterializedManifest::default();
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for s in &arts.skills {
        validate_id(&s.id)?;
        // Skills need `name` (matching the dir) + `description` frontmatter.
        let content = render_component_file(&s.id, "skill", &s.body, true);
        write_file(
            dest,
            format!("skills/{}/SKILL.md", s.id),
            &content,
            MaterializedKind::Skill,
            &mut manifest,
            &mut seen,
        )?;
    }
    Ok(manifest)
}

/// Emit the gemini-native artifact tree for `arts` rooted at `dest` (`dest` is
/// the handle dir's `.gemini/` config root, where csq already materializes
/// `settings.json`). an internal ticket S4.
///
/// **Skills AND commands are materialized natively.** Per the plan-01 capability
/// matrix (gemini 0.41.2), gemini has NATIVE `<scope>/skills/<name>/SKILL.md`
/// AND `<scope>/commands/**/*.toml` (`/<name>`) discovery — both
/// high-confidence. It has NO subagent registry (agents stay
/// `settings.json::system_instruction` prose) and no native rule primitive
/// (rules stay prose). So this writes `skills/<ID>/SKILL.md` (same shape as CC /
/// codex) AND `commands/<ID>.toml` (`description` + `prompt`, TOML-escaped via
/// [`toml_basic_quoted`]), chmod 0o600, id-validated, case-collision checked.
/// The caller delivers agents + rules (and skills/commands too, on any error
/// here) as Level-1 prose.
///
/// # Caller contract
///
/// Same as [`emit_cc_plugin`]: `dest` MUST be a fresh, csq-owned, non-symlink
/// dir; on any [`MaterializeError`] the partial tree is left in place and the
/// caller MUST tear it down AND fall back to prose (no rollback here).
pub fn emit_gemini_native(
    arts: &SurfaceArtifacts,
    dest: &Path,
) -> Result<MaterializedManifest, MaterializeError> {
    let mut manifest = MaterializedManifest::default();
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for s in &arts.skills {
        validate_id(&s.id)?;
        let content = render_component_file(&s.id, "skill", &s.body, true);
        write_file(
            dest,
            format!("skills/{}/SKILL.md", s.id),
            &content,
            MaterializedKind::Skill,
            &mut manifest,
            &mut seen,
        )?;
    }
    for c in &arts.commands {
        validate_id(&c.id)?;
        let content = render_gemini_command_toml(&c.id, &c.body);
        write_file(
            dest,
            format!("commands/{}.toml", c.id),
            &content,
            MaterializedKind::Command,
            &mut manifest,
            &mut seen,
        )?;
    }
    Ok(manifest)
}

/// Write one file at `dest/rel` with `content`, chmod 0o600, and record it in
/// the manifest. Rejects case-insensitive collisions against already-written
/// paths.
fn write_file(
    dest: &Path,
    rel: String,
    content: &str,
    kind: MaterializedKind,
    manifest: &mut MaterializedManifest,
    seen: &mut BTreeMap<String, String>,
    // NB: `rel` uses POSIX `/`; on Windows `Path::join` splits it correctly.
) -> Result<(), MaterializeError> {
    let folded = rel.to_ascii_lowercase();
    if let Some(first) = seen.get(&folded) {
        return Err(MaterializeError::FilenameCollision {
            first: first.clone(),
            second: rel,
            path: folded,
        });
    }
    seen.insert(folded, rel.clone());

    let abs = dest.join(&rel);
    if let Some(parent) = abs.parent() {
        std::fs::create_dir_all(parent).map_err(|e| MaterializeError::Io {
            path: parent.display().to_string(),
            source: e,
        })?;
    }
    std::fs::write(&abs, content).map_err(|e| MaterializeError::Io {
        path: abs.display().to_string(),
        source: e,
    })?;
    secure_file(&abs).map_err(|e| MaterializeError::Secure {
        path: abs.display().to_string(),
        reason: e.to_string(),
    })?;

    manifest.files.insert(rel, kind);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coc::translate::flatten::{FlatArtifact, SurfaceArtifacts};
    use std::fs;

    fn art(id: &str, body: &str) -> FlatArtifact {
        FlatArtifact {
            id: id.to_string(),
            precedence: 0,
            body: body.to_string(),
            paths: Vec::new(),
        }
    }

    fn sample() -> SurfaceArtifacts {
        SurfaceArtifacts {
            rules: vec![art("RULE-X", "rule body — MUST NOT be materialized")],
            agents: vec![art("AGENT-Y", "you are a reviewer\n")],
            skills: vec![art("SKILL-Z", "# skill\nprogressive disclosure\n")],
            commands: vec![art("COMMAND-W", "run the thing\n")],
        }
    }

    #[test]
    fn emit_writes_expected_tree_and_contents() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        let manifest = emit_cc_plugin(&sample(), dest).unwrap();

        // plugin.json + agent + skill + command = 4 files. Rules excluded.
        assert_eq!(manifest.len(), 4);
        assert!(
            !dest.join("rules").exists(),
            "rules must NOT be materialized"
        );

        let plugin = fs::read_to_string(dest.join(".claude-plugin/plugin.json")).unwrap();
        assert_eq!(
            plugin,
            "{\n  \"name\": \"csq-coc\",\n  \"version\": \"0.0.0\",\n  \"description\": \"csq capability-layer artifacts materialized from .coc/ for this session\"\n}\n",
            "plugin.json byte-exact"
        );

        // Agents/skills/commands carry a synthesized frontmatter block followed
        // by the full body. Agents+skills get `name`; commands do not (CC names
        // them by filename). The `description` is the body's first non-heading
        // line.
        assert_eq!(
            fs::read_to_string(dest.join("agents/AGENT-Y.md")).unwrap(),
            "---\nname: \"AGENT-Y\"\ndescription: \"you are a reviewer\"\n---\n\nyou are a reviewer\n"
        );
        assert_eq!(
            fs::read_to_string(dest.join("skills/SKILL-Z/SKILL.md")).unwrap(),
            "---\nname: \"SKILL-Z\"\ndescription: \"progressive disclosure\"\n---\n\n# skill\nprogressive disclosure\n"
        );
        assert_eq!(
            fs::read_to_string(dest.join("commands/COMMAND-W.md")).unwrap(),
            "---\ndescription: \"run the thing\"\n---\n\nrun the thing\n"
        );

        // Manifest kind classification.
        assert_eq!(
            manifest.files.get(".claude-plugin/plugin.json"),
            Some(&MaterializedKind::PluginManifest)
        );
        assert_eq!(
            manifest.files.get("agents/AGENT-Y.md"),
            Some(&MaterializedKind::Agent)
        );
        assert_eq!(
            manifest.files.get("skills/SKILL-Z/SKILL.md"),
            Some(&MaterializedKind::Skill)
        );
        assert_eq!(
            manifest.files.get("commands/COMMAND-W.md"),
            Some(&MaterializedKind::Command)
        );
    }

    #[test]
    fn synthesized_frontmatter_shape_and_derivation() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        let mut arts = SurfaceArtifacts::default();
        // Body opens with an ATX heading; description must skip it to the first
        // prose line (mirrors a real `.coc/` agent: `# AGENT-X\n\n<prose>`).
        arts.agents.push(art(
            "AGENT-X",
            "# AGENT-X\n\nReviews changes for rule compliance.\nMore.\n",
        ));
        // A body line containing YAML-hostile chars (`:` and `\"`) must be escaped.
        arts.skills
            .push(art("SKILL-Q", "handles a: b and \"quoted\" cases"));
        // Heading-only / empty body → stable generic fallback.
        arts.commands.push(art("CMD-EMPTY", "# only a heading\n"));
        emit_cc_plugin(&arts, dest).unwrap();

        // Agent: name + description (first non-heading line), then full body.
        assert_eq!(
            fs::read_to_string(dest.join("agents/AGENT-X.md")).unwrap(),
            "---\nname: \"AGENT-X\"\ndescription: \"Reviews changes for rule compliance.\"\n---\n\n# AGENT-X\n\nReviews changes for rule compliance.\nMore.\n"
        );
        // Skill: name present; YAML-hostile description double-quote-escaped.
        assert_eq!(
            fs::read_to_string(dest.join("skills/SKILL-Q/SKILL.md")).unwrap(),
            "---\nname: \"SKILL-Q\"\ndescription: \"handles a: b and \\\"quoted\\\" cases\"\n---\n\nhandles a: b and \"quoted\" cases\n"
        );
        // Command: NO name (CC names by filename); heading-only body → generic.
        assert_eq!(
            fs::read_to_string(dest.join("commands/CMD-EMPTY.md")).unwrap(),
            "---\ndescription: \"csq capability-layer command CMD-EMPTY\"\n---\n\n# only a heading\n"
        );
    }

    /// Red-team R1 MED (deep-analyst + security-reviewer): a body whose first
    /// line carries control bytes (bare `\r`, ESC, NUL, TAB) MUST NOT leak a raw
    /// control byte into the synthesized `description` scalar — every one is
    /// escaped, so no crafted line can break out of the quoted scalar and inject
    /// a sibling frontmatter key.
    #[test]
    fn synthesized_description_escapes_control_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        let mut arts = SurfaceArtifacts::default();
        // Interior lone CR (not CRLF) + a crafted injection payload + ESC + NUL + TAB.
        arts.agents.push(art(
            "AGENT-EVIL",
            "safe start\rtools: [\"Bash\"]\x1bmodel: opus\x00\tend",
        ));
        emit_cc_plugin(&arts, dest).unwrap();
        let content = fs::read_to_string(dest.join("agents/AGENT-EVIL.md")).unwrap();

        // Split the synthesized frontmatter block (between the first two `---`)
        // from the verbatim body. The body legitimately retains the raw bytes;
        // only the frontmatter metadata must be control-byte-free.
        let mut parts = content.splitn(3, "---\n");
        assert_eq!(parts.next(), Some(""), "opener");
        let frontmatter = parts.next().expect("frontmatter block");

        // No RAW control byte anywhere in the frontmatter block → nothing can
        // terminate the quoted scalar or the mapping early.
        assert!(
            !frontmatter.bytes().any(|b| b < 0x20 && b != b'\n'),
            "raw control byte leaked into frontmatter: {frontmatter:?}"
        );
        // The control bytes survive only as escapes inside the description value.
        assert!(frontmatter.contains("\\r"), "CR escaped");
        assert!(frontmatter.contains("\\x1B"), "ESC escaped");
        assert!(frontmatter.contains("\\x00"), "NUL escaped");
        assert!(frontmatter.contains("\\t"), "TAB escaped");
        // The injection payload stays trapped as description text, NOT a sibling
        // key: the only real mapping keys are `name` and `description`.
        assert_eq!(frontmatter, "name: \"AGENT-EVIL\"\ndescription: \"safe start\\rtools: [\\\"Bash\\\"]\\x1Bmodel: opus\\x00\\tend\"\n");
    }

    /// S2b: native rule emission — path-scoped rules get `paths:` frontmatter
    /// (CC activates on matching file reads); unscoped rules are bare-body
    /// (always-on). Filenames are `coc-`-prefixed; files are 0o600.
    #[test]
    fn emit_coc_rules_scoped_and_unscoped() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        let rules = vec![
            FlatArtifact {
                id: "RULE-SCOPED".to_string(),
                precedence: 0,
                body: "# RULE-SCOPED\nScoped body.".to_string(),
                paths: vec!["src/**/*.rs".to_string(), "lib/**".to_string()],
            },
            FlatArtifact {
                id: "RULE-UNSCOPED".to_string(),
                precedence: 0,
                body: "Always on.".to_string(),
                paths: Vec::new(),
            },
        ];
        let manifest = emit_coc_rules(&rules, dest).unwrap();
        assert_eq!(manifest.len(), 2);

        // Path-scoped → YAML `paths:` frontmatter + body.
        assert_eq!(
            fs::read_to_string(dest.join("coc-RULE-SCOPED.md")).unwrap(),
            "---\npaths:\n  - \"src/**/*.rs\"\n  - \"lib/**\"\n---\n\n# RULE-SCOPED\nScoped body.\n"
        );
        // Unscoped → bare body (CC loads it always-on), no frontmatter.
        assert_eq!(
            fs::read_to_string(dest.join("coc-RULE-UNSCOPED.md")).unwrap(),
            "Always on.\n"
        );
        assert_eq!(
            manifest.files.get("coc-RULE-SCOPED.md"),
            Some(&MaterializedKind::Rule)
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dest.join("coc-RULE-SCOPED.md"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "materialized rule files must be 0o600");
        }
    }

    /// S2b: a hostile `paths` glob cannot break out of the frontmatter.
    #[test]
    fn emit_coc_rules_escapes_hostile_paths() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        let rules = vec![FlatArtifact {
            id: "RULE-X".to_string(),
            precedence: 0,
            body: "body".to_string(),
            paths: vec!["a\"\n---\ninjected: true".to_string()],
        }];
        emit_coc_rules(&rules, dest).unwrap();
        let content = fs::read_to_string(dest.join("coc-RULE-X.md")).unwrap();
        // The frontmatter block (between the first two `---`) has exactly the
        // `paths:` mapping; the hostile payload is trapped inside the escaped scalar.
        let fm = content.split("---\n").nth(1).unwrap();
        // The payload is trapped inside the escaped one-line quoted scalar, NOT
        // emitted as a sibling mapping key (no line starts with `injected:`).
        assert!(
            !fm.lines().any(|l| l.trim_start().starts_with("injected:")),
            "hostile payload leaked as a frontmatter key: {fm:?}"
        );
        assert!(fm.contains("\\n"), "embedded newline escaped");
    }

    #[test]
    fn emit_is_byte_deterministic_across_two_runs() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let m1 = emit_cc_plugin(&sample(), a.path()).unwrap();
        let m2 = emit_cc_plugin(&sample(), b.path()).unwrap();

        // Manifests equal (BTreeMap → stable).
        assert_eq!(m1, m2);

        // Every corresponding file byte-identical.
        for rel in m1.files.keys() {
            let f1 = fs::read(a.path().join(rel)).unwrap();
            let f2 = fs::read(b.path().join(rel)).unwrap();
            assert_eq!(f1, f2, "file {rel} differs across runs");
        }
    }

    #[test]
    fn emit_empty_set_writes_only_plugin_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        let manifest = emit_cc_plugin(&SurfaceArtifacts::default(), dest).unwrap();

        assert_eq!(manifest.len(), 1);
        assert!(dest.join(".claude-plugin/plugin.json").exists());
        assert!(!dest.join("agents").exists());
        assert!(!dest.join("skills").exists());
        assert!(!dest.join("commands").exists());
    }

    #[test]
    fn written_files_are_0600() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let dest = dir.path();
            emit_cc_plugin(&sample(), dest).unwrap();
            let mode = fs::metadata(dest.join("agents/AGENT-Y.md"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "materialized files must be chmod 0o600");
        }
    }

    #[test]
    fn validate_id_accepts_production_ids() {
        assert!(validate_id("RULE-X").is_ok());
        assert!(validate_id("AGENT-Y-2").is_ok());
        assert!(validate_id("skill_a.b").is_ok());
    }

    #[test]
    fn validate_id_rejects_traversal_and_separators() {
        for bad in ["..", ".", "", "a/b", "a\\b", "../x", "x\0y"] {
            assert!(
                validate_id(bad).is_err(),
                "id {bad:?} must be rejected as unsafe"
            );
        }
    }

    #[test]
    fn emit_rejects_unsafe_agent_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut arts = SurfaceArtifacts::default();
        arts.agents.push(art("../escape", "x"));
        let err = emit_cc_plugin(&arts, dir.path()).unwrap_err();
        assert!(matches!(err, MaterializeError::UnsafeId { .. }));
        // Nothing escaped: the parent of dest holds no stray file.
        assert!(!dir.path().parent().unwrap().join("escape").exists());
    }

    #[test]
    fn emit_rejects_case_insensitive_collision() {
        let dir = tempfile::tempdir().unwrap();
        let mut arts = SurfaceArtifacts::default();
        // Two distinct ids that fold to the same filename.
        arts.agents.push(art("AGENT-A", "first"));
        arts.agents.push(art("agent-a", "second"));
        let err = emit_cc_plugin(&arts, dir.path()).unwrap_err();
        assert!(matches!(err, MaterializeError::FilenameCollision { .. }));
    }

    // ── S3 (an internal ticket): codex-native emitter ──────────────────────────────

    /// S3: codex materializes ONLY skills natively (`$CODEX_HOME/skills/<ID>/
    /// SKILL.md`). Agents (no registry), commands (TUI-only), and rules (no
    /// native primitive) are NOT written — they stay Level-1 prose. Same
    /// synthesized `name`+`description` SKILL.md shape as the CC plugin.
    #[test]
    fn emit_codex_native_writes_skills_only() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        let manifest = emit_codex_native(&sample(), dest).unwrap();

        // Only the one skill — no plugin.json, no agents/commands/rules.
        assert_eq!(manifest.len(), 1);
        assert!(!dest.join(".claude-plugin").exists(), "no plugin manifest");
        assert!(!dest.join("agents").exists(), "agents stay prose");
        assert!(!dest.join("commands").exists(), "commands stay prose");
        assert!(!dest.join("rules").exists(), "rules stay prose");

        assert_eq!(
            fs::read_to_string(dest.join("skills/SKILL-Z/SKILL.md")).unwrap(),
            "---\nname: \"SKILL-Z\"\ndescription: \"progressive disclosure\"\n---\n\n# skill\nprogressive disclosure\n"
        );
        assert_eq!(
            manifest.files.get("skills/SKILL-Z/SKILL.md"),
            Some(&MaterializedKind::Skill)
        );
    }

    /// S3: empty skill set → nothing written (caller delivers everything as prose).
    #[test]
    fn emit_codex_native_empty_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut arts = SurfaceArtifacts::default();
        arts.agents.push(art("AGENT-Y", "persona"));
        arts.commands.push(art("CMD-W", "do it"));
        let manifest = emit_codex_native(&arts, dir.path()).unwrap();
        assert!(manifest.is_empty(), "no skills → no native files");
        assert!(!dir.path().join("skills").exists());
    }

    // ── S4 (an internal ticket): gemini-native emitter ─────────────────────────────

    /// S4: gemini materializes skills (`skills/<ID>/SKILL.md`) AND commands
    /// (`commands/<ID>.toml` with `description` + `prompt`). Agents (no registry)
    /// and rules (no native primitive) stay prose.
    #[test]
    fn emit_gemini_native_writes_skills_and_commands() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        let manifest = emit_gemini_native(&sample(), dest).unwrap();

        // skill + command = 2 files; no agents, no rules, no plugin manifest.
        assert_eq!(manifest.len(), 2);
        assert!(!dest.join(".claude-plugin").exists());
        assert!(!dest.join("agents").exists(), "agents stay prose");
        assert!(!dest.join("rules").exists(), "rules stay prose");

        // Skill: identical SKILL.md shape as CC/codex.
        assert_eq!(
            fs::read_to_string(dest.join("skills/SKILL-Z/SKILL.md")).unwrap(),
            "---\nname: \"SKILL-Z\"\ndescription: \"progressive disclosure\"\n---\n\n# skill\nprogressive disclosure\n"
        );
        // Command: TOML with derived description + prompt (body TOML-escaped).
        assert_eq!(
            fs::read_to_string(dest.join("commands/COMMAND-W.toml")).unwrap(),
            "description = \"run the thing\"\nprompt = \"run the thing\\n\"\n"
        );
        assert_eq!(
            manifest.files.get("skills/SKILL-Z/SKILL.md"),
            Some(&MaterializedKind::Skill)
        );
        assert_eq!(
            manifest.files.get("commands/COMMAND-W.toml"),
            Some(&MaterializedKind::Command)
        );
    }

    /// S4: a hostile command body cannot break out of the TOML `prompt` string —
    /// quotes, backslashes, newlines, and control bytes are all escaped, so a
    /// crafted body cannot inject a sibling key or a `[section]` header.
    #[test]
    fn emit_gemini_command_toml_escapes_hostile_body() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        let mut arts = SurfaceArtifacts::default();
        // A body that tries to close the string and inject a new key + a triple
        // quote + a lone CR + NUL.
        arts.commands.push(art(
            "CMD-EVIL",
            "safe\"\nmalicious = \"x\"\n\"\"\"\rinjected\x00",
        ));
        emit_gemini_native(&arts, dest).unwrap();
        let content = fs::read_to_string(dest.join("commands/CMD-EVIL.toml")).unwrap();

        // Exactly two keys at line-start: `description` and `prompt`. The payload
        // never appears as a bare `malicious =` line.
        let key_lines: Vec<&str> = content
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                t.starts_with("description =") || t.starts_with("prompt =")
            })
            .collect();
        assert_eq!(key_lines.len(), 2, "exactly description + prompt keys");
        assert!(
            !content
                .lines()
                .any(|l| l.trim_start().starts_with("malicious")),
            "injected key leaked: {content:?}"
        );
        // No `"""` (multi-line delimiter) can form — every `\"` is escaped.
        assert!(!content.contains("\"\"\""), "no triple-quote sequence");
        // Newlines/CR/NUL survive only as escapes.
        assert!(content.contains("\\n"), "newline escaped");
        assert!(content.contains("\\r"), "CR escaped");
        assert!(content.contains("\\u0000"), "NUL escaped");

        // It round-trips as valid TOML with the body intact as the prompt value.
        let parsed: toml::Value = toml::from_str(&content).expect("valid TOML");
        assert_eq!(
            parsed.get("prompt").and_then(|v| v.as_str()),
            Some("safe\"\nmalicious = \"x\"\n\"\"\"\rinjected\u{0}")
        );
    }

    /// S3/S4: both native emitters produce byte-deterministic trees.
    #[test]
    fn native_emitters_are_byte_deterministic() {
        for emit in [
            emit_codex_native as fn(&SurfaceArtifacts, &Path) -> _,
            emit_gemini_native,
        ] {
            let a = tempfile::tempdir().unwrap();
            let b = tempfile::tempdir().unwrap();
            let m1 = emit(&sample(), a.path()).unwrap();
            let m2 = emit(&sample(), b.path()).unwrap();
            assert_eq!(m1, m2);
            for rel in m1.files.keys() {
                assert_eq!(
                    fs::read(a.path().join(rel)).unwrap(),
                    fs::read(b.path().join(rel)).unwrap(),
                    "file {rel} differs across runs"
                );
            }
        }
    }

    /// S3/S4: id validation + case-collision defense apply to the native
    /// emitters too (shared `validate_id` / `write_file` substrate).
    #[test]
    fn native_emitters_reject_unsafe_ids() {
        let dir = tempfile::tempdir().unwrap();
        let mut arts = SurfaceArtifacts::default();
        arts.skills.push(art("../escape", "x"));
        assert!(matches!(
            emit_codex_native(&arts, dir.path()).unwrap_err(),
            MaterializeError::UnsafeId { .. }
        ));
        assert!(matches!(
            emit_gemini_native(&arts, dir.path()).unwrap_err(),
            MaterializeError::UnsafeId { .. }
        ));
    }
}
