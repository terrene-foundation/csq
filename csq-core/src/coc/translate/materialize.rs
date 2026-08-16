//! `.coc/` → native-artifact emitters (an internal ticket, item 2). Pure, deterministic
//! writers for each surface's Level-2 native materialization, exercised by the
//! `csq run` spawn-wiring in `run.rs`:
//!
//! - **[`emit_cc_plugin`]** (S2) — agents + skills + commands → a Claude Code
//!   *plugin* tree that `claude --plugin-dir <abs>` points at.
//! - **[`emit_coc_rules`]** (S2b) — rules → native `$CLAUDE_CONFIG_DIR/rules/`
//!   files with `paths:` scoping. CC is NOT the only surface with a
//!   rules-directory primitive — Grok also has one (`.grok/rules/*.md`,
//!   harness-decomposition report 14 §6.1) — but this emitter targets only
//!   CC's `rules/` loader. Grok's rules-directory read path is rooted at
//!   the PROJECT tree, not at `$GROK_HOME`, so reaching it would mean
//!   writing into the user's repo — out of scope per the clobber-avoidance
//!   design documented on `grok::translate`. Grok's path-scoped rules
//!   instead broaden to global-scope `AGENTS.md` prose (see
//!   [`emit_grok_native`] + `GrokSpawnPayload::unscoped_path_rules`).
//! - **[`emit_codex_native`]** (S3) — skills → `$CODEX_HOME/skills/<ID>/SKILL.md`
//!   (codex has native skills only; agents/commands/rules stay prose).
//! - **[`emit_gemini_native`]** (S4) — skills → `.gemini/skills/<ID>/SKILL.md`
//!   and commands → `.gemini/commands/<ID>.toml` (gemini has native skills and
//!   commands; agents/rules stay prose).
//! - **[`emit_kimi_native`]** — skills → `<KIMI_CODE_HOME>/skills/csq-<ID>/
//!   SKILL.md` (`name: "csq-<ID>"`); commands DEGRADE to skills at the same
//!   path/name shape with `disable-model-invocation: true` (Kimi has no
//!   native command primitive — plugin-manifest only, harness-decomposition
//!   report 13 §3.5/§6.1; agents/rules stay prose, delivered via
//!   `AGENTS.md`). The `csq-` prefix (R11 MED-2, [`CSQ_OWNED_PREFIX`])
//!   namespaces BOTH the on-disk dir AND the synthesized `name:` — Kimi's
//!   own skill REGISTRY keys on `name:`, so a path-only prefix would still
//!   let a csq-emitted and a user-authored entry collide there. Consequence:
//!   a degraded command is user-invocable as `/skill:csq-<id>`, not
//!   `/skill:<id>`.
//! - **[`emit_grok_native`]** — skills → `$GROK_HOME/skills/csq-<ID>/
//!   SKILL.md` and commands → `$GROK_HOME/commands/csq-<ID>.md` (Grok has
//!   native skills AND commands — no degradation needed; agents →
//!   `$GROK_HOME/agents/csq-<ID>.md` as spawnable subagents, a genuine
//!   native win no other non-CC surface has; rules stay prose per the note
//!   above). Same `csq-` on-disk + `name:` namespacing as Kimi, same reason.
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
//! [`MaterializedManifest`] **on success**. There are NO timestamps, NO env
//! reads, and NO randomness in any successfully-emitted byte or in the
//! returned manifest. The returned manifest is `BTreeMap`-keyed by relative
//! path so its iteration/serialization order is stable (red-team R1 MED-2).
//! `plugin.json` is a fixed-field serde struct (declaration-order
//! serialization) pinned to a constant version.
//!
//! **Carve-out (R11 LOW-1, round-2 review):** the `path` field of a
//! returned [`MaterializeError`] (`Io`/`Secure`/`SymlinkAtDest`) is built
//! via `redact_path`, which DOES read `$HOME` to redact it out of the
//! message. This affects only the FAILURE-path error string — never a
//! written file's bytes or the returned manifest — so it does not weaken
//! the determinism guarantee above, which is a claim about emitted
//! artifacts on success, not about error message text.
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

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::flatten::{FlatArtifact, SurfaceArtifacts};
use crate::cli_deps::sanitize::redact_path;
use crate::platform::fs::secure_file;

/// Minimal Claude Code plugin name embedded in the emitted `plugin.json`.
const PLUGIN_NAME: &str = "csq-coc";
/// Version pinned to a constant (NOT a runtime value) so the manifest is
/// byte-identical across processes and csq builds.
const PLUGIN_VERSION: &str = "0.0.0";
/// Human-readable plugin description.
const PLUGIN_DESCRIPTION: &str =
    "csq capability-layer artifacts materialized from .coc/ for this session";

/// Filename/dirname AND synthesized-`name:`-frontmatter prefix applied to
/// every entry the PERSISTENT-vendor-home emitters ([`emit_kimi_native`],
/// [`emit_grok_native`]) write, so a csq-owned artifact is mechanically
/// distinguishable from a user-authored one sharing the same `dest` (R11
/// MED-2). Unlike [`emit_cc_plugin`]/[`emit_codex_native`]/
/// [`emit_gemini_native`] (whose `dest` is fresh per-spawn and thus never
/// holds user content), Kimi's and Grok's `dest` is the slot's PERSISTENT
/// vendor home — a directory the user (or the vendor CLI itself) may also
/// write into directly. Without this namespace, (a) a user who hand-authors
/// `skills/REVIEW/SKILL.md` loses it silently the first time `.coc/` ships a
/// skill id `REVIEW`, and (b) a future reconcile-on-emit pass ("delete
/// anything no longer present in `arts`" — a tracked wiring-shard AC, NOT
/// implemented by this module) would delete every user-authored entry it
/// cannot tell apart from a stale csq-owned one.
///
/// **The prefix applies to BOTH the on-disk relative path (directory/file
/// name) AND the synthesized `name:` frontmatter value (round-2 review
/// correction — a path-only prefix left the COLLISION at the vendor CLI's
/// own skill/command REGISTRY: `skills/csq-REVIEW/SKILL.md` containing
/// `name: "REVIEW"` still registers as `REVIEW`, colliding with a
/// user-authored `REVIEW` registered from `skills/REVIEW/SKILL.md`).** This
/// is a deliberate, user-visible behavior change: Kimi's degraded-command
/// invocation becomes `/skill:csq-<id>`, not `/skill:<id>`. Use
/// [`is_csq_owned_entry`] to test whether a given on-disk name carries this
/// prefix — a future reconcile-on-emit pass MUST filter every delete
/// candidate through it.
pub const CSQ_OWNED_PREFIX: &str = "csq-";

/// Returns `true` when `name` (a single path component — a skill/agent
/// directory name, or a command/agent filename stem without its
/// extension) carries the [`CSQ_OWNED_PREFIX`] namespace. This is the
/// predicate a future reconcile-on-emit pass for [`emit_kimi_native`] /
/// [`emit_grok_native`] MUST filter every delete candidate through (R11
/// MED-2) — an entry for which this returns `false` MUST NEVER be deleted.
///
/// **Case-insensitive fold (R12 LOW-fold).** `name` is folded to lowercase
/// before the prefix check, matching this module's own FS model: the
/// case-insensitive-collision doc on [`MaterializeError::FilenameCollision`]
/// states plainly that "the default macOS/Windows filesystems are
/// case-insensitive", and [`write_file`]'s own collision guard folds every
/// path the same way. Without the fold here, a user who hand-authors
/// `skills/CSQ-REVIEW/SKILL.md` on a case-insensitive filesystem and a
/// `.coc/` artifact id `REVIEW` (which this module writes as
/// `skills/csq-REVIEW/`) would collide at the FILESYSTEM layer — `write_file`
/// resolves both to the SAME directory — while an un-folded predicate still
/// classified the pre-existing entry as user-owned (`false`); a future
/// reconcile pass would then either silently clobber the user's file (it
/// isn't a fresh dir, `create_dir_all` just resolves into it) or, having
/// clobbered it, permanently exempt the resulting csq-written path from
/// future reconcile because the predicate never recognizes the case-variant
/// name as csq-owned. Folding closes that case.
///
/// **Inherent limitations (undecidable from a filename-prefix scheme
/// alone):**
/// - A user-authored entry literally named `csq-foo` (in ANY case, e.g.
///   `Csq-Foo`) is INDISTINGUISHABLE from a csq-owned one and WILL be
///   treated as csq-owned by any caller that filters on this predicate —
///   i.e. it becomes a reconcile-delete candidate if `.coc/` does not
///   currently ship an artifact id `foo`. This is an accepted, documented
///   boundary of the namespacing approach (not a defect introduced by this
///   function): a content-addressed or manifest-tracked ownership marker
///   would close it, but that is a larger design change than a filename
///   prefix and is out of scope for this fix.
/// - **Case-sensitive filesystems (most Linux filesystems) over-match.**
///   The fold above means a user-authored `skills/CSQ-foo/` on Linux — where
///   it does NOT collide with a csq-written `skills/csq-foo/` at the
///   filesystem layer, so both can coexist on disk simultaneously — is
///   STILL classified as csq-owned by this predicate and becomes a
///   reconcile-delete candidate. This trades the macOS/Windows
///   silent-clobber-then-permanent-exemption failure above for a rarer
///   Linux false-positive-ownership failure. Kept folded anyway: this
///   module's on-disk collision model is ALREADY case-insensitive
///   everywhere else, so an un-folded predicate would be the one
///   inconsistent piece — and would leave open the macOS/Windows case,
///   which is the platform the persistent-vendor-home emitters'
///   credential-adjacent `dest` overwhelmingly runs on.
pub fn is_csq_owned_entry(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with(CSQ_OWNED_PREFIX)
}

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
    /// A `.coc/` COMMAND materialized as `skills/<ID>/SKILL.md` with
    /// `disable-model-invocation: true` — Kimi's degradation path for
    /// commands (no native command primitive; harness-decomposition report
    /// 13 §3.5/§6.1). Distinct from [`MaterializedKind::Skill`] so a
    /// manifest consumer can tell "real skill" from "command wearing a
    /// skill's clothes" without re-parsing frontmatter.
    CommandAsSkill,
}

/// Deterministic record of every file [`emit_cc_plugin`] wrote, keyed by path
/// RELATIVE to `dest`. `BTreeMap`-backed so iteration and any serialization is
/// byte-stable across processes (spec 10 §10.3.5). Relative (not absolute)
/// paths keep the manifest independent of where `dest` lives on disk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaterializedManifest {
    /// Relative path (POSIX `/` separators) → the kind it holds.
    pub files: BTreeMap<String, MaterializedKind>,
    /// Relative paths (POSIX `/` separators) of every directory THIS call's
    /// `write_file` created (i.e. did NOT already exist at `dest` when the
    /// call started) — round-13 review LOW-2. `cleanup_partial_write`'s
    /// empty-directory removal walk consults this so it NEVER removes a
    /// directory that pre-existed the call (e.g. a vendor-created empty
    /// `skills/` from Kimi's own home-tree setup), even if this call's own
    /// files inside it are the only reason it later reads as empty.
    pub created_dirs: BTreeSet<String>,
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
    /// A body being materialized for Grok (agent, skill, or command)
    /// contains the literal `${{` sequence — Grok's
    /// `${{ tools.by_kind.<kind> }}` template DSL (harness-decomposition
    /// report 14 §3.3) substitutes that syntax at spawn time, and every
    /// artifact kind Grok materializes natively (`skills/`, `commands/`,
    /// `agents/` — see [`emit_grok_native`]) shares the same read path, so
    /// the guard covers all three, not agents alone (MED-E). Rather than
    /// guess an unverified escape mechanism, this fails closed: **the
    /// WHOLE [`emit_grok_native`] call fails, not just the offending
    /// artifact** — `emit_grok_native` pre-flights this check over every
    /// skill/command/agent BEFORE writing any of them (MED-M), so a
    /// collision on ANY artifact means NO artifact is written and the
    /// caller falls back to Level-1 prose delivery for the ENTIRE Grok
    /// payload (mirrors `UnsafeId`'s "fail closed on hostile/malformed
    /// input" posture — same all-or-nothing shape, not per-artifact
    /// granularity).
    #[error("artifact {id:?} ({kind}) body contains `${{{{` — collides with Grok's template DSL")]
    TemplateDslCollision {
        /// The offending artifact id.
        id: String,
        /// The artifact kind (`"agent"`, `"skill"`, or `"command"`).
        kind: &'static str,
    },
    /// A path this call was about to READ (the pre-write overwrite snapshot in
    /// the internal `write_file_restorable` helper) or WRITE is a PRE-EXISTING
    /// SYMLINK — refused before either operation follows it (R11 MED-1). `dest`
    /// for the persistent-vendor-home emitters ([`emit_kimi_native`],
    /// [`emit_grok_native`]) is long-lived and credential-adjacent: a same-UID
    /// process could plant e.g. `<KIMI_CODE_HOME>/skills/REVIEW/SKILL.md` as a
    /// symlink to `<KIMI_CODE_HOME>/credentials.json` or `~/.ssh/id_ed25519`,
    /// and a plain `std::fs::read` would follow it into the `prior`-content
    /// snapshot — which the internal `cleanup_partial_write` helper can later
    /// write back out as a REAL, world-model-visible file. Fails closed
    /// instead.
    #[error("refusing to materialize at {path}: a symlink exists at this path (would follow to an unintended target)")]
    SymlinkAtDest {
        /// The (redacted) path found to be a symlink.
        path: String,
    },
    /// A component of the path is NOT A DIRECTORY (`ENOTDIR`) — most often a
    /// leftover regular file sitting exactly where an artifact directory
    /// belongs, in one of the PERSISTENT vendor homes ([`emit_kimi_native`],
    /// [`emit_grok_native`]) that this module must not tear down.
    ///
    /// Split out from [`MaterializeError::SymlinkAtDest`] in round 6. Both
    /// conditions were folded into that one variant, whose message asserts
    /// "a symlink exists at this path" — a concrete, falsifiable claim that is
    /// simply FALSE for `ENOTDIR`, sending the operator hunting for a symlink
    /// that does not exist. The two also need opposite remedies: a symlink is
    /// a possible credential-redirection attempt, whereas this is ordinary
    /// cruft that must be removed or renamed, and no amount of retrying
    /// clears it. `ELOOP` keeps the symlink variant; `ENOTDIR` gets this one.
    #[error(
        "refusing to materialize at {path}: a component of this path is not a \
         directory (a regular file is in the way; remove or rename it — \
         retrying will not clear this)"
    )]
    NonDirectoryInPath {
        /// The (redacted) path whose parent chain contains a non-directory.
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

/// Escape a string as a YAML double-quoted scalar, neutralizing every `\` and
/// `"`, the line breaks `\n`/`\r`/`\t`, and any remaining Unicode General
/// Category **Cc** ("Control", i.e. C0/C1) byte that could break out of the
/// quoted scalar or the surrounding frontmatter block (as a `\xNN` escape).
/// The input comes from an arbitrary `.coc/` artifact body line, so the
/// guarantee "the emitted scalar is a single physical line with no raw Cc
/// control byte" MUST hold by construction — NOT by trusting `str::lines()` +
/// `str::trim()` (which leave interior lone `\r` / ESC / NUL) plus a lenient
/// downstream frontmatter parser. The synthesized frontmatter can carry
/// privilege-bearing keys (an injected `tools:` / `model:` sibling would
/// change agent capabilities), so this is the trust boundary between repo
/// content and CC's plugin manifest (red-team R1 MED — deep-analyst +
/// security-reviewer converged).
///
/// **Scope note (R11 NIT-1):** `char::is_control()` matches category **Cc**
/// only. Category **Cf** ("Format" — e.g. U+202E RLO, the U+2066–U+2069 bidi
/// isolates, U+200B ZWSP) passes through unescaped. This is NOT a gap: Cf
/// characters carry no quote, backslash, or line-break semantics of their
/// own, so none of them can terminate the quoted scalar or the frontmatter
/// block early — the escaping contract above is specifically about
/// breakout-capable bytes, and Cf cannot break out.
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

/// Render a synthesized-frontmatter file — the shared substrate for
/// [`render_component_file`] (CC/codex/gemini) AND [`render_skill_file`]
/// (Kimi/Grok). Collapsed from two independently maintained functions that
/// happened to be byte-identical for `render_skill_file(.., false)` ==
/// `render_component_file(.., true)` (LOW-J: nothing PINNED them equal, so
/// a frontmatter change to one could silently diverge the other; see
/// `render_skill_file_matches_render_component_file_when_not_disabled`).
/// `extra_line`, when `Some`, is inserted after `description:` and before
/// the closing `---` (used for Kimi's `disable-model-invocation: true`
/// degraded-command marker).
///
/// `id` and `desc_id` are DELIBERATELY separate (R12 NIT-desc): `id` names
/// the `name:` frontmatter value (and, at the caller, the on-disk path) —
/// for Kimi/Grok that is the [`CSQ_OWNED_PREFIX`]-prefixed `csq-<ID>`. But
/// [`derive_description`]'s body-less fallback interpolates whatever id it
/// receives into `"csq capability-layer {kind_label} {id}"` — if that were
/// the prefixed id, a body-less Kimi/Grok skill would render
/// `description: "csq capability-layer skill csq-SKILL-Z"` (user-visible,
/// double "csq"). `desc_id` is always the RAW, unprefixed artifact id, so
/// the fallback description stays `"csq capability-layer skill SKILL-Z"`
/// regardless of which emitter renders it.
fn render_frontmatter_file(
    id: &str,
    desc_id: &str,
    kind_label: &str,
    body: &str,
    include_name: bool,
    extra_line: Option<&str>,
) -> String {
    let desc = derive_description(desc_id, kind_label, body);
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
    if let Some(line) = extra_line {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("---\n\n");
    out.push_str(body);
    // POSIX-clean trailing newline (bodies may or may not carry one).
    if !body.ends_with('\n') {
        out.push('\n');
    }
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
///
/// `desc_id` is the raw, unprefixed artifact id used ONLY for
/// [`derive_description`]'s body-less fallback — see
/// [`render_frontmatter_file`]'s doc comment for why it is kept separate
/// from `id` (the `name:`/path value, prefixed for Grok's persistent-home
/// emitter).
fn render_component_file(
    id: &str,
    desc_id: &str,
    kind_label: &str,
    body: &str,
    include_name: bool,
) -> String {
    render_frontmatter_file(id, desc_id, kind_label, body, include_name, None)
}

/// Render a Kimi/Grok `SKILL.md`: synthesized `name` + `description`
/// frontmatter (same shape and escaping as [`render_component_file`] — both
/// build on the shared [`render_frontmatter_file`]), with an OPTIONAL
/// `disable-model-invocation: true` line. Used directly for real skills
/// (`disable_model_invocation: false`) and for Kimi's command-degraded-to-
/// skill path (`disable_model_invocation: true` — user-invocable as
/// `/skill:<id>`, never model-invocable, so a COC COMMAND doesn't silently
/// become something the model can call on its own; harness-decomposition
/// report 13 §6.1).
///
/// `desc_id` is the raw, unprefixed artifact id — see
/// [`render_frontmatter_file`]'s doc comment; `id` here is always the
/// [`CSQ_OWNED_PREFIX`]-prefixed `csq-<ID>` (Kimi/Grok are the only callers
/// of this function).
fn render_skill_file(
    id: &str,
    desc_id: &str,
    kind_label: &str,
    body: &str,
    disable_model_invocation: bool,
) -> String {
    render_frontmatter_file(
        id,
        desc_id,
        kind_label,
        body,
        true,
        disable_model_invocation.then_some("disable-model-invocation: true"),
    )
}

/// Escape a string as a TOML basic (single-line, double-quoted) string,
/// neutralizing every `\` and `"`, the line breaks `\n`/`\r`/`\t`, and any
/// remaining Unicode General Category **Cc** ("Control") character (as a
/// `\uNNNN` escape — every Cc char is ≤ U+009F, so four hex digits always
/// suffice). Newlines are ALWAYS escaped to `\n` (single-line form), so a body
/// line can never terminate the string early or form a `"""` sequence. The input
/// is an arbitrary `.coc/` command body, so — exactly like [`yaml_double_quoted`]
/// for the CC/gemini SKILL.md frontmatter — this is the trust boundary between
/// repo content and the gemini command `.toml` the CLI parses (a body that
/// injected a `[section]` or a sibling key could otherwise change command
/// semantics).
///
/// **Scope note (R11 NIT-1):** as with [`yaml_double_quoted`],
/// `char::is_control()` covers category **Cc** only; category **Cf** (bidi
/// overrides/isolates, ZWSP) passes through unescaped. Not a gap — Cf carries
/// no quote/backslash/line-break semantics, so it cannot break out of the
/// quoted TOML string either.
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
        let content = render_component_file(&a.id, &a.id, "agent", &a.body, true);
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
        let content = render_component_file(&s.id, &s.id, "skill", &s.body, true);
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
        let content = render_component_file(&c.id, &c.id, "command", &c.body, false);
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
/// when the rule is path-scoped) followed by the rule body wrapped in a
/// provenance boundary (`super::provenance::wrap_rule_provenance`). CC
/// natively loads `$CLAUDE_CONFIG_DIR/rules/*.md` (an internal ticket S2b) — a
/// path-scoped rule (`paths:` present) activates only when Claude reads a
/// matching file; an unscoped rule (no `paths:`) loads always-on at launch.
/// Each glob is YAML-escaped so a hostile `.coc/` `paths` value cannot break
/// the frontmatter.
///
/// The provenance boundary (`<!-- csq:coc-source id="<ID>" -->` … `<!-- /csq:
/// coc-source id="<ID>" -->`) marks exactly where `id`'s own `.coc/rules/`
/// body starts and ends, and is forgery-resistant against the body itself
/// (see `provenance` module docs) — it is NOT an instruction to distrust the
/// body; the body still loads with full governance authority.
fn render_rule_file(id: &str, paths: &[String], body: &str) -> String {
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
    out.push_str(&super::provenance::wrap_rule_provenance(id, body));
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
            &render_rule_file(&r.id, &r.paths, &r.body),
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
        let content = render_component_file(&s.id, &s.id, "skill", &s.body, true);
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
        let content = render_component_file(&s.id, &s.id, "skill", &s.body, true);
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

/// Emit the Kimi-native artifact tree for `arts` rooted at `dest` (`dest` is
/// `<KIMI_CODE_HOME>` — the csq-owned per-slot vendor home,
/// `native_home_path(base, slot, Surface::Kimi)`, confirmed by static trace
/// to be Kimi's own `<brandHome>/skills` read root; harness-decomposition
/// report 13 §8).
///
/// **Skills materialize natively. Commands DEGRADE to skills.** Kimi has
/// native `skills/<ID>/SKILL.md` discovery (same shape as CC/Codex/Gemini)
/// but no user-authored command primitive at all — commands are
/// plugin-manifest-only (report 13 §3.5). Rather than drop `.coc/`
/// COMMAND artifacts entirely, each is written to the SAME
/// `skills/csq-<ID>/SKILL.md` shape (see the [`CSQ_OWNED_PREFIX`] namespace
/// note below) with `disable-model-invocation: true` (report 13 §6.1) —
/// user-invocable as `/skill:csq-<id>`, never model-invocable, so the
/// degradation cannot silently grant the model an
/// invocation path `.coc/` never declared. Skills and commands share one
/// filename collision namespace (`skills/<id>/SKILL.md`) — `write_file`'s
/// `seen` map catches an id used by both a skill and a command.
///
/// Agents (no user-authored surface in Kimi 0.28.1 — four profiles are
/// compiled into the binary, report 13 §3.4) and rules (no native
/// primitive; `AGENTS.md`'s own system prompt demotes it to advisory
/// reference data, report 13 H1) stay Level-1 prose, delivered via
/// `KimiSpawnPayload::agents_md`.
///
/// **No ephemeral-dir lifecycle — `dest` is persistent, and stale entries
/// are NOT reconciled by this function.** Unlike [`emit_cc_plugin`]'s
/// per-spawn `dest` (a fresh directory torn down and recreated on every
/// `csq run`), Kimi's vendor home lives forever across every `csq run` on
/// this slot. Kimi's own `mergeAllAvailableSkills` default (report 13
/// §7.4) means it loads EVERY `skills/<id>/SKILL.md` already present, not
/// just the ones this call wrote — so a skill/command removed from
/// `.coc/` between two invocations keeps loading; this function only ever
/// ADDS/OVERWRITES, it never deletes a stale entry. Reconcile-on-emit
/// (diff `dest`'s existing `skills/csq-*/SKILL.md` — the [`CSQ_OWNED_PREFIX`]
/// namespace, R11 MED-2 — against `arts` and delete anything CSQ-OWNED no
/// longer present) and a per-slot write lock (two concurrent `csq run` on
/// the same slot race unguarded today) are explicit, tracked acceptance
/// criteria for the wiring shard that calls this function — NOT implemented
/// here. **The reconcile MUST filter every delete candidate through
/// [`is_csq_owned_entry`]** — an entry for which it returns `false` MUST
/// NEVER be a delete candidate; deleting it would silently destroy
/// hand-authored user content this emitter never wrote. Note
/// `is_csq_owned_entry`'s own doc comment for its two inherent limitations
/// (a user file literally named `csq-foo` in any case is indistinguishable
/// and WILL be reconciled; on case-sensitive filesystems, the same
/// case-insensitive fold that closes a macOS/Windows collision also
/// over-matches a genuinely distinct `CSQ-foo` on Linux). Do not build
/// reconcile in this PR; this doc comment is the
/// contract the wiring shard must satisfy before this emitter is wired to a
/// live spawn.
///
/// # Caller contract — `dest` is PERSISTENT and credential-bearing
///
/// Unlike [`emit_cc_plugin`]/[`emit_codex_native`]/[`emit_gemini_native`]
/// (whose `dest` is a fresh, disposable per-spawn directory the caller owns
/// for exactly one spawn's lifetime), `dest` here is the slot's
/// PERSISTENT, csq-owned vendor home (`native_home_path`) — created once
/// at `csq login N --provider kimi-cli` and reused by every subsequent
/// `csq run` on that slot. It ALSO holds Kimi's own OAuth credentials,
/// device id, and vendor config, written by Kimi's own login/refresh flow.
/// **It is NOT fresh and MUST NOT be torn down.**
///
/// - **Existing, csq-owned, non-symlink `dest`.** Kimi itself creates its
///   home at `0o700` (`ensureKimiHome`/`mkdirSync(homeDir, {mode: 0o700})`);
///   this emitter does not fight that, it only writes files at `0o600`
///   inside it. This function joins `dest` with fixed relative components
///   and never follows `..`. **R11 MED-1 closed the LEAF-level gap; R-toctou
///   (round-7) closed the remaining check-then-read race in that fix, on
///   Unix.** `write_file_restorable` refuses a pre-existing symlink at each
///   artifact's own path (e.g. `skills/csq-<ID>/SKILL.md`) before the write —
///   on Unix via [`snapshot_prior_if_exists`]'s `O_NOFOLLOW` open, which
///   makes "checked, not a symlink" and "read" the SAME syscall (no window
///   for a same-UID racer to swap the leaf between them); on non-Unix via
///   the original sequential `symlink_metadata`-then-`read` (a documented,
///   un-closed residual window on that platform — see that function's doc
///   comment). Either way, a same-UID plant of the LEAF file cannot redirect
///   the write. **Still open, and still the wiring shard's
///   obligation:** a pre-planted symlink at `dest` ITSELF, or at an
///   intermediate directory (`dest/skills`, `dest/AGENTS.md`'s parent) —
///   `create_dir_all` would still follow such a directory-level symlink and
///   create the leaf underneath an attacker-chosen target. The "same as
///   [`emit_cc_plugin`]" hand-off does NOT transfer: `emit_cc_plugin`'s dest
///   is fresh per-spawn, so a pre-plant is impossible; THIS dest is
///   persistent with an unbounded pre-plant window. Directory-level
///   symlink/TOCTOU hardening (re-stat + refuse-on-symlink on `dest` and
///   every intermediate component before every write, a per-slot write
///   lock, reconcile-on-emit) remains a HARD acceptance criterion of the
///   wiring shard — recorded alongside the audit-parity AC in
///   `launch_native`'s doc comment (run.rs) — not a delegable caller
///   concern.
/// - **On any [`MaterializeError`] this function SELF-CLEANS.** Every file
///   THIS call wrote is removed before the error is returned (tracked
///   internally, mirroring the manifest bookkeeping), so `dest` is left
///   exactly as the caller found it: credentials, device id, vendor
///   config, and any `skills/` content from a PRIOR successful call are
///   untouched. **The caller MUST NOT delete `dest` on error** — doing so
///   destroys the slot's OAuth credentials and logs the account out. The
///   caller's only remaining job on `Err` is to fall back to Level-1 prose
///   delivery — there is nothing left to clean up on its side.
pub fn emit_kimi_native(
    arts: &SurfaceArtifacts,
    dest: &Path,
) -> Result<MaterializedManifest, MaterializeError> {
    let mut manifest = MaterializedManifest::default();
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut prior = PriorContents::new();
    match emit_kimi_native_inner(arts, dest, &mut manifest, &mut seen, &mut prior) {
        Ok(()) => Ok(manifest),
        Err(e) => {
            // `dest` is a PERSISTENT, credential-bearing vendor home (see
            // doc comment above) — self-clean ONLY the files this call
            // wrote so far (restoring any it overwrote); never touch
            // anything else under `dest`.
            cleanup_partial_write(dest, &manifest, &prior);
            Err(e)
        }
    }
}

fn emit_kimi_native_inner(
    arts: &SurfaceArtifacts,
    dest: &Path,
    manifest: &mut MaterializedManifest,
    seen: &mut BTreeMap<String, String>,
    prior: &mut PriorContents,
) -> Result<(), MaterializeError> {
    for s in &arts.skills {
        validate_id(&s.id)?;
        // R11 MED-2 (round-2 review): prefix the CONTENT id, not just the
        // path — `render_skill_file`'s `name:` frontmatter is what Kimi's
        // own skill REGISTRY keys on, so a path-only prefix still lets a
        // csq-emitted `REVIEW` collide with a user-authored `REVIEW` at the
        // registry layer even though their on-disk dirs differ.
        let csq_id = format!("{CSQ_OWNED_PREFIX}{}", s.id);
        // NIT-desc: the RAW id feeds the body-less description fallback —
        // `csq_id` would double-stamp "csq" (see render_frontmatter_file's
        // doc comment).
        let content = render_skill_file(&csq_id, &s.id, "skill", &s.body, false);
        write_file_restorable(
            dest,
            format!("skills/{csq_id}/SKILL.md"),
            &content,
            MaterializedKind::Skill,
            manifest,
            seen,
            prior,
        )?;
    }
    for c in &arts.commands {
        validate_id(&c.id)?;
        let csq_id = format!("{CSQ_OWNED_PREFIX}{}", c.id);
        let content = render_skill_file(&csq_id, &c.id, "command", &c.body, true);
        write_file_restorable(
            dest,
            format!("skills/{csq_id}/SKILL.md"),
            &content,
            MaterializedKind::CommandAsSkill,
            manifest,
            seen,
            prior,
        )?;
    }
    Ok(())
}

/// Best-effort removal of every file recorded in `manifest` (RESTORING
/// any it overwrote from `prior`), used by
/// [`emit_kimi_native`]/[`emit_grok_native`] on failure. Their `dest` is a
/// PERSISTENT, credential-bearing vendor home (see their doc comments), so
/// a failed call MUST leave `dest` in exactly the state it found it —
/// nothing outside `manifest.files` is touched, and `dest` itself is NEVER
/// deleted. Errors during cleanup are swallowed (acceptable per
/// `no-stubs.md`'s cleanup/teardown carve-out): the ORIGINAL
/// [`MaterializeError`] is what the caller needs to see, and a cleanup
/// failure here must not mask it or abort the unwind partway through.
fn cleanup_partial_write(dest: &Path, manifest: &MaterializedManifest, prior: &PriorContents) {
    for rel in manifest.files.keys() {
        if let Some(bytes) = prior.get(rel) {
            // Round-6 MED: this call OVERWROTE a prior artifact and then
            // failed — restore the prior content atomically so `dest` is
            // left exactly as found (the contract this function's doc
            // states), not minus the prior version.
            let abs = dest.join(rel);
            let tmp = crate::platform::fs::unique_tmp_path(&abs);
            let restored = std::fs::write(&tmp, bytes).is_ok()
                && secure_file(&tmp).is_ok()
                && crate::platform::fs::atomic_replace(&tmp, &abs).is_ok();
            if !restored {
                let _ = std::fs::remove_file(&tmp);
                let _ = std::fs::remove_file(&abs);
                // R9 LOW: the restore failed (e.g. ENOSPC, correlated with
                // the emit's own failure) and the prior artifact is now
                // GONE — say so, or the operator never learns a previously
                // working artifact was lost (a csq-owned one regenerates
                // on the next successful emit, but only if they know to
                // retry). Fixed-vocabulary tag; no content interpolation.
                tracing::warn!(
                    error_kind = "materialize_restore_failed",
                    rel_path = rel.as_str(),
                    "emit cleanup could not restore the prior artifact; it was removed — re-run the emit to regenerate it"
                );
            }
            continue;
        }
        let _ = std::fs::remove_file(dest.join(rel));
    }
    // R4-5: also remove any directory THIS call left empty (e.g. a
    // `skills/<ID>/` dir whose only file was just removed) — walk each
    // removed file's ancestors up to `dest`, deepest first. `remove_dir`
    // fails on a non-empty dir, so content from PRIOR successful calls
    // (sibling `skills/<OTHER>/` dirs, `credentials/`) is never disturbed.
    //
    // Round-13 review LOW-2: `remove_dir`-fails-on-non-empty guards CONTENT
    // safety but not IDENTITY safety — a directory that pre-existed this
    // call (e.g. a vendor-created empty `skills/` from Kimi's own
    // home-tree setup) can still end up empty purely because this call's
    // OWN files inside it were just removed above, and the old code would
    // remove it too. `manifest.created_dirs` (populated by `write_file`
    // before its `create_dir_all`) is the authoritative "did THIS call
    // bring this directory into existence" answer — gate removal on it so
    // a pre-existing directory is NEVER a removal candidate, regardless of
    // whether it reads as empty right now.
    // Candidates come from BOTH the written files' parents AND `created_dirs`
    // (round-13 redteam LOW). Deriving them from `files` alone under-covers:
    // `write_file` records a directory before `create_dir_all`, but only
    // inserts into `files` after `atomic_replace` succeeds — so a directory
    // created for a file whose write then failed has no `files` key, is never
    // visited, and survives as an empty csq-created dir. `created_dirs` is the
    // authoritative record of what this call brought into existence, so it is
    // the authoritative candidate list; the membership check below then just
    // filters the `files`-derived ancestors.
    let mut dirs: Vec<std::path::PathBuf> = manifest
        .files
        .keys()
        .filter_map(|rel| std::path::Path::new(rel).parent().map(|p| dest.join(p)))
        .chain(manifest.created_dirs.iter().map(|rel| dest.join(rel)))
        .collect();
    dirs.sort();
    dirs.dedup();
    for dir in dirs.into_iter().rev() {
        let mut current = dir.as_path();
        while current != dest {
            let Ok(rel_dir) = current.strip_prefix(dest) else {
                break;
            };
            let rel_dir_str = rel_dir.to_string_lossy().replace('\\', "/");
            if !manifest.created_dirs.contains(&rel_dir_str) {
                // Not a directory this call created — leave it exactly as
                // found, even if it currently reads as empty.
                break;
            }
            if std::fs::remove_dir(current).is_err() {
                break;
            }
            match current.parent() {
                Some(p) => current = p,
                None => break,
            }
        }
    }
}

/// Emit the Grok-native artifact tree for `arts` rooted at `dest` (`dest` is
/// `$GROK_HOME` — `native_home_path(base, slot, Surface::Grok)`; probe P2 in
/// harness-decomposition report 14 §5.3 empirically verified every artifact
/// kind below loads from a synthetic `GROK_HOME`).
///
/// **Skills, commands, AND agents all materialize natively** — Grok is the
/// best-served non-CC surface csq has (report 14 §6.1): `skills/csq-<ID>/
/// SKILL.md` (identical shape to CC/Codex/Kimi, no degradation needed
/// since Grok has a real command primitive), `commands/csq-<ID>.md` (stem
/// becomes `/csq-<ID>`, simpler than Gemini's TOML shape), and
/// `agents/csq-<ID>.md` as spawnable subagents (YAML frontmatter
/// `name`/`description` — no other non-CC surface today materializes
/// agents natively). Rules stay
/// Level-1 prose (delivered via `GrokSpawnPayload::agents_md`) — see the
/// module doc comment for why the real `.grok/rules/` primitive is not
/// targeted here.
///
/// Every skill, command, AND agent body is checked for the literal `${{`
/// sequence before writing — Grok's `${{ tools.by_kind.<kind> }}` template
/// DSL (report 14 §3.3) substitutes that syntax at spawn time, and the
/// substitution applies to whatever Grok reads from `$GROK_HOME`
/// regardless of which subdir it came from (skills/commands/agents share
/// one read path). Restricting the guard to agents alone would leave
/// skills and commands exposed to the identical collision. A `.coc/` body
/// of any kind that happens to contain it fails closed
/// ([`MaterializeError::TemplateDslCollision`]) rather than shipping an
/// unverified escape.
///
/// **No ephemeral-dir lifecycle — `dest` is persistent, and stale entries
/// are NOT reconciled by this function.** Same caveat as
/// [`emit_kimi_native`]: `dest` lives forever across every `csq run` on
/// this slot rather than being recreated per spawn, and this function is
/// additive-only — it never deletes a `skills/`/`commands/`/`agents/`
/// entry that a prior call wrote but that no longer appears in `arts`.
/// (Grok's own read-side handling of stale entries is not independently
/// verified here the way Kimi's `mergeAllAvailableSkills` default is —
/// report 14 documents the write-side read paths, not a "merge all"
/// setting — but the additive-only behavior of this function holds either
/// way.) Reconcile-on-emit and a per-slot write lock are explicit, tracked
/// acceptance criteria for the wiring shard that calls this function — NOT
/// implemented here. **Same [`is_csq_owned_entry`] filtering requirement as
/// [`emit_kimi_native`] (R11 MED-2):** the reconcile MUST filter every
/// delete candidate through it; a user-authored, unprefixed
/// `skills/`/`commands/`/`agents/` file MUST NEVER be a delete candidate.
///
/// # Caller contract — `dest` is PERSISTENT and credential-bearing
///
/// Same PERSISTENT/credential-bearing shape as [`emit_kimi_native`]'s
/// caller contract (see its doc comment for the full rationale): `dest`
/// here is the slot's persistent vendor home (`native_home_path`), holds
/// Grok's own OAuth state, and MUST NOT be torn down. This function
/// SELF-CLEANS on any [`MaterializeError`] — only the files THIS call
/// wrote are removed before the error is returned; the caller's only job
/// on `Err` is to fall back to Level-1 prose delivery.
pub fn emit_grok_native(
    arts: &SurfaceArtifacts,
    dest: &Path,
) -> Result<MaterializedManifest, MaterializeError> {
    let mut manifest = MaterializedManifest::default();
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut prior = PriorContents::new();
    match emit_grok_native_inner(arts, dest, &mut manifest, &mut seen, &mut prior) {
        Ok(()) => Ok(manifest),
        Err(e) => {
            // `dest` is a PERSISTENT, credential-bearing vendor home (see
            // doc comment above) — self-clean ONLY the files this call
            // wrote so far (restoring any it overwrote); never touch
            // anything else under `dest`.
            cleanup_partial_write(dest, &manifest, &prior);
            Err(e)
        }
    }
}

fn emit_grok_native_inner(
    arts: &SurfaceArtifacts,
    dest: &Path,
    manifest: &mut MaterializedManifest,
    seen: &mut BTreeMap<String, String>,
    prior: &mut PriorContents,
) -> Result<(), MaterializeError> {
    // MED-M: pre-flight the `${{` template-DSL scan across EVERY skill,
    // command, AND agent BEFORE writing any of them. The prior shape
    // interleaved the scan with the write loop (validate item N, write
    // item N, validate item N+1, …), so a collision on a LATER artifact
    // left EARLIER artifacts already written to disk when the error
    // propagated — self-cleaned by the caller (`emit_grok_native`'s doc
    // comment) but still an order-dependent partial write during the call
    // itself. Scanning everything first makes "a rejected artifact set
    // writes nothing" true by construction, not merely true-after-cleanup.
    for s in &arts.skills {
        check_no_template_dsl(&s.id, "skill", &s.body)?;
    }
    for c in &arts.commands {
        check_no_template_dsl(&c.id, "command", &c.body)?;
    }
    for a in &arts.agents {
        check_no_template_dsl(&a.id, "agent", &a.body)?;
    }

    for s in &arts.skills {
        validate_id(&s.id)?;
        // R11 MED-2 (round-2 review): prefix the CONTENT id — see the
        // matching comment in `emit_kimi_native_inner`.
        let csq_id = format!("{CSQ_OWNED_PREFIX}{}", s.id);
        // NIT-desc: RAW id for the description fallback, csq_id for name/path.
        let content = render_skill_file(&csq_id, &s.id, "skill", &s.body, false);
        write_file_restorable(
            dest,
            format!("skills/{csq_id}/SKILL.md"),
            &content,
            MaterializedKind::Skill,
            manifest,
            seen,
            prior,
        )?;
    }
    for c in &arts.commands {
        validate_id(&c.id)?;
        // Grok has a real command primitive — no degradation, unlike Kimi.
        let csq_id = format!("{CSQ_OWNED_PREFIX}{}", c.id);
        let content = render_component_file(&csq_id, &c.id, "command", &c.body, false);
        write_file_restorable(
            dest,
            format!("commands/{csq_id}.md"),
            &content,
            MaterializedKind::Command,
            manifest,
            seen,
            prior,
        )?;
    }
    for a in &arts.agents {
        validate_id(&a.id)?;
        let csq_id = format!("{CSQ_OWNED_PREFIX}{}", a.id);
        let content = render_component_file(&csq_id, &a.id, "agent", &a.body, true);
        write_file_restorable(
            dest,
            format!("agents/{csq_id}.md"),
            &content,
            MaterializedKind::Agent,
            manifest,
            seen,
            prior,
        )?;
    }
    Ok(())
}

/// Fails closed with [`MaterializeError::TemplateDslCollision`] when `body`
/// contains the literal `${{` sequence — Grok's template-substitution
/// marker (report 14 §3.3). Shared by every artifact kind
/// [`emit_grok_native`] writes (MED-E: previously agent-only, which left
/// skills and commands exposed to the identical collision even though they
/// land under the same `$GROK_HOME` read path).
///
/// `pub` for the wiring shard (R7): `GrokSpawnPayload.agents_md` carries
/// rule prose this crate does not render, so the `$GROK_HOME/AGENTS.md`
/// write in `run.rs` MUST run this same pre-flight over that body —
/// see `launch_native`'s "Additional wiring-shard obligations".
pub fn check_no_template_dsl(
    id: &str,
    kind: &'static str,
    body: &str,
) -> Result<(), MaterializeError> {
    if body.contains("${{") {
        return Err(MaterializeError::TemplateDslCollision {
            id: id.to_string(),
            kind,
        });
    }
    Ok(())
}

/// Write one file at `dest/rel` with `content`, chmod 0o600, and record it in
/// the manifest. Rejects case-insensitive collisions against already-written
/// paths.
/// Prior content of a file an emit overwrote, for restore-on-failure
/// (round-6 MED). Keyed by the same POSIX relative path as the manifest.
type PriorContents = BTreeMap<String, Vec<u8>>;

/// [`write_file`] plus the snapshot the persistent-dest emitters need to
/// honor their "leave `dest` exactly as found" contract: if a file
/// already exists at `rel` (a PRIOR successful call's artifact), its
/// content is recorded so [`cleanup_partial_write`] can RESTORE it when
/// this call fails after overwriting. Without the snapshot the cleanup
/// would delete the file outright, silently unloading the prior
/// artifact (the round-6 MED: overwrite-then-fail lost the valid
/// previous version).
/// NOTE (R7 NIT): the restore in [`cleanup_partial_write`] is
/// unconditional — if a same-UID third party edits the file BETWEEN this
/// call's overwrite and a later failure in the same call, the stale
/// snapshot is written back over their edit. The window is sub-second
/// (the emit is in-process, no awaits; the vendor CLI writes its home at
/// spawn/exit, not during csq's pre-spawn emit) and the wiring shard's
/// per-slot write lock (see `launch_native`) closes the realistic racer
/// (a concurrent `csq run` on the same slot).
///
/// R11 MED-1, hardened by R-toctou (round-7 review): the pre-write snapshot
/// read refuses a symlink at `abs`, and does so WITHOUT the check-then-read
/// gap the original `symlink_metadata` + `std::fs::read` pair left open.
/// `std::fs::read` FOLLOWS symlinks, and the snapshot is not inert —
/// [`cleanup_partial_write`] can write it back out as a REAL 0o600 file on a
/// later failure in this same call. Without the check, a same-UID process
/// that planted e.g. `<KIMI_CODE_HOME>/skills/REVIEW/SKILL.md` as a symlink
/// to `<KIMI_CODE_HOME>/credentials.json` (or `~/.ssh/id_ed25519`) would
/// have that target's plaintext captured into `prior`, and a subsequent
/// failure (e.g. a later artifact's `FilenameCollision`) would materialize
/// it as a real file inside the tree the vendor CLI enumerates as skill
/// content — model-visible.
///
/// **On Unix, the check IS the read** ([`snapshot_prior_if_exists`]):
/// `abs` is opened with `O_NOFOLLOW`, which makes the kernel refuse to open
/// a path whose final component is a symlink — there is no window between
/// "checked, not a symlink" and "read" for a same-UID racer to swap the
/// target in, because those are now one syscall instead of two
/// (`lstat` + `open`, R11 MED-1's original sequential form). **On
/// non-Unix, the sequential `symlink_metadata`-then-`read` form is kept**
/// (no portable single-syscall no-follow-open exists via std) — the
/// documented residual TOCTOU window on that platform, not claimed closed.
fn write_file_restorable(
    dest: &Path,
    rel: String,
    content: &str,
    kind: MaterializedKind,
    manifest: &mut MaterializedManifest,
    seen: &mut BTreeMap<String, String>,
    prior: &mut PriorContents,
) -> Result<(), MaterializeError> {
    let abs = dest.join(&rel);
    snapshot_prior_if_exists(&abs, &rel, prior)?;
    write_file(dest, rel, content, kind, manifest, seen)
}

/// Records `abs`'s current content into `prior` (keyed by `rel`) if a
/// regular file already exists there, refusing (never reading through) a
/// symlink. See [`write_file_restorable`] for why this snapshot cannot be
/// allowed to follow a symlink.
///
/// **Unix: atomic check-and-read.** `abs` is opened with `O_NOFOLLOW`, so a
/// symlink at the final path component fails the `open` call itself
/// (`ELOOP`, and — defensively, in case a platform variant surfaces it
/// differently for a same-shape condition — `ENOTDIR`) rather than being
/// discovered by a separate `lstat` that a racer can invalidate before the
/// following `read`. A missing file (`ENOENT`) is the benign no-snapshot
/// case (nothing to restore later), not an error. Any OTHER io error (e.g.
/// permission denied) is surfaced as [`MaterializeError::Io`] rather than
/// silently treated as "no prior content" — an unexpected failure to read
/// an existing file is not the same condition as the file not existing.
///
/// **Non-Unix: sequential fallback, TOCTOU window open.** No portable
/// single-syscall no-follow-open exists via std, so this falls back to the
/// pre-R-toctou sequential form (`symlink_metadata` then `read`) — a
/// same-UID racer with a sub-syscall window could still swap a symlink in
/// between the two calls on this platform. Documented, not claimed closed;
/// the realistic racer (a concurrent `csq run` on the same slot) is the
/// wiring shard's per-slot write lock, same as the sub-second window noted
/// above for the overwrite-restore race.
fn snapshot_prior_if_exists(
    abs: &Path,
    rel: &str,
    prior: &mut PriorContents,
) -> Result<(), MaterializeError> {
    #[cfg(unix)]
    {
        use std::io::Read as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(abs)
        {
            Ok(mut f) => {
                let mut bytes = Vec::new();
                match f.read_to_end(&mut bytes) {
                    Ok(_) => {
                        prior.insert(rel.to_string(), bytes);
                        Ok(())
                    }
                    // LOW-1 (round-13 review): `open` succeeding is not the
                    // same guarantee as `read_to_end` succeeding — an
                    // `O_NOFOLLOW` open of a DIRECTORY at `abs` succeeds and
                    // then `read_to_end` fails `EISDIR` (likewise any other
                    // read-time error, e.g. `EIO`). Swallowing that error
                    // silently treated it as "no prior content", which
                    // re-opens the exact round-6 MED this snapshot exists to
                    // prevent: no snapshot recorded means a LATER failure in
                    // the same call has nothing to restore, and
                    // `cleanup_partial_write` deletes the artifact this call
                    // overwrote instead of restoring it. Surface it as `Io`,
                    // matching the doc comment above.
                    Err(e) => Err(MaterializeError::Io {
                        path: redact_path(abs),
                        source: e,
                    }),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            // ELOOP is the O_NOFOLLOW-hit-a-symlink signal — the credential
            // redirection this guard exists for. ENOTDIR is a DIFFERENT
            // condition: a non-final path component is not a directory,
            // typically a leftover regular file where an artifact dir belongs.
            // Round 6 found these folded together, so an ordinary file
            // collision was reported as "a symlink exists at this path" — a
            // claim that is false, unfalsifiable from the operator's side, and
            // points at the wrong remedy. Kept fail-closed either way; only
            // the diagnosis is split.
            Err(e) if matches!(e.raw_os_error(), Some(code) if code == libc::ELOOP) => {
                Err(MaterializeError::SymlinkAtDest {
                    path: redact_path(abs),
                })
            }
            Err(e) if matches!(e.raw_os_error(), Some(code) if code == libc::ENOTDIR) => {
                Err(MaterializeError::NonDirectoryInPath {
                    path: redact_path(abs),
                })
            }
            Err(e) => Err(MaterializeError::Io {
                path: redact_path(abs),
                source: e,
            }),
        }
    }
    #[cfg(not(unix))]
    {
        // This branch used to be two `if let Ok(...)` arms that DISCARDED both
        // errors and returned `Ok(())` regardless — the exact silent swallow
        // the unix arm above documents at length as re-opening the defect this
        // snapshot exists to prevent: "no snapshot recorded means a LATER
        // failure in the same call has nothing to restore, and
        // `cleanup_partial_write` deletes the artifact this call overwrote
        // instead of restoring it." The unix side was fixed; Windows was left
        // behind, so the same call was fail-closed on one platform and
        // fail-open on the other.
        //
        // Found because a round-6 regression test asserting the ENOTDIR
        // diagnosis passed on macOS and failed on windows-latest: the two
        // platforms genuinely disagreed about what this function does. Both
        // arms now classify the same three outcomes, so the test is one
        // cross-platform assertion rather than a unix-only one.
        match std::fs::symlink_metadata(abs) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(MaterializeError::SymlinkAtDest {
                    path: redact_path(abs),
                });
            }
            Ok(_) => {}
            // Nothing at `abs` yet — the ordinary first-write case.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            // A component of the path is not a directory (a regular file in
            // the way). Windows surfaces this as `NotADirectory` for the same
            // condition unix reports as ENOTDIR.
            Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => {
                return Err(MaterializeError::NonDirectoryInPath {
                    path: redact_path(abs),
                });
            }
            Err(e) => {
                return Err(MaterializeError::Io {
                    path: redact_path(abs),
                    source: e,
                });
            }
        }
        match std::fs::read(abs) {
            Ok(bytes) => {
                prior.insert(rel.to_string(), bytes);
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => {
                Err(MaterializeError::NonDirectoryInPath {
                    path: redact_path(abs),
                })
            }
            // Anything else (EISDIR on a directory at `abs`, an IO error) is
            // surfaced, matching the unix arm rather than being swallowed.
            Err(e) => Err(MaterializeError::Io {
                path: redact_path(abs),
                source: e,
            }),
        }
    }
}

/// Writes one artifact file ATOMICALLY (tmp + secure 0o600 + rename).
///
/// R4/D4-4: the persistent-dest emitters write into credential-bearing
/// vendor homes (`<KIMI_CODE_HOME>`, `$GROK_HOME`), so the credential-file
/// discipline (security.md §4) is the right standard even though the
/// payload itself is non-secret prose: a plain `std::fs::write` leaves a
/// truncated file behind on SIGKILL/power loss, and no reconcile pass is
/// wired to detect it. Once the wiring shard lands, kimi_merge's merged
/// `config.toml` output (which DOES carry OAuth wiring) MUST also go
/// through an atomic path — never a bare write.
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
        // Round-13 review LOW-2: record which ancestor directories (dest or
        // below) do NOT yet exist BEFORE `create_dir_all` creates them, so
        // `cleanup_partial_write` can restrict its empty-directory removal
        // to directories THIS call created. Without this, a pre-existing
        // (possibly vendor-created) empty directory — e.g. Kimi's own
        // `skills/` from its home-tree setup — that merely ENDS UP empty
        // after this call's own files inside it are cleaned up would be
        // removed too, violating this module's "leave `dest` exactly as
        // found" contract for content this call never created.
        let mut to_create: Vec<std::path::PathBuf> = Vec::new();
        let mut current = parent;
        while current.starts_with(dest) && !current.exists() {
            to_create.push(current.to_path_buf());
            match current.parent() {
                Some(p) => current = p,
                None => break,
            }
        }
        // CREATION ITSELF IS THE EVIDENCE OF AUTHORSHIP — not the `!exists()`
        // probe above (round-4 redteam).
        //
        // An earlier version recorded every path in `to_create` before calling
        // `create_dir_all`, justified as: "each pushed path was observed absent
        // moments earlier, so if it exists afterwards this call made it." That
        // is false whenever anything else creates the path inside the window
        // between the probe and the create — and this module documents exactly
        // such a racer: two concurrent `csq run` on the same slot are unguarded
        // today (see the per-slot write-lock note), and the protected subject is
        // literally "a vendor-created empty `skills/` from Kimi's own home-tree
        // setup". If the vendor created `skills/` inside that window, `skills`
        // was still in `created_dirs`, and a later partial-write cleanup would
        // `remove_dir` it once this call's own files inside it were removed —
        // deleting a directory csq did not create, which is the precise
        // contract violation the recording exists to prevent.
        //
        // So create one component at a time, shallowest first, and record ONLY
        // what `create_dir` reports as newly created. `Ok(())` is proof of
        // authorship; `AlreadyExists` means someone else owns it, so it is
        // neither recorded nor ever a removal candidate. This also subsumes the
        // non-atomic-`create_dir_all` case the previous ordering was written
        // for: with per-component recording there is no window between
        // observing and creating, so a mid-chain failure still leaves every
        // component this call actually made recorded.
        for created in to_create.iter().rev() {
            match std::fs::create_dir(created) {
                Ok(()) => {
                    if let Ok(rel_dir) = created.strip_prefix(dest) {
                        // `dest.strip_prefix(dest)` is `""` when `dest` itself
                        // was absent. Cleanup's `while current != dest` never
                        // looks it up, but an empty entry would make the
                        // field's stated invariant false.
                        if !rel_dir.as_os_str().is_empty() {
                            manifest
                                .created_dirs
                                .insert(rel_dir.to_string_lossy().replace('\\', "/"));
                        }
                    }
                }
                // Lost the race (or the probe was stale): the directory exists
                // but this call did not make it. Do not record it.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(MaterializeError::Io {
                        // R11 LOW-1: redact at construction so every caller
                        // (today: run.rs's `anyhow!("materializing ...: {e}")`
                        // chains) inherits the redaction automatically.
                        path: redact_path(created),
                        source: e,
                    });
                }
            }
        }
        // ASSERT the chain exists — do NOT create it (round-5 redteam).
        //
        // This was a `create_dir_all(parent)` backstop, which reopened a narrow
        // version of the very bug the loop above closes: `create_dir_all`
        // recurses internally and records NOTHING, so if a racer DELETED an
        // ancestor between the loop's last iteration and this call, this call
        // would silently recreate it un-recorded — and a later
        // `cleanup_partial_write` would then remove a directory csq cannot
        // prove it created. Smaller window and a rarer racer (delete, not
        // create) than the original defect, but the identical contract
        // violation, so it is closed rather than argued down.
        //
        // Removing the creation loses no coverage: `to_create` is seeded with
        // `parent` itself and walks upward, so whenever `parent` is absent and
        // under `dest` it is the FIRST element the loop creates. (`parent` is
        // always under `dest` — the `UnsafeId` guard rejects any id that would
        // escape it.)
        //
        // Round-6 correction: the earlier version of this branch asserted a
        // SINGLE cause — "removed concurrently" — and that premise is
        // incomplete. The loop above walks upward while
        // `current.starts_with(dest) && !current.exists()`, and
        // `Path::exists()` does not distinguish a file from a directory. So if
        // `parent` is ALREADY OCCUPIED BY A REGULAR FILE before this call
        // starts — leftover cruft or a user-planted file in one of the
        // PERSISTENT vendor homes `emit_kimi_native` / `emit_grok_native`
        // write into — the `while` sees `exists() == true`, `to_create` stays
        // empty, nothing is attempted, and control lands here with
        // `is_dir() == false` for a path that was never a directory and that
        // nothing removed. Deterministic, reproducible every time, no race.
        //
        // Reporting that as a race is actively misleading: retrying will never
        // clear it, and the operator needs to remove or rename the blocking
        // entry. Distinguish the two states and say which one happened.
        //
        // (A file blocking a MID-chain ancestor is NOT this branch — it is
        // caught earlier by `create_dir`'s real OS error, `ENOTDIR`, which is
        // surfaced verbatim. Only the leaf `parent` reaches here.)
        if !parent.is_dir() {
            let (kind, detail) = match parent.symlink_metadata() {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
                    std::io::ErrorKind::NotFound,
                    "parent directory absent after the creation loop — it was \
                     removed concurrently; refusing to recreate it un-recorded",
                ),
                Ok(_) => (
                    std::io::ErrorKind::AlreadyExists,
                    "a non-directory entry already occupies the parent path — \
                     this is not a race and retrying will not clear it; remove \
                     or rename the blocking entry",
                ),
                Err(_) => (
                    std::io::ErrorKind::Other,
                    "parent path could not be inspected after the creation \
                     loop; refusing to write beneath an unverified parent",
                ),
            };
            return Err(MaterializeError::Io {
                path: redact_path(parent),
                source: std::io::Error::new(kind, detail),
            });
        }
    }
    let tmp = crate::platform::fs::unique_tmp_path(&abs);
    if let Err(e) = std::fs::write(&tmp, content) {
        let _ = std::fs::remove_file(&tmp);
        return Err(MaterializeError::Io {
            path: redact_path(&abs),
            source: e,
        });
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(MaterializeError::Secure {
            path: redact_path(&abs),
            reason: e.to_string(),
        });
    }
    if let Err(e) = crate::platform::fs::atomic_replace(&tmp, &abs) {
        let _ = std::fs::remove_file(&tmp);
        return Err(MaterializeError::Secure {
            path: redact_path(&abs),
            reason: e.to_string(),
        });
    }

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

    /// R11 NIT-1 non-vacuity (round-2 review): pins BOTH halves of the
    /// "Scope note" added to `yaml_double_quoted`'s doc comment — Cc
    /// (Control) bytes ARE escaped; Cf (Format) characters (RLO here) pass
    /// through UNESCAPED, deliberately, because they carry no
    /// quote/backslash/line-break semantics and so cannot break out of the
    /// quoted scalar. Without this test the Cf-passthrough half of the doc
    /// claim has no behavioral anchor — the only prior test
    /// (`synthesized_description_escapes_control_bytes`) pins the Cc half
    /// alone, so a future reader could "fix" the perceived gap and the
    /// doc's "deliberate, not an oversight" reasoning would go stale with
    /// no test to catch it.
    #[test]
    fn yaml_double_quoted_escapes_cc_but_not_cf() {
        // Cc — ESC (U+001B) — MUST be escaped as `\xNN`.
        assert_eq!(yaml_double_quoted("x\u{1b}y"), "\"x\\x1By\"");
        // Cf — RLO (U+202E) — MUST pass through unescaped.
        assert_eq!(yaml_double_quoted("x\u{202e}y"), "\"x\u{202e}y\"");
    }

    /// R11 NIT-1 non-vacuity, TOML twin: same Cc/Cf pinning for
    /// `toml_basic_quoted`'s matching "Scope note".
    #[test]
    fn toml_basic_quoted_escapes_cc_but_not_cf() {
        // Cc — ESC (U+001B) — MUST be escaped as `\uNNNN`.
        assert_eq!(toml_basic_quoted("x\u{1b}y"), "\"x\\u001By\"");
        // Cf — RLO (U+202E) — MUST pass through unescaped.
        assert_eq!(toml_basic_quoted("x\u{202e}y"), "\"x\u{202e}y\"");
    }

    /// LOW-J: `render_skill_file(.., false)` and `render_component_file(..,
    /// true)` must stay byte-identical — both build on the shared
    /// `render_frontmatter_file` substrate now, so a frontmatter change to
    /// one cannot silently diverge the other (previously two independently
    /// maintained functions that happened to agree).
    #[test]
    fn render_skill_file_matches_render_component_file_when_not_disabled() {
        let a = render_skill_file("ID-X", "ID-X", "skill", "body text\nmore\n", false);
        let b = render_component_file("ID-X", "ID-X", "skill", "body text\nmore\n", true);
        assert_eq!(a, b);
    }

    /// S2b: native rule emission — path-scoped rules get `paths:` frontmatter
    /// (CC activates on matching file reads); unscoped rules are bare-body
    /// (always-on). Filenames are `coc-`-prefixed; files are 0o600.
    ///
    /// CHANGED (provenance increment): the body is now wrapped in a
    /// `csq:coc-source` provenance boundary naming the rule's id (see the
    /// `provenance` module) — the frontmatter/no-frontmatter shape and the
    /// filename/permission contract this test pins are otherwise unchanged.
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

        // Path-scoped → YAML `paths:` frontmatter + provenance-wrapped body.
        assert_eq!(
            fs::read_to_string(dest.join("coc-RULE-SCOPED.md")).unwrap(),
            "---\npaths:\n  - \"src/**/*.rs\"\n  - \"lib/**\"\n---\n\n\
             <!-- csq:coc-source id=\"RULE-SCOPED\" -->\n\
             # RULE-SCOPED\nScoped body.\n\
             <!-- /csq:coc-source id=\"RULE-SCOPED\" -->\n"
        );
        // Unscoped → no frontmatter, but still provenance-wrapped (CC loads
        // it always-on either way).
        assert_eq!(
            fs::read_to_string(dest.join("coc-RULE-UNSCOPED.md")).unwrap(),
            "<!-- csq:coc-source id=\"RULE-UNSCOPED\" -->\n\
             Always on.\n\
             <!-- /csq:coc-source id=\"RULE-UNSCOPED\" -->\n"
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

    /// Round-5 F3: the shared write_file path guarantees 0o600 for the
    /// native emitters too — pinned directly, because "shares an
    /// implementation" is a property of the current code, not a
    /// guarantee (the same logic that justified the grok self-clean
    /// twin test).
    #[test]
    fn written_files_are_0600_for_native_emitters() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for emit in [
                emit_kimi_native
                    as fn(
                        &SurfaceArtifacts,
                        &Path,
                    ) -> Result<MaterializedManifest, MaterializeError>,
                emit_grok_native,
            ] {
                let dir = tempfile::tempdir().unwrap();
                let dest = dir.path();
                let manifest = emit(&sample(), dest).unwrap();
                for rel in manifest.files.keys() {
                    let mode = fs::metadata(dest.join(rel)).unwrap().permissions().mode() & 0o777;
                    assert_eq!(mode, 0o600, "native-emitted file {rel} must be 0o600");
                }
            }
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

    /// R11 LOW-1 non-vacuity: `MaterializeError` MUST NOT leak an unredacted
    /// absolute `$HOME`-rooted path — every `Io`/`Secure` variant is
    /// constructed with `redact_path` at the point of construction, so every
    /// caller (today: `run.rs`'s `anyhow!("materializing ...: {e}")` chains)
    /// inherits the redaction automatically rather than having to remember to
    /// wrap `{e}` itself.
    ///
    /// Round-2 review: rooted via `tempfile::tempdir_in(&home)`, NOT a bare
    /// `tempfile::tempdir()` — the latter roots under `$TMPDIR`
    /// (`/var/folders/...` on macOS, `/tmp` on Linux), which shares NO prefix
    /// with `$HOME`. `redact_path` only rewrites a `$HOME`-rooted prefix, so
    /// against a bare tempdir "the rendered string contains no raw home path"
    /// would pass whether or not redaction ran at all — vacuously. Rooting
    /// under `$HOME` makes the assertion actually exercise the substitution,
    /// which the test also confirms in the POSITIVE direction (`contains
    /// "~/"`), not just the negative one.
    #[test]
    fn materialize_error_display_never_leaks_raw_home_path() {
        let home = std::env::var("HOME").expect("HOME must be set in the test environment");
        let dir = tempfile::tempdir_in(&home).expect("tempdir rooted under $HOME");
        let dest = dir.path();

        // Force a `create_dir_all` failure: plant a REGULAR FILE at
        // `dest/skills`, so the skill emitter's `skills/<id>/` directory
        // creation fails with "not a directory" instead of succeeding —
        // hitting the `MaterializeError::Io` mkdir-failure branch.
        std::fs::write(dest.join("skills"), b"not a directory").unwrap();
        let mut arts = SurfaceArtifacts::default();
        arts.skills.push(art("SKILL-BLOCKED", "body"));
        let err = emit_cc_plugin(&arts, dest).unwrap_err();
        assert!(matches!(err, MaterializeError::Io { .. }));
        let rendered = err.to_string();

        assert!(
            !rendered.contains(&home),
            "MaterializeError::Display leaked the raw $HOME path: {rendered:?}"
        );
        assert!(
            rendered.contains("~/"),
            "expected the $HOME prefix redacted to `~/`, got: {rendered:?}"
        );
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

    /// S3/S4 (+ Kimi/Grok): every native emitter produces byte-deterministic
    /// trees.
    #[test]
    fn native_emitters_are_byte_deterministic() {
        for emit in [
            emit_codex_native as fn(&SurfaceArtifacts, &Path) -> _,
            emit_gemini_native,
            emit_kimi_native,
            emit_grok_native,
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

    /// S3/S4 (+ Kimi/Grok): id validation + case-collision defense apply to
    /// every native emitter (shared `validate_id` / `write_file` substrate).
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
        assert!(matches!(
            emit_kimi_native(&arts, dir.path()).unwrap_err(),
            MaterializeError::UnsafeId { .. }
        ));
        assert!(matches!(
            emit_grok_native(&arts, dir.path()).unwrap_err(),
            MaterializeError::UnsafeId { .. }
        ));
    }

    // ── Kimi-native emitter ─────────────────────────────────────────────

    /// Kimi materializes skills natively AND degrades commands to skills
    /// with `disable-model-invocation: true` (no native command primitive;
    /// report 13 §3.5/§6.1). Agents/rules stay prose — no `agents/` or
    /// `rules/` dir is written.
    #[test]
    fn emit_kimi_native_writes_skills_and_degrades_commands() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        let manifest = emit_kimi_native(&sample(), dest).unwrap();

        // One real skill + one command-degraded-to-skill = 2 files.
        assert_eq!(manifest.len(), 2);
        assert!(!dest.join(".claude-plugin").exists());
        assert!(!dest.join("agents").exists(), "agents stay prose");
        assert!(!dest.join("rules").exists(), "rules stay prose");

        // Real skill: no disable-model-invocation line. R11 MED-2 (round-2
        // review): BOTH the on-disk dir AND the synthesized `name:` are
        // `csq-`-prefixed — Kimi's own skill REGISTRY keys on `name:`, so a
        // path-only prefix would still let this collide with a user-authored
        // `REVIEW`-shaped skill at the registry layer even with distinct
        // on-disk dirs.
        let skill = fs::read_to_string(dest.join("skills/csq-SKILL-Z/SKILL.md")).unwrap();
        assert_eq!(
            skill,
            "---\nname: \"csq-SKILL-Z\"\ndescription: \"progressive disclosure\"\n---\n\n# skill\nprogressive disclosure\n"
        );
        assert!(
            skill.starts_with("---\nname: \"csq-SKILL-Z\"\n"),
            "frontmatter name MUST carry the csq- prefix (registry-collision fix): {skill:?}"
        );
        assert_eq!(
            manifest.files.get("skills/csq-SKILL-Z/SKILL.md"),
            Some(&MaterializedKind::Skill)
        );

        // Degraded command: same SKILL.md shape, PLUS disable-model-invocation.
        // Consequence of the `name:` prefix: user-invocable as
        // `/skill:csq-COMMAND-W`, not `/skill:COMMAND-W`.
        let cmd = fs::read_to_string(dest.join("skills/csq-COMMAND-W/SKILL.md")).unwrap();
        assert_eq!(
            cmd,
            "---\nname: \"csq-COMMAND-W\"\ndescription: \"run the thing\"\ndisable-model-invocation: true\n---\n\nrun the thing\n"
        );
        assert_eq!(
            manifest.files.get("skills/csq-COMMAND-W/SKILL.md"),
            Some(&MaterializedKind::CommandAsSkill)
        );
    }

    /// A skill id and a command id that collide under the shared
    /// `skills/<id>/SKILL.md` namespace MUST be caught as a filename
    /// collision, not silently overwrite one another.
    #[test]
    fn emit_kimi_native_rejects_skill_command_id_collision() {
        let dir = tempfile::tempdir().unwrap();
        let mut arts = SurfaceArtifacts::default();
        arts.skills.push(art("SAME-ID", "skill body"));
        arts.commands.push(art("SAME-ID", "command body"));
        let err = emit_kimi_native(&arts, dir.path()).unwrap_err();
        assert!(matches!(err, MaterializeError::FilenameCollision { .. }));
    }

    #[test]
    fn emit_kimi_native_empty_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut arts = SurfaceArtifacts::default();
        arts.agents.push(art("AGENT-Y", "persona"));
        let manifest = emit_kimi_native(&arts, dir.path()).unwrap();
        assert!(manifest.is_empty(), "agents-only input writes nothing");
        assert!(!dir.path().join("skills").exists());
    }

    /// HIGH-A non-vacuity: `dest` for Kimi is a PERSISTENT,
    /// credential-bearing vendor home (unlike `emit_cc_plugin`'s disposable
    /// per-spawn `dest`). A partial failure MUST self-clean only the files
    /// THIS call wrote and MUST NOT touch pre-existing sibling content
    /// (stand-in for `credentials/`, `oauth/`, `device_id`) or `dest`
    /// itself. Two artifacts: the first (a real skill) succeeds and gets
    /// written; the second (an unsafe id) fails — proving the first
    /// artifact's file is removed on unwind while the pre-existing
    /// credential-like file survives untouched.
    #[test]
    fn emit_kimi_native_self_cleans_partial_write_on_error() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        // Stand-in for Kimi's own persistent credential state — must survive.
        fs::create_dir_all(dest.join("credentials")).unwrap();
        fs::write(dest.join("credentials/oauth.json"), "secret-token").unwrap();

        let mut arts = SurfaceArtifacts::default();
        arts.skills.push(art("SKILL-OK", "a real skill"));
        arts.commands.push(art("../escape", "unsafe id"));

        let err = emit_kimi_native(&arts, dest).unwrap_err();
        assert!(matches!(err, MaterializeError::UnsafeId { .. }));

        assert!(
            !dest.join("skills/csq-SKILL-OK/SKILL.md").exists(),
            "partial write from the failed call must be self-cleaned"
        );
        assert_eq!(
            fs::read_to_string(dest.join("credentials/oauth.json")).unwrap(),
            "secret-token",
            "credential-bearing sibling content must survive a failed materialize call"
        );
        assert!(
            dest.exists(),
            "dest (the persistent vendor home) must not be deleted"
        );
    }

    /// Every directory in a MULTI-COMPONENT chain that this call created is
    /// removed when the call later fails — not just the leaf.
    ///
    /// Round-4 redteam (testing lens): the two pre-existing cleanup tests both
    /// assert only on the leaf FILE, so neither could observe whether the
    /// intermediate `skills/` directory was recorded and removed. This one
    /// asserts the whole chain, which is what per-component recording now
    /// guarantees: `create_dir` returning `Ok(())` is the authorship record.
    ///
    /// Note on scope, stated rather than implied: the concurrent interleaving
    /// that motivated the change (a vendor creating `skills/` between the
    /// probe and the create) is not deterministically reproducible in a unit
    /// test. What IS testable — and is tested here and in
    /// `..._does_not_remove_preexisting_empty_vendor_dir` — is the pair of
    /// invariants the fix rests on: a directory this call created is removed,
    /// and a directory it did not create is never touched.
    /// Round-6 (rust lens): the leaf-parent guard used to assert a single
    /// cause — "removed concurrently" — for a branch that a DETERMINISTIC,
    /// non-racy state also reaches. A regular file sitting at the artifact's
    /// parent path makes `Path::exists()` true, so the upward creation walk
    /// creates nothing and the guard fires with a race diagnosis for a
    /// collision that will reproduce on every run and that retrying can never
    /// clear.
    ///
    /// This is the persistent-vendor-home case specifically: `emit_kimi_native`
    /// writes into a dir it MUST NOT tear down, so leftover cruft at
    /// `skills/csq-<ID>` is reachable state, not a hypothetical.
    ///
    /// Asserts the DIAGNOSIS, not merely that it failed — the pre-fix code
    /// also failed here, just while telling the operator the wrong thing.
    #[test]
    fn leaf_parent_blocked_by_a_regular_file_is_not_reported_as_a_race() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        // Persistent vendor home, pre-populated the way a real one would be.
        fs::create_dir_all(dest.join("skills")).unwrap();
        // A REGULAR FILE exactly where the skill's directory belongs.
        fs::write(dest.join("skills/csq-SKILL-Z"), b"leftover cruft").unwrap();

        let mut arts = SurfaceArtifacts::default();
        arts.skills.push(art("SKILL-Z", "a real skill"));
        let err = emit_kimi_native(&arts, dest).unwrap_err();

        // Asserts the PROPERTY, not the variant — the two platforms reach the
        // same correct outcome through DIFFERENT guards, and pinning one
        // variant made this test fail on Windows for a non-defect (two CI
        // rounds spent learning that):
        //
        //   unix    — `symlink_metadata` on `<file>/SKILL.md` yields ENOTDIR,
        //             so the snapshot's O_NOFOLLOW arm classifies it first
        //             -> `NonDirectoryInPath`
        //   Windows — the same call reports NotFound, so the snapshot passes
        //             and the later leaf-parent guard catches it
        //             -> `Io { AlreadyExists, "a non-directory entry ..." }`
        //
        // Both are honest and both name the same remedy. What must hold on
        // EVERY platform is that the operator is not told "symlink" and IS
        // told something actionable — so that is what is asserted.
        let msg = err.to_string();
        assert!(
            !msg.contains("symlink"),
            "there is no symlink in this fixture — claiming one sends the \
             operator hunting for a file that does not exist. Got: {msg:?}"
        );
        // Asserts the REMEDY clause, not the condition. Round 7 caught that
        // the earlier `contains("not a directory")` disjunction survived
        // "delete the ENOTDIR arm entirely" only by ACCIDENT: the raw OS
        // error renders `"Not a directory (os error 20)"` with a capital N,
        // so the lowercase needle missed it. Lowercase that phrasing anywhere,
        // or run on a libc whose string differs, and the mutation starts
        // passing — a one-capital-letter margin.
        //
        // `remove or rename` appears in BOTH platforms' wordings and cannot be
        // produced by a raw `io::Error`, so it separates "our actionable
        // diagnosis" from "whatever the OS said" with no accidental margin.
        assert!(
            msg.contains("remove or rename"),
            "expected an actionable diagnosis naming the REMEDY (a raw OS \
             error cannot produce this), got: {msg:?}"
        );
        // Fails closed: the blocking file is left exactly as found.
        assert_eq!(
            fs::read(dest.join("skills/csq-SKILL-Z")).unwrap(),
            b"leftover cruft",
            "the blocking entry must never be overwritten"
        );
    }

    /// The kimi/grok emitters never reach the leaf-parent guard — their
    /// pre-write snapshot's `O_NOFOLLOW` open classifies the collision first.
    /// `emit_cc_plugin` DOES reach it: it calls `write_file` directly, with no
    /// `write_file_restorable` snapshot in front, so on unix the
    /// `AlreadyExists` branch is live production behaviour.
    ///
    /// Round 7: that branch had zero coverage on unix — the sibling test
    /// exercises it only on Windows, via CI. This makes it a local assertion
    /// too, so a regression is caught on the platform people develop on.
    #[test]
    fn emit_cc_plugin_leaf_parent_blocked_by_a_regular_file_names_the_remedy() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        fs::create_dir_all(dest.join("skills")).unwrap();
        // A REGULAR FILE exactly where the skill's directory belongs. NOTE the
        // path differs from the native emitters': `emit_cc_plugin` writes
        // `skills/<ID>/`, the kimi/grok emitters write `skills/csq-<ID>/`.
        // Blocking the wrong one lets the emit SUCCEED and the test asserts
        // nothing — which is exactly what the first draft of this test did.
        fs::write(dest.join("skills/SKILL-Z"), b"leftover cruft").unwrap();

        let mut arts = SurfaceArtifacts::default();
        arts.skills.push(art("SKILL-Z", "a real skill"));
        let err = emit_cc_plugin(&arts, dest).unwrap_err();

        let msg = err.to_string();
        assert!(
            !msg.contains("symlink"),
            "no symlink exists in this fixture — claiming one sends the \
             operator hunting for a file that is not there. Got: {msg:?}"
        );
        assert!(
            msg.contains("remove or rename"),
            "expected the remedy clause (a raw OS error cannot produce it), \
             got: {msg:?}"
        );
        assert_eq!(
            fs::read(dest.join("skills/SKILL-Z")).unwrap(),
            b"leftover cruft",
            "the blocking entry must never be overwritten"
        );
    }

    #[test]
    fn emit_kimi_native_cleanup_removes_every_dir_it_created_not_just_the_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();

        // Nothing pre-exists: the emitter must create BOTH `skills/` and
        // `skills/csq-SKILL-OK/` before the unsafe command aborts the call.
        assert!(!dest.join("skills").exists());

        let mut arts = SurfaceArtifacts::default();
        arts.skills.push(art("SKILL-OK", "a real skill"));
        arts.commands.push(art("../escape", "unsafe id"));

        let err = emit_kimi_native(&arts, dest).unwrap_err();
        assert!(matches!(err, MaterializeError::UnsafeId { .. }));

        assert!(
            !dest.join("skills/csq-SKILL-OK").exists(),
            "the skill directory this call created must be removed"
        );
        assert!(
            !dest.join("skills").exists(),
            "the INTERMEDIATE directory this call created must also be removed — \
             asserting only on the leaf is what let the chain-recording gap hide"
        );
        assert!(dest.exists(), "dest itself must never be deleted");
    }

    /// Companion to the above: when a PRIOR successful call already wrote a
    /// skill, and a LATER call fails partway through writing a DIFFERENT
    /// skill, the prior call's file must survive — self-clean only removes
    /// what the failing call itself wrote.
    #[test]
    fn emit_kimi_native_self_clean_does_not_touch_prior_successful_writes() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();

        let mut prior = SurfaceArtifacts::default();
        prior
            .skills
            .push(art("SKILL-PRIOR", "written by an earlier call"));
        emit_kimi_native(&prior, dest).unwrap();
        assert!(dest.join("skills/csq-SKILL-PRIOR/SKILL.md").exists());

        let mut arts = SurfaceArtifacts::default();
        arts.skills.push(art("SKILL-NEW", "written by this call"));
        arts.commands.push(art("../escape", "unsafe id"));
        let err = emit_kimi_native(&arts, dest).unwrap_err();
        assert!(matches!(err, MaterializeError::UnsafeId { .. }));

        assert!(
            !dest.join("skills/csq-SKILL-NEW/SKILL.md").exists(),
            "this call's partial write must be cleaned"
        );
        assert!(
            dest.join("skills/csq-SKILL-PRIOR/SKILL.md").exists(),
            "a PRIOR successful call's file must survive this call's failure"
        );
    }

    /// Round-13 review LOW-2 non-vacuity: a directory that PRE-EXISTED this
    /// call (e.g. Kimi's own empty `skills/` from its home-tree setup) must
    /// NEVER be removed by cleanup, even if this call's own files inside it
    /// are the only reason it reads as empty after cleanup runs. The old
    /// `remove_dir`-fails-on-non-empty guard only protects CONTENT, not
    /// IDENTITY — an empty pre-existing dir has no content to protect but
    /// still must not be deleted, since this module's contract is to leave
    /// `dest` in EXACTLY the state it found it.
    #[test]
    fn emit_kimi_native_self_clean_does_not_remove_preexisting_empty_vendor_dir() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        // Stand-in for a vendor-created empty `skills/` directory that
        // exists BEFORE this call ever runs (not created by csq).
        fs::create_dir_all(dest.join("skills")).unwrap();
        assert!(dest.join("skills").exists());

        let mut arts = SurfaceArtifacts::default();
        arts.skills.push(art("SKILL-NEW", "written by this call"));
        arts.commands.push(art("../escape", "unsafe id"));
        let err = emit_kimi_native(&arts, dest).unwrap_err();
        assert!(matches!(err, MaterializeError::UnsafeId { .. }));

        assert!(
            !dest.join("skills/csq-SKILL-NEW").exists(),
            "this call's own subdirectory must still be cleaned"
        );
        assert!(
            dest.join("skills").exists(),
            "a directory that pre-existed this call must NEVER be removed, \
             even though it now reads as empty"
        );
    }

    /// Round-6 MED: an overwrite-then-fail must RESTORE the prior
    /// artifact, not delete it. Before the fix, run B overwrote SKILL-A's
    /// v1 with v2 and the cleanup deleted the file outright — the prior
    /// valid artifact was silently unloaded.
    #[test]
    fn emit_kimi_native_self_clean_restores_overwritten_prior_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();

        let mut first = SurfaceArtifacts::default();
        first.skills.push(art("SKILL-A", "version one"));
        emit_kimi_native(&first, dest).unwrap();
        let v1 = fs::read_to_string(dest.join("skills/csq-SKILL-A/SKILL.md")).unwrap();

        let mut second = SurfaceArtifacts::default();
        second.skills.push(art("SKILL-A", "version two"));
        second.skills.push(art("SKILL-B", "new this call"));
        second.commands.push(art("../escape", "unsafe id"));
        let err = emit_kimi_native(&second, dest).unwrap_err();
        assert!(matches!(err, MaterializeError::UnsafeId { .. }));

        let after = fs::read_to_string(dest.join("skills/csq-SKILL-A/SKILL.md"))
            .expect("prior artifact must be RESTORED, not deleted");
        assert_eq!(after, v1, "the overwrite must be rolled back to v1");
        assert!(
            !dest.join("skills/csq-SKILL-B/SKILL.md").exists(),
            "this call's new partial write must be removed"
        );
    }

    /// R11 MED-2 non-vacuity: a user-authored, NON-`csq-`-prefixed skill
    /// directory shares `dest` with the emitter and MUST survive an emit
    /// untouched — it lives outside the `csq-` namespace this function ever
    /// writes to or (eventually) reconciles against.
    #[test]
    fn emit_kimi_native_does_not_touch_user_authored_unprefixed_skill() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        fs::create_dir_all(dest.join("skills/user-authored")).unwrap();
        fs::write(
            dest.join("skills/user-authored/SKILL.md"),
            "hand-written by the user, not csq",
        )
        .unwrap();

        let mut arts = SurfaceArtifacts::default();
        arts.skills.push(art("SKILL-Z", "a real skill"));
        emit_kimi_native(&arts, dest).unwrap();

        assert_eq!(
            fs::read_to_string(dest.join("skills/user-authored/SKILL.md")).unwrap(),
            "hand-written by the user, not csq",
            "a user-authored, unprefixed skill file must survive an emit untouched"
        );
        assert!(
            dest.join("skills/csq-SKILL-Z/SKILL.md").exists(),
            "the csq-owned entry is written under the namespaced dir"
        );
    }

    /// R11 MED-2 non-vacuity: a csq-owned (namespaced) entry from a PRIOR
    /// successful call IS overwritten by a later call for the same id — the
    /// namespacing pins collision-avoidance against user content, not
    /// idempotent-overwrite of csq's own prior output.
    #[test]
    fn emit_kimi_native_csq_owned_entry_is_overwritten_on_next_emit() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();

        let mut first = SurfaceArtifacts::default();
        first.skills.push(art("SKILL-A", "version one"));
        emit_kimi_native(&first, dest).unwrap();

        let mut second = SurfaceArtifacts::default();
        second.skills.push(art("SKILL-A", "version two"));
        emit_kimi_native(&second, dest).unwrap();

        let content = fs::read_to_string(dest.join("skills/csq-SKILL-A/SKILL.md")).unwrap();
        assert!(
            content.contains("version two"),
            "a csq-owned entry must be overwritten by a later successful emit: {content:?}"
        );
    }

    // ── Grok-native emitter ─────────────────────────────────────────────

    /// Grok materializes skills, commands (no degradation — real command
    /// primitive), AND agents (spawnable subagents). Rules stay prose.
    #[test]
    fn emit_grok_native_writes_skills_commands_and_agents() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        let manifest = emit_grok_native(&sample(), dest).unwrap();

        // skill + command + agent = 3 files. Rules excluded.
        assert_eq!(manifest.len(), 3);
        assert!(!dest.join(".claude-plugin").exists());
        assert!(!dest.join("rules").exists(), "rules stay prose");

        // R11 MED-2 (round-2 review): on-disk paths AND every synthesized
        // `name:` frontmatter (skill, agent — commands have no `name:`
        // field, CC/Grok name them by filename) are `csq-`-prefixed.
        let skill = fs::read_to_string(dest.join("skills/csq-SKILL-Z/SKILL.md")).unwrap();
        assert_eq!(
            skill,
            "---\nname: \"csq-SKILL-Z\"\ndescription: \"progressive disclosure\"\n---\n\n# skill\nprogressive disclosure\n"
        );
        // Command: real .md file, NOT degraded, filename becomes /csq-COMMAND-W.
        // No `name:` field at all for commands, so its content is unaffected
        // by the content-id prefix — only the filename changed.
        assert_eq!(
            fs::read_to_string(dest.join("commands/csq-COMMAND-W.md")).unwrap(),
            "---\ndescription: \"run the thing\"\n---\n\nrun the thing\n"
        );
        // Agent: name + description frontmatter, spawnable subagent. The
        // `name:` prefix means Grok registers the subagent as `csq-AGENT-Y`.
        let agent = fs::read_to_string(dest.join("agents/csq-AGENT-Y.md")).unwrap();
        assert_eq!(
            agent,
            "---\nname: \"csq-AGENT-Y\"\ndescription: \"you are a reviewer\"\n---\n\nyou are a reviewer\n"
        );
        assert!(
            skill.starts_with("---\nname: \"csq-SKILL-Z\"\n"),
            "skill frontmatter name MUST carry the csq- prefix: {skill:?}"
        );
        assert!(
            agent.starts_with("---\nname: \"csq-AGENT-Y\"\n"),
            "agent frontmatter name MUST carry the csq- prefix: {agent:?}"
        );
        assert_eq!(
            manifest.files.get("commands/csq-COMMAND-W.md"),
            Some(&MaterializedKind::Command)
        );
        assert_eq!(
            manifest.files.get("agents/csq-AGENT-Y.md"),
            Some(&MaterializedKind::Agent)
        );
    }

    /// Non-vacuity pair for the `${{` template-DSL guard: an agent body
    /// WITHOUT the sequence materializes cleanly (boundary case 1); the
    /// SAME body WITH the sequence fails closed with
    /// `TemplateDslCollision` rather than silently shipping a payload Grok
    /// would substitute at spawn time (boundary case 2). Together these
    /// prove the guard actually discriminates on the `${{` byte sequence,
    /// not on some other property of the body.
    #[test]
    fn emit_grok_native_agent_without_template_dsl_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let mut arts = SurfaceArtifacts::default();
        arts.agents
            .push(art("AGENT-SAFE", "plain reviewer persona"));
        let manifest = emit_grok_native(&arts, dir.path()).unwrap();
        assert_eq!(manifest.len(), 1);
    }

    #[test]
    fn emit_grok_native_rejects_agent_body_containing_template_dsl() {
        let dir = tempfile::tempdir().unwrap();
        let mut arts = SurfaceArtifacts::default();
        // MED-M non-vacuity: a SAFE skill sits alongside the evil agent.
        // The pre-flight scan runs across ALL kinds before ANY write, so
        // this proves the claim "nothing was written" for real — a prior
        // interleaved-scan shape would have written `skills/SKILL-SAFE/`
        // to disk before ever reaching the agents loop that rejects.
        arts.skills
            .push(art("SKILL-SAFE", "a perfectly safe skill"));
        arts.agents.push(art(
            "AGENT-EVIL",
            "reviewer persona using ${{ tools.by_kind.execute }}",
        ));
        let err = emit_grok_native(&arts, dir.path()).unwrap_err();
        match err {
            MaterializeError::TemplateDslCollision { id, kind } => {
                assert_eq!(id, "AGENT-EVIL");
                assert_eq!(kind, "agent");
            }
            other => panic!("expected TemplateDslCollision, got {other:?}"),
        }
        // Nothing was written — the tree stays empty on this failure path,
        // INCLUDING the safe skill the pre-flight scan never got to write.
        assert!(!dir.path().join("agents").exists());
        assert!(
            !dir.path().join("skills").exists(),
            "pre-flight scan must reject BEFORE any write, not after a partial write"
        );
    }

    #[test]
    fn emit_grok_native_empty_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut arts = SurfaceArtifacts::default();
        arts.rules.push(art("RULE-X", "rule body"));
        let manifest = emit_grok_native(&arts, dir.path()).unwrap();
        assert!(manifest.is_empty(), "rules-only input writes nothing");
    }

    /// MED-E non-vacuity: the `${{` guard previously covered agents only —
    /// a skill body containing the sequence must now fail closed
    /// identically to an agent body (boundary case: reject).
    #[test]
    fn emit_grok_native_rejects_skill_body_containing_template_dsl() {
        let dir = tempfile::tempdir().unwrap();
        let mut arts = SurfaceArtifacts::default();
        arts.skills.push(art(
            "SKILL-EVIL",
            "instructions using ${{ tools.by_kind.execute }}",
        ));
        let err = emit_grok_native(&arts, dir.path()).unwrap_err();
        match err {
            MaterializeError::TemplateDslCollision { id, kind } => {
                assert_eq!(id, "SKILL-EVIL");
                assert_eq!(kind, "skill");
            }
            other => panic!("expected TemplateDslCollision, got {other:?}"),
        }
        assert!(!dir.path().join("skills").exists());
    }

    /// MED-E: same guard for commands (boundary case: reject). Paired with
    /// `emit_grok_native_writes_skills_commands_and_agents`'s plain
    /// COMMAND-W body (no `${{`) as the accept boundary case — together
    /// they prove the guard discriminates on the byte sequence for every
    /// artifact kind, not just agents.
    #[test]
    fn emit_grok_native_rejects_command_body_containing_template_dsl() {
        let dir = tempfile::tempdir().unwrap();
        let mut arts = SurfaceArtifacts::default();
        arts.commands
            .push(art("CMD-EVIL", "run using ${{ tools.by_kind.execute }}"));
        let err = emit_grok_native(&arts, dir.path()).unwrap_err();
        match err {
            MaterializeError::TemplateDslCollision { id, kind } => {
                assert_eq!(id, "CMD-EVIL");
                assert_eq!(kind, "command");
            }
            other => panic!("expected TemplateDslCollision, got {other:?}"),
        }
        assert!(!dir.path().join("commands").exists());
    }

    /// HIGH-A non-vacuity, Grok variant — same self-clean contract as Kimi
    /// (see `emit_kimi_native_self_cleans_partial_write_on_error`): `dest`
    /// here is Grok's own persistent, credential-bearing vendor home.
    #[test]
    fn emit_grok_native_self_cleans_partial_write_on_error() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        fs::create_dir_all(dest.join("credentials")).unwrap();
        fs::write(dest.join("credentials/auth.json"), "secret-token").unwrap();

        let mut arts = SurfaceArtifacts::default();
        arts.skills.push(art("SKILL-OK", "a real skill"));
        arts.commands.push(art("../escape", "unsafe id"));

        let err = emit_grok_native(&arts, dest).unwrap_err();
        assert!(matches!(err, MaterializeError::UnsafeId { .. }));

        assert!(
            !dest.join("skills/csq-SKILL-OK/SKILL.md").exists(),
            "partial write from the failed call must be self-cleaned"
        );
        assert_eq!(
            fs::read_to_string(dest.join("credentials/auth.json")).unwrap(),
            "secret-token",
            "credential-bearing sibling content must survive a failed materialize call"
        );
        assert!(
            dest.exists(),
            "dest (the persistent vendor home) must not be deleted"
        );
    }

    /// R2 testing lens: the Grok twin of
    /// `emit_kimi_native_self_clean_does_not_touch_prior_successful_writes`.
    ///
    /// Both emitters share one `cleanup_partial_write`, so the behavioural
    /// risk is near-zero today — but "shares an implementation" is a
    /// property of the current code, not a guarantee, and the asymmetry is
    /// exactly what would let a future Grok-specific cleanup path regress
    /// unnoticed. The distinction pinned here is narrower than the
    /// sibling-content test above: that one proves an UNRELATED file
    /// survives; this proves a file written by an EARLIER successful call
    /// to the same emitter survives — i.e. cleanup is scoped to this call's
    /// manifest, not to everything the emitter has ever produced.
    #[test]
    fn emit_grok_native_self_clean_does_not_touch_prior_successful_writes() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();

        let mut prior = SurfaceArtifacts::default();
        prior
            .skills
            .push(art("SKILL-PRIOR", "written by an earlier call"));
        emit_grok_native(&prior, dest).unwrap();
        assert!(dest.join("skills/csq-SKILL-PRIOR/SKILL.md").exists());

        let mut arts = SurfaceArtifacts::default();
        arts.skills.push(art("SKILL-NEW", "written by this call"));
        arts.commands.push(art("../escape", "unsafe id"));
        let err = emit_grok_native(&arts, dest).unwrap_err();
        assert!(matches!(err, MaterializeError::UnsafeId { .. }));

        assert!(
            !dest.join("skills/csq-SKILL-NEW/SKILL.md").exists(),
            "this call's partial write must be cleaned"
        );
        assert!(
            dest.join("skills/csq-SKILL-PRIOR/SKILL.md").exists(),
            "a PRIOR successful call's file must survive this call's failure"
        );
    }

    /// Round-6 MED, grok twin: same restore contract as the kimi emitter.
    #[test]
    fn emit_grok_native_self_clean_restores_overwritten_prior_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();

        let mut first = SurfaceArtifacts::default();
        first.skills.push(art("SKILL-A", "version one"));
        emit_grok_native(&first, dest).unwrap();
        let v1 = fs::read_to_string(dest.join("skills/csq-SKILL-A/SKILL.md")).unwrap();

        let mut second = SurfaceArtifacts::default();
        second.skills.push(art("SKILL-A", "version two"));
        second.skills.push(art("SKILL-B", "new this call"));
        second.commands.push(art("../escape", "unsafe id"));
        let err = emit_grok_native(&second, dest).unwrap_err();
        assert!(matches!(err, MaterializeError::UnsafeId { .. }));

        let after = fs::read_to_string(dest.join("skills/csq-SKILL-A/SKILL.md"))
            .expect("prior artifact must be RESTORED, not deleted");
        assert_eq!(after, v1, "the overwrite must be rolled back to v1");
        assert!(
            !dest.join("skills/csq-SKILL-B/SKILL.md").exists(),
            "this call's new partial write must be removed"
        );
    }

    /// R11 MED-2 non-vacuity, Grok twin: a user-authored, unprefixed skill
    /// survives; the csq-owned namespaced entry is written alongside it.
    #[test]
    fn emit_grok_native_does_not_touch_user_authored_unprefixed_skill() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        fs::create_dir_all(dest.join("skills/user-authored")).unwrap();
        fs::write(
            dest.join("skills/user-authored/SKILL.md"),
            "hand-written by the user, not csq",
        )
        .unwrap();

        let mut arts = SurfaceArtifacts::default();
        arts.skills.push(art("SKILL-Z", "a real skill"));
        emit_grok_native(&arts, dest).unwrap();

        assert_eq!(
            fs::read_to_string(dest.join("skills/user-authored/SKILL.md")).unwrap(),
            "hand-written by the user, not csq",
            "a user-authored, unprefixed skill file must survive an emit untouched"
        );
        assert!(dest.join("skills/csq-SKILL-Z/SKILL.md").exists());
    }

    /// R11 MED-2 non-vacuity (round-2 review, explicit ask): the synthesized
    /// `name:` frontmatter — not just the on-disk path — MUST carry the
    /// `csq-` prefix, for BOTH Kimi and Grok skills. Uses an id (`REVIEW`)
    /// chosen to make the registry-collision motivation concrete: without
    /// this, a csq-emitted skill and a user-authored skill both named
    /// `REVIEW` would register under the SAME name in the vendor CLI's own
    /// skill registry even though their on-disk directories differ
    /// (`skills/csq-REVIEW/` vs `skills/REVIEW/`).
    #[test]
    fn native_persistent_emitters_prefix_frontmatter_name_to_avoid_registry_collision() {
        for emit in [
            emit_kimi_native as fn(&SurfaceArtifacts, &Path) -> _,
            emit_grok_native,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let dest = dir.path();
            let mut arts = SurfaceArtifacts::default();
            arts.skills.push(art("REVIEW", "review skill body"));
            emit(&arts, dest).unwrap();

            let body = fs::read_to_string(dest.join("skills/csq-REVIEW/SKILL.md")).unwrap();
            assert!(
                body.starts_with("---\nname: \"csq-REVIEW\"\n"),
                "frontmatter name must be namespaced to avoid a vendor-registry \
                 collision with a user-authored `REVIEW` skill: {body:?}"
            );
        }
    }

    /// R11 MED-1 non-vacuity: a pre-planted symlink at the LEAF artifact path
    /// (mirroring the exploit in the finding — a same-UID process redirecting
    /// `skills/csq-<ID>/SKILL.md` at a credential file) is refused BEFORE the
    /// pre-write snapshot read follows it, for BOTH Kimi and Grok.
    ///
    /// Unix-only per `testing.md` SHOULD-3. The `#[cfg(unix)]` used to sit on
    /// the `symlink()` call ALONE, which left the rest of the body running on
    /// Windows with its premise unmet: no symlink was ever planted, so the
    /// emit legitimately SUCCEEDED and `unwrap_err()` panicked. The test was
    /// asserting a refusal of something it had not created. Creating a
    /// Windows symlink is not the fix — it needs Developer Mode or admin, so
    /// the test would be privilege-flaky rather than platform-correct.
    #[cfg(unix)]
    #[test]
    fn native_persistent_emitters_refuse_preexisting_symlink_at_leaf_path() {
        for emit in [
            emit_kimi_native as fn(&SurfaceArtifacts, &Path) -> _,
            emit_grok_native,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let dest = dir.path();
            // Stand-in for a credential file elsewhere in the same
            // persistent vendor home.
            fs::write(dest.join("secret.json"), "super-secret-token").unwrap();
            fs::create_dir_all(dest.join("skills/csq-SKILL-Z")).unwrap();
            #[cfg(unix)]
            std::os::unix::fs::symlink(
                dest.join("secret.json"),
                dest.join("skills/csq-SKILL-Z/SKILL.md"),
            )
            .unwrap();

            let mut arts = SurfaceArtifacts::default();
            arts.skills.push(art("SKILL-Z", "a real skill"));
            let err = emit(&arts, dest).unwrap_err();
            assert!(
                matches!(err, MaterializeError::SymlinkAtDest { .. }),
                "expected SymlinkAtDest, got {err:?}"
            );
            // The planted symlink itself must be untouched (still a
            // symlink, never followed/overwritten), and the credential file
            // it points at must be untouched.
            assert!(
                fs::symlink_metadata(dest.join("skills/csq-SKILL-Z/SKILL.md"))
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "the pre-existing symlink must be left exactly as found"
            );
            assert_eq!(
                fs::read_to_string(dest.join("secret.json")).unwrap(),
                "super-secret-token",
                "the symlink target must never be read/overwritten via the plant"
            );
        }
    }

    /// LOW-1 (round-13 review) non-vacuity: `snapshot_prior_if_exists`'s own
    /// doc comment promises that "any OTHER io error … is surfaced as
    /// `MaterializeError::Io` rather than silently treated as 'no prior
    /// content'." A pre-existing DIRECTORY at the leaf artifact path is a
    /// constructible EISDIR without needing special permissions: the
    /// `O_NOFOLLOW` open of a directory succeeds (the flag only refuses a
    /// symlink), and `read_to_end` then fails. Before the fix this branch
    /// swallowed that error and returned `Ok(())` with nothing recorded in
    /// `prior` — silently re-opening the round-6 MED the snapshot exists to
    /// prevent (a later failure in the same emit would have nothing to
    /// restore). Unix-only: the non-Unix fallback uses a different
    /// sequential form not touched by this fix.
    #[cfg(unix)]
    #[test]
    fn snapshot_prior_if_exists_surfaces_read_error_instead_of_silently_treating_as_no_prior() {
        let dir = tempfile::tempdir().unwrap();
        let abs = dir.path().join("leaf-is-a-directory");
        fs::create_dir(&abs).unwrap();

        let mut prior = PriorContents::new();
        let err = snapshot_prior_if_exists(&abs, "leaf-is-a-directory", &mut prior).unwrap_err();
        assert!(
            matches!(err, MaterializeError::Io { .. }),
            "a directory at the leaf path must surface as Io, not be swallowed: {err:?}"
        );
        assert!(
            prior.is_empty(),
            "no snapshot must be recorded when the read itself failed"
        );
    }

    /// R12 LOW-fold non-vacuity: this module's own FS model treats the
    /// default macOS/Windows filesystem as case-insensitive (see
    /// `emit_rejects_case_insensitive_collision` for `write_file`'s side of
    /// the same model) — `is_csq_owned_entry` MUST fold case the same way,
    /// or a user-authored `CSQ-REVIEW` (a case-variant of the owned prefix)
    /// would be misclassified as user-owned (`false`) even though it
    /// collides at the filesystem layer with a csq-emitted `csq-REVIEW`.
    #[test]
    fn is_csq_owned_entry_folds_case_before_matching_prefix() {
        assert!(is_csq_owned_entry("csq-review"));
        assert!(
            is_csq_owned_entry("CSQ-REVIEW"),
            "an upper-case variant of the csq- prefix must also match"
        );
        assert!(is_csq_owned_entry("Csq-Foo"));
        assert!(!is_csq_owned_entry("review"));
        assert!(!is_csq_owned_entry("REVIEW"));
    }

    /// R12 NIT-desc non-vacuity: a body-less (heading-only) skill's
    /// synthesized `description` fallback must interpolate the RAW artifact
    /// id, not the `csq-`-prefixed on-disk/registry id — otherwise it
    /// doubles the prefix (`"csq capability-layer skill csq-SKILL-Z"`),
    /// user-visible in the vendor CLI's skill list.
    #[test]
    fn native_persistent_emitters_description_fallback_uses_raw_id_not_prefixed() {
        for emit in [
            emit_kimi_native as fn(&SurfaceArtifacts, &Path) -> _,
            emit_grok_native,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let dest = dir.path();
            let mut arts = SurfaceArtifacts::default();
            // Heading-only body -> derive_description's `None` branch (the
            // generic fallback) — the one that previously double-stamped
            // "csq" when fed the prefixed id.
            arts.skills.push(art("SKILL-Z", "# just a heading\n"));
            emit(&arts, dest).unwrap();

            let body = fs::read_to_string(dest.join("skills/csq-SKILL-Z/SKILL.md")).unwrap();
            assert!(
                body.contains("description: \"csq capability-layer skill SKILL-Z\""),
                "description fallback must use the raw id, not the csq-prefixed \
                 one (would double-stamp \"csq\"): {body:?}"
            );
        }
    }
}
