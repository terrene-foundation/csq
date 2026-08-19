//! Kimi `config.toml` merge helper (report 13 §6.3 "config.toml is a
//! merge, never a write").
//!
//! `<KIMI_CODE_HOME>/config.toml` is WRITTEN BY KIMI ITSELF — the live
//! csq-managed slot's file carries `[providers."managed:kimi-code"]`,
//! `[services.*.oauth]` (`key = "oauth/kimi-code"`), and `[models.*]` —
//! the slot's OAuth wiring. A plain overwrite logs the slot out. This
//! module performs a `toml::Value` round-trip merge, modeled on
//! `codex_merge::merge_instructions_via_toml_value` but adapted to Kimi's
//! shape:
//!
//! - `[[hooks]]` (top-level array-of-tables) and `[permission] rules` use a
//!   **replace-mine-preserve-theirs** merge (MED-L), NOT a whole-array
//!   replace. Every entry THIS module writes is tracked by a small
//!   ownership marker (`csq_managed_hook_commands` /
//!   `csq_managed_permission_patterns`, nested under the vendor's own
//!   `[raw]` passthrough table — see
//!   [`CSQ_MANAGED_HOOK_COMMANDS_KEY`]/[`CSQ_MANAGED_PERMISSION_PATTERNS_KEY`]
//!   for why the marker can't live inside the entry itself). On every
//!   call: entries NOT in the marker (hand-authored by the user, or
//!   pre-dating csq's first write) survive untouched; entries THAT ARE in
//!   the marker are dropped and replaced by this call's contribution —
//!   which may be EMPTY, and an empty contribution now correctly RETRACTS
//!   whatever csq previously wrote rather than being indistinguishable
//!   from "nothing changed" (the bug: previously, empty always meant
//!   "leave the whole array untouched", so csq could delete a user's hook
//!   on write but could never retract its own).
//! - `config_toml_overlay` is applied as typed TOML scalars via the same
//!   synthetic single-key-document parse discipline as `codex_merge`.
//! - `default_model` in the overlay is a hard refusal — csq pins the
//!   model via `--model` at spawn (`providers::native::KIMI.pinned_model`);
//!   a config write would collide (report 13 §6.3 "Corollary worth
//!   flagging").
//! - Every emitted hook `matcher` is regex-validated before merge, in TWO
//!   layers. (1) Rust `regex::Regex::new` compile check — Kimi compiles
//!   matchers with `new RegExp(...)` and swallows a malformed pattern into
//!   "matches nothing" (report 13 §4.3), so a Rust-invalid pattern would
//!   otherwise silently ship a hook that never fires. (2) A JS-dialect
//!   compatibility check ([`is_js_regex_compatible`]) — a pattern can be
//!   VALID Rust regex yet compile to a DIFFERENT matcher under Kimi's JS
//!   non-unicode `RegExp` (Unicode property escapes `\p{L}`/`\P{...}` and
//!   POSIX bracket expressions `[:alpha:]` are both silently
//!   reinterpreted, not rejected, by JS Annex-B semantics), which layer
//!   (1) cannot detect because the pattern IS valid Rust regex. Layer (2)
//!   also rejects an EMPTY matcher: Kimi's own hook engine special-cases
//!   an empty pattern to fire on every tool call (report 13), silently
//!   inverting a deny-style hook into fire-on-everything — an author who
//!   wants "match everything" should omit `matcher` (`None`), not pass
//!   `Some("")`.
//! - Parse errors do not echo the parser's error body (same token-leak
//!   discipline as `codex_merge` round-1 H6 / round-2 H2).

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, Context, Result};

use super::types::{KimiHook, KimiPermissionRule};

const KIMI_HOOKS_KEY: &str = "hooks";
const KIMI_PERMISSION_KEY: &str = "permission";
const KIMI_PERMISSION_RULES_KEY: &str = "rules";
/// Top-level key recording the `command` values of every `[[hooks]]` entry
/// this merge function itself wrote on a PRIOR call — the ownership marker
/// (MED-L) that lets [`merge_kimi_config_via_toml_value`] distinguish (a)
/// user hand-authored hooks, which always survive untouched, from (b)
/// csq-owned hooks, which THIS call's `hooks` argument fully replaces —
/// including replacing them with NOTHING (a legitimate retraction, not
/// "no change"). The marker deliberately lives in a SEPARATE top-level
/// key, not inside the individual `[[hooks]]` entry — `HookDefSchema` is
/// `.strict()` (exactly `{event, matcher?, command, timeout?}`, no extra
/// keys — report 13 §4.1), so a marker field on the entry itself would
/// either be rejected by Kimi's schema or silently break the hook.
/// `command` is the identity key: `HookDefSchema` requires it non-empty on
/// every entry, so it is always present and (in practice) unique per hook.
///
/// WIRING-SHARD OBLIGATION (round-4 R4-4): "(in practice) unique" is not a
/// structural guarantee — a user-authored hook whose `command` byte-equals
/// a csq-managed one would be reclassified csq-owned and retracted/replaced
/// on the next call. The wiring shard MUST mint csq hook commands carrying a
/// csq-unique token (e.g. a `csq-hook-gate-<hook-id>` script name or a
/// `# csq-managed: <uuid>` marker line inside the script body) so a
/// collision is structurally impossible, not empirically rare.
const CSQ_MANAGED_HOOK_COMMANDS_KEY: &str = "csq_managed_hook_commands";
/// Same ownership-tracking pattern as [`CSQ_MANAGED_HOOK_COMMANDS_KEY`],
/// applied to `[[permission.rules]]`, keyed by `pattern` (the field
/// `PermissionRuleSchema` requires to be non-empty and vendor-validated via
/// `isValidPermissionPattern` — report 13 H7 — so it is a stable per-rule
/// identity the way `command` is for a hook).
const CSQ_MANAGED_PERMISSION_PATTERNS_KEY: &str = "csq_managed_permission_patterns";

/// Vendor-declared passthrough table the ownership markers live under.
///
/// Report 13 §3.7 enumerates `KimiConfigSchema`'s 22 top-level keys, and
/// **neither marker is among them** — they are csq's own bookkeeping, not
/// vendor config. Writing them at the top level would bet the slot's OAuth
/// wiring on two facts the research explicitly left open (report 13 §1.4):
/// whether the strict schema (`KimiConfigPatchSchema`) or the permissive one
/// (`KimiConfigSchema`) guards a hand-edited file, and whether Kimi rewrites
/// `config.toml` on exit. If the strict schema applies, an unknown top-level
/// key makes the vendor reject the whole file — destroying exactly the
/// credential wiring this module exists to preserve. If the vendor rewrites
/// and drops unknown keys, the marker silently vanishes and every csq hook is
/// reclassified user-authored on the next call: unretractable, accumulating
/// per `csq run`.
///
/// `raw: record(string(), unknown()).optional()` (report 13 §1.4) is the
/// vendor's OWN documented escape hatch for arbitrary keys, so nesting inside
/// it is schema-valid under either guard and is the shape a rewrite is
/// designed to preserve.
///
/// The prior top-level placement cited `HookDefSchema`'s `.strict()` as
/// justification. That is correct about the *in-entry* question — it is why
/// the markers are not fields on a `[[hooks]]` table — but it does not speak
/// to the top-level question at all.
const KIMI_RAW_PASSTHROUGH_KEY: &str = "raw";

/// Read a csq ownership marker from `[raw]`. `None` when `raw` is absent, is
/// not a table, or carries no such key.
fn raw_marker<'a>(table: &'a toml::value::Table, key: &str) -> Option<&'a toml::Value> {
    table
        .get(KIMI_RAW_PASSTHROUGH_KEY)
        .and_then(|v| v.as_table())
        .and_then(|raw| raw.get(key))
}

/// True when `[raw]` carries `key` — the "csq owned something on a prior
/// call" predicate that decides whether a retraction pass must run.
fn has_raw_marker(table: &toml::value::Table, key: &str) -> bool {
    raw_marker(table, key).is_some()
}

/// Read a csq ownership marker as the set of previously-managed strings.
///
/// A marker that is PRESENT but not an array of strings (hand-edited file, a
/// future marker-format change, partial write) degrades to the empty set:
/// every entry csq previously owned is reclassified user-authored and
/// preserved alongside this call's contribution, i.e. silent duplicate
/// accumulation across merges rather than a crash.
///
/// The degradation is deliberate — refusing to merge would leave the slot's
/// config unwritable until an operator hand-repaired `[raw]` — but it MUST
/// NOT be silent (`zero-tolerance.md` Rule 3). The WARN is the operative
/// signal; the same loud-fallback shape as the poisoned-`quota.json` path.
/// Non-string members of an otherwise-valid array are also counted and
/// reported, since they represent the same partial ownership loss.
fn managed_marker_set(table: &toml::value::Table, key: &str) -> BTreeSet<String> {
    let (set, defect) = read_managed_marker(table, key);
    match defect {
        None => {}
        Some(MarkerDefect::NotAnArray { found_type }) => tracing::warn!(
            marker_key = key,
            found_type,
            error_kind = "kimi_marker_malformed",
            "csq ownership marker under [raw] is not an array — treating as \
             'csq owned nothing'; previously csq-managed entries will be \
             preserved as user-authored and may accumulate on re-merge"
        ),
        Some(MarkerDefect::NonStringMembers { total, usable }) => tracing::warn!(
            marker_key = key,
            total,
            usable,
            error_kind = "kimi_marker_non_string_member",
            "csq ownership marker under [raw] has non-string members — those \
             entries lose csq ownership and may accumulate on re-merge"
        ),
    }
    set
}

/// How a present-but-unusable ownership marker is malformed.
///
/// Split out of [`managed_marker_set`] so the DETECTION is unit-assertable
/// without capturing a `tracing` subscriber — otherwise the only way to test
/// the loud-fallback requirement is through its behavioral side effect, which
/// is identical to the silent version.
#[derive(Debug, PartialEq, Eq)]
enum MarkerDefect {
    /// `[raw].<key>` exists but is not an array (scalar, table, …).
    NotAnArray { found_type: &'static str },
    /// `[raw].<key>` is an array but some members are not strings.
    NonStringMembers { total: usize, usable: usize },
}

/// Read an ownership marker, returning the usable set AND any defect.
///
/// Absent marker ⇒ `(empty, None)` — that is the normal virgin-canonical
/// case, not a defect.
fn read_managed_marker(
    table: &toml::value::Table,
    key: &str,
) -> (BTreeSet<String>, Option<MarkerDefect>) {
    let Some(value) = raw_marker(table, key) else {
        return (BTreeSet::new(), None);
    };
    let Some(arr) = value.as_array() else {
        return (
            BTreeSet::new(),
            Some(MarkerDefect::NotAnArray {
                found_type: value.type_str(),
            }),
        );
    };
    let set: BTreeSet<String> = arr
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    // Compare against the count of string members, not the set length —
    // duplicates in the array are harmless and must not be reported as a
    // defect (a set of 1 from ["a", "a"] is correct, not lossy).
    let string_members = arr.iter().filter(|v| v.is_str()).count();
    let defect = (string_members != arr.len()).then_some(MarkerDefect::NonStringMembers {
        total: arr.len(),
        usable: string_members,
    });
    (set, defect)
}

/// Write a csq ownership marker into `[raw]`, creating the table if absent.
///
/// A non-table `raw` (the operator hand-wrote a scalar there) is REPLACED
/// with a table. That is the only lossy branch, and it is the correct one:
/// the vendor's own schema types `raw` as a record, so a scalar there is
/// already invalid config, and preserving it would mean silently declining to
/// track ownership — which is the unretractable-hook failure this exists to
/// prevent.
fn set_raw_marker(table: &mut toml::value::Table, key: &str, value: toml::Value) {
    let raw = table
        .entry(KIMI_RAW_PASSTHROUGH_KEY.to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
    if !raw.is_table() {
        *raw = toml::Value::Table(toml::value::Table::new());
    }
    if let Some(raw_table) = raw.as_table_mut() {
        raw_table.insert(key.to_string(), value);
    }
}

/// Merge `config_toml_overlay` + `permission_rules` + `hooks` into the
/// canonical Kimi `config.toml` text. Returns the serialized merged TOML.
///
/// * `canonical` — full text of the slot's existing
///   `<KIMI_CODE_HOME>/config.toml` (vendor-written; carries OAuth wiring).
/// * `config_toml_overlay` — pre-rendered TOML scalar expressions for
///   additional top-level keys (same convention as
///   `CodexSpawnPayload::config_toml_overlay`).
/// * `permission_rules` — `[[permission.rules]]` entries THIS call
///   contributes. Replaces only the entries csq itself previously wrote
///   (tracked via [`CSQ_MANAGED_PERMISSION_PATTERNS_KEY`]); user-authored
///   entries always survive. Empty ⇒ retract every csq-owned entry while
///   still preserving user-authored ones and the rest of `[permission]`.
/// * `hooks` — `[[hooks]]` entries THIS call contributes. Same
///   replace-mine-preserve-theirs semantics as `permission_rules`, tracked
///   via [`CSQ_MANAGED_HOOK_COMMANDS_KEY`].
pub fn merge_kimi_config_via_toml_value(
    canonical: &str,
    config_toml_overlay: &BTreeMap<String, String>,
    permission_rules: &[KimiPermissionRule],
    hooks: &[KimiHook],
) -> Result<String> {
    if config_toml_overlay.contains_key("default_model") {
        return Err(anyhow!(
            "config_toml_overlay must not set `default_model` — csq pins the model via \
             `--model` at spawn (providers::native::KIMI.pinned_model); a config write \
             would collide"
        ));
    }
    // The ownership markers live NESTED under `[raw]` (raw_marker /
    // set_raw_marker) — a top-level overlay key of the same name inserts
    // at a DIFFERENT TOML path and cannot touch them. Such a key is
    // nevertheless refused: it is inert-but-misleading (a reader would
    // reasonably believe it sets the marker), and the overlay is not the
    // channel for state this module owns. The REAL clobber class — a
    // scalar overlay at `raw`/`hooks`/`permission`/`services` —
    // wholesale-replacing those tables is refused below, target-aware,
    // after the composite-value rejection.
    for marker in [
        CSQ_MANAGED_HOOK_COMMANDS_KEY,
        CSQ_MANAGED_PERMISSION_PATTERNS_KEY,
    ] {
        if config_toml_overlay.contains_key(marker) {
            return Err(anyhow!(
                "config_toml_overlay must not set `{marker}` — it collides with csq's \
                 ownership marker name for the hooks/permission entries this merge writes \
                 (the markers live under `[{KIMI_RAW_PASSTHROUGH_KEY}]`). A top-level key \
                 of that name would be inert but indistinguishable from the real marker \
                 to a human reader"
            ));
        }
    }

    // Discard the parser's error body — corrupt canonical bytes could
    // contain fragmented OAuth material not matched by
    // `error::redact_tokens` (mirrors codex_merge round-2 H2).
    let mut table: toml::Value = toml::from_str(canonical).map_err(|_| {
        anyhow!(
            "canonical kimi config.toml parse failed; re-run \
             `csq login N --provider kimi-cli` to re-seed"
        )
    })?;
    let table_mut = table
        .as_table_mut()
        .ok_or_else(|| anyhow!("canonical kimi config.toml is not a TOML Table"))?;

    // MED-L: replace-mine-preserve-theirs + a retraction signal. Only
    // enter this branch when there is something to reconcile — either csq
    // has content to contribute NOW, or csq owned something on a PRIOR
    // call (tracked by the marker key) that this call might be retracting.
    // Skipping the branch entirely when NEITHER holds preserves the
    // original zero-footprint behavior for slots that never touch hooks
    // (no `hooks = []` / marker key bloat written for a virgin canonical).
    if !hooks.is_empty() || has_raw_marker(table_mut, CSQ_MANAGED_HOOK_COMMANDS_KEY) {
        let previously_managed_commands: BTreeSet<String> =
            managed_marker_set(table_mut, CSQ_MANAGED_HOOK_COMMANDS_KEY);
        // Anything on disk whose `command` was NOT csq-managed on the
        // prior call is user-authored (or pre-dates this ownership
        // scheme) — it survives untouched regardless of what csq
        // contributes this call.
        let user_authored_hooks: Vec<toml::Value> = table_mut
            .get(KIMI_HOOKS_KEY)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|h| {
                !h.get("command")
                    .and_then(|v| v.as_str())
                    .is_some_and(|c| previously_managed_commands.contains(c))
            })
            .collect();
        let csq_hooks: Vec<toml::Value> =
            hooks.iter().map(render_hook_value).collect::<Result<_>>()?;
        let mut merged_hooks = user_authored_hooks;
        merged_hooks.extend(csq_hooks);
        table_mut.insert(KIMI_HOOKS_KEY.to_string(), toml::Value::Array(merged_hooks));

        let new_managed_commands: Vec<toml::Value> = hooks
            .iter()
            .map(|h| toml::Value::String(h.command.clone()))
            .collect();
        set_raw_marker(
            table_mut,
            CSQ_MANAGED_HOOK_COMMANDS_KEY,
            toml::Value::Array(new_managed_commands),
        );
    }
    // else: csq has never touched hooks and still has nothing to
    // contribute — leave the `hooks` key exactly as found (possibly
    // absent).

    if !permission_rules.is_empty()
        || has_raw_marker(table_mut, CSQ_MANAGED_PERMISSION_PATTERNS_KEY)
    {
        let previously_managed_patterns: BTreeSet<String> =
            managed_marker_set(table_mut, CSQ_MANAGED_PERMISSION_PATTERNS_KEY);
        let existing_rules: Vec<toml::Value> = table_mut
            .get(KIMI_PERMISSION_KEY)
            .and_then(|v| v.as_table())
            .and_then(|t| t.get(KIMI_PERMISSION_RULES_KEY))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let user_authored_rules: Vec<toml::Value> = existing_rules
            .into_iter()
            .filter(|r| {
                !r.get("pattern")
                    .and_then(|v| v.as_str())
                    .is_some_and(|p| previously_managed_patterns.contains(p))
            })
            .collect();
        let csq_rules: Vec<toml::Value> = permission_rules
            .iter()
            .map(render_permission_rule_value)
            .collect::<Result<Vec<_>>>()?;
        let mut merged_rules = user_authored_rules;
        merged_rules.extend(csq_rules);

        let mut perm_table = match table_mut.remove(KIMI_PERMISSION_KEY) {
            Some(toml::Value::Table(t)) => t,
            _ => toml::value::Table::new(),
        };
        perm_table.insert(
            KIMI_PERMISSION_RULES_KEY.to_string(),
            toml::Value::Array(merged_rules),
        );
        table_mut.insert(
            KIMI_PERMISSION_KEY.to_string(),
            toml::Value::Table(perm_table),
        );

        let new_managed_patterns: Vec<toml::Value> = permission_rules
            .iter()
            .map(|r| toml::Value::String(r.pattern.clone()))
            .collect();
        set_raw_marker(
            table_mut,
            CSQ_MANAGED_PERMISSION_PATTERNS_KEY,
            toml::Value::Array(new_managed_patterns),
        );
    }
    // else: preserve `[permission]` untouched (including any sub-keys
    // other than `rules` a future csq version or the user may set).

    // Round-2 R2-C1-equivalent: overlay values are pre-rendered TOML
    // scalar expressions. Parse via a synthetic single-key document to
    // extract the typed scalar; reject anything beyond a single scalar.
    for (k, raw_value) in config_toml_overlay {
        let synthetic = format!("__x = {raw_value}");
        // Discard the parser's error body — same token-leak discipline as
        // the canonical-parse `map_err(|_| ...)` above (LOW-I; mirrors
        // codex_merge round-2 H2). `with_context` would otherwise wrap the
        // raw `toml::de::Error` as the anyhow chain's source, and
        // `toml::de::Error::Display` echoes a snippet of the OFFENDING
        // INPUT (the raw scalar expression, which could carry fragmented
        // credential material) — visible to any `{err:?}`/`{err:#}`
        // formatting even though the top-level `{err}` Display looks safe.
        let parsed: toml::Value = toml::from_str(&synthetic)
            .map_err(|_| anyhow!("config_toml_overlay key {k}: invalid TOML scalar expression"))?;
        let parsed_table = parsed.as_table().ok_or_else(|| {
            anyhow!("config_toml_overlay key {k}: expected scalar, got non-table")
        })?;
        if parsed_table.len() != 1 || !parsed_table.contains_key("__x") {
            return Err(anyhow!(
                "config_toml_overlay key {k}: raw_value must be a single TOML scalar \
                 expression with no trailing comments, multi-line tables, or extra keys"
            ));
        }
        let scalar = parsed_table["__x"].clone();
        // MED-K: `parsed_table.len() != 1` above catches EXTRA keys, not a
        // COMPOSITE `__x` value — `raw_value = "{ }"` parses to exactly one
        // key (`__x`) holding an inline TABLE, which passes that check.
        // Inserting a table/array wholesale REPLACES the existing top-level
        // key of the same name — e.g. `overlay["services"] = "{ }"` would
        // silently delete `services.kimi-code.oauth`, exactly the
        // credential-preservation this module exists to protect. Reject
        // composites explicitly; only true scalars may reach `insert`.
        if matches!(scalar, toml::Value::Table(_) | toml::Value::Array(_)) {
            let kind = if scalar.is_table() { "table" } else { "array" };
            return Err(anyhow!(
                "config_toml_overlay key {k}: raw_value must be a scalar (string, \
                 integer, float, boolean, or datetime), got a TOML {kind} — a composite \
                 value would silently REPLACE the existing top-level `{k}` key wholesale \
                 (e.g. `services`, which carries Kimi's own OAuth wiring) instead of \
                 merging into it"
            ));
        }
        // R4-1/D4-1 (round-4, both lenses): the composite check above
        // guards the VALUE side only. `insert` REPLACES whatever lives at
        // `k` — so a SCALAR overlay at a key whose EXISTING canonical
        // value is a table/array wholesale-deletes that subtree:
        // `overlay["raw"] = "\"x\""` destroys BOTH csq ownership markers
        // (the next call then reads previously-managed = empty → every
        // csq-written hook reclassified user-authored → preserved AND
        // re-appended → duplicates without bound); `overlay["hooks"]`
        // silently replaces the merged hooks array written ABOVE (csq's
        // hooks never reach the vendor while the marker claims
        // ownership); `overlay["services"]` deletes the vendor OAuth
        // wiring. `raw`/`hooks`/`permission`/`services`/`providers` are
        // all schema-valid top-level table keys (report 13 §3.7), so a
        // future overlay plausibly carries them. Refuse target-aware.
        if let Some(existing) = table_mut.get(k) {
            if matches!(existing, toml::Value::Table(_) | toml::Value::Array(_)) {
                return Err(anyhow!(
                    "config_toml_overlay key {k}: the canonical config already has a \
                     table/array at `{k}` — a scalar overlay would REPLACE it wholesale, \
                     silently deleting its contents (vendor OAuth wiring, the merged \
                     hooks array, or csq's ownership markers under `[raw]`). csq does not \
                     overlay composite keys; edit config.toml directly to restructure `{k}`"
                ));
            }
        }
        table_mut.insert(k.clone(), scalar);
    }

    let serialized = toml::to_string(&table).context("serializing merged kimi config.toml")?;

    // Round-trip parse as a safety net for serializer bugs (mirrors
    // codex_merge round-1 R1-C1 + round-2 R2-H1).
    let _verify: toml::Value =
        toml::from_str(&serialized).context("merged kimi config.toml fails round-trip parse")?;

    Ok(serialized)
}

/// POSIX bracket-expression class names (`[:alpha:]`, `[:digit:]`, …) that
/// Rust's `regex` crate interprets as a POSIX character class inside a
/// bracket expression, but a JS non-unicode `RegExp` (Annex B semantics,
/// no `u` flag) parses as a LITERAL run of characters — `[[:alpha:]]`
/// becomes a character class containing the literal bytes `[`, `:`, `a`,
/// `l`, `p`, `h`, followed by a stray literal `]`, not "any ASCII letter".
/// Neither engine throws, so this is a silent-divergence class, not a
/// silent-non-fire class — see [`is_js_regex_compatible`].
const POSIX_CLASS_NAMES: &[&str] = &[
    "alpha", "digit", "alnum", "upper", "lower", "space", "punct", "cntrl", "print", "graph",
    "blank", "xdigit", "ascii", "word",
];

/// True when the pattern contains a REAL Unicode property escape
/// (`\p{...}` / `\P{...}`), escape-aware: an escaped backslash before the
/// letter (`\\p`, which both engines read as a literal backslash followed
/// by a literal `p`) is NOT a property escape. A context-free
/// `contains("\\p")` over-rejects that literal shape (round-4 NIT).
fn has_unicode_property_escape(pattern: &str) -> bool {
    let b = pattern.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == b'\\' {
            if b[i + 1] == b'\\' {
                // Escaped backslash — the next char is literal, skip both.
                i += 2;
                continue;
            }
            if b[i + 1] == b'p' || b[i + 1] == b'P' {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// True when the pattern contains a braced escape (`\x{…}`, `\u{…}`,
/// `\U{…}`), escape-aware. All three are valid Rust regex, but under
/// Kimi's JS non-unicode RegExp (Annex B) a `\x` NOT followed by two
/// hex digits is a literal `x` — so `\x{41}` means `x` + the `{41}`
/// quantifier in JS (matching "x×41") and `A` in Rust: the same
/// silent-divergence class as `\p`. Round-10 F1.
fn has_braced_escape(pattern: &str) -> Option<&'static str> {
    let b = pattern.as_bytes();
    let mut i = 0;
    while i + 2 < b.len() {
        if b[i] == b'\\' {
            if b[i + 1] == b'\\' {
                i += 2;
                continue;
            }
            // Rust-only braced forms — JS parses the letter as literal
            // and the braces as a quantifier.
            if b[i + 2] == b'{' {
                match b[i + 1] {
                    b'x' => return Some("\\x{…}"),
                    b'u' => return Some("\\u{…}"),
                    b'U' => return Some("\\U{…}"),
                    _ => {}
                }
            }
            // Rust's unbraced 8-hex form `\UFFFFFFFF` — JS `\u` takes
            // exactly 4 hex digits, so JS Annex B reads a literal `U`
            // followed by the digits. (The 2-hex `\xFF` and 4-hex
            // `\uFFFF` forms ARE valid JS — not divergent, allowed.)
            if b[i + 1] == b'U' {
                let hex_end = i + 10;
                if hex_end <= b.len() && b[i + 2..hex_end].iter().all(|c| c.is_ascii_hexdigit()) {
                    return Some("\\UFFFFFFFF");
                }
            }
        }
        i += 1;
    }
    None
}

/// Rejects a matcher pattern that is valid Rust regex but would compile to
/// a DIFFERENT matcher (or an unintended "match everything") under Kimi's
/// JS non-unicode `RegExp` compile. See the module doc comment's "TWO
/// layers" note for why the Rust-compile check in [`render_hook_value`]
/// alone cannot catch these — every construct rejected here compiles
/// successfully in BOTH engines, just to different meanings.
fn is_js_regex_compatible(pattern: &str) -> Result<(), String> {
    if pattern.is_empty() {
        return Err(
            "empty matcher — Kimi's own hook engine special-cases an empty matcher to \
             fire on EVERY tool call (report 13 §4.3), silently inverting a deny-style \
             hook into fire-on-everything; omit `matcher` entirely (`None`) if \"match \
             everything\" is genuinely intended"
                .to_string(),
        );
    }
    if has_unicode_property_escape(pattern) {
        return Err(format!(
            "matcher `{pattern}` uses a Unicode property escape (`\\p`/`\\P`) — valid \
             Rust regex, but Kimi compiles matchers as a JS non-unicode RegExp where \
             `\\p`/`\\P` are literal characters (`p`/`P`), not a Unicode class; the \
             pattern would silently match something different at Kimi's end"
        ));
    }
    for name in POSIX_CLASS_NAMES {
        // Both the plain `[[:alpha:]]` and the NEGATED `[[:^alpha:]]`
        // forms — the `^` variant is valid Rust regex too and just as
        // divergent in JS, but a naive `[[:alpha:]]` substring check
        // misses it (round-10 F1).
        for shape in [format!("[:{name}:]"), format!("[:^{name}:]")] {
            if pattern.contains(&shape) {
                return Err(format!(
                    "matcher `{pattern}` uses a POSIX bracket expression (`{shape}`) — \
                     valid Rust regex, but Kimi compiles matchers as a JS non-unicode \
                     RegExp where `{shape}` is parsed as a literal character class, not \
                     a POSIX class; the pattern would silently match something different \
                     at Kimi's end"
                ));
            }
        }
    }
    if let Some(shape) = has_braced_escape(pattern) {
        return Err(format!(
            "matcher `{pattern}` uses a braced escape (`{shape}`) — valid Rust regex, \
             but Kimi compiles matchers as a JS non-unicode RegExp where the escape \
             letter is literal and the braces form a quantifier; the pattern would \
             silently match something different at Kimi's end"
        ));
    }
    Ok(())
}

/// Render one `[[hooks]]` entry. Fails closed on an uncompilable
/// `matcher` — Kimi's own `new RegExp(...).catch(() => false)` behavior
/// (report 13 §4.3) means a bad pattern doesn't error at Kimi's end, it
/// silently disables the hook. csq refuses to ship that at merge time.
/// Also fails closed on a pattern that compiles successfully under BOTH
/// engines but MEANS something different — see
/// [`is_js_regex_compatible`].
fn render_hook_value(hook: &KimiHook) -> Result<toml::Value> {
    if let Some(m) = &hook.matcher {
        regex::Regex::new(m).map_err(|_| {
            anyhow!(
                "hook matcher `{m}` is not a valid regex — Kimi swallows a malformed \
                 matcher into \"matches nothing\", silently disabling the hook"
            )
        })?;
        is_js_regex_compatible(m).map_err(|reason| anyhow!("hook matcher rejected: {reason}"))?;
    }
    let mut t = toml::value::Table::new();
    t.insert(
        "event".to_string(),
        toml::Value::String(hook.event.as_str().to_string()),
    );
    if let Some(m) = &hook.matcher {
        t.insert("matcher".to_string(), toml::Value::String(m.clone()));
    }
    t.insert(
        "command".to_string(),
        toml::Value::String(hook.command.clone()),
    );
    if let Some(secs) = hook.timeout_secs {
        // Vendor schema: `timeout: number().int().min(1).max(600)`
        // (report 13 §4.2) under a `.strict()` HookDefSchema — an
        // out-of-range value makes the vendor reject the entry, and
        // hooks fail OPEN always (report 13 §7), so a csq-authored
        // governance hook would silently never run. Fail closed at
        // render time instead (types.rs documents 1..=600; enforce it).
        if !(1..=600).contains(&secs) {
            return Err(anyhow!(
                "hook timeout_secs {secs} is outside the vendor's 1..=600 schema bound — \
                 Kimi's strict HookDefSchema would reject the entry and the hook would \
                 silently never run (hooks fail open)"
            ));
        }
        t.insert("timeout".to_string(), toml::Value::Integer(i64::from(secs)));
    }
    Ok(toml::Value::Table(t))
}

/// Validates a permission-rule pattern against the vendor's grammar
/// (`isValidPermissionPattern`: `ToolName` or `ToolName(argPattern)`,
/// `pattern: string().min(1).refine(...)` — report 13 §H7). An empty or
/// non-grammar pattern passes csq's render today and errors only when
/// Kimi LOADS the credential-bearing config — and the marker identity
/// key IS the pattern, so two invalid-but-equal patterns would also
/// collapse to one marker entry, mis-retracting later. Fail closed at
/// render time, symmetric with [`render_hook_value`]'s two layers.
fn validate_permission_pattern(pattern: &str) -> Result<()> {
    if pattern.is_empty() {
        return Err(anyhow!(
            "permission rule pattern is empty — the vendor requires min(1) and would \
             reject the config on load"
        ));
    }
    // Grammar: `ToolName` or `ToolName(argPattern)` — tool name is any
    // run of non-paren, non-whitespace chars; the arg pattern is any
    // balanced single pair of parens. A `(` inside the arg body is a
    // nested-paren violation; a `)` inside the arg body is an
    // unbalanced extra closer (`Tool(arg)extra)` passed the naive
    // ends_with check — R7 NIT).
    let tool_end = pattern.find('(').unwrap_or(pattern.len());
    let tool = &pattern[..tool_end];
    let valid = !tool.is_empty()
        && !tool.chars().any(|c| c.is_whitespace() || c == ')')
        && if tool_end < pattern.len() {
            pattern.ends_with(')')
                && !pattern[tool_end + 1..pattern.len() - 1]
                    .chars()
                    .any(|c| c == '(' || c == ')')
        } else {
            true
        };
    if !valid {
        return Err(anyhow!(
            "permission rule pattern `{pattern}` is not the vendor's \
             `ToolName`/`ToolName(argPattern)` grammar — Kimi's schema refine would \
             reject the config on load"
        ));
    }
    Ok(())
}

/// Render one `[[permission.rules]]` entry. `HookDefSchema`'s sibling
/// `PermissionRuleSchema` is not `.strict()` per report 13 §H7, so an
/// absent `reason` is simply omitted rather than needing a null.
fn render_permission_rule_value(rule: &KimiPermissionRule) -> Result<toml::Value> {
    validate_permission_pattern(&rule.pattern)?;
    let mut t = toml::value::Table::new();
    t.insert(
        "decision".to_string(),
        toml::Value::String(rule.decision.as_str().to_string()),
    );
    t.insert(
        "scope".to_string(),
        toml::Value::String(rule.scope.as_str().to_string()),
    );
    t.insert(
        "pattern".to_string(),
        toml::Value::String(rule.pattern.clone()),
    );
    if let Some(reason) = &rule.reason {
        t.insert("reason".to_string(), toml::Value::String(reason.clone()));
    }
    Ok(toml::Value::Table(t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coc::translate::types::{KimiDecision, KimiHookEvent, KimiScope};

    fn no_overlay() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    /// The live-slot shape from report 13 §6.3 — a minimal stand-in for
    /// `[providers."managed:kimi-code"]` / `[services.*.oauth]` /
    /// `[models.*]`, the content that MUST survive the merge untouched.
    fn canonical_live_slot() -> &'static str {
        r#"default_model = "kimi-code/kimi-for-coding"

[thinking]
enabled = true

[providers."managed:kimi-code"]
kind = "managed"

[services.kimi-code.oauth]
key = "oauth/kimi-code"

[models."kimi-code/k3"]
alias = "K3"
"#
    }

    #[test]
    fn merge_preserves_oauth_and_provider_tables_untouched() {
        let merged =
            merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &[], &[])
                .unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        assert_eq!(
            parsed["services"]["kimi-code"]["oauth"]["key"]
                .as_str()
                .unwrap(),
            "oauth/kimi-code",
            "OAuth wiring must survive the merge: {merged}"
        );
        assert_eq!(
            parsed["providers"]["managed:kimi-code"]["kind"]
                .as_str()
                .unwrap(),
            "managed"
        );
        assert_eq!(
            parsed["models"]["kimi-code/k3"]["alias"].as_str().unwrap(),
            "K3"
        );
        // The vendor's own default_model is untouched — csq never writes
        // this key (it pins via --model at spawn instead).
        assert_eq!(
            parsed["default_model"].as_str().unwrap(),
            "kimi-code/kimi-for-coding"
        );
    }

    #[test]
    fn merge_refuses_default_model_in_overlay() {
        let mut overlay = BTreeMap::new();
        overlay.insert("default_model".to_string(), "\"kimi-code/k3\"".to_string());
        let err = merge_kimi_config_via_toml_value(canonical_live_slot(), &overlay, &[], &[])
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("default_model"),
            "error must name the field: {msg}"
        );
    }

    #[test]
    fn merge_with_empty_hooks_and_rules_preserves_canonical_hooks_table() {
        let canonical = r#"default_model = "kimi-code/kimi-for-coding"

[[hooks]]
event = "PreToolUse"
command = "existing-user-hook.sh"
"#;
        let merged = merge_kimi_config_via_toml_value(canonical, &no_overlay(), &[], &[]).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        let hooks = parsed["hooks"].as_array().unwrap();
        assert_eq!(
            hooks.len(),
            1,
            "empty payload.hooks must not delete an existing hook"
        );
        assert_eq!(
            hooks[0]["command"].as_str().unwrap(),
            "existing-user-hook.sh"
        );
    }

    #[test]
    fn merge_with_non_empty_hooks_preserves_user_hook_and_adds_csq_hook() {
        // MED-L: `stale-hook.sh` is NOT in `csq_managed_hook_commands` (the
        // key is absent from canonical) — it is a stand-in for a
        // user-hand-authored hook (or one pre-dating the ownership
        // scheme). It MUST survive; csq's contribution is ADDED alongside
        // it, not a wholesale replacement. (Renamed from
        // `merge_with_non_empty_hooks_replaces_canonical_hooks_table`,
        // which asserted the deletion as correct — that assertion pinned
        // the MED-L bug: a user's hand-written hook silently deleted.)
        let canonical = r#"default_model = "kimi-code/kimi-for-coding"

[[hooks]]
event = "PreToolUse"
command = "user-hook.sh"
"#;
        let hooks = vec![KimiHook {
            event: KimiHookEvent::PreToolUse,
            matcher: Some("^Bash$".to_string()),
            command: "csq-gate.sh".to_string(),
            timeout_secs: Some(30),
        }];
        let merged =
            merge_kimi_config_via_toml_value(canonical, &no_overlay(), &[], &hooks).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        let arr = parsed["hooks"].as_array().unwrap();
        assert_eq!(
            arr.len(),
            2,
            "user hook survives + csq hook is added, not a wholesale replace: {arr:?}"
        );
        let commands: std::collections::BTreeSet<&str> = arr
            .iter()
            .filter_map(|h| h.get("command").and_then(|v| v.as_str()))
            .collect();
        assert!(commands.contains("user-hook.sh"), "user hook survives");
        assert!(commands.contains("csq-gate.sh"), "csq hook added");

        let csq_hook = arr
            .iter()
            .find(|h| h.get("command").and_then(|v| v.as_str()) == Some("csq-gate.sh"))
            .unwrap();
        assert_eq!(csq_hook["event"].as_str().unwrap(), "PreToolUse");
        assert_eq!(csq_hook["matcher"].as_str().unwrap(), "^Bash$");
        assert_eq!(csq_hook["timeout"].as_integer().unwrap(), 30);
        // Exactly the four HookDefSchema keys on the csq-written entry —
        // nothing extra (.strict()); the ownership marker is a SEPARATE
        // top-level key, never injected into the entry itself.
        let keys: std::collections::BTreeSet<&str> = csq_hook
            .as_table()
            .unwrap()
            .keys()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(
            keys,
            ["event", "matcher", "command", "timeout"]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
        );
        // The ownership marker records exactly this call's contribution.
        let managed = parsed["raw"]["csq_managed_hook_commands"]
            .as_array()
            .unwrap();
        assert_eq!(
            managed
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>(),
            vec!["csq-gate.sh"]
        );
    }

    /// MED-L: a hook whose command IS in the prior call's ownership
    /// marker is csq-owned — THIS call's contribution replaces it (even
    /// with a hook of a different command), while a genuinely
    /// user-authored sibling hook (never in the marker) survives
    /// untouched throughout.
    #[test]
    fn merge_replaces_only_previously_csq_managed_hooks_preserving_user_hooks() {
        let canonical = r#"default_model = "kimi-code/kimi-for-coding"
[raw]
csq_managed_hook_commands = ["old-csq-gate.sh"]

[[hooks]]
event = "PreToolUse"
command = "user-hook.sh"

[[hooks]]
event = "PreToolUse"
command = "old-csq-gate.sh"
"#;
        let hooks = vec![KimiHook {
            event: KimiHookEvent::PreToolUse,
            matcher: None,
            command: "new-csq-gate.sh".to_string(),
            timeout_secs: None,
        }];
        let merged =
            merge_kimi_config_via_toml_value(canonical, &no_overlay(), &[], &hooks).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        let arr = parsed["hooks"].as_array().unwrap();
        let commands: std::collections::BTreeSet<&str> = arr
            .iter()
            .filter_map(|h| h.get("command").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(
            commands,
            ["user-hook.sh", "new-csq-gate.sh"]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
            "old csq-managed hook replaced, user hook preserved, new csq hook added: {arr:?}"
        );
    }

    /// MED-L non-vacuity, the retraction case: an EMPTY `hooks` payload on
    /// a call where csq previously owned a hook MUST retract that hook —
    /// NOT preserve it (the pre-fix bug: empty was indistinguishable from
    /// "no change", so csq could never take back what it wrote). The
    /// user-authored sibling hook still survives.
    #[test]
    fn merge_empty_hooks_retracts_previously_csq_managed_hooks_but_preserves_user_hooks() {
        let canonical = r#"default_model = "kimi-code/kimi-for-coding"
[raw]
csq_managed_hook_commands = ["old-csq-gate.sh"]

[[hooks]]
event = "PreToolUse"
command = "user-hook.sh"

[[hooks]]
event = "PreToolUse"
command = "old-csq-gate.sh"
"#;
        let merged = merge_kimi_config_via_toml_value(canonical, &no_overlay(), &[], &[]).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        let arr = parsed["hooks"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "csq-owned hook retracted: {arr:?}");
        assert_eq!(arr[0]["command"].as_str().unwrap(), "user-hook.sh");
        let managed = parsed["raw"]["csq_managed_hook_commands"]
            .as_array()
            .unwrap();
        assert!(
            managed.is_empty(),
            "marker reflects the retraction (empty), not the stale prior value"
        );
    }

    /// Non-vacuity proof for the regex guard: an unanchored, syntactically
    /// INVALID regex (unbalanced parenthesis) MUST be refused at merge
    /// time, not shipped to silently never-fire.
    #[test]
    fn merge_rejects_malformed_hook_matcher_regex() {
        let hooks = vec![KimiHook {
            event: KimiHookEvent::PreToolUse,
            matcher: Some("(unbalanced".to_string()),
            command: "csq-gate.sh".to_string(),
            timeout_secs: None,
        }];
        let err =
            merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &[], &hooks)
                .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("regex"), "error must name the defect: {msg}");
    }

    /// MED-F non-vacuity, reject boundary 1: a Unicode property escape is
    /// VALID Rust regex (so the malformed-regex check alone would pass it)
    /// but silently means something different under Kimi's JS non-unicode
    /// `RegExp` — MUST be refused, not shipped as a silent divergence.
    #[test]
    fn merge_rejects_js_divergent_unicode_property_matcher() {
        // Sanity: this pattern IS valid Rust regex — the malformed-regex
        // check in isolation would let it through.
        assert!(regex::Regex::new(r"\p{L}+").is_ok());

        let hooks = vec![KimiHook {
            event: KimiHookEvent::PreToolUse,
            matcher: Some(r"\p{L}+".to_string()),
            command: "csq-gate.sh".to_string(),
            timeout_secs: None,
        }];
        let err =
            merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &[], &hooks)
                .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Unicode property"),
            "error must name the JS-divergence defect: {msg}"
        );
    }

    /// MED-F non-vacuity, reject boundary 2: a POSIX bracket expression is
    /// likewise VALID Rust regex but silently reinterpreted (not rejected)
    /// by JS's non-unicode dialect.
    #[test]
    fn merge_rejects_js_divergent_posix_class_matcher() {
        assert!(regex::Regex::new("[[:alpha:]]+").is_ok());

        let hooks = vec![KimiHook {
            event: KimiHookEvent::PreToolUse,
            matcher: Some("[[:alpha:]]+".to_string()),
            command: "csq-gate.sh".to_string(),
            timeout_secs: None,
        }];
        let err =
            merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &[], &hooks)
                .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("POSIX bracket expression"),
            "error must name the JS-divergence defect: {msg}"
        );
    }

    /// Round-10 F1(a): the NEGATED POSIX class `[[:^alpha:]]` is just as
    /// JS-divergent — a naive substring sweep misses it (the `^` breaks
    /// the literal `[:alpha:]` match).
    #[test]
    fn merge_rejects_negated_posix_class_matcher() {
        assert!(regex::Regex::new("[[:^alpha:]]+").is_ok());
        let hooks = vec![KimiHook {
            event: KimiHookEvent::PreToolUse,
            matcher: Some("[[:^alpha:]]+".to_string()),
            command: "csq-gate.sh".to_string(),
            timeout_secs: None,
        }];
        let err =
            merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &[], &hooks)
                .unwrap_err();
        assert!(
            format!("{err}").contains("[:^alpha:]"),
            "negated class must be named in the rejection"
        );
    }

    /// Round-10 F1(b): braced escapes (`\x{41}` = literal `A` in Rust,
    /// `x` + `{41}` quantifier in JS Annex B) — the same silent-divergence
    /// class as `\p`, rejected escape-aware (an escaped backslash first
    /// is fine: `\\x{41}` is literal text in both engines).
    #[test]
    fn merge_rejects_braced_escape_matcher_but_accepts_escaped() {
        for bad in [r"\x{41}", r"\u{1F600}", r"\U0001F600"] {
            let hooks = vec![KimiHook {
                event: KimiHookEvent::PreToolUse,
                matcher: Some(bad.to_string()),
                command: "csq-gate.sh".to_string(),
                timeout_secs: None,
            }];
            let err =
                merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &[], &hooks)
                    .unwrap_err();
            assert!(
                format!("{err}").contains("braced escape"),
                "braced escape {bad} must be rejected"
            );
        }
        let ok = vec![KimiHook {
            event: KimiHookEvent::PreToolUse,
            matcher: Some(r"\\x{41}".to_string()),
            command: "csq-gate.sh".to_string(),
            timeout_secs: None,
        }];
        merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &[], &ok)
            .expect("escaped backslash + x{41} is literal in both engines");
    }

    /// Boundary: the 2-hex `\x41` and 4-hex `\u0041` forms ARE valid in
    /// JS's non-unicode RegExp (JS natively supports both) — NOT
    /// divergent, must not be rejected by an over-broad sweep.
    #[test]
    fn merge_accepts_js_compatible_hex_escapes() {
        for fine in [r"\x41", r"\u0041"] {
            let hooks = vec![KimiHook {
                event: KimiHookEvent::PreToolUse,
                matcher: Some(fine.to_string()),
                command: "csq-gate.sh".to_string(),
                timeout_secs: None,
            }];
            merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &[], &hooks)
                .unwrap_or_else(|e| panic!("{fine} is valid in both engines: {e}"));
        }
    }

    /// MED-F non-vacuity, reject boundary 3: an empty matcher is valid
    /// Rust regex (matches everywhere) — Kimi's own hook engine special-
    /// cases it to fire on EVERY tool call, inverting a deny-style hook.
    /// MUST be refused; `None` is the correct way to express "match
    /// everything".
    #[test]
    fn merge_rejects_empty_hook_matcher() {
        assert!(regex::Regex::new("").is_ok());

        let hooks = vec![KimiHook {
            event: KimiHookEvent::PreToolUse,
            matcher: Some(String::new()),
            command: "csq-gate.sh".to_string(),
            timeout_secs: None,
        }];
        let err =
            merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &[], &hooks)
                .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("empty matcher") && msg.contains("fire on EVERY tool call"),
            "error must name the empty-matcher inversion: {msg}"
        );
    }

    /// MED-F non-vacuity, accept boundary: an ordinary anchored ASCII
    /// pattern with no divergent construct — proves the new checks
    /// discriminate on the specific divergent constructs, not on
    /// "anything non-trivial".
    #[test]
    fn merge_accepts_ordinary_ascii_matcher() {
        let hooks = vec![KimiHook {
            event: KimiHookEvent::PreToolUse,
            matcher: Some("^Bash\\(rm .*\\)$".to_string()),
            command: "csq-gate.sh".to_string(),
            timeout_secs: None,
        }];
        merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &[], &hooks)
            .expect("an ordinary ASCII-anchored pattern must be accepted");
    }

    /// Every emitted matcher, when non-malformed, compiles as a real regex
    /// — proves `render_hook_value`'s escape/anchor contract holds for a
    /// representative anchored pattern.
    #[test]
    fn every_emitted_matcher_compiles_as_regex() {
        let hooks = vec![
            KimiHook {
                event: KimiHookEvent::PreToolUse,
                matcher: Some("^Bash$".to_string()),
                command: "a.sh".to_string(),
                timeout_secs: None,
            },
            KimiHook {
                event: KimiHookEvent::PostToolUse,
                matcher: None,
                command: "b.sh".to_string(),
                timeout_secs: None,
            },
        ];
        let merged =
            merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &[], &hooks)
                .unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        for entry in parsed["hooks"].as_array().unwrap() {
            if let Some(m) = entry.get("matcher").and_then(|v| v.as_str()) {
                regex::Regex::new(m).unwrap_or_else(|e| {
                    panic!("emitted matcher `{m}` failed to compile as regex: {e}")
                });
            }
        }
    }

    #[test]
    fn merge_with_empty_permission_rules_preserves_canonical_permission_table() {
        let canonical = r#"default_model = "kimi-code/kimi-for-coding"

[permission]
default_scope = "user"
"#;
        let merged = merge_kimi_config_via_toml_value(canonical, &no_overlay(), &[], &[]).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        assert_eq!(
            parsed["permission"]["default_scope"].as_str().unwrap(),
            "user",
            "unrelated [permission] sub-keys must survive an empty rules payload"
        );
        assert!(parsed["permission"].get("rules").is_none());
    }

    #[test]
    fn merge_with_non_empty_permission_rules_writes_rules_and_preserves_siblings() {
        let canonical = r#"default_model = "kimi-code/kimi-for-coding"

[permission]
default_scope = "user"
"#;
        let rules = vec![KimiPermissionRule {
            decision: KimiDecision::Deny,
            scope: KimiScope::Project,
            pattern: "Bash(rm -rf *)".to_string(),
            reason: Some("destructive shell command".to_string()),
        }];
        let merged =
            merge_kimi_config_via_toml_value(canonical, &no_overlay(), &rules, &[]).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        assert_eq!(
            parsed["permission"]["default_scope"].as_str().unwrap(),
            "user",
            "sibling key must survive"
        );
        let arr = parsed["permission"]["rules"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["decision"].as_str().unwrap(), "deny");
        assert_eq!(arr[0]["scope"].as_str().unwrap(), "project");
        assert_eq!(arr[0]["pattern"].as_str().unwrap(), "Bash(rm -rf *)");
        assert_eq!(
            arr[0]["reason"].as_str().unwrap(),
            "destructive shell command"
        );
    }

    /// MED-L, permission-rules variant of
    /// `merge_replaces_only_previously_csq_managed_hooks_preserving_user_hooks`:
    /// a rule whose `pattern` IS in the prior call's ownership marker is
    /// csq-owned and gets replaced; a user-authored sibling rule (never in
    /// the marker) survives untouched.
    #[test]
    fn merge_replaces_only_previously_csq_managed_permission_rules_preserving_user_rules() {
        let canonical = r#"default_model = "kimi-code/kimi-for-coding"
[raw]
csq_managed_permission_patterns = ["Bash(rm -rf *)"]

[permission]
default_scope = "user"

[[permission.rules]]
decision = "allow"
scope = "user"
pattern = "Bash(git *)"

[[permission.rules]]
decision = "deny"
scope = "project"
pattern = "Bash(rm -rf *)"
"#;
        let rules = vec![KimiPermissionRule {
            decision: KimiDecision::Deny,
            scope: KimiScope::Project,
            pattern: "Bash(curl *)".to_string(),
            reason: None,
        }];
        let merged =
            merge_kimi_config_via_toml_value(canonical, &no_overlay(), &rules, &[]).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        assert_eq!(
            parsed["permission"]["default_scope"].as_str().unwrap(),
            "user",
            "sibling key must survive"
        );
        let arr = parsed["permission"]["rules"].as_array().unwrap();
        let patterns: std::collections::BTreeSet<&str> = arr
            .iter()
            .filter_map(|r| r.get("pattern").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(
            patterns,
            ["Bash(git *)", "Bash(curl *)"]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
            "old csq-managed rule replaced, user rule preserved, new csq rule added: {arr:?}"
        );
    }

    /// MED-L non-vacuity, permission-rules retraction case: an EMPTY
    /// `permission_rules` payload on a call where csq previously owned a
    /// rule MUST retract it, preserving the user-authored sibling rule and
    /// the `[permission]` table's own siblings.
    #[test]
    fn merge_empty_permission_rules_retracts_previously_csq_managed_rules_but_preserves_user_rules()
    {
        let canonical = r#"default_model = "kimi-code/kimi-for-coding"
[raw]
csq_managed_permission_patterns = ["Bash(rm -rf *)"]

[permission]
default_scope = "user"

[[permission.rules]]
decision = "allow"
scope = "user"
pattern = "Bash(git *)"

[[permission.rules]]
decision = "deny"
scope = "project"
pattern = "Bash(rm -rf *)"
"#;
        let merged = merge_kimi_config_via_toml_value(canonical, &no_overlay(), &[], &[]).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        assert_eq!(
            parsed["permission"]["default_scope"].as_str().unwrap(),
            "user"
        );
        let arr = parsed["permission"]["rules"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "csq-owned rule retracted: {arr:?}");
        assert_eq!(arr[0]["pattern"].as_str().unwrap(), "Bash(git *)");
        let managed = parsed["raw"]["csq_managed_permission_patterns"]
            .as_array()
            .unwrap();
        assert!(managed.is_empty(), "marker reflects the retraction");
    }

    #[test]
    fn merge_applies_typed_overlay_scalar() {
        let mut overlay = BTreeMap::new();
        overlay.insert("yolo".to_string(), "false".to_string());
        let merged =
            merge_kimi_config_via_toml_value(canonical_live_slot(), &overlay, &[], &[]).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        assert_eq!(
            parsed["yolo"].as_bool(),
            Some(false),
            "overlay value `\"false\"` must serialize as TOML boolean, not string: {merged}"
        );
    }

    /// MED-K non-vacuity: a composite (table-shaped) overlay value MUST be
    /// rejected — accepting it would silently REPLACE the target
    /// top-level key wholesale.
    #[test]
    fn merge_rejects_table_shaped_overlay_value() {
        let mut overlay = BTreeMap::new();
        overlay.insert("services".to_string(), "{ }".to_string());
        let err = merge_kimi_config_via_toml_value(canonical_live_slot(), &overlay, &[], &[])
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("composite") || msg.contains("table"),
            "error must name the defect: {msg}"
        );
    }

    #[test]
    fn merge_rejects_array_shaped_overlay_value() {
        let mut overlay = BTreeMap::new();
        overlay.insert("providers".to_string(), "[1, 2]".to_string());
        let err = merge_kimi_config_via_toml_value(canonical_live_slot(), &overlay, &[], &[])
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("array"), "error must name the defect: {msg}");
    }

    /// MED-K regression, the exact clobber the finding demonstrated:
    /// BEFORE the fix, `overlay["services"] = "{ }"` validated and the
    /// merged output LOST `services.kimi-code.oauth` — precisely the
    /// credential-preservation this module exists for.
    #[test]
    fn merge_rejects_overlay_value_that_would_clobber_oauth_wiring() {
        let mut overlay = BTreeMap::new();
        overlay.insert("services".to_string(), "{ }".to_string());
        let err = merge_kimi_config_via_toml_value(canonical_live_slot(), &overlay, &[], &[])
            .unwrap_err();
        assert!(format!("{err}").contains("services"));
    }

    /// LOW-I non-vacuity: an invalid overlay scalar expression is rejected
    /// with the sanitized message, not silently accepted.
    #[test]
    fn merge_rejects_invalid_overlay_scalar_expression() {
        let mut overlay = BTreeMap::new();
        overlay.insert("bad".to_string(), "not valid toml {{{".to_string());
        let err = merge_kimi_config_via_toml_value(canonical_live_slot(), &overlay, &[], &[])
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("invalid TOML scalar expression"),
            "error must name the defect: {msg}"
        );
    }

    /// LOW-I regression: `{err:?}` (anyhow's Debug chain, which — unlike
    /// the top-level `{err}` Display — walks the FULL source chain) must
    /// NOT echo a JWT-like fragment embedded in a malformed overlay scalar
    /// expression. Before the fix, `.with_context(...)` wrapped the raw
    /// `toml::de::Error` as the anyhow chain's source, and
    /// `toml::de::Error`'s own Display quotes the offending source line
    /// verbatim (confirmed empirically) — this test pins that the
    /// `map_err(|_| ...)` fix discards it, mirroring
    /// `merge_corrupt_canonical_does_not_echo_parse_error_body` below for
    /// the canonical-parse leg.
    #[test]
    fn merge_overlay_parse_error_does_not_echo_scalar_value_via_debug_chain() {
        let mut overlay = BTreeMap::new();
        overlay.insert(
            "bad".to_string(),
            "eyJhbGciOi.fake_jwt_fragment.x not-a-scalar {{{".to_string(),
        );
        let err = merge_kimi_config_via_toml_value(canonical_live_slot(), &overlay, &[], &[])
            .unwrap_err();
        let debug_text = format!("{err:?}");
        assert!(
            !debug_text.contains("eyJhbGciOi"),
            "error Debug chain must not echo JWT-like fragments from a malformed \
             overlay value: {debug_text}"
        );
    }

    #[test]
    fn merge_corrupt_canonical_does_not_echo_parse_error_body() {
        let corrupt = "default_model = eyJhbGciOi.fake_jwt_payload.x\n";
        let err = merge_kimi_config_via_toml_value(corrupt, &no_overlay(), &[], &[]).unwrap_err();
        let err_text = format!("{err}");
        assert!(
            !err_text.contains("eyJhbGciOi"),
            "error must not echo JWT-like fragments from parse failure: {err_text}"
        );
        assert!(
            err_text.contains("re-run") && err_text.contains("csq login"),
            "error must direct operator to recovery: {err_text}"
        );
    }

    // ── Round-4 (R4-1/D4-1): scalar overlay at a table/array key ─────

    /// D4-1 scenario A: `overlay["raw"] = "\"x\""` would wholesale-replace
    /// the `[raw]` table, destroying BOTH csq ownership markers — the
    /// next call would read previously-managed = empty and duplicate
    /// every csq hook without bound. Refused target-aware.
    #[test]
    fn merge_rejects_scalar_overlay_at_raw_table_key() {
        let canonical = r#"default_model = "kimi-code/kimi-for-coding"

[raw]
csq_managed_hook_commands = ["csq-gate.sh"]
"#;
        let mut overlay = BTreeMap::new();
        overlay.insert("raw".to_string(), "\"x\"".to_string());
        let err = merge_kimi_config_via_toml_value(canonical, &overlay, &[], &[]).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("raw") && msg.contains("REPLACE"),
            "error must name the key and the clobber: {msg}"
        );
    }

    /// D4-1 scenario B: `overlay["hooks"] = "\"\""` would replace the
    /// merged hooks array written by THIS call's merge branch (csq's
    /// hooks never reach the vendor while the marker claims ownership).
    #[test]
    fn merge_rejects_scalar_overlay_at_hooks_array_key() {
        let canonical = r#"default_model = "kimi-code/kimi-for-coding"

[[hooks]]
event = "PreToolUse"
command = "user-hook.sh"
"#;
        let mut overlay = BTreeMap::new();
        overlay.insert("hooks".to_string(), "\"\"".to_string());
        let err = merge_kimi_config_via_toml_value(canonical, &overlay, &[], &[]).unwrap_err();
        assert!(format!("{err}").contains("hooks"));
    }

    /// R4-1: the sec lens's original key class — `services` carries the
    /// vendor OAuth wiring; a scalar overlay there is the same clobber.
    #[test]
    fn merge_rejects_scalar_overlay_at_services_table_key() {
        let mut overlay = BTreeMap::new();
        overlay.insert("services".to_string(), "\"x\"".to_string());
        let err = merge_kimi_config_via_toml_value(canonical_live_slot(), &overlay, &[], &[])
            .unwrap_err();
        assert!(format!("{err}").contains("services"));
    }

    /// R9 NIT-3: the target-aware check reads POST-merge table state —
    /// a table THIS call's merge branch synthesized (canonical lacked
    /// `[permission]`, non-empty rules create it) must ALSO be refused.
    /// A future refactor moving the overlay loop before the merge
    /// branches would flip this to a silent clobber with no failing test.
    #[test]
    fn merge_rejects_scalar_overlay_at_synthesized_permission_table() {
        let canonical = r#"default_model = "kimi-code/kimi-for-coding"
"#;
        let rules = vec![KimiPermissionRule {
            decision: crate::coc::translate::types::KimiDecision::Allow,
            scope: crate::coc::translate::types::KimiScope::User,
            pattern: "Bash(git *)".to_string(),
            reason: None,
        }];
        let mut overlay = BTreeMap::new();
        overlay.insert("permission".to_string(), "\"x\"".to_string());
        let err = merge_kimi_config_via_toml_value(canonical, &overlay, &rules, &[]).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("permission") && msg.contains("REPLACE"),
            "synthesized table must be refused: {msg}"
        );
    }

    /// Positive control: a scalar overlay at an ABSENT key (no existing
    /// subtree to clobber) still inserts fine.
    #[test]
    fn merge_allows_scalar_overlay_at_absent_key() {
        let mut overlay = BTreeMap::new();
        overlay.insert("my_feature_flag".to_string(), "true".to_string());
        let merged =
            merge_kimi_config_via_toml_value(canonical_live_slot(), &overlay, &[], &[]).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        assert!(
            parsed["my_feature_flag"].as_bool().unwrap(),
            "absent scalar key must insert: {merged}"
        );
        // And the OAuth wiring is untouched.
        assert_eq!(
            parsed["services"]["kimi-code"]["oauth"]["key"]
                .as_str()
                .unwrap(),
            "oauth/kimi-code"
        );
    }

    // ── Round-4 (D4-3): timeout_secs vendor schema bound ─────────────

    #[test]
    fn merge_rejects_hook_timeout_out_of_vendor_range() {
        for bad in [0u16, 601u16] {
            let hooks = vec![KimiHook {
                event: KimiHookEvent::PreToolUse,
                matcher: None,
                command: "csq-gate.sh".to_string(),
                timeout_secs: Some(bad),
            }];
            let err =
                merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &[], &hooks)
                    .unwrap_err();
            let msg = format!("{err}");
            assert!(
                msg.contains("1..=600"),
                "timeout {bad} must be rejected with the vendor bound named: {msg}"
            );
        }
    }

    #[test]
    fn merge_accepts_hook_timeout_at_vendor_bounds() {
        for ok in [1u16, 600u16] {
            let hooks = vec![KimiHook {
                event: KimiHookEvent::PreToolUse,
                matcher: None,
                command: "csq-gate.sh".to_string(),
                timeout_secs: Some(ok),
            }];
            merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &[], &hooks)
                .unwrap_or_else(|e| panic!("timeout {ok} must be accepted: {e}"));
        }
    }

    // ── Round-4 (D4-2): permission pattern vendor grammar ────────────

    #[test]
    fn merge_rejects_empty_permission_pattern() {
        let rules = vec![KimiPermissionRule {
            decision: crate::coc::translate::types::KimiDecision::Allow,
            scope: crate::coc::translate::types::KimiScope::User,
            pattern: String::new(),
            reason: None,
        }];
        let err =
            merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &rules, &[])
                .unwrap_err();
        assert!(format!("{err}").contains("empty"));
    }

    #[test]
    fn merge_rejects_non_grammar_permission_pattern() {
        // "Bash(arg)extra)" has a stray `)` inside the arg body — passed
        // the naive ends_with check (R7 NIT); "Bash((x))" nests.
        for bad in [
            "Bash(rm",
            "Bash)",
            "Ba sh",
            "(Bash)",
            "Bash(arg)extra)",
            "Bash((x))",
        ] {
            let rules = vec![KimiPermissionRule {
                decision: crate::coc::translate::types::KimiDecision::Allow,
                scope: crate::coc::translate::types::KimiScope::User,
                pattern: bad.to_string(),
                reason: None,
            }];
            let err =
                merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &rules, &[])
                    .unwrap_err();
            assert!(
                format!("{err}").contains("grammar"),
                "pattern `{bad}` must be rejected with the grammar named"
            );
        }
    }

    #[test]
    fn merge_accepts_vendor_grammar_permission_patterns() {
        for ok in ["Bash(rm -rf *)", "Read", "Bash()"] {
            let rules = vec![KimiPermissionRule {
                decision: crate::coc::translate::types::KimiDecision::Allow,
                scope: crate::coc::translate::types::KimiScope::User,
                pattern: ok.to_string(),
                reason: None,
            }];
            merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &rules, &[])
                .unwrap_or_else(|e| panic!("pattern `{ok}` must be accepted: {e}"));
        }
    }

    // ── Round-4 (D4-7): escape-aware Unicode-property scan ───────────

    #[test]
    fn merge_accepts_escaped_backslash_before_p_matcher() {
        // `\\pine` is an escaped backslash + literal `pine` in BOTH
        // engines — NOT a Unicode property escape. The context-free
        // substring check over-rejected this shape.
        let hooks = vec![KimiHook {
            event: KimiHookEvent::PreToolUse,
            matcher: Some(r"\\pine".to_string()),
            command: "csq-gate.sh".to_string(),
            timeout_secs: None,
        }];
        merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &[], &hooks)
            .expect("escaped-backslash literal must be accepted");
    }

    /// R12-F3: an unrelated, non-csq key already under `[raw]` MUST survive
    /// csq writing its own ownership markers into the same table.
    ///
    /// `[raw]` is the vendor's documented arbitrary-keys escape hatch, so a
    /// user (or a future csq feature) can legitimately hold state there.
    /// `set_raw_marker` uses `.entry().or_insert_with()` precisely so the
    /// table is extended rather than replaced — but every existing test that
    /// populates `[raw]` puts ONLY csq markers there, so a regression that
    /// replaced the table wholesale
    /// (`table_mut.insert("raw", Value::Table(only_the_marker))`) would pass
    /// the whole suite while silently dropping unrelated `[raw]` content on
    /// every merge.
    #[test]
    fn merge_preserves_unrelated_raw_keys_while_writing_own_markers() {
        let canonical = r#"default_model = "kimi-code/kimi-for-coding"

[raw]
some_user_flag = true
user_note = "hand-written, not csq's"
"#;
        let hooks = vec![KimiHook {
            event: KimiHookEvent::PreToolUse,
            matcher: None,
            command: "csq-gate.sh".to_string(),
            timeout_secs: None,
        }];
        let rules = vec![KimiPermissionRule {
            decision: KimiDecision::Deny,
            scope: KimiScope::Project,
            pattern: "Bash(rm -rf*)".to_string(),
            reason: None,
        }];

        let merged =
            merge_kimi_config_via_toml_value(canonical, &no_overlay(), &rules, &hooks).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        let raw = parsed["raw"].as_table().expect("[raw] must remain a table");

        assert_eq!(
            raw.get("some_user_flag").and_then(|v| v.as_bool()),
            Some(true),
            "unrelated boolean under [raw] must survive; got: {raw:?}"
        );
        assert_eq!(
            raw.get("user_note").and_then(|v| v.as_str()),
            Some("hand-written, not csq's"),
            "unrelated string under [raw] must survive; got: {raw:?}"
        );
        // ...and csq's own markers landed alongside, not instead.
        assert!(
            raw.contains_key(CSQ_MANAGED_HOOK_COMMANDS_KEY)
                && raw.contains_key(CSQ_MANAGED_PERMISSION_PATTERNS_KEY),
            "csq markers must be written into the same [raw] table; got: {raw:?}"
        );

        // Second merge must not disturb them either — the retraction pass
        // re-reads and re-writes [raw], which is where a wholesale replace
        // would surface.
        let remerged =
            merge_kimi_config_via_toml_value(&merged, &no_overlay(), &rules, &hooks).unwrap();
        let reparsed: toml::Value = toml::from_str(&remerged).unwrap();
        let raw2 = reparsed["raw"].as_table().unwrap();
        assert_eq!(
            raw2.get("some_user_flag").and_then(|v| v.as_bool()),
            Some(true),
            "unrelated [raw] key must survive a RE-merge too; got: {raw2:?}"
        );
    }

    /// R12-F4: a malformed (non-array) prior ownership marker degrades to
    /// "csq owned nothing" rather than crashing — and the degradation is
    /// LOUD, not silent.
    ///
    /// Reading the marker goes through `managed_marker_set`, which warns
    /// (`error_kind = "kimi_marker_malformed"`) before returning the empty
    /// set. This test pins the graceful half — the merge still succeeds and
    /// the previously-csq-managed hook is preserved as user-authored, which
    /// is the honest consequence: csq can no longer prove it owned the
    /// entry, so it must not delete it.
    #[test]
    fn merge_tolerates_malformed_non_array_ownership_marker() {
        // Marker is a STRING, not an array — hand-edit or format change.
        let canonical = r#"default_model = "kimi-code/kimi-for-coding"

[[hooks]]
event = "PreToolUse"
command = "csq-gate.sh"

[raw]
csq_managed_hook_commands = "csq-gate.sh"
"#;
        let hooks = vec![KimiHook {
            event: KimiHookEvent::PreToolUse,
            matcher: None,
            command: "csq-gate.sh".to_string(),
            timeout_secs: None,
        }];

        let merged = merge_kimi_config_via_toml_value(canonical, &no_overlay(), &[], &hooks)
            .expect("malformed marker must not fail the merge");
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        let arr = parsed["hooks"].as_array().unwrap();

        // The on-disk hook could not be proven csq-owned, so it is kept AND
        // csq's contribution is added: two entries with the same command.
        // That accumulation is the documented cost of an unreadable marker.
        assert_eq!(
            arr.len(),
            2,
            "unprovable ownership must PRESERVE the on-disk hook and ADD              csq's, not delete the on-disk one; got: {arr:?}"
        );
        assert!(
            arr.iter()
                .all(|h| h["command"].as_str() == Some("csq-gate.sh")),
            "both entries are the same command; got: {arr:?}"
        );

        // The marker is repaired to a well-formed array on the way out, so
        // the NEXT merge can prove ownership again and stops accumulating.
        let raw = parsed["raw"].as_table().unwrap();
        let marker = raw
            .get(CSQ_MANAGED_HOOK_COMMANDS_KEY)
            .and_then(|v| v.as_array())
            .expect("marker must be rewritten as an array");
        assert_eq!(marker.len(), 1);
        assert_eq!(marker[0].as_str(), Some("csq-gate.sh"));

        // Prove the self-healing claim, and prove it does not merely stop
        // growing — it CONVERGES. Ownership is tracked by `command`, so once
        // the marker is a readable array BOTH same-command entries are
        // provably csq-owned on the next pass and collapse into this call's
        // single contribution. The duplicate the unreadable marker caused is
        // therefore transient: one merge to appear, one to clear.
        let remerged =
            merge_kimi_config_via_toml_value(&merged, &no_overlay(), &[], &hooks).unwrap();
        let reparsed: toml::Value = toml::from_str(&remerged).unwrap();
        let arr2 = reparsed["hooks"].as_array().unwrap();
        assert_eq!(
            arr2.len(),
            1,
            "with a repaired marker both same-command entries are provably \
             csq-owned and collapse to the single contribution — the \
             malformed-marker duplicate must not persist; got: {arr2:?}"
        );
        assert_eq!(arr2[0]["command"].as_str(), Some("csq-gate.sh"));

        // ...and it is a fixed point from there.
        let third =
            merge_kimi_config_via_toml_value(&remerged, &no_overlay(), &[], &hooks).unwrap();
        assert_eq!(third, remerged, "merge must be idempotent once converged");
    }

    /// R12-F4 detection: the malformed-marker DEFECT is classified, not just
    /// silently absorbed. `zero-tolerance.md` Rule 3 forbids silent
    /// fallbacks; the behavioral tests below cannot tell a warning
    /// implementation from a silent one, so the classifier is asserted here
    /// directly.
    #[test]
    fn read_managed_marker_classifies_every_defect_shape() {
        let parse = |t: &str| -> toml::value::Table {
            toml::from_str::<toml::Value>(t)
                .unwrap()
                .as_table()
                .unwrap()
                .clone()
        };
        let k = CSQ_MANAGED_HOOK_COMMANDS_KEY;

        // Absent marker is the virgin-canonical case — NOT a defect.
        let (set, defect) = read_managed_marker(&parse("a = 1"), k);
        assert!(set.is_empty());
        assert_eq!(
            defect, None,
            "absent marker must not be reported as a defect"
        );

        // Absent `[raw]` key but `[raw]` present — still not a defect.
        let (_, defect) = read_managed_marker(&parse("[raw]\nother = true"), k);
        assert_eq!(defect, None);

        // Well-formed array — no defect.
        let (set, defect) = read_managed_marker(
            &parse("[raw]\ncsq_managed_hook_commands = [\"a\", \"b\"]"),
            k,
        );
        assert_eq!(set.len(), 2);
        assert_eq!(defect, None);

        // Duplicates collapse in the set but are NOT a defect — the array is
        // entirely strings, nothing was lost.
        let (set, defect) = read_managed_marker(
            &parse("[raw]\ncsq_managed_hook_commands = [\"a\", \"a\"]"),
            k,
        );
        assert_eq!(set.len(), 1);
        assert_eq!(
            defect, None,
            "duplicate string members are harmless, not a defect"
        );

        // Scalar where an array belongs.
        let (set, defect) =
            read_managed_marker(&parse("[raw]\ncsq_managed_hook_commands = \"a\""), k);
        assert!(set.is_empty());
        assert_eq!(
            defect,
            Some(MarkerDefect::NotAnArray {
                found_type: "string"
            })
        );

        // Table where an array belongs.
        let (_, defect) = read_managed_marker(&parse("[raw.csq_managed_hook_commands]\nx = 1"), k);
        assert_eq!(
            defect,
            Some(MarkerDefect::NotAnArray {
                found_type: "table"
            })
        );

        // Array with a non-string member.
        let (set, defect) =
            read_managed_marker(&parse("[raw]\ncsq_managed_hook_commands = [\"a\", 42]"), k);
        assert_eq!(set.len(), 1, "the usable member still counts");
        assert_eq!(
            defect,
            Some(MarkerDefect::NonStringMembers {
                total: 2,
                usable: 1
            })
        );
    }

    /// R12-F4 sibling: a marker array whose MEMBERS are not strings loses
    /// ownership for exactly those members (and warns), rather than silently
    /// treating the whole marker as empty.
    #[test]
    fn merge_tolerates_marker_array_with_non_string_members() {
        let canonical = r#"default_model = "kimi-code/kimi-for-coding"

[[hooks]]
event = "PreToolUse"
command = "csq-gate.sh"

[[hooks]]
event = "PreToolUse"
command = "csq-other.sh"

[raw]
csq_managed_hook_commands = ["csq-gate.sh", 42]
"#;
        let hooks = vec![KimiHook {
            event: KimiHookEvent::PreToolUse,
            matcher: None,
            command: "csq-gate.sh".to_string(),
            timeout_secs: None,
        }];

        let merged =
            merge_kimi_config_via_toml_value(canonical, &no_overlay(), &[], &hooks).unwrap();
        let parsed: toml::Value = toml::from_str(&merged).unwrap();
        let commands: Vec<&str> = parsed["hooks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["command"].as_str().unwrap())
            .collect();

        // "csq-gate.sh" WAS provably csq-managed (usable string member), so
        // the on-disk copy is replaced by this call's contribution — one
        // entry, not two. "csq-other.sh" was only "owned" via the unusable
        // member, so it survives as user-authored.
        assert_eq!(
            commands.iter().filter(|c| **c == "csq-gate.sh").count(),
            1,
            "provably-owned command must be replaced, not duplicated; got: {commands:?}"
        );
        assert!(
            commands.contains(&"csq-other.sh"),
            "entry whose ownership claim was unusable must be preserved; got: {commands:?}"
        );
    }

    /// Round-5 F1: merge∘merge is byte-stable (idempotent). The
    /// ownership-marker scheme's core promise is stability across
    /// repeated `csq run` re-merges of the SAME payload into the SAME
    /// config — if the serializer emits the `[raw]` marker in a shape
    /// `raw_marker` cannot re-read, the second merge would reclassify
    /// every csq entry as user-authored and duplicate without bound
    /// (the D4-1 class). Every other second-call test hand-writes its
    /// canonical; this one feeds the function's OWN output back.
    #[test]
    fn merge_is_idempotent_across_remerge_of_own_output() {
        let hooks = vec![KimiHook {
            event: KimiHookEvent::PreToolUse,
            matcher: Some("^Bash$".to_string()),
            command: "csq-gate.sh".to_string(),
            timeout_secs: Some(30),
        }];
        let rules = vec![KimiPermissionRule {
            decision: crate::coc::translate::types::KimiDecision::Allow,
            scope: crate::coc::translate::types::KimiScope::User,
            pattern: "Bash(git *)".to_string(),
            reason: Some("coc rule".to_string()),
        }];
        let first =
            merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &rules, &hooks)
                .unwrap();
        let second =
            merge_kimi_config_via_toml_value(&first, &no_overlay(), &rules, &hooks).unwrap();
        assert_eq!(
            first, second,
            "re-merging the same payload into csq's own output must be a no-op"
        );
        // And a THIRD merge with an EMPTY contribution must RETRACT the
        // csq entries: markers emptied (no stale ownership), no csq hook
        // or rule left behind, vendor/user content intact. (The merge
        // normalizes the presence of `hooks`/`[permission]`/`[raw]` as
        // EMPTY containers rather than deleting the keys — schema-valid
        // and harmless; byte-retraction to the pre-csq canonical is NOT
        // the contract.)
        let retracted = merge_kimi_config_via_toml_value(&first, &no_overlay(), &[], &[]).unwrap();
        let parsed: toml::Value = toml::from_str(&retracted).unwrap();
        assert_eq!(
            parsed["hooks"].as_array().map(|a| a.len()),
            Some(0),
            "retraction must leave zero csq hooks: {retracted}"
        );
        assert_eq!(
            parsed["permission"]["rules"].as_array().map(|a| a.len()),
            Some(0),
            "retraction must leave zero csq rules: {retracted}"
        );
        assert_eq!(
            parsed["raw"]["csq_managed_hook_commands"]
                .as_array()
                .map(|a| a.len()),
            Some(0),
            "hook ownership marker must be emptied (no stale ownership): {retracted}"
        );
        assert_eq!(
            parsed["services"]["kimi-code"]["oauth"]["key"]
                .as_str()
                .unwrap(),
            "oauth/kimi-code",
            "vendor OAuth wiring survives the retraction"
        );
    }

    /// Round-5 F4: multi-entry contributions preserve their Vec order —
    /// the permission_rules/hooks docs promise "preserves this Vec's
    /// insertion order verbatim" and the future populating shard relies
    /// on it for deterministic precedence.
    #[test]
    fn merge_preserves_contribution_insertion_order() {
        let mk = |cmd: &str| KimiHook {
            event: KimiHookEvent::PreToolUse,
            matcher: None,
            command: cmd.to_string(),
            timeout_secs: None,
        };
        let hooks = vec![mk("a-first.sh"), mk("b-second.sh"), mk("c-third.sh")];
        let merged =
            merge_kimi_config_via_toml_value(canonical_live_slot(), &no_overlay(), &[], &hooks)
                .unwrap();
        let pos_a = merged.find("a-first.sh").unwrap();
        let pos_b = merged.find("b-second.sh").unwrap();
        let pos_c = merged.find("c-third.sh").unwrap();
        assert!(
            pos_a < pos_b && pos_b < pos_c,
            "hook order must follow the input Vec: {merged}"
        );
    }

    /// Round-5 F6: the R4-1 guard's boundary is DOCUMENTED — a scalar
    /// overlay at an absent composite-named key (no existing subtree to
    /// clobber) is ACCEPTED today (operator GIGO, fail-visible at vendor
    /// load). Pin the boundary so a future tightening is a deliberate
    /// change, not a silent one.
    #[test]
    fn merge_accepts_scalar_overlay_at_absent_composite_named_key() {
        let canonical = "default_model = \"kimi-code/kimi-for-coding\"\n";
        let mut overlay = BTreeMap::new();
        overlay.insert("hooks".to_string(), "\"x\"".to_string());
        let merged = merge_kimi_config_via_toml_value(canonical, &overlay, &[], &[]).unwrap();
        assert!(
            merged.contains("hooks = \"x\""),
            "absent-key scalar overlay is the documented accepted boundary: {merged}"
        );
    }

    /// Round-5 F2/F5: every KimiHookEvent's serde wire name equals its
    /// TOML `as_str` name — the two channels cannot drift silently.
    #[test]
    fn serde_wire_names_match_as_str_for_all_hook_events() {
        use crate::coc::translate::types::KimiHookEvent;
        let all = [
            KimiHookEvent::PreToolUse,
            KimiHookEvent::PostToolUse,
            KimiHookEvent::PostToolUseFailure,
            KimiHookEvent::PermissionRequest,
            KimiHookEvent::PermissionResult,
            KimiHookEvent::UserPromptSubmit,
            KimiHookEvent::Stop,
            KimiHookEvent::StopFailure,
            KimiHookEvent::Interrupt,
            KimiHookEvent::SessionStart,
            KimiHookEvent::SessionEnd,
            KimiHookEvent::SubagentStart,
            KimiHookEvent::SubagentStop,
            KimiHookEvent::PreCompact,
            KimiHookEvent::PostCompact,
            KimiHookEvent::Notification,
        ];
        for v in all {
            let wire = serde_json::to_value(v).unwrap();
            assert_eq!(
                wire,
                serde_json::Value::String(v.as_str().to_string()),
                "serde wire name must equal as_str for {v:?}"
            );
        }
    }

    /// Round-5 F2/F5: KimiDecision + KimiScope full-variant sweeps.
    #[test]
    fn serde_wire_names_match_as_str_for_decision_and_scope() {
        use crate::coc::translate::types::{KimiDecision, KimiScope};
        for v in [KimiDecision::Allow, KimiDecision::Deny] {
            let wire = serde_json::to_value(v).unwrap();
            assert_eq!(
                wire,
                serde_json::Value::String(v.as_str().to_string()),
                "decision wire name must equal as_str for {v:?}"
            );
        }
        for v in [
            KimiScope::TurnOverride,
            KimiScope::SessionRuntime,
            KimiScope::Project,
            KimiScope::User,
        ] {
            let wire = serde_json::to_value(v).unwrap();
            assert_eq!(
                wire,
                serde_json::Value::String(v.as_str().to_string()),
                "scope wire name must equal as_str for {v:?}"
            );
        }
    }
}
