# 09 Unified `.coc/` Artifact Standard — csq Consumer Contract

Spec version: 2.2.0 | Status: DRAFT | Governs: how csq reads `.coc/` artifacts, the legacy fallback chain, frontmatter contract, version envelope, read-only invariant

---

## 9.0 Scope

This spec is the csq-side **consumer contract** for the unified `.coc/` artifact format. csq is a consumer of `.coc/` content; this spec fixes only what csq reads, what shape csq depends on, and how csq behaves when the format changes underneath it.

The scope of this spec is exactly:

1. The minimum directory shape csq depends on (`§ 9.1`).
2. The frontmatter fields csq reads from each artifact (`§ 9.2`).
3. The in-memory `CocSet` type csq parses `.coc/` content into (`§ 9.2`).
4. The fallback chain when `.coc/` is absent (`§ 9.3`).
5. The precedence rule when `.coc/` and a legacy format coexist (`§ 9.4`).
6. The `coc.version` envelope and degrade-on-newer behavior (`§ 9.5`).
7. The per-Surface × per-OS resolution paths for both `.coc/` and the legacy fallback chain (`§ 9.6`).
8. The schema-version compatibility matrix (`§ 9.9`, mirroring spec 07 §7.4.1).
9. The read-only invariant (`§ 9.10`).

What this spec does NOT cover:

- The producer-side `.coc/` emit logic. csq's contract begins at "a `.coc/` directory exists in the working tree."
- The downstream pipeline that consumes the parsed `CocSet`.

---

## 9.1 Directory shape

csq reads `.coc/` from the project root with the minimum shape:

```
<project_root>/
└── .coc/
    ├── COC.md            ← top-level primer (required)
    ├── COC.lock          ← canonical content hash, cache-invalidation key (required)
    ├── rules/            ← required directory; may be empty
    ├── agents/           ← required directory; may be empty
    ├── skills/           ← required directory; may be empty
    └── commands/         ← required directory; may be empty
```

`COC.md` carries the human-readable primer. `COC.lock` is a JSON file capturing the SHA-256 of every file under `.coc/` that csq depends on; csq uses the SHA-256 of `COC.lock`'s own content as the parse-cache invalidation key (see `csq-core/src/coc/cache.rs`).

csq tolerates additional siblings under `.coc/` (e.g. `hooks/`, `templates/`, `.coc/.cache/`) without reading them, on the principle "csq depends on the canonical shape AND nothing else." Forward-compat content lives in unknown directories until csq learns about them.

The four canonical subdirectories (`rules/`, `agents/`, `skills/`, `commands/`) MUST exist as directories even when empty. An empty subdirectory is structurally distinct from an absent one; csq tolerates the former and treats the latter as "not a `.coc/` shape" (falls through to the fallback chain in `§ 9.3`).

### 9.1.1 csq's read-time invariants

| Invariant         | Statement                                                                                       | Test                                             |
| ----------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| MUST-NOT-WRITE    | csq MUST NOT write under `.coc/` from any code path                                             | `§ 9.10` static grep test                        |
| MUST-RESOLVE-ROOT | csq's `.coc/` root MUST be resolved by walking from CWD upward to the first hit                 | `csq-core/src/coc/loader.rs` discovery loop      |
| MUST-CANONICALIZE | csq MUST canonicalize the resolved path (resolve symlinks) before computing the parse-cache key | `csq-core/src/coc/cache.rs` `lock_sha256` keying |
| DETERMINISTIC     | csq's `fs::read_dir` traversal MUST sort entries before consuming them                          | `§ 9.2.5` `BTreeMap` discipline + clippy lint    |

---

## 9.2 Frontmatter contract

Every artifact under `.coc/rules/`, `.coc/agents/`, `.coc/skills/`, `.coc/commands/` is a Markdown file with YAML frontmatter. csq reads only these fields:

### 9.2.1 Required fields

| Field         | Type     | Notes                                                                            |
| ------------- | -------- | -------------------------------------------------------------------------------- |
| `id`          | `string` | RULE_ID / AGENT_ID / SKILL_ID / COMMAND_ID. MUST match `^[A-Z][A-Z0-9-]{1,32}$`. |
| `coc.version` | `string` | Consumer-contract semver. csq honors `<major>.<minor>.<patch>` per `§ 9.5`.      |

### 9.2.2 Optional fields

| Field         | Type          | Default   | Notes                                                                                                                                                                                                                                                                                                                                                                                                               |
| ------------- | ------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `paths`       | `Vec<string>` | `["**"]`  | Parsed into the typed `RuleDef.paths` field but **not consumed by spawn-time artifact selection**: `flatten::in_scope` filters on `applies_to` only. The capability layer flattens the whole `.coc/` into one system prompt at session start — there is no current-file context — so CC's per-file rule path scoping has no spawn analogue; codex/gemini have no per-file rule-scoping mechanism. Rules-only field. |
| `coc.disable` | `Vec<string>` | `[]`      | Per-artifact technique opt-out array. Allowed values: `"scaffold"`, `"mcp-gate"`, `"post-validate"`, `"struct-out"`.                                                                                                                                                                                                                                                                                                |
| `applies_to`  | `Vec<string>` | `["all"]` | Surface allowlist. Allowed: `"all"` / `"claude-code"` / `"codex"` / `"gemini"`. Filtering is OR-of-listed.                                                                                                                                                                                                                                                                                                          |
| `precedence`  | `i32`         | `0`       | Tie-break for collision resolution within `.coc/`. Higher wins. Default 0.                                                                                                                                                                                                                                                                                                                                          |

### 9.2.3 Unknown-field tolerance (forward-compat)

csq MUST tolerate fields not in `§ 9.2.1` and `§ 9.2.2`. Unknown fields are surfaced via `csq inspect coc --show-unknowns` (debug-mode listing). They MUST NOT trigger parse failure; they MUST NOT be silently dropped without surfacing.

This is the inverse of `serde_json`'s `deny_unknown_fields` — csq uses `#[serde(default)]` with explicit pass-through capture for unknowns. Implementation: `CocFrontmatter` struct with `#[serde(flatten)]` on a `BTreeMap<String, serde_json::Value>` for the unknown bucket.

### 9.2.4 In-memory type — `CocSet`

csq parses `.coc/` content into the canonical `CocSet` Rust struct. This struct is contractual — implementations of `csq-core/src/coc/parser.rs` MUST produce this shape, and downstream consumers MUST consume only this shape:

```rust
pub struct CocSet {
    /// Rules organized by id, sorted (BTreeMap → deterministic iteration).
    pub rules: BTreeMap<RuleId, RuleDef>,
    /// Agents organized by id, sorted.
    pub agents: BTreeMap<AgentId, AgentDef>,
    /// Skills organized by id, sorted.
    pub skills: BTreeMap<SkillId, SkillDef>,
    /// Commands organized by id, sorted.
    pub commands: BTreeMap<CommandId, CommandDef>,
    /// Version envelope from `COC.md` frontmatter (NOT per-artifact).
    pub version: CocVersion,
    /// Origin marker — which fallback level produced this set.
    pub source: CocSource,
}

pub enum CocSource {
    /// Loaded from `.coc/` with a `COC.lock` content hash recorded.
    Coc { lock_sha256: [u8; 32] },
    /// Fallback to `.claude/`.
    LegacyClaude,
    /// Fallback to `.gemini/`.
    LegacyGemini,
    /// Fallback to `AGENTS.md` discovery (codex resolver chain).
    LegacyAgentsMd,
    /// No source found — downstream consumer disables for this invocation.
    Empty,
}

pub struct RuleId(pub String);  // newtype, validated against `§ 9.2.1` regex
pub struct AgentId(pub String);
pub struct SkillId(pub String);
pub struct CommandId(pub String);

pub struct RuleDef {
    pub id: RuleId,
    pub paths: Vec<String>, // rules-only; parsed but NOT consumed by `flatten::in_scope` (§9.2.2 — no spawn analogue)
    pub applies_to: BTreeSet<Surface>,
    pub precedence: i32,
    pub disable: BTreeSet<TechniqueOptOut>,
    pub body: String,                                  // raw Markdown body
    pub unknowns: BTreeMap<String, serde_json::Value>, // forward-compat bucket
}
// AgentDef, SkillDef, CommandDef have the same shape minus `paths` for non-rule kinds.

pub enum TechniqueOptOut {
    Scaffold,
    McpGate,
    PostValidate,
    StructOut,
}

pub struct CocVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}
```

The `CocSet` is the **only** form in which `.coc/` content reaches the downstream pipeline. Translators consume `&CocSet`; they do not re-parse Markdown. The `COC.lock` SHA-256 captured on the `Coc` source variant covers exactly the bytes that produce this struct, serving as the parse-cache invalidation key (see `csq-core/src/coc/cache.rs`).

#### 9.2.4.1 Universal-artifact semantics

An artifact (rule, agent, skill, or command) with `applies_to: BTreeSet::new()` (empty set) is **universal** — every consumer MUST include it regardless of the target Surface, **for the artifact families that consumer processes**:

- **Translators + live scaffold** both flatten via the shared `csq_core::coc::translate::flatten::flatten_artifacts`, which applies the universal-artifact filter (the single `flatten::in_scope` predicate) to all four artifact families (rules + agents + skills + commands). The per-translator filter sites and the live `csq run` scaffold stage (`csq_core::capability_layer::scaffold::ScaffoldStage`) all flatten through this one predicate, so the live scaffold delivers rules + agents + skills + commands.
- **Citation rule-id set** (`csq_core::capability_layer::driver::extract_rule_ids_in_scope`) applies the SAME `flatten::in_scope` predicate, scoped to rules only.

The shared universal-artifact filter expression (`flatten::in_scope`) is:

```rust
.filter(|x| x.applies_to.is_empty() || x.applies_to.contains(&surface))
```

12 regression tests (`universal_{rule,agent,skill,command}_appears_in_{cc,codex,gemini}_translator`) pin the contract.

### 9.2.5 Determinism by type construction

`BTreeMap` and `BTreeSet` enforce sorted iteration without per-call `.sorted()` calls. The `CocSet` shape, combined with deterministic file-system traversal under `§ 9.1.1` and a clippy-banned `HashMap` rule scoped to `csq-core/src/coc/**`, gives cross-process determinism by construction — the same `.coc/` produces byte-identical translator output across runs and across machines.

---

## 9.3 Fallback chain

When `§ 9.1`'s shape is absent, csq attempts a fixed-order fallback. The first non-empty source wins; the search stops there.

### 9.3.1 Resolution order

| #   | Source                     | Probe                                                                           | Source marker               |
| --- | -------------------------- | ------------------------------------------------------------------------------- | --------------------------- |
| 1   | `.coc/`                    | per `§ 9.1` shape                                                               | `CocSource::Coc { ... }`    |
| 2   | `.claude/`                 | `.claude/` directory present + at least one of `rules/`/`agents/`/`skills/`     | `CocSource::LegacyClaude`   |
| 3   | `.gemini/` + `AGENTS.md`   | `.gemini/settings.json` present OR `AGENTS.md` resolved by codex resolver chain | `CocSource::LegacyGemini`   |
| 4   | `AGENTS.md` codex resolver | Walk from CWD upward; first `AGENTS.md` hit wins (codex's documented behavior)  | `CocSource::LegacyAgentsMd` |
| 5   | (none)                     | All probes failed                                                               | `CocSource::Empty`          |

When the chain falls through to `CocSource::Empty`, the downstream consumer is **disabled** for this `csq run` invocation (the layer has no rules to apply). csq logs `coc.fallback: none` and spawns the CLI with baseline semantics.

### 9.3.2 Resolution stops at first match

Resolution does NOT union multiple sources. If `.claude/` resolves, `.gemini/` is not read. This is the "first non-empty source wins" rule. The intent is single-source-of-truth per invocation — no multi-format merge logic, no precedence-by-source-rank.

If a project has both `.coc/` and `.claude/`, `.coc/` wins per `§ 9.4` (the precedence rule applies WITHIN the resolution, not across sources).

### 9.3.3 Logging

Every resolution emits exactly one `tracing::info` event named `coc.fallback`:

| Source           | Event payload                                             |
| ---------------- | --------------------------------------------------------- |
| `Coc`            | `{ source: "coc", lock_sha256: "...", verified: true }`   |
| `LegacyClaude`   | `{ source: "claude-native" }`                             |
| `LegacyGemini`   | `{ source: "gemini-native" }`                             |
| `LegacyAgentsMd` | `{ source: "agents-md", resolved_at: "<absolute path>" }` |
| `Empty`          | `{ source: "none" }`                                      |

---

## 9.4 Precedence on collision

When the same `id` (RULE_ID / AGENT_ID / SKILL_ID / COMMAND_ID) appears in BOTH `.coc/` AND a legacy source AND the resolution lands on `.coc/`, `.coc/` wins. The collision is logged.

### 9.4.1 Logging

csq emits `coc.legacy_shadowed` with one entry per shadowed id:

```json
{
  "event": "coc.legacy_shadowed",
  "shadowed": [
    {
      "id": "RULE-X",
      "coc_path": ".coc/rules/RULE-X.md",
      "legacy_path": ".claude/rules/RULE-X.md"
    },
    {
      "id": "AGENT-Y",
      "coc_path": ".coc/agents/AGENT-Y.md",
      "legacy_path": ".claude/agents/AGENT-Y.md"
    }
  ]
}
```

Operators consume this event to validate that a `.coc/` migration is shadowing the expected legacy artifacts and nothing else.

### 9.4.2 Within-`.coc/` precedence tie-break

If the same `id` appears in two files within `.coc/` (e.g. `rules/RULE-X.md` and `rules/RULE-X.legacy.md`), csq breaks the tie by `precedence` field (higher wins). If `precedence` is equal, csq errors with `coc.duplicate_id` — this is a producer-side authoring bug and MUST surface, not silently pick one. csq does NOT fall through to legacy on within-`.coc/` collision; the duplicate must be fixed at the source.

---

## 9.5 Version envelope

`COC.md` frontmatter declares the `coc.version` envelope for the entire artifact set:

```yaml
---
coc.version: 1.0.0
...
---
```

### 9.5.1 csq's compatibility window

csq carries a hard-coded `MAX_KNOWN_COC_MAJOR` constant (initial value: `1`). The compatibility envelope is:

| Artifact `coc.version` | csq behavior                                                                                                                                |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `<= MAX_KNOWN`         | Load with full feature set.                                                                                                                 |
| `> MAX_KNOWN.major`    | **Refuse to load.** Error message: `"coc.version 2.x.y exceeds csq's max known major (1). Upgrade csq to >= <next-csq-version>."`           |
| `< current.major - 2`  | Load in `coc.fallback: forward-compat` mode (degraded — known fields used, unknown fields ignored). Surface a one-time warning per session. |

The "degrade-on-older" path mirrors spec 07 §7.4.1's `quota.json` schema-version handling — readers older than the writer by ≤ 2 minor releases tolerate the write and apply defaults; older readers hard-refuse.

### 9.5.2 Refusal must be actionable

When csq refuses a `coc.version`, the error MUST name:

1. The version observed.
2. The max version csq knows.
3. The csq version (or higher) required to consume it (computed by `csq-core/src/coc/version.rs::min_csq_for_coc_major`).

### 9.5.3 Soft-grace window for unknown majors

The pure "load if known, refuse if too new" model (§ 9.5.1 row 2) would brick every csq install the moment a producer emits a coc.version 2.0.0 — until each user upgrades csq, every project pin to a 2.x `.coc/` artifact is unusable. Real-world csq deployments lag releases, and a hard refuse during a maintainer absence breaks production.

The mitigation is a **30-day soft-grace window** between the first observation of an unknown major and the hard refuse:

- **First observation of an unknown major** (csq has never seen this version on this machine): csq records `(observed_version, first_seen_unix)` in `<base_dir>/coc-version-grace.json` and loads in degraded passthrough mode. Degraded mode treats the `.coc/` as opaque — known fields parse, unknown fields are ignored, the downstream pipeline runs without RULE_ID-citation enforcement (the shape can't validate against an unknown rule grammar).
- **csq surfaces a `coc.update_needed` event** during degraded loads. The event carries `(observed_version, required_csq, days_remaining)`. Subscribers (the desktop tray banner, `csq status`, future MCP tools) MUST display "csq update needed" with the actionable upgrade target.
- **Days 1–30**: every load is degraded + emits the event. The grace clock counts from FIRST observation, not most recent — repeated observations of the same unknown version do NOT reset the clock.
- **Day 31+**: the original `RefuseTooNew` posture from § 9.5.1 row 2 returns. Hard refuse, with the actionable upgrade message from § 9.5.2.

Different unknown versions get independent grace clocks. A project that hops from 2.0.0 to 2.1.0 in week 2 sees a fresh 30-day window for 2.1.0 even though 2.0.0's clock has already started. The conservative posture is intentional — both versions require csq to upgrade, so each gets its own window.

The CompatVerdict variant for the grace window is `CompatVerdict::GraceWindowDegraded` with `days_remaining` exposed so banner consumers can render countdown UX.

State file: `coc-version-grace.json` schema is `{"schema_version": 1, "records": [{"observed_version": "<semver>", "first_seen_unix": <i64>}]}`. Atomic-write with the security.md §5a tmp-file cleanup contract (no secrets in this file but the same rigor pattern; future fields could carry PII, e.g. project realpath provenance).

Authoritative Rust: `csq-core/src/coc/version_grace.rs` + `CompatVerdict::apply_grace` in `csq-core/src/coc/version.rs`.

---

## 9.6 Per-Surface × per-OS resolution paths

The legacy fallback chain (`§ 9.3`) resolves to per-Surface, per-OS paths. csq's fallback resolver MUST honor every cell in this matrix.

### 9.6.1 Surface resolution table

| Surface       | OS      | Primary config dir resolution                                                        | AGENTS.md discovery                                                      |
| ------------- | ------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| `claude-code` | macOS   | `~/Library/Application Support/Claude/` (CC's documented home; spec 01 §1.1 derived) | N/A — CC does not consume `AGENTS.md`                                    |
| `claude-code` | Linux   | `${XDG_CONFIG_HOME:-$HOME/.config}/claude/`                                          | N/A                                                                      |
| `claude-code` | Windows | `%APPDATA%/Claude/` (typically `C:\Users\<user>\AppData\Roaming\Claude\`)            | N/A                                                                      |
| `codex`       | macOS   | `~/.codex/` (codex's documented home)                                                | Walk from CWD upward; first `AGENTS.md` hit wins (codex behavior)        |
| `codex`       | Linux   | `~/.codex/`                                                                          | Same upward walk                                                         |
| `codex`       | Windows | `%USERPROFILE%/.codex/` (typically `C:\Users\<user>\.codex\`)                        | Same upward walk; case-insensitive on NTFS                               |
| `gemini`      | macOS   | `~/.gemini/settings.json`                                                            | csq does NOT use AGENTS.md for gemini; uses `.gemini/system_instruction` |
| `gemini`      | Linux   | `~/.gemini/settings.json`                                                            | (same)                                                                   |
| `gemini`      | Windows | `%USERPROFILE%/.gemini/settings.json`                                                | (same; gemini-cli is supported on Windows)                               |

### 9.6.2 Project-tree resolution (independent of Surface)

The project-tree resolution (where csq looks for `.coc/`, `.claude/`, `.gemini/`, `AGENTS.md`) is OS-independent. csq walks from the current working directory upward to the first hit. Maximum walk depth is 64 directory levels (defensive; deeper trees are pathological).

### 9.6.3 Per-Surface CI matrix coverage

The harness implementation suite is gated out on Windows. The CI matrix codifies:

| Runner           | Suites run                                        | Implementation suite |
| ---------------- | ------------------------------------------------- | -------------------- |
| `macos-latest`   | capability + compliance + safety + implementation | YES                  |
| `ubuntu-latest`  | capability + compliance + safety + implementation | YES                  |
| `windows-latest` | capability + compliance + safety                  | NO (gated out)       |

The Surface × OS table in `§ 9.6.1` confirms gemini-cli works on Windows for the three runnable suites.

---

## 9.9 Schema-version compatibility matrix

The compatibility matrix below mirrors spec 07 §7.4.1's `quota.json` pattern: the same lifecycle discipline for the `.coc/` consumer contract.

### 9.9.1 Matrix

| Writer emits `coc.version` | csq reader at `MAX_KNOWN = 1` (current) | csq reader at `MAX_KNOWN = 2` (future) |
| -------------------------- | --------------------------------------- | -------------------------------------- |
| `1.x.y`                    | OK (load, downstream layer applies)     | OK (legacy support)                    |
| `2.x.y`                    | **REFUSE** with actionable error        | OK                                     |
| `3.x.y`                    | REFUSE                                  | REFUSE                                 |
| `0.x.y` (experimental)     | OK + warning "experimental schema"      | OK + warning                           |

### 9.9.2 Forward-compat soft window (≤ 2 minor releases)

Within the same major, csq reader tolerates writer at `current_minor + 1` and `current_minor + 2`:

- Unknown frontmatter fields are tolerated (`§ 9.2.3`).
- Unknown sub-directories under `.coc/` are tolerated (`§ 9.1`).
- A `coc.fallback: forward-compat` log event is emitted once per session.

Beyond `+ 2` (e.g. csq HEAD-2 reading writer HEAD), csq emits a hard refusal with the actionable upgrade message.

### 9.9.3 Test contract

The test contract for `§ 9.9` mirrors spec 07 §7.4.2:

1. Parse `coc.version: 1.0.0` cleanly.
2. Parse `coc.version: 1.0.1` cleanly (patch within window).
3. Parse `coc.version: 1.1.0` cleanly (minor within window).
4. Parse `coc.version: 1.2.0` cleanly (minor at top of window).
5. Refuse `coc.version: 2.0.0` with actionable error naming `MAX_KNOWN`.
6. Refuse `coc.version: 99.0.0` with actionable error.
7. Round-trip `CocSet` → re-parse: deterministic.
8. Unknown frontmatter field on `RULE-X.md` parses; `csq inspect coc --show-unknowns` lists the field.

These tests are canonical in the `#[cfg(test)]` module of `csq-core/src/coc/version.rs`.

---

## 9.10 Read-only invariant

csq MUST NOT write under `.coc/` from any code path. The `.coc/` directory is consumer-only. Every code site that has the path string `.coc/` near it MUST be a read site (`fs::read`, `fs::read_dir`, `fs::metadata`, `tokio::fs::read*`, `std::fs::canonicalize`).

### 9.10.1 Static enforcement

A grep test in `csq-core/tests/coc_readonly.rs`:

```rust
#[test]
fn coc_directory_is_read_only_in_source() {
    // Walk csq-core/src and csq/src; for each `.coc/` mention,
    // assert the surrounding context is a read API call, not a write.
    let writes: Vec<_> = walk_sources()
        .filter(|line| line.contains(".coc"))
        .filter(|line| line.contains("fs::write")
                    || line.contains("OpenOptions::create")
                    || line.contains("File::create")
                    || line.contains("create_dir")
                    || line.contains("tokio::fs::write"))
        .collect();
    assert!(writes.is_empty(), "read-only violation: write call site under .coc/ — {:?}", writes);
}
```

This test runs on every PR.

### 9.10.2 Why static enforcement, not runtime

A runtime guard (e.g. wrapping `fs::write` in a custom permission check) is more code, slower, and bypassable by anyone who imports `std::fs::write` directly. The static grep is one test, runs in CI, and catches the failure mode at code-review time. The cost of a false positive is one comment in the test exclusions list; the cost of a runtime guard is permanent overhead in csq's IPC critical path.

### 9.10.3 Producer-side note

The producer DOES write under `.coc/` — that's the emit step. This invariant binds csq, the consumer, not the producer. This spec's invariant is the csq-side enforcement of the clean producer/consumer separation.

---

## 9.11 Cross-references

- `specs/07-provider-surface-dispatch.md` §7.4.1 — `quota.json` schema-version pattern that `§ 9.9` mirrors.
- `specs/01-cc-credential-architecture.md` — CC config-dir resolution behind the per-OS table in `§ 9.6.1`.

## 9.12 Revision history

| Rev | Date       | Change                                                                                                                                                                                                                                                                                                      |
| --- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1.0 | 2026-05-01 | Initial draft.                                                                                                                                                                                                                                                                                              |
| 2.1 | 2026-06-11 | Citation accuracy pass: `min_csq_for_coc_major` (`coc/version.rs`); §9.9.3 canonical-test citation to the `#[cfg(test)]` module of `csq-core/src/coc/version.rs`; §9.10 walk-roots `csq/src`.                                                                                                               |
| 2.2 | 2026-06-19 | §9.2.4 rewritten to current truth — the previously per-translator filter functions and the scaffold's rules-only path collapsed onto the single shared flattener (`csq-core/src/coc/translate/flatten.rs`); removed the stale "scaffold consumes rules only" framing and citations to removed filter sites. |
