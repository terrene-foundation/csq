# 13 — Multi-CLI Detection Contract

**Spec version:** 1.5.1
**Status:** active

## 1. Purpose

This spec governs how csq detects, version-gates, installs, and upgrades the three external CLIs csq integrates with: `claude` (Anthropic Claude Code), `codex` (OpenAI codex-cli), `gemini` (Google gemini-cli). It owns:

- The structural surface for binary detection (`cli_deps` module public API).
- Per-surface minimum-version constants and their code-cited rationale.
- Manager classification (npm / brew / native installer / unknown).
- Install/upgrade dispatch table + range-pinning policy.
- `csq doctor` reporting contract + JSON `schema_version`.
- `csq login` / `csq run` pre-flight gate semantics.
- `csq cli install/upgrade <name>` security boundary.

Distinct from spec 07 (provider-surface-dispatch), which owns _how csq dispatches sessions to surfaces_. Spec 13 owns _whether the surface's binary is installed and at-or-above-minimum_.

## 2. SurfaceCli enum

```rust
#[non_exhaustive]
pub enum SurfaceCli { Claude, Codex, Gemini }
```

`#[non_exhaustive]` is mandatory. Adding a fourth CLI surface (e.g. a hypothetical Bedrock CLI) MUST be a non-breaking change for downstream consumers. Add a new variant + extend dispatch + minimums; consumers' `match` blocks gain a new arm but never lose an existing one.

## 3. CliStatus + WrongBinaryReason

```rust
pub enum CliStatus {
    Ok { version: Version, path: PathBuf, manager: InstallManager },
    Outdated { version: Version, min_required: Version, path: PathBuf, manager: InstallManager },
    WrongBinary { raw_version_output: String, path: PathBuf, reason: WrongBinaryReason },
    Missing,
    UnrecognizedVersion { raw_output: String, path: PathBuf, manager: InstallManager },
    ProbeTimedOut { path: PathBuf, elapsed_ms: u64 },
}
// Note: `elapsed_ms` is `u64` milliseconds, NOT `std::time::Duration`.
// This avoids a `Duration` dependency in the serialization path and keeps
// the JSON shape stable (`"elapsed_ms": 2001` rather than struct-of-secs/nanos).

pub enum WrongBinaryReason {
    PrefixMismatch { expected: &'static str, got: String },
    InstallPathBlocklisted { resolved: PathBuf },
    ComponentTooLarge { segment: String },
}
```

| Variant               | Doctor row | Login default     | Login `--ignore-cli-version` |
| --------------------- | ---------- | ----------------- | ---------------------------- |
| `Ok`                  | ✓          | proceed           | proceed                      |
| `Outdated`            | ⚠          | BAIL              | proceed-with-WARN (see §3.1) |
| `WrongBinary`         | ⚠          | BAIL              | BAIL (no override)           |
| `Missing`             | ✗          | BAIL              | BAIL (no override)           |
| `UnrecognizedVersion` | ⚠          | BAIL              | proceed-with-WARN            |
| `ProbeTimedOut`       | ⚠          | proceed-with-WARN | proceed-with-WARN            |

`Missing` and `WrongBinary` cannot be overridden — there is nothing to proceed against. `ProbeTimedOut` proceeds by default — don't punish the user for a slow upstream `--version`.

### 3.1 WARN line shape (every honor of `--ignore-cli-version` and every `ProbeTimedOut` / `probe-disabled` proceed)

WARN lines MUST be emitted to stderr on every honor — no per-process suppression, no rate-limiting. Format:

```
⚠ <surface>-cli <version-or-status> below minimum <min>; --ignore-cli-version honored
⚠ probe disabled (CSQ_CLI_DEPS_PROBE_DISABLE=1 set)
⚠ probe timed out (>2s) at <path>; proceeding without version check
```

Per-invocation only. No marker file, no env-var memory, no config persistence — the WARN line IS the user-visible state.

## 4. Minimum versions

| CLI    | Floor  | Rationale (code-cited at HEAD)                                                                                                                                                                                                                                                      |
| ------ | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Codex  | 0.40.0 | `--device-auth` landing version per `csq-core/src/providers/codex/desktop_login.rs` (parser orchestration handles v0.40.x AND v0.41+). 0.24 predates it.                                                                                                                            |
| Gemini | 0.41.2 | `csq-core/src/providers/gemini/oauth_login.rs` — "rewritten for gemini-cli v0.41.2+." Pre-0.41.2 had `gemini auth login` subcommand csq's flow no longer expects.                                                                                                                   |
| Claude | 2.0.0  | csq's credential-format assumptions tied to Claude Code's 2.x `claudeAiOauth` schema. Anchor: spec 01 — the `storageData.claudeAiOauth = { accessToken, refreshToken, expiresAt, scopes }` write in Claude Code's published OAuth storage behavior. 1.x predates that schema shape. |

`PINNED_GEMINI_CLI_VERSION = "0.38"` in `csq-core/src/providers/gemini/mod.rs` retains its "QA'd against" meaning — distinct concept, distinct constant. If line numbers drift, re-locate via `grep -n` against the symbol/comment quoted.

## 5. Manager classification

| Resolved-canonical path prefix                                                             | Manager                                                                                                                |
| ------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `~/.local/share/claude/versions/`                                                          | `ClaudeNativeInstaller`                                                                                                |
| `/opt/homebrew/Caskroom/claude-code/`                                                      | `BrewCask`                                                                                                             |
| `/opt/homebrew/lib/node_modules/`, `~/.npm-global/lib/...`, `/usr/local/lib/node_modules/` | `NpmGlobal`                                                                                                            |
| `/opt/homebrew/Cellar/gemini-cli/`                                                         | `BrewFormula`                                                                                                          |
| `/opt/homebrew/Cellar/codex/`                                                              | **blocklisted** — wrong codex; classified as `WrongBinary { InstallPathBlocklisted }` regardless of `--version` output |
| Other                                                                                      | `Unknown`                                                                                                              |

The blocklist for codex defends against the homebrew-formula `codex` (a different OpenAI tool with the same name, different version scheme `0.1.250529...`).

**Windows note:** On Windows, all paths are classified as `Unknown` — the `InstallManager` pattern matching relies on Unix path patterns (`/opt/homebrew/`, `/.local/share/`, etc.) that don't occur on Windows. This is intentional. Doctor still surfaces the correct version/status; only the manager label will show `unknown` on Windows.

## 6. Dispatch table

| `(SurfaceCli, InstallManager)`    | install argv                                                      | upgrade argv                                   |
| --------------------------------- | ----------------------------------------------------------------- | ---------------------------------------------- |
| `(Codex, NpmGlobal)`              | `["npm", "i", "-g", "@openai/codex@>=0.40.0 <1.0.0"]`             | same                                           |
| `(Gemini, NpmGlobal)`             | `["npm", "i", "-g", "@google/gemini-cli@>=0.41.2 <1.0.0"]`        | same                                           |
| `(Gemini, BrewFormula)`           | `["brew", "install", "gemini-cli"]`                               | `["brew", "upgrade", "gemini-cli"]`            |
| `(Claude, NpmGlobal)`             | `["npm", "i", "-g", "@anthropic-ai/claude-code@>=2.0.0 <3.0.0"]`  | same                                           |
| `(Claude, BrewCask)`              | `["brew", "install", "--cask", "claude-code"]`                    | `["brew", "upgrade", "--cask", "claude-code"]` |
| `(Claude, ClaudeNativeInstaller)` | **`None`** — csq prints the official upgrade command for the user | **`None`** — same                              |
| `(*, Unknown)`                    | `None` — csq prints the npm hint                                  | `None`                                         |

`@>=floor <next-major>` semver-range pinning (NOT `@latest`) makes registry-side downgrade attacks visible: a registry returning `0.39.0` for the codex install fails with "outside requested range."

**Symmetry MUST rule:** every `(SurfaceCli, InstallManager)` row defines BOTH `install_command` AND `upgrade_command`. `same` means the argv literal matches; `None` is permitted symmetrically (e.g. `(Claude, ClaudeNativeInstaller)` returns `None` for both). Adding a row with one half defined and the other absent is BLOCKED — implementer authoring a fourth surface MUST wire both halves in the same change.

## 7. 1.0-bump policy

When an upstream CLI publishes its first 1.0 release, csq MUST update `min_version` AND the `<next-major>` upper bound in the dispatch table in the SAME release. The CHANGELOG entry MUST name both old and new versions. Bumping `min_version` without the dispatch-table upper-bound update is BLOCKED. Wildcards (`@latest`) at runtime are BLOCKED regardless of upstream major.

Example: codex hits 1.0.0. csq's release that adds 1.x compatibility:

- `min_version(Codex)` updated to (e.g.) `1.0.0`.
- Dispatch table entries updated: `@>=1.0.0 <2.0.0`.
- CHANGELOG: `feat(deps): codex-cli 1.0+ compatibility — minimum bumped from 0.40.0 to 1.0.0; install range now 1.x.`

Bumping to a 1.x minimum is gated on csq's CI exercising the new major. csq MUST NOT silently accept 1.x at runtime via wildcard.

## 8. Probe contract

- **Wall-clock budget:** 2s per probe (`tokio::time::timeout`). Timeout → `ProbeTimedOut`; subprocess killed.
- **stdout cap (read-time):** the probe reads stdout incrementally. On hitting 8 KiB, the subprocess is killed and the partial buffer is treated per the partial-line rule below. Read-time enforcement (NOT capture-then-truncate); the subprocess does not get to push more bytes than the budget allows.
- **First-line input dispositions (exhaustive):**
  - One or more complete `\n`-terminated lines arrive within budget → parser reads `lines.next()?`; downstream parser gates apply.
  - Partial-line capture (≥1 byte, no `\n`) at the deadline → `WrongBinary { ComponentTooLarge }`. Not `UnrecognizedVersion`.
  - Zero-byte or zero-newline capture at the 2s deadline → `ProbeTimedOut`. Subprocess never produced parseable output.
- **Two-gate WrongBinary:** prefix gate (codex requires literal `codex-cli ` prefix; gemini and claude have no prefix requirement) AND install-path gate (resolved-canonical path matched against blocklist) BEFORE version parsing. Either gate triggers `WrongBinary`.
- **Hand-rolled parser:** `\d{1,5}\.\d{1,5}\.\d{1,5}(-[A-Za-z0-9.-]+)?`; each segment capped at u32::MAX. No `semver` crate dependency.
- **Leading-zero rejection:** a segment that starts with `'0'` AND has length > 1 (e.g. `01`, `002`) is `BadFormat`. Single-zero segments (`0.0.0`, `0.40.0`) are valid.
- **Pre-release suffix:** `meets_minimum(0.41.2-rc.1, 0.41.2) == true` — release portion meets minimum is sufficient.
- **Single canonicalize:** ONE `std::fs::canonicalize` call per `probe()` invocation; the resolved path is captured into the cached `CliStatus` so subsequent gate sites (login, run, doctor, post-install re-probe) reuse it without re-canonicalizing. Per-process cache lifetime.
- **Caching:** result cached in-memory for the lifetime of the calling process. `pub fn invalidate(cli: SurfaceCli)` clears a single surface; required for the post-install re-probe (otherwise the cache returns stale `Missing` after a successful install).

## 9. Schema versioning

`csq doctor --json` emits `"schema_version": 8` at the top level. The current schema is v8; the subsections below document each schema version's additions in turn. Version history at a glance: v1 was unversioned (absence of the field is the v1 signal); v2 and v3 added per-surface keys and the `identity_store` field; v4 added the identity-store consistency variants and the `legacy_compat_state` field; v5 added the `phase4_incomplete` alarm; v6 added `pass0_skipped_slots`; v7 retired the `MirrorDriftAtSlot` consistency variant; v8 changed `identity_store.consistency` from a single object to an array.

Per-surface keys (`claude_code`, `codex_cli`, `gemini_cli`) populated as objects when the surface has authenticated slots; OMITTED entirely (NOT null) when no authenticated slots. Suppression tightens to "slot has authenticated `.credentials.json` present" — not just dir presence.

### v3 additions: `identity_store` field

v3 adds an optional top-level `identity_store` key emitted when `audit_coexistence(base)` succeeds. OMITTED (NOT null) when audit fails non-fatally (e.g. no profiles.json present). Shape:

```json
{
  "identity_store": {
    "state": "LegacyOnly" | "Coexisting" | "IdentityOnly",
    "store_version": <u32>,
    "identity_count": <usize>,
    "profile_slot_count": <usize>,
    "consistency": {
      "kind": "Consistent"
    }
    // OR
    "consistency": {
      "kind": "SlotCountMismatch",
      "legacy": <usize>,
      "identity": <usize>
    }
    // OR
    "consistency": {
      "kind": "OrphanIdentity",
      "uuid": "<UUID string>"
    }
    // OR
    "consistency": {
      "kind": "OrphanLegacySlot",
      "slot": <u16>
    }
  }
}
```

`state` semantics:

- `LegacyOnly` — `identities/` dir absent or empty; daemon mint has not run yet.
- `Coexisting` — both `config-N/` legacy slots AND UUID identity entries exist.
- `IdentityOnly` — UUID identity entries exist but no `config-N/` legacy slots remain.

`consistency` semantics:

- `Consistent` — identity count matches profile slot count; no orphans detected.
- `SlotCountMismatch` — counts differ (partial migration or concurrent write).
- `OrphanIdentity` — a UUID identity has no corresponding legacy profile slot.
- `OrphanLegacySlot` — a legacy slot has no corresponding UUID identity entry.

Text mode: `identity-store: LegacyOnly (0 identities, 0 slots, consistent)` or similar one-liner rendered after per-surface rows.

### v4 additions: identity-store consistency variants

v4 adds three new `consistency` variant shapes to the `identity_store.consistency` field. These variants are emitted when `audit_coexistence` detects layout invariant violations (UUID-keyed file absence or mirror drift). The v3 shape is a subset of v4 — all v3 variants remain valid. **Note: one of the three, `MirrorDriftAtSlot`, was retired in v7 — it is no longer emitted. See the v7 subsection. The block below is retained as historical record.**

```json
// NEW in v4 — identity exists in profiles.json::by_slot but
// identities/<UUID>/credentials.json is absent.
"consistency": {
  "kind": "MissingCredentialsAtUuidPath",
  "uuid": "<UUID string>"
}

// NEW in v4 — identity exists in profiles.json::by_slot but
// identities/<UUID>/settings.json is absent.
"consistency": {
  "kind": "MissingSettingsAtUuidPath",
  "uuid": "<UUID string>"
}

// NEW in v4 — RETIRED in v7. config-<N>/.credentials.json and
// identities/<UUID>/credentials.json both exist but their byte content
// differs. No longer emitted: see the v7 subsection.
"consistency": {
  "kind": "MirrorDriftAtSlot",
  "slot": <u16>,
  "uuid": "<UUID string>"
}
```

`consistency` v4 semantics:

- `MissingCredentialsAtUuidPath` — a mapped identity's UUID-keyed `credentials.json` is absent; the UUID-keyed write-path has not run for this identity yet, or the file was deleted.
- `MissingSettingsAtUuidPath` — a mapped identity's UUID-keyed `settings.json` is absent; the UUID-keyed write-path has not run for this identity yet, or the file was deleted.
- `MirrorDriftAtSlot` — **RETIRED in v7, no longer emitted.** Historically: `config-<N>/.credentials.json` and `identities/<UUID>/credentials.json` had diverged. See the v7 subsection for why this check was withdrawn.

Text mode for these variants: `  Identity store: ⚠ coexisting (3 identities, 3 legacy slots, INCONSISTENT: MissingCredentialsAtUuidPath(<UUID>))`.

**Backward-compatibility note:** Consumers that handle the v3 `consistency` field MUST treat unrecognized `kind` values as an unknown inconsistency (warn, do not error). The v4 variants are additive — existing v3 consumers see them as unknown variants on v4 payloads.

### v4 additions: `legacy_compat_state` field

v4 adds an optional top-level `legacy_compat_state` array enumerating any compat-bridge surface that still has a footprint on disk during the downgrade window. The field is emitted by the doctor implementation (`csq/src/cli/commands/doctor.rs`). Empty array means "no compat-bridge surfaces detected" — the canonical final state once the legacy compat bridges are retired and the downgrade window closes.

```json
{
  "legacy_compat_state": [
    {
      "kind": "v1_accounts_field_still_present",
      "evidence": "profiles.json::accounts has <count> non-empty entries (empty-write affordance)",
      "scheduled_for": "future release"
    },
    {
      "kind": "legacy_canonical_credentials_file_still_written",
      "evidence": "credentials/<N>.json mirror written alongside identities/<UUID>/credentials.json",
      "scheduled_for": "future release"
    },
    {
      "kind": "legacy_canonical_codex_credentials_file_still_written",
      "evidence": "credentials/codex-<N>.json mirror written alongside identities/<UUID>/credentials-codex.json",
      "scheduled_for": "future release"
    },
    {
      "kind": "decimal_marker_content_present",
      "evidence": "config-<N>/.csq-account contains a decimal slot id (pure-legacy install pre-mint)",
      "scheduled_for": "future shard after the gate check refuses pure-legacy installs"
    }
  ]
}
```

Enumeration value semantics:

- `v1_accounts_field_still_present` — `profiles.json::accounts` has at least one non-empty entry (either the `update_email` user-rename exception or a downgrade re-save that re-populated the field).
- `legacy_canonical_credentials_file_still_written` — the Anthropic legacy-keyed canonical at `credentials/<N>.json` is still written alongside the identity-keyed `identities/<UUID>/credentials.json` for downgrade compat.
- `legacy_canonical_codex_credentials_file_still_written` — the Codex legacy-keyed canonical at `credentials/codex-<N>.json` is still written alongside `identities/<UUID>/credentials-codex.json` for downgrade compat.
- `decimal_marker_content_present` — at least one `config-<N>/.csq-account` marker still carries a decimal slot id rather than the slot's UUID. Pure-legacy install where `mint_for_login` failed or was skipped; the marker reader is tolerant of both formats, so this is informational.

Text mode: `  Legacy compat: <count> bridge(s) active — v1_accounts_field, legacy_credentials_file` rendered as a single line after the per-surface rows. Empty array renders `  Legacy compat: none (final state)`.

**Backward-compatibility note:** v3 consumers that do not handle `legacy_compat_state` see it as an unknown top-level key. Per JSON's standard "ignore-unknown-fields" contract, this is non-breaking; explicit v3 consumers MUST NOT error on its presence.

### v5 additions: `phase4_incomplete` field

v5 adds an optional top-level `phase4_incomplete` object that surfaces the same condition that would cause `csq_core::daemon::startup_reconciler::phase4_gate_check` to refuse daemon start. The field is OMITTED (NOT null) when the identity store is healthy — empty alarm is structurally identical to "no alarm needed." Backed by the read-only `csq_core::daemon::startup_reconciler::phase4_gate_status` helper.

```json
{
  "phase4_incomplete": {
    "affected_slot_count": <usize>,
    "missing_file_count": <usize>
  }
}
```

Semantics:

- `affected_slot_count` — distinct count of UUID-mapped slots (in `profiles.json::by_slot`) that have at least one identity-keyed file missing on disk. A single slot missing `credentials.json` AND `settings.json` contributes 1 here.
- `missing_file_count` — total count of (slot, file) pairs whose identity-keyed file is missing. The same slot missing `credentials.json` AND `settings.json` contributes 2 here. Pairs are inspected against three identity files: `identities/<UUID>/credentials.json`, `identities/<UUID>/settings.json`, and (for Codex-bound slots only — `credentials/codex-<N>.json` present on disk) `identities/<UUID>/credentials-codex.json`.

Text mode rendering: a `Phase 4: ✗ INCOMPLETE — <slot_count> slots affected (<file_count> identity files missing); daemon will refuse to start` line rendered NEAR THE TOP of the doctor report (after the `Platform:` line, before the per-CLI surface rows), followed by a two-line remediation hint pointing at `csq doctor --repair-identities`. The position is load-bearing: operators scanning the report see the impending refusal first.

**Remediation contract:** the alarm fires when `phase4_gate_check` would refuse start, and the canonical operator action is `csq doctor --repair-identities` (auto-heals slots whose legacy source exists on disk; per-record outcome surfaced via that command's text + JSON output). Slots whose legacy source is also absent require `csq login <N>` to re-OAuth.

**Read-only:** `phase4_gate_status` performs no writes; doctor never modifies the on-disk store. Symmetric with `phase4_gate_check` (refuse) and `phase4_gate_self_heal` (write) — three siblings sharing the same `profiles.json::by_slot` walk.

**Backward-compatibility note:** v4 consumers that do not handle `phase4_incomplete` see it as an unknown top-level key. Per JSON's standard "ignore-unknown-fields" contract, this is non-breaking; explicit v4 consumers MUST NOT error on its presence.

### v6 additions: `pass0_skipped_slots` field

v6 adds an optional top-level `pass0_skipped_slots` array that surfaces slots the daemon's initial identity mint skipped because the slot's credential file had no resolvable `oauthAccount.emailAddress` — the warn-log path in `csq-core/src/daemon/identity_mint.rs`. The field is OMITTED (NOT null) when empty.

```json
{
  "pass0_skipped_slots": [
    { "slot": 3, "reason": "oauth_email_unresolved" },
    { "slot": 5, "reason": "oauth_email_unresolved" }
  ]
}
```

Semantics:

- `slot` — the slot number whose credentials file has no resolvable OAuth email.
- `reason` — closed enumeration, currently `"oauth_email_unresolved"` (matches the daemon's `error_kind` tag). Future skip-reason kinds extend the enumeration; v6 consumers MUST tolerate unknown reason strings as forward-compatible.

Field population gates:

- The `store-version` sentinel (`<base>/store-version`) MUST exist (the initial mint has run on this host). Pre-sentinel: the field is omitted — a "skip" framing would be premature noise.
- A slot is included only when both (a) `AccountInfo.oauth_email == None` from `discover_anthropic` and (b) `profiles::resolve_slot_to_uuid(base, slot) == None`. Slots whose `by_slot[N]` UUID is present have already been remediated (most commonly by `mint_for_login` after the operator re-OAuth'd) and are excluded — surfacing them would be a stale signal.

Text mode rendering: a two-line block near the bottom of the report (after the unrecoverable-label warning, before the trailing blank line):

```text
  Pass-0 skip:   ⚠ 2 slot(s) skipped (oauth_email unresolved): slot 3, slot 5
                 (log in again to mint identity UUIDs and re-run csq doctor)
```

**Remediation contract:** `csq login <N>` for each named slot triggers `mint_for_login`, which carries an explicit OAuth-flow email and writes the `by_slot[N]` UUID — after which the next `csq doctor` run drops the slot from the array.

**Read-only:** doctor performs no writes for this surface; the field is derived from the existing `discover_anthropic` walk + `profiles::resolve_slot_to_uuid` lookup. No new on-disk artifact.

**Backward-compatibility note:** v5 consumers that do not handle `pass0_skipped_slots` see it as an unknown top-level key. Per JSON's standard "ignore-unknown-fields" contract, this is non-breaking; explicit v5 consumers MUST NOT error on its presence.

### v7 change: `MirrorDriftAtSlot` consistency variant retired

v7 removes the `MirrorDriftAtSlot` variant from `identity_store.consistency`. It is no longer emitted by `csq doctor` in any mode.

**Why retired.** The variant byte-compared `config-<N>/.credentials.json` against `identities/<UUID>/credentials.json` and flagged a mismatch. It was authored while `config-<N>/.credentials.json` was a maintained live mirror. That mirror was later retired: per spec 02 §INV-05, token refresh writes `identities/<UUID>/credentials.json` ONLY, and `config-<N>/.credentials.json` is an inert legacy file thereafter (written once by Claude Code's own OAuth flow at login, never re-synced by csq). After that change the canonical is the sole authority and has no mirror to be consistent with — so the check flagged an expected, harmless steady state on every host.

**Consumer impact.** The v7 `consistency` shape is a strict subset of v6: every still-emitted `kind` was already valid in v6, and `MirrorDriftAtSlot` simply never appears. A v6 consumer parsing a v7 payload sees no new `kind` and is unaffected. A v7 consumer parsing an older payload that still carries `MirrorDriftAtSlot` MUST treat it as an unknown-kind inconsistency per the §v4 backward-compatibility note (warn, do not error).

Spec authority: spec 02 §INV-05.

### v8 change: `identity_store.consistency` becomes a list

v8 changes `identity_store.consistency` from a single object to an **array of
issue objects**, and removes the `Consistent` variant.

```json
// v8 — consistency is an array. EMPTY array = consistent.
"identity_store": {
  "state": "Coexisting",
  "store_version": 2,
  "identity_count": 8,
  "profile_slot_count": 14,
  "consistency": []
}

// v8 — a non-empty array carries EVERY detected issue at once.
"consistency": [
  { "kind": "OrphanLegacySlot", "slot": 10 },
  { "kind": "MissingCredentialsAtUuidPath", "uuid": "<UUID string>" }
]
```

**Why.** Pre-v8, `consistency` was a single `ConsistencyState`;
`audit_coexistence` returned on the FIRST issue found. Each time a stale
predicate was fixed it "unmasked" the next hidden one. A list surfaces every
issue at once, ending that treadmill. The `Consistent` variant is removed: an
empty array is the consistent signal, and `[Consistent]` would be incoherent.

Two predicate corrections ship with the shape change:

- The Coexisting-branch `SlotCountMismatch` emission is **removed** — it
  compared `config_slot_count` (which counts non-OAuth `config-N/` dirs) against
  the OAuth-only `by_slot_count`, so it false-fired on every multi-slot host,
  and both its comparisons were redundant with the per-slot
  `OrphanIdentity` / `OrphanLegacySlot` / `Missing*` checks. The
  **LegacyOnly-branch** `SlotCountMismatch` emission (a populated `by_slot` in
  a `LegacyOnly` layout — a genuine half-written state) is kept; the
  `SlotCountMismatch` variant therefore survives.
- `OrphanIdentity` keeps its `by_slot`-only referenced-set, and the variant's
  doc comment is corrected to match. `by_email` is a lookup index NOT pruned
  in lockstep with `by_slot`, so a stale `by_email` entry would MASK a
  genuine orphan; the `by_slot`-only check is the correct one.

**Consumer impact.** This IS a breaking shape change for the
`identity_store.consistency` field — object → array. csq's own `csq doctor`
is the only known consumer. External consumers that read `consistency.kind`
directly must adapt to iterating the array; the `schema_version` bump 7 → 8
is the signal. The individual issue-object shapes (`kind` + fields) are
unchanged from v7.

## 10. Security boundary

- **Argv allowlist:** `csq cli install/upgrade <name>` accepts only literal `claude | codex | gemini` via clap `value_parser` allowlist. Any other input rejected at parser layer.
- **Hard-coded dispatch:** `(manager, package_id)` tuple is hard-coded. No user-supplied string reaches argv.
- **No `shell=true`:** `Command::new(arg0).args(rest)` only. No `sh -c`, no string interpolation.
- **Range-pinned argv:** `@>=<floor> <next-major>` not `@latest`.
- **No curl-bash regression:** `(Claude, ClaudeNativeInstaller)` returns `None`; csq prints the official upgrade command.
- **Sanitize-for-display:** every string captured from a third-party subprocess passes through `sanitize_for_display` (strips bytes in `\x00..=\x1f` EXCEPT `\t`; ALSO strips `\x7f` (DEL); caps result to 200 bytes) before printing.
- **Stderr redaction:** failed-install stderr passes through `error::redact_tokens`.
- **Single canonicalize per probe:** no double-resolution TOCTOU.
- **Restrictive `UnrecognizedVersion`:** bails by default; `--ignore-cli-version` flag downgrades to WARN.
- **Consent contract:** each `Command::new` spawn requires its own `[y/N]` prompt. No persistent consent on SERVER-side or FILESYSTEM-side. Client-side aliasing is OUTSIDE csq's defense boundary; WARN-every-honor is the structural defense.
- **Probe-disabled disclosure:** `CSQ_CLI_DEPS_PROBE_DISABLE=1` honored at `cli_deps::probe()` itself; the `CliStatus::Ok { version: 0.0.0, manager: Unknown }` return (structural) is the machine-readable signal — `csq doctor --json` serializes this as `"status": "probe_disabled"`. The advisory `eprintln!("⚠ probe disabled …")` at each gate site (login, run, doctor) is a human-readable supplement; it is NOT the disclosure mechanism. Structural disclosure via the JSON field is what matters for programmatic consumers.
- **Non-TTY refusal:** `csq cli install/upgrade` exits non-zero with "interactive consent required; rerun in a TTY" when stdin is closed OR `CI=1` env is set.
- **No privilege escalation:** csq does NOT invoke sudo. EACCES on install surfaces three options without picking. csq does NOT escalate.

## 11. Probe-driven verification

Per the probe-driven-verification rules, every gate test asserts:

- **Structural:** exit code + JSON-shaped error variant (e.g. `{ "kind": "outdated", "version": "0.24.0", "min_required": "0.40.0" }`).
- **NOT prose-regex:** assertions like `assert "outdated" in stderr` are BLOCKED.

A stub CLI binary is used for integration tests. It takes `--exit-code N --stdout STR --stderr STR --hang-ms N --emit-bytes N --binary-name <name>` flags so tests can drive every `CliStatus` variant deterministically, and is consumed via `Command::new(env!("CARGO_BIN_EXE_stub-cli"))`.

## 12. Interactive boundary

`cli_deps` is interactive-only. The csq daemon does NOT call `cli_deps::probe`. Pre-flight is per-command boundary:

- `csq doctor` → renders all surfaces.
- `csq login N` → probes the slot's surface immediately before the login spawn.
- `csq run N` → probes the slot's surface once at startup; cached for the lifetime of the `csq run` process.
- `csq cli install/upgrade` → probes before AND after spawn (with `invalidate` between calls).

Daemon health checks, refresh paths, and quota pollers do NOT call `cli_deps`. Surfacing "your codex is outdated" mid-poll is a category error (the user is not actively interacting; there is no remediation surface).

## Cross-references

- `01-cc-credential-architecture.md` — claude minimum 2.0.0 derives from Claude Code's `claudeAiOauth` schema (§4 cite anchored)
- `02-csq-handle-dir-model.md` — `discover_<surface>` returns slots; spec 13 §9 tightens to "authenticated credentials present"
- `04-csq-daemon-architecture.md` — §12 of THIS spec binds the daemon to NOT call `cli_deps`; that contract surfaces in spec 04's IPC + supervisor sections
- `07-provider-surface-dispatch.md` — sibling concern; spec 13 owns binary detection, 07 owns session dispatch
- `12-audit-trail.md` — `cli_deps` probe results are NOT audit-emitted; the interactive-only boundary (§12) explicitly excludes this surface from spec 12's JSONL contract
- The security rules — security boundary derivations (§10)
