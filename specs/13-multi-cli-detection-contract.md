# 13 — Multi-CLI Detection Contract

**Spec version:** 1.9.1
**Reference sync:** §9 (schema versioning) describes every schema version the community build emits, v1–v33, as of the reference contract's 1.25.0 revision; the enterprise-only versions v17, v18 and v20–v22 are intentionally omitted. The other sections are the community text as of 1.8.0 and have not been re-audited against that revision; do not read this spec version as equal to the reference version.
**Status:** active

## 1. Purpose

This spec governs how csq detects, version-gates, installs, and upgrades the external CLIs csq integrates with. Two roles share the machinery:

- **Session surfaces** — `claude` (Anthropic Claude Code), `codex` (OpenAI codex-cli), `gemini` (Google gemini-cli): `csq run` / `csq login` dispatch interactive sessions to them.
- **Managed tools** — `kimi` (Moonshot Kimi Code), `grok` (xAI Grok CLI): csq installs and keeps them current (`csq cli install/upgrade`) but does not dispatch sessions to their native binaries. They self-update via their own subcommand (`kimi upgrade` / `grok update`); first install is the vendor `install.sh`, which csq prints but never auto-executes (§10).

It owns:

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
pub enum SurfaceCli { Claude, Codex, Gemini, Kimi, Grok }
```

`#[non_exhaustive]` is mandatory. Adding a further CLI surface MUST be a non-breaking change for downstream consumers. Add a new variant + extend dispatch + minimums; consumers' `match` blocks gain a new arm but never lose an existing one. `Kimi`/`Grok` are managed tools (not session surfaces) — the session-dispatch consumers reach them only via safe default arms, never as a spawn target.

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
| `Ok`                  | ✓          | proceed (see §3.2) | proceed (see §3.2)          |
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

### 3.2 Track-latest opt-in (`--track-latest` / `CSQ_TRACK_LATEST=1`)

The default gate is **floor-guarded**: auto-update fires only on `Outdated` (below the §4 floor). A binary that probes `Ok` (≥ floor) is left alone even when a newer release exists. **Track-latest** is an opt-in mode (default **OFF**) that, on an `Ok` probe, additionally attempts an upgrade to the latest release **within the supported major**:

- **Enable:** `--track-latest` on `csq run` / `csq login`, OR `CSQ_TRACK_LATEST=1`.
- **Master kill-switch:** `--no-auto-update-cli` / `CSQ_NO_AUTO_UPDATE_CLI=1` suppresses track-latest too, not just the `Outdated` floor-update.
- **Mechanism:** reuses the same upgrade path as the `Outdated` arm. The §6 `upgrade_command` table is **range-pinned** (`@pkg@>=M.m.p <N.0.0`), so `npm install -g` resolves the newest release inside the supported range and NEVER crosses a major boundary. A true cross-major `@latest` requires a `min_version` bump per §7. Managers with no upgrade path are a silent no-op.
- **Throttle:** at most once per CLI per 24h, via a per-CLI stamp `~/.claude/accounts/.track-latest-<cli>.stamp` (recorded before the attempt so a persistent failure does not re-hammer the registry; an absurd future stamp self-heals to due).
- **Concurrency:** a per-CLI non-blocking advisory lock serializes concurrent launches so two `csq run`s don't both fire `npm install -g`; the loser skips. An unwritable base dir also skips (degrades to OFF).
- **Non-fatal:** runs against an already-floor-passing binary, so any failure (offline, npm error, no upgrade path) proceeds with the installed version — it never BAILs.

Track-latest has NO effect on any non-`Ok` variant — `Outdated` still floor-updates, `Missing` / `WrongBinary` still BAIL.

## 4. Minimum versions

| CLI    | Floor  | Rationale (code-cited at HEAD)                                                                                                                                                                                                                                                      |
| ------ | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Codex  | 0.40.0 | `--device-auth` landing version per `csq-core/src/providers/codex/desktop_login.rs` (parser orchestration handles v0.40.x AND v0.41+). 0.24 predates it.                                                                                                                            |
| Gemini | 0.41.2 | `csq-core/src/providers/gemini/oauth_login.rs` — "rewritten for gemini-cli v0.41.2+." Pre-0.41.2 had `gemini auth login` subcommand csq's flow no longer expects.                                                                                                                   |
| Claude | 2.0.0  | csq's credential-format assumptions tied to Claude Code's 2.x `claudeAiOauth` schema. Anchor: spec 01 — the `storageData.claudeAiOauth = { accessToken, refreshToken, expiresAt, scopes }` write in Claude Code's published OAuth storage behavior. 1.x predates that schema shape. |
| Kimi   | 0.27.0 | csq-integration baseline (first shipped `kimi` bundled with csq). No feature-gate rationale yet; floor = first-integrated version. `kimi --version` prints a bare semver.                                                                                                           |
| Grok   | 0.2.0  | csq-integration baseline (first shipped `grok`). `grok --version` prints `grok <semver> (<hash>)`; the `"grok "` prefix gate (§8) distinguishes it from the unrelated Elastic `grok` tool.                                                                                          |

`PINNED_GEMINI_CLI_VERSION = "0.38"` in `csq-core/src/providers/gemini/mod.rs` retains its "QA'd against" meaning — distinct concept, distinct constant. If line numbers drift, re-locate via `grep -n` against the symbol/comment quoted.

## 5. Manager classification

| Resolved-canonical path prefix                                                             | Manager                                                                                                                |
| ------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `~/.local/share/claude/versions/`                                                          | `ClaudeNativeInstaller`                                                                                                |
| `/opt/homebrew/Caskroom/claude-code/`                                                      | `BrewCask`                                                                                                             |
| `/opt/homebrew/lib/node_modules/`, `~/.npm-global/lib/...`, `/usr/local/lib/node_modules/` | `NpmGlobal`                                                                                                            |
| `/opt/homebrew/Cellar/gemini-cli/`                                                         | `BrewFormula`                                                                                                          |
| `/opt/homebrew/Cellar/codex/`                                                              | **blocklisted** — wrong codex; classified as `WrongBinary { InstallPathBlocklisted }` regardless of `--version` output |
| `~/.kimi-code/`, `~/.grok/` (any ancestor)                                                 | `SelfManaged` — self-updating CLI; upgrade via own subcommand                                                          |
| Other                                                                                      | `Unknown`                                                                                                              |

**Known-location fallback (§8):** `kimi`/`grok` install to `~/.kimi-code/bin` / `~/.grok/bin` and add it to the interactive-shell PATH. Because csq subprocesses can run under a minimal PATH that omits it, `find_in_path` checks these fixed dirs after the PATH walk fails. Grok's `bin/grok` symlinks into `~/.grok/downloads/`, so classification matches the `~/.grok/` ancestor, not the `bin/` leaf.

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
| `(Kimi, SelfManaged)`             | **`None`** — csq prints the `install.sh` hint (no curl-bash)      | `["kimi", "upgrade"]`                          |
| `(Grok, SelfManaged)`             | **`None`** — csq prints the `install.sh` hint (no curl-bash)      | `["grok", "update"]`                           |
| `(*, Unknown)`                    | `None` — csq prints the npm hint                                  | `None`                                         |

`@>=floor <next-major>` semver-range pinning (NOT `@latest`) makes registry-side downgrade attacks visible: a registry returning `0.39.0` for the codex install fails with "outside requested range."

**Symmetry MUST rule:** every `(SurfaceCli, InstallManager)` row defines BOTH `install_command` AND `upgrade_command`. `same` means the argv literal matches; `None` is permitted symmetrically (e.g. `(Claude, ClaudeNativeInstaller)` returns `None` for both). Adding a row with one half defined and the other absent is BLOCKED for package-manager managers (`NpmGlobal`, `BrewFormula`, `BrewCask`) — an implementer authoring a package-manager surface MUST wire both halves in the same change.

**SelfManaged asymmetry carve-out:** `SelfManaged` CLIs are the one permitted asymmetry — `install_command` is `None` (first install is the vendor `install.sh`, which csq prints but never auto-runs per §10's no-curl-bash boundary) while `upgrade_command` is the CLI's own update subcommand (`kimi upgrade` / `grok update`, which requires the binary to already exist). This is not a wiring gap: the two halves have genuinely different mechanisms.

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

`csq doctor --json` emits a top-level `"schema_version"` whose current value is **33**. `schema_version` is one monotonic counter; a small number of intermediate versions (v17–v18) correspond to fields this edition does not emit, so the community ceiling advances only when the community build actually serializes a newly-added field. v19 (`mcp_partial_coverage`) was the first such addition after v16 and v23 (`stale_quota_slots`) the next, so the ceiling jumped 16 → 19 and 19 → 23 (expected: v17, v18 and v20–v22 are fields this edition does not emit — skipped, not missing). Every version from v24 through v33 is emitted by both editions, so the current community ceiling is **33**. Versions 1–8 evolved the identity-store / multi-CLI-detection surface this spec owns; versions 9–16 add audit-chain fields whose semantics are owned by the audit-chain domain (`12-audit-trail.md`), cross-referenced where that spec documents the field and summarized inline otherwise (see the `v9–v16` subsection below); v19 adds the MCP partial-coverage advisory documented in the `v19` subsection below. Every additive field is either `#[serde(skip_serializing_if = …)]` (omitted when empty) or always-serialized with a concrete value (e.g. v19's `mcp_partial_coverage`, present on every report from v19 onward); a new key is therefore never emitted as `null`, and a consumer targeting an older shape treats any unrecognized top-level key as an ignorable unknown. Version history at a glance: v1 was unversioned (absence of the field is the v1 signal); v2 and v3 added per-surface keys and the `identity_store` field; v4 added the identity-store consistency variants and the `legacy_compat_state` field; v5 added the `phase4_incomplete` alarm; v6 added `pass0_skipped_slots`; v7 retired the `MirrorDriftAtSlot` consistency variant; v8 changed `identity_store.consistency` from a single object to an array; v9–v16 add the audit-chain surfaces enumerated in the `v9–v16` subsection below; v19 adds `mcp_partial_coverage` (see the `v19` subsection below); v23 adds `stale_quota_slots` (see the `v23–v31` subsection below, which documents v23 through v31); v24 `unshared_handle_state`; v25 `codex_shared_shape_mismatches`; v26 `cli_shim`; v27 `gate_status`; v28 `session_logins` and `keychain_mirror`; v29 the retained message-archive occupancy fields; v30 `codex_project_trust`; v31 `mcp_images`; v32 `launch_blocked_slots` and `launch_blocked_unknown_state` (see the `v32` subsection below); v33 Codex hook-trust carry diagnostics (see the `v33` subsection below).

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

### v9–v16: audit-chain fields

Versions 9 through 16 add audit-trail fields to the doctor report. These belong to the audit-chain domain owned by `12-audit-trail.md`; the entries below record only the doctor JSON schema-version contract (which version introduced which field). Where spec 12 documents the field (v9–v11), its full semantics and JSON shape live there at the cross-referenced section; the provenance-seam surfaces (v13–v16) are summarized inline below. Each field is either `#[serde(skip_serializing_if = …)]` (omitted when empty — e.g. `seam_quarantine_count`, `seam_held_predecessor_count`, `audit_roster_floor_anchor`) or always-serialized with a concrete value (e.g. `signing_key`, `audit_chain_state`, `audit_keychain_anchor`, `seam_registry_status`, `seam_capture_conformance`); either way a consumer reading an older shape sees an omitted key as absent and an always-serialized key as a concrete value — never null.

- **v9 — `signing_key`** (bumps 8 → 9). Reports the local Ed25519 audit-signing key id (`ed25519:<sha256_pubkey_hex>`). Local key custody. Authority: `12-audit-trail.md` §12.9 (Local Ed25519 signing-key custody).
- **v10 — `audit_chain_state`** (bumps 9 → 10). `AuditHealth` classification (`verified` / `degraded` / `broken` / `unknown`) from the CLI-side `verify_chain` run; a separate axis that never bricks the daemon. Authority: `12-audit-trail.md` §12.10.6 (audit-verify decoupling).
- **v11 — `audit_keychain_anchor`** (bumps 10 → 11). `KeychainAnchorStatus` (`confirmed` / `unconfirmed` / `mismatch`) — a non-fatal tamper DETECTOR cross-checking the file / keychain / `chain.json` signing-cutoff anchor. Authority: `12-audit-trail.md` §12.9.4 (file-vs-keychain cross-check).
- **v13 — provenance-seam surfaces** (bumps 11 → 13; v12 is never emitted). Adds `seam_quarantine_count`, `seam_pending_provenance_count`, and `seam_registry_status` for the provenance ingestion frontier — the audit subsystem that validates and chain-links externally-supplied provenance anchors before they enter the local chain. The two new `EventKind`s (`SeamEventRejected`, `ProvenanceAnchored`) and these doctor surfaces landed in one commit, so the counter advanced two steps at once.
- **v14 — capture-conformance** (bumps 13 → 14). Adds the provenance capture-capability matrix / `SeamConformanceState` surface (`NotConfigured` / `Conformant` / `Drift` / `PolicyUnreadable`).
- **v15 — `seam_held_predecessor_count`** (bumps 14 → 15). Count of seam events held pending an out-of-order intra-source predecessor (degraded-reconcile outbox drain).
- **v16 — `audit_roster_floor_anchor`** (bumps 15 → 16). `RosterFloorAnchorStatus` — a keychain-anchored authority-roster version-floor rollback DETECTOR (mirrors the v11 keychain-anchor detector posture). This is the last audit-chain field; the schema ceiling later advanced to v19 with the MCP partial-coverage advisory (`v19` subsection below).

The provenance-seam surfaces (v13–v16) are on-disk custody counters for the ingestion frontier; an install with no configured provenance source emits `seam_registry_status: "ok"` with the counts at zero or omitted. Their deep contract is part of the audit subsystem; this spec records only the doctor-schema-version mapping. Every audit-chain field is additive (each either omitted-when-empty via `skip_serializing_if` or always-serialized with a concrete value), so a consumer that handles only the identity-store surface (v1–v8) sees the v9–v16 keys as unknown top-level keys and, per JSON's standard "ignore-unknown-fields" contract, MUST NOT error on their presence.

### v19: MCP partial-coverage advisory

- **v19 — `mcp_partial_coverage`** (raises the community ceiling 16 → 19; the intervening v17–v18 are fields this edition does not emit). Like several of the audit-chain fields above (`audit_chain_state`, `audit_keychain_anchor`, `seam_registry_status`, `seam_capture_conformance`), this is an always-serialized object — present on every `csq doctor --json`, never omitted:

  ```json
  {
    "mcp_partial_coverage": {
      "warn": <bool>,
      "cli_sources": ["claude", "codex", "gemini"]
    }
  }
  ```

  `cli_sources` lists the CLI surfaces that have their own native MCP servers configured, detected under `$HOME` regardless of `warn` (empty array when none). `warn` is `true` when `cli_sources` is non-empty AND csq's COC capability layer is not fully disabled. It is an advisory, not an error: csq's tool-policy gate governs the COC prompt-edit tool allow/deny surface it manages, but a CLI's own MCP servers exchange runtime tool traffic outside that surface — so `warn: true` tells the operator that some MCP activity sits beyond csq's governed view. Impl: `csq/src/cli/commands/doctor.rs::check_mcp_partial_coverage` + `csq-core/src/capability_layer/mcp_coverage.rs`.

### Shared-`$HOME` cross-edition read: `mcp_gate_outbox_backlog`

A pure community install NEVER produces the `csq-runs/.pending-mcp-gate/` outbox — that durable governance-record outbox is written only by the enterprise edition — so the optional top-level `mcp_gate_outbox_backlog` object is ABSENT from a community `csq doctor --json`, and it does NOT advance the community `schema_version` ceiling (the versions that introduced and reshaped it, v20 and v21, are skipped by this edition).

However, the community `csq doctor` outbox READ is **edition-agnostic**: it inspects the outbox directory under `$HOME` with no edition-specific logic. So when a community `csq` and the enterprise edition share a `$HOME` (both resolve `~/.claude/accounts/`), a community `csq doctor` run FAITHFULLY reports the enterprise-written backlog — a benign, edition-neutral count + oldest-file age + a daemon-liveness `state` (`stuck` / `draining` / `pending_daemon_down`), with no proprietary logic and no enterprise-only content in the reported values:

```json
{
  "mcp_gate_outbox_backlog": {
    "pending_count": <u32>,
    "oldest_age_secs": <u64|null>,
    "state": "stuck" | "draining" | "pending_daemon_down",
    "last_drain_age_secs": <u64|null>,
    "warn": <bool>
  }
}
```

This is the ONLY way the field appears on a community build, and it is a read-only diagnostic reflecting what the co-resident enterprise daemon has (or has not) drained — never something the community edition itself writes or governs. A community-only user who never runs the enterprise edition never sees this key.

### v23–v31: cross-edition diagnostic additions

None of the nine fields below is gated on the edition: the community build computes and emits each one exactly like the enterprise build, so the community ceiling moves with them (19 → 23 at v23, then one step per version to 31). Fields of the enterprise edition that sit between v19 and v23 (v20–v22) are NOT described here and are not emitted by this edition. Every field is additive: it is either omitted when empty or always serialized with a concrete value, and a consumer targeting an older shape treats an unrecognized top-level key as ignorable.

- **v23 — `stale_quota_slots`** (community 19 → 23). Array of `{ slot, label, surface, age_secs, remedy }`, omitted when empty. It closes the gap where `csq doctor` reported all-green while `csq status` showed the same slot `stale Nd` or older. Rows come from the same channel `csq status` reads (the existing quota-freshness classifier), so no second staleness threshold exists. `remedy` is surface-specific: for a native Kimi or Grok slot it directs the operator through csq (`csq login <N> --provider kimi-cli|grok`) rather than a bare vendor-CLI login, which writes only to the vendor's own home directory and leaves the csq slot token expired with quota frozen.
- **v24 — `unshared_handle_state`** (23 → 24). Array of `{ name, handle_dirs, total_bytes }`, omitted when empty. A per-terminal handle directory symlinks an allowlist of items back to the account's permanent directory; anything not on that list becomes a real file that disappears with the terminal. Because the allowlist is maintained against upstream CLIs csq does not control, it goes stale, so the audit inverts the question: every entry is expected to be a symlink except a small enumerable set that is per-terminal on purpose (the materialized `settings.json` and `.claude.json`, the `.live-pid` liveness marker and the `.swap-lock` lock). Anything else is reported. Reported, never repaired: whether an item should be shared is a per-item judgement.
- **v25 — `codex_shared_shape_mismatches`** (24 → 25). Array of `{ slot, name, found, expected, self_heals, hint }`, omitted when empty. It reports a shared Codex-home entry whose on-disk shape (file versus directory) disagrees with what codex-cli needs, the state behind codex's `failed to start embedded app server`, an upstream error that names neither the entry nor the shape. The expected shape comes from the same table the provisioning path uses, so the diagnostic cannot drift from the writer. `self_heals` separates the remedies: an EMPTY directory where a file belongs is repaired by the next `csq run <slot>` (no data loss possible), while a non-empty directory, or a file where a directory belongs, is left alone and needs an operator, because self-healing must never delete state a user would miss. Reported even when `self_heals` is true.
- **v26 — `cli_shim`** (25 → 26). Always-serialized object `{ path, check_status, stale_or_unverifiable, verified_version_line, managed_plist_installed, managed_plist_allowed, desktop_managed, receipt_status, last_refresh }` plus the optional `managed_service_state`. `path` is home-redacted. `check_status` is `current`, `stale` (a verified version mismatch), `unverifiable` or `not_checked`; a newer verified CLI of the same edition is current (a refused downgrade is not staleness), and a symlink target is `not_checked` (doctor neither follows nor executes it, claims no staleness and keeps managed-plist admission false). Freshness of a regular-file target always requires a new installed signature and exec probe. `receipt_status` is `present`, `absent` or `unreadable`; `last_refresh` is null without a readable receipt, otherwise it carries the sanitized outcome, plist decision, stale-plist decision, expected desktop line and a Unix timestamp. `managed_plist_installed` is on-disk plist presence (null off macOS), not loaded-job evidence. `desktop_managed` requires a matching-target desktop receipt or an existing managed plist. `managed_service_state` is omitted when the managed service was not queried; otherwise `not_loaded` (definite native absence), `running` (loaded job with a nonzero PID observed), `dormant` (loaded job with an affirmatively zero or absent PID) or `unknown` (an uncertain probe or an unavailable PID observation). These are bounded observations, not continuous health guarantees, and receipts never supply them. Doctor performs no repair and no `launchctl` mutation; the warning for a stopped managed service describes that service, not the health of a possible in-process backup.
- **v27 — `gate_status`** (26 → 27). Optional report, omitted unless both `--gate-repo` and `--gate-pin` are given. It uses the same verifier and report builder as `csq gate status`; a green report states a pinned integrity snapshot while activation stays `unknown`. With gate diagnosis a red report exits 1 after emitting one doctor JSON object. The pair conflicts with `--slot`, `--repair-identities` and `--check-token-owners`. The default diagnostic route skips the background update check. The wire shape of the report is not specified here.
- **v28 — `session_logins` and `keychain_mirror`** (27 → 28). Both read the same bounded, token-free persisted daemon observation; the projection performs no credential-content and no keychain read. It also lists bounded live handle directories, reads bounded nonsecret PID routing markers and checks filesystem metadata for changes after the sweep. `session_logins` is omitted when empty; each row has `handle_pid`, optional `account` and `evidence` (`state`, a fixed `reason`, optional `remedy`), where `state` is one of current, superseded, unproven, keychain_unavailable, keychain_absent or undetermined. No credential, fingerprint, arbitrary upstream message or path is emitted. Superseded evidence requires the keychain refresh fingerprint's LAST history occurrence to be strictly before the canonical fingerprint's LAST occurrence; a concurrent change to the marker, canonical credential, history, owner-verified evidence or liveness invalidates the proof, and a successful write without readback is undetermined, not proof of adoption. Unknown sessions stay visible and a collection failure sets the always-present `sessions_undetermined` flag. A `keychain_sync` remedy appears only when the write policy permits it. `keychain_mirror` is the optional persisted aggregate (synced, skipped, failed, lock_timed_out, lock_failed, deferred, malformed, pending, `updated_at_unix_ms`) with its optional observed age `keychain_mirror_age_secs`; age is informational, because healthy idle ticks write no snapshot. A row is invalidated when its live PID disappears or its local owner or credential metadata changes after the sweep; a live PID absent from the snapshot is `undetermined / not_in_snapshot`; directory or metadata collection errors and limits make global coverage unknown, as do missing, corrupt or future-dated observations. Non-macOS hosts omit `keychain_disabled` session rows. Snapshot evidence never establishes a running process's cached token. `csq status` emits `csq.status.v2`, preserving its `data` slot rows and adding these diagnostics.
- **v29 — retained message-archive occupancy** (28 → 29). `message_archive_capacity` is always 8,000; `message_archive_state` is a fixed `OK`, `FULL` or `UND`; `message_archive_records` is the validated, unexpired archive count and is omitted when the scan is undetermined. A missing archive is known empty (`0`, `OK`); a count at capacity is `FULL`; invalid, unreadable or incomplete archive evidence is `UND`, never an empty count. The count applies the same strict validation and seven-day retention as inbox history. Doctor emits no record body, ID, sender or path and mutates nothing. These are current-occupancy observations, not a cumulative eviction counter (eviction policy: spec 32).
- **v30 — `codex_project_trust`** (29 → 30). Array of `{ slot, drift, warning? }`, omitted when every detected Codex-bound slot matches the canonical owner projects snapshot. `warning` is one of `missing_source`, `unreadable_source`, `unparseable_source`, `unreadable_slot`, `unparseable_slot`; a warning means the comparison is undetermined and `drift` is false, not a conformance claim. A valid owner file without projects is an authoritative empty set. The comparison shares its source and logic with launch-time synchronization and reads configuration TOML plus canonical binding metadata and credential file presence, never credential payloads. The diagnostic never writes trust, adds entries, reads the global `auth.json`, executes authentication or emits project paths or config contents. It is configuration-drift evidence, not proof that a running native process adopted a trust decision.
- **v31 — `mcp_images`** (30 → 31). Always-serialized `{ coverage, rows }`; `coverage` is complete, limited or unavailable. Rows carry `state` (same_image, different_image or undetermined), a closed `reason`, and optional validated child, session, build, reported-loaded, observed-loaded and installed file-metadata facts; text mode uses the same tokens. Discovery admits at most 32 distinct handle candidates and 128 rows. Missing, partial, unsafe, raced, platform-unavailable or build-unavailable evidence stays explicitly undetermined. A positive Linux comparison needs exact child and nearest-owner session starts, a canonical handle hash, independently observed loaded-image metadata before and after one checked report read, and a stable installed target retained from the one-time shim verification; macOS and non-Unix platforms do not fabricate loaded-image evidence. This is executable-file metadata identity, not byte or source attestation, process age, client adoption, or a cause for a messaging failure. The `cli_shim` projection is unchanged.

### v32 additions: `launch_blocked_slots`

v32 adds an optional top-level `launch_blocked_slots` array, `[{ "slot": N, "holder": H }, ...]`, omitted when empty. It lists slots whose sign-in is shared with another slot. `csq run N`, `csq swap N`, `csq exec` and the desktop session open refuse these slots with a fixed message naming the slot and `csq login N`; there is no override flag or environment variable, and sessions that are already open are not stopped. The rows come from the same check the refusals use, so the diagnostic cannot disagree with them.

A second optional boolean, `launch_blocked_unknown_state` (`true`, omitted when false), reports that the refresh-suppression record is damaged, refused or in an old format with no usable last-good copy. In that state every Anthropic slot that has not completed a `csq login` during the current damage of the record is refused (a login made before the record was repaired, deleted or damaged again does not count); a record that was never written (a fresh install) is not this state, non-Anthropic slots are unaffected, and csq never deletes the record. The text mode prints the same facts with the recovery: re-login each affected slot, then repair or remove the record yourself.

### v33 additions: Codex hook-trust carry diagnostics

v33 adds, in both editions, read-only fields that are omitted when empty and never `null`: `codex_hooks_global_missing`, `codex_hooks_handles` (per handle: link state, hooks-config state, `hook_trust` counts/status/ok and the `config_near_limit` / `config_oversize` flags), `codex_slots_hooks_not_a_table`, `codex_slot_write_status` (status words `raced`, `exchange-unsupported`, `purge-failed`, `carry-skipped`, `unrecognised-marker`; the union of the slot status file and its lock-free status markers), `codex_config_exchange_unavailable`, `slots_disable_all_hooks` and `global_settings_unusable`. No config contents, hook commands, hashes or paths are emitted.

## 10. Security boundary

- **Argv allowlist:** `csq cli install/upgrade <name>` accepts only literal `claude | codex | gemini | kimi | grok` via clap `value_parser` allowlist. Any other input rejected at parser layer.
- **Hard-coded dispatch:** `(manager, package_id)` tuple is hard-coded. No user-supplied string reaches argv.
- **No `shell=true`:** `Command::new(arg0).args(rest)` only. No `sh -c`, no string interpolation.
- **Range-pinned argv:** `@>=<floor> <next-major>` not `@latest`.
- **No curl-bash regression:** `(Claude, ClaudeNativeInstaller)` AND `(Kimi|Grok, SelfManaged)` return `None` for `install_command`; csq prints the vendor install command/`install.sh` for the operator to run. csq NEVER auto-executes a `curl … | bash`. Self-managed **upgrade** runs the CLI's own subcommand (`kimi upgrade` / `grok update`) via `Command::new(arg0).args(rest)` — argv-only, no shell, no remote script.
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

