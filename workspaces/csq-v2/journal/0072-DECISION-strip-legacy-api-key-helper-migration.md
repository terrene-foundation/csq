---
type: DECISION
date: 2026-04-24
created_at: 2026-04-24T01:30:00Z
author: co-authored
session_id: 2026-04-24-issue-184
session_turn: 22
project: csq-v2
topic: Issue #184 — one-shot daemon-startup migration to strip legacy `apiKeyHelper` field from pre-alpha.8 csq-written 3P settings files (`config-N/settings.json`, `settings-mm.json`, `settings-zai.json`). The write paths were hardened in alpha.8 but on-disk artifacts on upgraded machines were never cleaned up; users still see CC's `apiKeyHelper failed: exited 127: /bin/sh: You: command not found` + auth-conflict warnings on every launch. Migration runs as `pass4` of the daemon's startup reconciler; idempotent; both-present strip predicate (`apiKeyHelper` AND `env.ANTHROPIC_AUTH_TOKEN`) so user-authored helper scripts are preserved. 11 unit tests cover acceptance criteria + edge cases. Ships in v2.1.1 (or whatever next patch lands after v2.1.0 cut).
phase: implement
tags:
  [
    issue-184,
    bug-fix,
    migration,
    daemon-startup,
    3p-providers,
    apiKeyHelper,
    pre-alpha.8-cleanup,
  ]
---

# Decision — strip legacy `apiKeyHelper` from 3P settings on daemon startup

## Context

Issue #184 (`gh issue view 184 --repo terrene-foundation/csq`) reported that pre-alpha.8 csq wrote `Provider::system_primer` (a long English instruction string) under a top-level `apiKeyHelper` key in 3P provider settings files. CC interprets `apiKeyHelper` as a shell command that prints an API key, so every CC launch on an affected slot emits:

```text
apiKeyHelper failed: exited 127: /bin/sh: You: command not found
⚠ Auth conflict: Both a token (ANTHROPIC_AUTH_TOKEN) and an API key (apiKeyHelper) are set.
```

The write paths were hardened (regression test `bind_strips_api_key_helper` at `csq-core/src/accounts/third_party.rs:615-643`; `providers/settings.rs:148-159` no longer emits the field), but **on-disk artifacts on upgraded machines were never cleaned up**. The user reporting the issue had three contaminated files on a single machine (`config-9/settings.json`, `settings-mm.json`, `settings-zai.json`) — the production landmine survives across every csq install upgrade since alpha.7.

## Decision

Land a **one-shot migration as `pass4` of the daemon's startup reconciler** in a new module `csq-core/src/daemon/migrate_legacy_api_key_helper.rs`. The module exposes `pub fn run(base_dir: &Path) -> ApiKeyHelperMigrationSummary` which the reconciler invokes after the existing pass1/2/3 (Codex credential mode flip, Codex config.toml drift, quota v1→v2).

### Walk

Two file shapes under `base_dir`:

1. `<base_dir>/config-<N>/settings.json` — slot-bound 3P settings (any N parseable as `u16`).
2. `<base_dir>/settings-<provider>.json` — provider-level files (`settings-mm.json`, `settings-zai.json`, `settings-ollama.json`, etc.). The bare `<base_dir>/settings.json` is the OAuth Anthropic shape and is intentionally NOT walked.

### Strip predicate

A file is rewritten ONLY when BOTH conditions hold:

- top-level `apiKeyHelper` is present
- `env.ANTHROPIC_AUTH_TOKEN` is present

Both-present is the unambiguous legacy-bug signature: csq itself never wrote an `apiKeyHelper` shape. Files where `apiKeyHelper` is the only auth source (impossible from csq, but defensive) are left alone — that protects hypothetical user-authored helper scripts at the same key.

### Write semantics

- `unique_tmp_path` + `std::fs::write` + `secure_file` (clamps to 0o600) + `atomic_replace` — matches the existing `providers::settings::save_settings` pattern.
- Per `rules/security.md` §5a, every failure branch removes the umask-default tmp file before propagating the error. The migrated content carries the `env.ANTHROPIC_AUTH_TOKEN`; an early `?` return without cleanup would leave a token-bearing file at world-readable perms on disk.
- No-op files are NOT rewritten (mtime is preserved). Critical because CC re-stats settings.json on mtime change per spec 01 §1.4 — an unnecessary mtime tick triggers every running CC to re-stat for no reason.

### Out of scope

User-authored `apiKeyHelper` entries outside csq-managed files (`~/.claude/settings.json`, `~/.codex/`, etc.) are NOT touched. Those are the user's own CC config and csq must not edit them.

## Quality gates

- 11 new unit tests in `migrate_legacy_api_key_helper::tests`:
  - `strips_helper_and_preserves_env_and_perms` (acceptance #1; asserts 0o600 perms via `MetadataExt::mode`)
  - `clean_settings_file_is_noop_no_mtime_bump` (acceptance #2; asserts mtime preservation)
  - `helper_only_no_token_is_left_alone` (acceptance #3; user-auth-script defensive)
  - `provider_level_files_are_migrated` (settings-mm.json + settings-zai.json shapes)
  - `bare_settings_json_at_base_root_is_not_touched` (Anthropic OAuth file boundary)
  - `second_run_is_idempotent` (acceptance: idempotent by construction)
  - `mixed_population_counts_are_correct` (4 files, 2 migrate, counts assert)
  - `non_numeric_config_suffix_is_skipped` (`config-foo` is not a slot dir)
  - `missing_base_dir_is_empty_summary` (fresh install)
  - `unparseable_json_is_skipped_and_preserved` (user-repair surface)
  - `predicate_requires_both_helper_and_token` (predicate sanity)
- `cargo test --workspace`: **1224 / 1224 passing**, 0 failures (was 1213; +11).
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.
- `cargo fmt --all --check`: clean.

## Alternatives considered

**A. Strip on lazy first read** (in `load_settings` / `bind_provider_to_slot` read paths). Rejected — the failure mode triggers on EVERY CC launch from the existing on-disk file, not on the next bind. Lazy migration only fires when the user re-binds a slot, which they generally don't do. Daemon-startup migration runs proactively the next time the daemon starts (within seconds of the next `csq run` or desktop launch).

**B. Add a CLI sub-command (`csq doctor --strip-api-key-helper`)** instead of automatic. Rejected — the bug is a known historical defect, the strip predicate is unambiguous (both-present), and the operation is reversible only by re-binding (which is what the user wanted to do anyway). Putting a manual gate in front of an unambiguously-correct action discriminates against users who don't know the issue exists.

**C. Run migration on every `csq install` rather than every daemon start.** Rejected — the daemon runs constantly; `csq install` is rare. Daemon-startup migration is the more aggressive (and more user-friendly) cleanup posture.

**D. Promote `apiKeyHelper` removal to ALWAYS strip (no env.ANTHROPIC_AUTH_TOKEN check).** Rejected — that would silently delete user-authored helper scripts at the same key. The both-present check is the unambiguous-bug-signature gate that distinguishes csq's own pre-alpha.8 footprint from user customization.

## Consequences

- Affected users see the bug repaired the next time the daemon starts (typically within seconds of opening the desktop app or running `csq run N`). No user action required; no UI surface for the migration.
- The daemon's startup reconciler now runs four passes; the new pass adds two counter fields to `ReconcileSummary` (`api_key_helper_files_seen`, `api_key_helper_files_migrated`) for telemetry / `csq doctor`.
- Migration is structured-logged at INFO with `error_kind = "migrate_strip_api_key_helper"` per file rewrite so operators can trace which files were touched.
- The migration can be retired once we are confident no live user is on a pre-alpha.8 binary. Conservative timeline: keep through v2.2.x (~6 months), retire in v2.3 if the structured-log telemetry shows zero hits across a 3-month window.

## R-state of issue #184

| State        | Date        | Note                                               |
| ------------ | ----------- | -------------------------------------------------- |
| Reported     | 2026-04-23  | Filed by user during PR-C8 / v2.1 session          |
| Diagnosed    | 2026-04-23  | Issue body identifies write-path fix + on-disk gap |
| **Resolved** | 2026-04-24  | This PR — daemon-startup migration as `pass4`      |
| Retired      | TBD (~v2.3) | Once telemetry confirms zero hits                  |

## For Discussion

1. **The migration runs unconditionally on every daemon start. Counterfactual: if a future user genuinely wants `apiKeyHelper` AND `env.ANTHROPIC_AUTH_TOKEN` both set (e.g. for a custom CC fork that handles the conflict differently), the migration would silently strip their config. Should we add a "migration applied" marker so we never strip the same file twice? (Lean: no — the both-present shape produces the auth-conflict warning in vanilla CC, so a user genuinely wanting both would be opting into a broken config. Defending against that imaginary user adds complexity for zero observed benefit. The strip is observably correct for the bug we have; defending against the bug we don't have is overengineering.)**

2. **The migration's strip predicate is `apiKeyHelper` AND `env.ANTHROPIC_AUTH_TOKEN`. Counterfactual: an early csq version may have written `apiKeyHelper` WITHOUT the env token (if the slot was bound without a key). Would those files miss the migration? Evidence: the alpha.7 `bind_provider_to_slot` always wrote both — the env token came from the user's `--key <K>` argument and the helper string was the system_primer. There is no "helper-only, no token" code path in any historical csq version. The predicate is safe. (Lean: confirms the both-present check is correct; the "what if csq wrote helper without token" hypothesis is refuted by reading the historical write code.)**

3. **`pass4` adds counters to `ReconcileSummary` but the daemon's startup log line is the only consumer. Should `csq doctor` and the desktop tray surface these counters too, so the user can see "csq cleaned up 3 legacy 3P config files for you"? (Lean: yes for `csq doctor` (one line per non-zero counter is cheap and informative), no for the tray (the migration is a silent fix, not a feature; surfacing it would invite "what does this mean?" support questions for a backstory the user has no context for).)**

## Cross-references

- GitHub issue: https://github.com/terrene-foundation/csq/issues/184
- `csq-core/src/daemon/migrate_legacy_api_key_helper.rs` — the migration module + 11 unit tests.
- `csq-core/src/daemon/startup_reconciler.rs` `pass4_strip_legacy_api_key_helper` — the reconciler hook + extended `ReconcileSummary`.
- `csq-core/src/providers/settings.rs:148-159` — the post-alpha.8 NOTE explaining why `system_primer` is no longer serialized.
- `csq-core/src/accounts/third_party.rs:615-643` — `bind_strips_api_key_helper` regression test for the write path.
- `.claude/rules/security.md` §5a — partial-failure cleanup pattern the migration follows on every error branch.
- `specs/01-cc-credential-architecture.md` §1.4 — CC re-stats settings.json on mtime change (justifies preserve-mtime-on-noop).
