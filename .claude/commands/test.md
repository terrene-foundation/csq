---
name: test
description: "Run csq's test suites: cargo (Rust), vitest (Svelte), svelte-check (types), optional live OAuth/race tests."
---

Run the csq test surface. Adapt scope via `$ARGUMENTS`:

| Command          | Action                                                                                                      |
| ---------------- | ----------------------------------------------------------------------------------------------------------- |
| `/test`          | Run the default tier: `cargo test --workspace` + Svelte vitest + svelte-check                               |
| `/test rust`     | `cargo test --workspace` only                                                                               |
| `/test frontend` | `cd csq-desktop && npx vitest run` + `npm run check`                                                        |
| `/test types`    | `cd csq-desktop && npm run check` (svelte-check + tsc) only                                                 |
| `/test e2e`      | The OAuth E2E harness (`csq-core/tests/oauth_e2e.rs`)                                                       |
| `/test live`     | The ignored live-only tests (`oauth_race_live.rs`) — burns OAuth flow against real Anthropic; CONFIRM first |
| `/test all`      | Default + `/test e2e` (skips `live` to protect real tokens)                                                 |

## Default workflow

### Step 1: Rust workspace tests

```bash
cargo test --workspace --all-targets
```

This runs unit tests (in-source `#[cfg(test)]` modules) + integration tests in `csq-core/tests/`:

- `auto_rotate_integration.rs`, `credential_integration.rs`, `daemon_integration.rs`
- `integration_codex_refresher_windows.rs`, `integration_codex_sweep.rs`
- `oauth_e2e.rs`, `oauth_replay.rs`, `platform_integration.rs`
- `settings_materialization_smoke.rs`, `no_direct_gemini_spawn.rs`

Tests that require real OAuth tokens (`oauth_race_live.rs`) are `#[ignore]`d by default.

### Step 2: Svelte vitest

```bash
cd csq-desktop && npx vitest run
```

Component tests under `csq-desktop/src/lib/__tests__/` and similar. Real DOM via jsdom.

### Step 3: TypeScript + Svelte type-check

```bash
cd csq-desktop && npm run check
```

Runs `svelte-check --tsconfig ./tsconfig.app.json && tsc -p tsconfig.node.json`. Type errors here are real bugs — Svelte 5's `$state` proxying surfaces type mismatches that runtime would only catch under specific reactive triggers.

## Live OAuth tests (`/test live`)

`csq-core/tests/oauth_race_live.rs` runs the parallel-race OAuth flow against the real Anthropic endpoint. Each run consumes one authorization. Per the user's standing feedback "No burst testing" and "No credential copies in benchmarks" — burning tokens to verify a refactor is BLOCKED. Run only when:

- Verifying a change directly to the OAuth race orchestrator (`csq-core/src/oauth/race.rs`).
- The change cannot be covered by `oauth_e2e.rs` (which uses fakes via `oauth_e2e_support/`).

Before running `/test live`, confirm with the user.

## Test policy (Tier 2/3)

Per `rules/testing.md` and `rules/account-terminal-separation.md`: integration tests against real file locks, real atomic writes, real keychain (when targeting macOS), real symlink-resolve paths. csq's bugs are races between REAL processes on REAL files — mocks hide them.

```
DO: cargo test exercises real handle-dir symlink resolution
DO NOT: mock the keychain or fs in csq-core integration tests
```

**Why:** Mocking the surfaces csq actually races against turns integration tests into self-confirming theatre. The bugs that blocked v2.0.0 were all in real-file race conditions that mocks would have papered over.

## Convergence

Test run is converged when:

1. `cargo test --workspace` exits 0.
2. `npx vitest run` exits 0.
3. `npm run check` exits 0.
4. No new `#[ignore]` markers added without journal entry explaining why.

Any failure: diagnose root cause, fix in same session per `rules/zero-tolerance.md` Rule 1. Pre-existing failures are owned, not reported.

## Agent Teams

Deploy as needed:

- **testing-specialist** — Test architecture, choosing the right tier, Tauri integration patterns.
- **tdd-implementer** — Red-green-refactor when adding new tests.
- **rust-specialist** — Rust test failures (ownership, async, lifetimes).
- **svelte-specialist** — Vitest failures, Svelte 5 reactivity edge cases.
- **build-fix** — Build-only failures (linking, FFI, target mismatches).

## Cross-References

- `rules/testing.md` — three-tier policy
- `rules/account-terminal-separation.md` — why csq tests use real files
- `csq-core/tests/oauth_e2e_support/` — fake OAuth fixtures for safe E2E
- Skill: `tauri-reference/` — Tauri command testing patterns
