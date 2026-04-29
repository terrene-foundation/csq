# H3 — Launcher table (cc-only) + auth probe + state enum + stub-HOME canary

**Goal.** Wire up cc launcher with per-suite permission modes. Auth probe before each suite loop. Validate stub-HOME isolation IMMEDIATELY (canary moved up from H6 per R1-AD-01) so subsequent PRs can trust isolation works.

**Depends on:** H1 (validators, redact, dataclasses), H2 (fixture lifecycle).

**Blocks:** H5 (capability needs launcher), H6 (compliance), H7 (implementation needs sandbox + launcher), H8 (safety needs INV-PERM-1).

## Tasks

### Build — cc launcher

- [ ] Implement `cc_launcher(LaunchInputs) -> LaunchSpec` in `coc-eval/lib/launcher.py`:
  - Permission-mode mapping: `plan` for capability/compliance/safety; `--dangerously-skip-permissions` for implementation.
  - `--print` + `--output-format json` for implementation; bare `-p` for others.
  - INV-PERM-1 runtime check at spawn: `_assert_permission_mode_valid(spec, inputs)` per `05-launcher-table-contract.md`. Mismatch raises hard panic.
  - Sandbox wrapper for implementation: `["sandbox-exec", "-f", profile_path]` (macOS) or `["bwrap", ...]` (Linux). Phase 1 gates Windows out at argparse with `error: implementation suite requires sandbox-exec or bwrap; Windows not supported in Phase 1`.
- [ ] Register cc entry in `CLI_REGISTRY`: `cli_id="cc"`, `binary="claude"`, launcher, probe, timeout overrides per `05-launcher-table-contract.md`, default permission modes per suite.

### Build — auth probe (real, not mtime)

- [ ] Create `coc-eval/lib/auth.py`:
  - `probe_auth("cc") -> AuthProbeResult`: runs `claude --print "ping"` with 10s timeout; `ok=True` if exit 0; otherwise `ok=False` with stderr in `reason` (R1-MED-02 — replaces mtime heuristic).
  - INV-AUTH-3: cache for current suite only; re-probe before each suite begins; mid-run `401|invalid_grant|expired_token` stderr triggers re-probe with `auth_state_changed: true` flag.
  - `AuthProbeResult` dataclass: `ok: bool, reason: str | None, version: str, probed_at: float`.

### Build — stub-HOME builder (with $HOME override)

- [ ] Implement `build_stub_home(suite, fixture_dir) -> tuple[Path, Path]` in `coc-eval/lib/launcher.py`:
  - Returns `(stub_home, home_root)`.
  - `<fixture_dir>/_stub_home/.credentials.json` symlink to user's real `~/.claude/.credentials.json` (or `~/.claude/accounts/config-N/.credentials.json` if found).
  - `<fixture_dir>/_stub_home/.claude.json` with `{"hasCompletedOnboarding": true}`.
  - `<fixture_dir>/_stub_root/` as fake `$HOME`: empty placeholder dirs `.ssh/`, `.codex/`, `.gemini/`, `.aws/`, `.gnupg/` (R1-CRIT-02).
  - Launcher sets BOTH `CLAUDE_CONFIG_DIR=stub_home` AND `HOME=home_root` env vars.

### Build — settings-key positive allowlist

- [ ] Implement `_filter_settings_overlay(merged: dict) -> dict` in `coc-eval/lib/launcher.py`:
  - Allowlist: `{"env", "model", "permissions"}`. Every other key recursively dropped (R1-HIGH-02).
  - `env` filtered to `ANTHROPIC_*` keys plus harness allowlist (refuse `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `PATH`).
  - `permissions` validated to `{allow, deny, defaultMode}` keys with simple-string-pattern values, not file refs.

### Build — pre-spawn symlink revalidation + process-group kill

- [ ] Pre-spawn revalidation (INV-ISO-6): `os.readlink(stub_home / ".credentials.json")` returns expected path; `os.stat(target).st_ino == expected_ino`. Mismatch raises `error_fixture`.
- [ ] Process-group SIGTERM/SIGKILL on timeout (INV-RUN-3): `subprocess.Popen(start_new_session=True)` then `os.killpg(os.getpgid(p.pid), signal.SIGTERM)` on timeout, wait 5s, `os.killpg(..., SIGKILL)`. Credential symlink fd opened with `O_CLOEXEC` via `fcntl.fcntl(fd, fcntl.FD_CLOEXEC)`.

### Build — AC-16 canary fixture (moved from H6)

- [ ] Create `coc-eval/tests/integration/test_stub_home_canary.py` (R1-AD-01):
  - Test setup: writes `~/.claude/rules/_test_canary.md` containing `CANARY_USER_RULE_ZWP4` (CI auto-removes on test end via `try/finally`).
  - Throwaway compliance fixture with one CM-shape test asserting rule citation.
  - Asserts response does NOT contain `CANARY_USER_RULE_ZWP4` substring.
  - Asserts `auth_probes["cc"].ok == True`.

### Test

- [ ] `coc-eval/tests/lib/test_cc_launcher.py`:
  - `test_permission_mode_per_suite`: cc_launcher returns `--permission-mode plan` for compliance; `--dangerously-skip-permissions` for implementation.
  - `test_inv_perm_1_bypass`: a LaunchInputs with `(suite='safety', cli='cc', permission_mode='write')` raises RuntimeError at spawn (AC-22a).
  - `test_settings_allowlist`: merged settings with `mcpServers`, `hooks`, `statusLine.command` filtered to empty dict.
  - `test_home_override`: launcher env contains both `CLAUDE_CONFIG_DIR=<stub>` and `HOME=<root>`.
- [ ] `coc-eval/tests/lib/test_auth_probe.py`:
  - `test_probe_real`: probe_auth returns `ok=True` if `claude --version` succeeds (skip if claude binary absent).
  - `test_probe_timeout`: synthetic slow-binary returns `ok=False` after 10s.
- [ ] `coc-eval/tests/lib/test_process_group.py`:
  - `test_sigterm_ignoring_child`: spawn helper that traps SIGTERM and `sleep(99999)`. After timeout, helper IS killed within 5s of grace expiry (AC-19a).

### Smoke integration

- [ ] Run a single capability test (C1-baseline-root) end-to-end with cc launcher + stub HOME + auth probe; assert it produces output containing `MARKER_CC_BASE=cc-base-loaded-CC9A1`. (Pre-cursor to H5; just validates launcher contract.)

## Gate

- `pytest coc-eval/tests/lib/` + `pytest coc-eval/tests/integration/test_stub_home_canary.py` green.
- AC-16 canary green (the most important gate — proves stub-HOME isolation).
- AC-22a INV-PERM-1 bypass canary aborts at spawn.
- Smoke compliance test on cc passes end-to-end.

## Acceptance criteria

- AC-9 (cc-missing skip; tested by renaming claude binary)
- AC-16 (canary)
- AC-19a (process-group reaper)
- AC-22 (settings allowlist)
- AC-22a (INV-PERM-1 bypass)

## Cross-cutting (per implementation-plan §Cross-cutting)

- [ ] /validate runs cargo + clippy + fmt + tests + svelte-check + vitest + stub scan + new pytest path
- [ ] Journal entry written (DECISION/DISCOVERY/RISK as appropriate)
- [ ] Mutation test new test code (PR #214 precedent)
- [ ] PR title format `feat(coc-eval): H3 <summary>`
- [ ] Branch name `feat/coc-harness-h3-launcher-cc-canary`
- [ ] specs/08-coc-eval-harness.md updated if domain truth changed (rules/specs-authority.md Rule 4)

## Risk

Stub-HOME builder is the load-bearing isolation for capability/compliance/safety. Testing the AC-16 canary HERE (before H5/H6 build atop it) is critical — if H3 ships with a partial isolation, every subsequent PR's results are contaminated. Per `04-validate/02-redteam-round2-findings.md`, this canary placement is the round-2 fix for AD-01.

## Verification

Closed 2026-04-29 — `/implement` cycle complete. See `journal/0010-DECISION-h3-launcher-cc-canary-shipped.md`.

**Plan reference:** `02-plans/01-implementation-plan.md` §H3 + `01-analysis/05-launcher-table-contract.md`. Every checklist item below maps to a plan paragraph or contract section.

**Build — cc launcher**

- `cc_launcher(LaunchInputs) -> LaunchSpec` — `coc-eval/lib/launcher.py`. Permission mapping: `--permission-mode plan` for capability/compliance/safety; `--print --output-format json --dangerously-skip-permissions` for implementation. INV-PERM-1 asserted at the top of `cc_launcher`.
- Sandbox wrapper: `_resolve_sandbox_wrapper` returns `("sandbox-exec", "-f", profile_path)` on macOS and the documented bwrap argv on Linux; raises on other platforms.
- cc registered in `CLI_REGISTRY` at module-import time via `CLI_REGISTRY["cc"] = CliEntry(...)`.

**Build — auth probe (real, not mtime)**

- `coc-eval/lib/auth.py` — `probe_auth("cc", suite, env=...)`. Runs `claude --print --permission-mode plan ping` 10s timeout. INV-AUTH-3 cache cleared via `mark_auth_changed("cc")` on `is_auth_error_line` matches.
- `AuthProbeResult` dataclass already in `launcher.py` per H1 — re-exported from `auth.py` indirectly via the proxy `_probe_auth_cc_proxy()`.

**Build — stub-HOME builder (with $HOME override)**

- `build_stub_home(suite, fixture_dir) -> (stub_home, home_root)` — symlinks `<fixture_dir>/_stub_home/.credentials.json` to the user's real credential, writes `<fixture_dir>/_stub_home/.claude.json` with `{"hasCompletedOnboarding": true}`, creates empty `<fixture_dir>/_stub_root/{.ssh,.codex,.gemini,.aws,.gnupg}/`.
- `_find_user_credentials()` checks `~/.claude/.credentials.json` first then falls back to most-recently-modified `~/.claude/accounts/config-N/.credentials.json` (csq layout).
- `_build_cc_env` sets BOTH `CLAUDE_CONFIG_DIR=stub_home` AND `HOME=home_root`, plus inherits PATH/LANG/LC\_\*.

**Build — settings-key positive allowlist**

- `filter_settings_overlay(merged: dict) -> dict` — top-level allowlist `{env, model, permissions}`. `_filter_env_keys` allows `ANTHROPIC_*` + `CLAUDE_CONFIG_DIR`; rejects `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `PATH`. `_filter_permissions_keys` validates `{allow, deny, defaultMode}` with simple-string-only `allow`/`deny` (rejects `file:`-scheme + objects).

**Build — pre-spawn revalidation + process-group kill**

- `_assert_credentials_symlink_intact(stub_home)` — INV-ISO-6: `os.readlink` + double-stat for inode parity. Raises RuntimeError on any mismatch.
- `spawn_cli(spec, inputs)` — `start_new_session=True`; INV-PERM-1 + INV-ISO-6 checks BEFORE Popen. Stdout/stderr captured; stdin DEVNULL.
- `kill_process_group(proc, grace_secs=5.0)` — `os.killpg(SIGTERM)` → `wait(grace)` → `os.killpg(SIGKILL)` → `wait(2.0)`.
- O_CLOEXEC: PEP 446 makes Python 3.4+ `os.open()` non-inheritable by default; documented in the spawn_cli docstring.

**Build — AC-16 canary**

- `coc-eval/tests/integration/test_stub_home_canary.py` — writes `~/.claude/rules/_test_canary.md`, runs cc with stub HOME, asserts `CANARY_USER_RULE_ZWP4` absent. Cleanup in `try/finally`. **GREEN against real cc.**

**Test files**

- `tests/lib/test_cc_launcher.py` — 27 tests: permission mode per suite, settings allowlist, build_stub_home layout (incl. stale-symlink replacement + missing-creds error), HOME-override env wiring, sandbox wrapper presence-by-suite.
- `tests/lib/test_auth_probe.py` — 14 tests: missing-binary, real probe (skip-or-success), timeout path, non-zero exit, cache scoping, mid-run invalidation, `is_auth_error_line` patterns.
- `tests/lib/test_process_group.py` — 6 tests: SIGTERM-ignoring child reaped within 5s, cooperative child sub-second, already-dead returns rc, spawn_cli aborts on INV-PERM-1 + INV-ISO-6 violations.

**Smoke integration**

- `tests/integration/test_capability_smoke.py` — C1-baseline-root marker `MARKER_CC_BASE=cc-base-loaded-CC9A1` surfaces in cc's response. **GREEN.**

**Gate**

- `pytest coc-eval/tests/lib/`: 182 passed (135 baseline + 47 new).
- `pytest coc-eval/tests/integration/`: 2 passed.
- `cargo check --workspace`: clean.
- `cargo fmt --check`: clean.
- Stub scan + `shell=True` + `os.system` greps: clean.

**Acceptance criteria**

- AC-9 — `TestProbeMissingBinary::test_returns_skip_when_claude_absent`.
- AC-16 — `test_stub_home_isolation_canary_absent` GREEN.
- AC-19a — `TestKillProcessGroupSigtermIgnoringChild` GREEN; elapsed <5s.
- AC-22 — `TestSettingsAllowlist` (8 tests) GREEN.
- AC-22a — `TestInvPerm1RuntimeCheck` (4 tests) + `test_inv_perm_1_blocks_wrong_mode_in_launcher` + `test_spawn_aborts_on_inv_perm_1_violation` GREEN.

**Cross-cutting**

- specs/08-coc-eval-harness.md unchanged — H3 matches existing spec wording for INV-PERM-1, INV-AUTH-3, INV-ISO-6, INV-RUN-3, settings allowlist, sandbox profile path.
- Journal 0010 written with §For Discussion items on AC-16 positive control, probe overhead, and timeout ceiling.
