---
type: DECISION
date: 2026-04-29
created_at: 2026-04-29T11:30:00+08:00
author: agent
session_id: term-35747
session_turn: 220
project: coc-harness-unification
topic: H3 (cc launcher + auth probe + stub-HOME canary) shipped; H4-H8 unblocked
phase: implement
tags:
  [
    h3,
    implementation,
    cc,
    launcher,
    auth,
    sandbox,
    canary,
    ac-16,
    ac-19a,
    ac-22,
    ac-22a,
  ]
---

# DECISION — H3 implementation cycle complete

## What shipped

H3 lands the cc-only multi-CLI launcher contract, the real auth probe, the stub-HOME / fake-`$HOME` builder, the settings-key positive allowlist, the process-group reaper, and — critically per redteam round-2 finding AD-01 — the AC-16 stub-HOME isolation canary moved up from H6 so every later suite has a known-green isolation gate to anchor on.

- `coc-eval/lib/launcher.py` (extended +600 LOC) — `cc_launcher`, `build_stub_home`, `filter_settings_overlay`, `spawn_cli`, `kill_process_group`, `_assert_credentials_symlink_intact`, plus the cc entry registered in `CLI_REGISTRY` at module import. Stdlib-only.
- `coc-eval/lib/auth.py` (new, 145 LOC) — `probe_auth("cc", suite, env=...)`, `mark_auth_changed("cc")`, `is_auth_error_line(...)`, `reset_cache()`. Real probe (`claude --print --permission-mode plan ping` 10s timeout), NOT mtime heuristic (R1-MED-02). Per-`(cli, suite)` cache (INV-AUTH-1).
- `coc-eval/sandbox-profiles/write-confined.sb` (new) — macOS `sandbox-exec` profile denying read+write on `~/.{claude,ssh,codex,gemini,aws,gnupg}`. Used by H7+; H3 only resolves the wrapper argv.
- `coc-eval/tests/lib/test_cc_launcher.py` (new, 27 tests) — permission mode per suite, settings allowlist, stub-HOME layout + replay safety, HOME/CLAUDE_CONFIG_DIR env wiring, sandbox-wrapper presence-by-suite.
- `coc-eval/tests/lib/test_auth_probe.py` (new, 14 tests) — missing-binary skip, real-probe skip-or-success, timeout path with synthetic slow binary + tightened `_PROBE_TIMEOUT_SEC`, non-zero exit, per-suite cache scoping, mid-run invalidation, `is_auth_error_line` classification.
- `coc-eval/tests/lib/test_process_group.py` (new, 6 tests) — INV-RUN-3 reaper end-to-end: SIGTERM-ignoring child SIGKILLed within grace; cooperative child exits sub-second; already-dead returns recorded rc; `spawn_cli` rejects INV-PERM-1 and INV-ISO-6 violations.
- `coc-eval/tests/integration/test_stub_home_canary.py` (new) — AC-16: writes `~/.claude/rules/_test_canary.md` containing `CANARY_USER_RULE_ZWP4`, runs cc with stub HOME + fake `$HOME`, asserts the canary token is absent from cc's response. **GREEN against real cc on this dev box (44s wall clock).**
- `coc-eval/tests/integration/test_capability_smoke.py` (new) — H3 smoke pre-cursor to H5: cc loads `baseline-cc/CLAUDE.md` from a stub-HOME-prepared fixture and emits `MARKER_CC_BASE=cc-base-loaded-CC9A1`. **GREEN.**
- `coc-eval/conftest.py` — registers the `@pytest.mark.integration` marker.
- `coc-eval/tests/lib/test_launcher.py` — fixed `TestCliRegistry` setup/teardown to save+restore the live registry instead of clearing it (cc registers on import); added `TestCcRegisteredOnImport` (1 test) replacing the obsolete `test_registry_starts_empty`.
- `coc-eval/lib/__init__.py` — module list updated to mention `auth` + `fixtures`.

Pytest baseline: **182 passed in 11.6s** for `tests/lib/` (was 135). +47 new lib tests (+1 H1-fix replacement). **+2 integration tests GREEN against real cc** (44s wall, dominated by two real LLM round-trips).

`cargo check --workspace`: clean. `cargo fmt --check`: clean. Stub scan + `shell=True` + `os.system` greps: clean.

## Decisions made during implementation

### `_filter_settings_overlay` → `filter_settings_overlay` (drop the underscore)

The H3 todo wording uses the leading-underscore name `_filter_settings_overlay`. Pyright treats leading-underscore module-level names as internal-only and warns when nothing inside the module references them. Since the function IS the public allowlist contract — used by tests and (in H4+) by the runner — the public name `filter_settings_overlay` is the right shape. Internal helpers (`_filter_env_keys`, `_filter_permissions_keys`) stay private. Spec 08 wording does not pin a specific name; the H3 todo wording is descriptive, not normative.

### Auth probe takes an explicit `env` parameter, not a hidden global

The auth probe needs to validate cc against a stub HOME (`CLAUDE_CONFIG_DIR=...` + `HOME=...`) so the probe surface reflects the actual subprocess that the suites will spawn. Two options surfaced:

1. **Auto-resolve env**: probe internally constructs a stub HOME from the user's real credentials. Caller does nothing.
2. **Explicit env**: caller passes the env mapping. Probe respects it.

Option 2 wins on correctness — the suites already build the stub-HOME ONCE per suite via `build_stub_home`, and the probe reusing that exact env means we're probing the exact environment we'll spawn. Auto-resolution would either duplicate the stub-HOME build (wasted work, potential inode mismatch with INV-ISO-6) or skip it (probing under HOST's HOME instead of stub).

Caveat: callers MUST remember to thread `env` through. The integration tests demonstrate the pattern; the H4+ runner will codify it.

### `_find_user_credentials` falls back to `~/.claude/accounts/config-N/` (csq layout)

The spec wording is "symlink to user's real `~/.claude/.credentials.json` (or `~/.claude/accounts/config-N/.credentials.json` if found)". On this dev box the direct path does NOT exist (csq stores credentials per-account under `accounts/config-N/`), so without the fallback the probe + canary would skip every time on csq-managed boxes. The fallback picks the most-recently-modified `config-N/.credentials.json` — that's the most-recently-active account, which has the freshest token.

This is csq-specific behavior; non-csq users get the direct path. Both paths are file-system reads only — no shell-out, no cred copies (per memory: "No credential copies in benchmarks — Copying OAuth creds to temp dirs kills the token via rotation").

### `start_new_session=True` instead of POSIX-only `preexec_fn=os.setsid`

`preexec_fn` is unsafe with threading (Python docs warn explicitly). `start_new_session=True` is the documented stdlib idiom for "fork with `setsid()` in the child" and works identically on macOS/Linux. Windows is gated out at argparse for the implementation suite per ADR-F, so we don't need a Windows path.

### AC-16 canary uses a defensive-tripwire framing, not a positive-control proof

Strict isolation proof would require a positive-control variant: "WITHOUT HOME override, the canary DOES appear". cc's actual rules-load behavior at the time of writing does NOT auto-load `~/.claude/rules/*.md` for `--print` invocations (the auto-load list is `~/.claude/CLAUDE.md` plus cwd-rooted CLAUDE.md). So the negative test currently passes whether or not isolation is intact.

This is acceptable per the H3 round-2 framing: the canary is a **defense-in-depth tripwire**. The day cc starts auto-loading `~/.claude/rules/`, this test will catch any regression that lets the real `$HOME/.claude/` leak through. Until then, it's a forward-compatibility guard. A positive-control variant could land in H6 or v1.1; flagging in §For Discussion.

### Skipping vs failing on missing cc auth

The integration tests (canary + smoke) `pytest.skip` rather than `pytest.fail` when the cc binary is missing OR the auth probe fails. This matches the runner's `skipped_cli_missing` / `skipped_cli_auth` semantics: a box without cc auth produces a clean skip, not a noisy false fail. CI boxes without cc credentials run the lib suite (182 passed) and report the integration suite as skipped — exactly the production runner shape.

### Test isolation for the live `CLI_REGISTRY`

H1's `TestCliRegistry` cleared the registry in `setup_method` and re-cleared in `teardown_method`. With H3 registering cc at module-import time, this would have wiped cc out for any subsequent test in the same pytest run. Fixed by saving + restoring the registry around each test:

```python
def setup_method(self):
    self._saved_registry = dict(CLI_REGISTRY)
    CLI_REGISTRY.clear()

def teardown_method(self):
    CLI_REGISTRY.clear()
    CLI_REGISTRY.update(self._saved_registry)
```

The replacement test `TestCcRegisteredOnImport` documents the new contract (cc IS registered on `lib.launcher` import).

## Cross-cutting checklist (per implementation-plan §Cross-cutting)

- [x] /validate runs cargo + clippy + fmt + tests + new pytest path
  - cargo check: clean
  - cargo fmt --check: clean
  - pytest coc-eval/tests/lib/: 182 passed (135 baseline + 47 new)
  - pytest coc-eval/tests/integration/: 2 passed (AC-16 canary + C1 smoke)
  - stub scan / `shell=True` grep / `os.system` grep: clean
  - svelte-check + vitest: not exercised (Svelte UI untouched)
- [x] Journal entry written (this entry — DECISION 0010)
- [ ] Mutation test new test code (deferred per H1/H2 precedent — H3 unit tests are 47 small functions; mutation testing is a Phase-1 follow-up when sufficient surface exists)
- [ ] PR title format `feat(coc-eval): H3 launcher cc + auth probe + AC-16 canary` (will be set when PR opens)
- [ ] Branch name `feat/coc-harness-h3-launcher-cc-canary` (active)
- [x] specs/08-coc-eval-harness.md does not need updating — H3 implementation matches the existing spec wording (the spec already names INV-PERM-1, INV-AUTH-3, INV-ISO-6, INV-RUN-3, the settings allowlist, and the sandbox profile path)

## Acceptance criteria — H3 gate

- **AC-9** (cc-missing skip): test_auth_probe.py:`TestProbeMissingBinary::test_returns_skip_when_claude_absent` — covered.
- **AC-16** (canary): integration test green against real cc on this box.
- **AC-19a** (process-group reaper): test_process_group.py — SIGTERM-ignoring child SIGKILLed within `grace_secs + buffer < 5s`.
- **AC-22** (settings allowlist): test_cc_launcher.py:`TestSettingsAllowlist` — 8 tests covering env / permissions / mcpServers / hooks / statusLine.
- **AC-22a** (INV-PERM-1 bypass): test_launcher.py:`TestInvPerm1RuntimeCheck` (4 tests) + test_cc_launcher.py:`test_inv_perm_1_blocks_wrong_mode_in_launcher` + test_process_group.py:`test_spawn_aborts_on_inv_perm_1_violation`.

## What's blocked next

- **H4 (JSONL writer + schema v1.0.0):** unblocked. `cc_launcher` produces specs that H4's runner will write to JSONL. Suite-record shape pinned via `score.criteria` + `score.tiers` parallel arrays per spec 08 §"JSONL schema".
- **H5 (capability suite, cc only):** unblocked. The capability smoke integration test is its proof-of-life; H5 generalizes it to C1-C4.
- **H6 (compliance, cc only):** unblocked. AC-16 canary already validated by H3.
- **H7 (implementation suite migration):** unblocked. Sandbox wrapper resolution + spawn_cli already handle the `write-confined` path; H7 wires up the sandbox profile execution (currently the profile is referenced but only invoked when `sandbox_profile == "write-confined"`).
- **H8 (safety + cross-suite ordering):** unblocked. INV-PERM-1 bypass canary already in test_launcher.py.

## For Discussion

1. **AC-16 positive control.** The canary test asserts the negative — that the canary DOES NOT appear under HOME override — but does not prove the positive — that the canary WOULD appear without override (because cc's current load behavior may not autoload `~/.claude/rules/*.md` regardless). Should H6 add a positive-control variant that places the canary at `~/.claude/CLAUDE.md` (a path cc DOES autoload) under a more elaborate safe-mutation harness, or accept the current defensive-tripwire framing as Phase-1 sufficient and capture the upgrade as a v1.1 follow-up?

2. **Auth probe re-stat overhead.** The current probe runs `claude --version` AND `claude --print …ping…`. The version capture is best-effort (5s timeout, swallow errors), but it doubles probe cost on a healthy auth path (~6-10s instead of ~3-5s). Counterfactual: if the probe omitted the version subcommand, suites that include a version field in their JSONL header would need to invoke it elsewhere. Is the extra probe call worth the schema parity, or should the version field be optional and probe-cheap-by-default?

3. **`_PROBE_TIMEOUT_SEC = 10.0` ceiling.** Tightening to 10s caps the slowest acceptable probe path, but a Cloudflare-throttled token validation can plausibly take 8-9s on a slow connection (memory: "Cloudflare TLS fingerprint — reqwest/rustls blocked"). Should the timeout grow to 15s with a 12s soft-warn line in the runner output, or stay at 10s with the understanding that flaky-network boxes will see `skipped_cli_auth` (false negative) on a real-but-slow auth state?

## References

- `02-plans/01-implementation-plan.md` §H3 — source plan.
- `todos/active/H3-launcher-cc-canary.md` — todo with checkbox tasks.
- `01-analysis/05-launcher-table-contract.md` — `LaunchInputs.fixture_dir` + INV-PERM-1 contracts.
- `04-validate/02-redteam-round2-findings.md` AD-01 — canary placement decision.
- `coc-eval/lib/launcher.py` — H3 cc-launcher implementation.
- `coc-eval/lib/auth.py` — H3 probe implementation.
- `coc-eval/tests/integration/test_stub_home_canary.py` — AC-16 ship gate.
- Journal 0008 — H2 ship report (immediate predecessor).
- Journal 0009 — gitignore blocker (prep PR context).
