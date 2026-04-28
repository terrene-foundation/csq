# ADRs — coc-harness-unification

For each: **Options / Criteria / Recommendation / Why**.

## ADR-A — Port loom suites to Python vs keep Node

**Options:**

1. Port loom's `suites/*.mjs` to Python; harness becomes 100% Python.
2. Keep Node suites; csq Python orchestrator shells out to `node suites/<name>.mjs`.
3. Polyglot: orchestrator dispatches Python for implementation, Node for the others.

**Criteria:** `independence.md` §3 (stdlib-only); maintenance burden; debugging across language boundaries; fixture-prep code reuse.

**Recommendation: Option 1 — port to Python.**

**Why:** csq's `independence.md` says "Python 3 stdlib + system tools only — no PyPI, no Node modules, no Rust crates." Keeping Node violates the spirit. Loom is small (~380 LOC `harness.mjs` + 3 suites of similar size), translates 1:1 to stdlib (`subprocess`, `tempfile`, `json`, `pathlib`, `re`). Port cost is one autonomous session. Maintenance unifies with `runner.py`/`scoring.py`. Polyglot doubles surface for zero gain. Shell-out leaves us debugging across `subprocess.run(["node", ...])` boundaries forever.

## ADR-B — Implementation suite under codex/gemini

**Options:**

1. Scope cc-only initially; design portability later.
2. Design fixture portability now (every implementation test runs against all 3 CLIs).
3. Scope cc-only forever.

**Criteria:** Implementation scaffolds CC-shaped artifacts; codex `--sandbox workspace-write` and gemini `--approval-mode auto-edit` have different write semantics; scoring is artifact-based (`git diff`); fixture is `coc-env` (shared mutable working tree).

**Recommendation: Option 1 — cc-only initially, launcher table extensible to codex/gemini in Phase 2.**

**Why:** Implementation's `coc-env` fixture strategy is fundamentally cc-shaped. Codex/gemini can be pointed at `coc-env`, but value-add of running EVAL-A004 (hook security audit) against a non-Anthropic-hook model is ambiguous. Phase 1 ships cc-only with clean abstraction (`LaunchInputs` + per-test `permission_mode`); Phase 2 extends. Option 2 is a Phase-1 trap — fixture portability is genuine engineering and results may not justify it. Option 3 too rigid; nothing forecloses portability.

## ADR-C — Settings-profile (csq's model-routing layer) survives or drops

**Options:**

1. Drop profiles; harness only tests user's default-configured CLI.
2. Keep profiles; `--profile mm` runs implementation suite against MiniMax via csq's existing settings overlay.
3. Replace profiles with per-test `extra_env` (operator passes `ANTHROPIC_MODEL` directly).

**Criteria:** `coc-eval` was originally a "test models" tool, not just a "test CLIs" tool. Capability/compliance/safety probe CLI behavior; implementation probes model behavior. Profiles are CC-specific.

**Recommendation: Option 2 — keep profiles, with data-driven CLI compatibility (R1-revised).**

**Why:** csq is uniquely positioned to test model-X-with-CC-CLI because of `build_coc_config`, `build_bare_config`, `build_ablation_config`, model-override env. Throwing this away loses the published Foundation evaluation pathway (MiniMax/Z.AI/Ollama scored against COC implementation).

**R1 reframe (per redteam AD-03):** Profile compatibility is data-driven, not architectural. Each suite definition declares `profile_compatible_clis: list[str]`. In Phase 1, only implementation × cc has profile compatibility (that is the only path csq has settings overlay logic for). The argparse rejection becomes a data-driven message: "no profile overlay registered for codex; available profiles for codex: (none) — list with `--list-profiles --cli codex`." When Phase 2 adds codex profile overlays, the data updates and the rejection disappears automatically. Per-test `extra_env` (Option 3) is too granular for "run all tests on MiniMax." The Phase-1 implementation reality (cc-only profile overlays) is preserved without encoding it as permanent architecture.

## ADR-D — coc-env becomes one of the fixtures, or stays separate

**Options:**

1. Migrate coc-env into `fixtures/implementation/`.
2. Keep coc-env as top-level peer to `fixtures/`; implementation has `fixture_strategy: "coc-env"`.
3. Eliminate coc-env; rebuild implementation suite using per-test isolated fixtures.

**Criteria:** coc-env is a real working git repo with hundreds of files representing realistic COC artifact load — that's the test's whole point. Loom's `cp -r src dst` × 5 implementation tests × 200MB coc-env = 1GB per run.

**Recommendation: Option 2 — keep coc-env as top-level peer.**

**Why:** coc-env is structurally different: stable repo with reset between tests, not a fresh copy per test. Pulling it under `fixtures/` would either suggest it's per-test-copied (false, prohibitive) or require special-case docs (confusing). Cleaner mental model: `fixtures/` are loom-shape (cp + git init + test); `coc-env/` is csq-shape (mutate + reset). Launcher dispatches via `fixture_strategy`. Option 3 discards the realistic-COC-load property that makes implementation valuable.

## ADR-E — Permission-mode discipline: per-suite vs per-test

**Options:**

1. Suite-level only: one permission profile per suite.
2. Suite-level default + per-test override.
3. Per-test only.

**Recommendation: Option 2 — suite default + per-test override.**

**Why:** Suite default handles 95% case (every compliance test is plan-mode). Per-test override handles the 5% case. Override field: `permission_mode_override: Literal["plan", "read-only", "write", null]`. A test in `permission_profile: "plan"` requesting `"write"` MUST set `requires_write_justification: str` — catches accidental cross-suite leakage.

## ADR-F — Stub-HOME isolation strategy given OAuth coupling

**Options:**

1. Punt as loom did: real HOME wins; user's `~/.claude/rules/` may contaminate compliance.
2. Symlink-credentials-into-stub-HOME: stub HOME contains only credential file (symlink), nothing else.
3. Run capability/compliance/safety against a freshly-authed dedicated test account.
4. Skip OAuth via API-key auth path.

**Criteria:** User's `~/.claude/rules/` actively poisons compliance — a CLI with these rules refuses stubs without the fixture rule, generating fake-pass results.

**Recommendation: Option 2 — symlink-credentials-into-stub-HOME, with `$HOME` override AND process sandbox (R1-revised).**

**Why:** csq's existing `_symlink_credentials` proves the pattern. **R1 correction (per redteam R1-CRIT-02):** the original framing of Option 2 was incomplete. Stub-HOME via `CLAUDE_CONFIG_DIR=fixture_dir/_stub_home/` only isolates CC's LOADER. The model's tool calls resolve absolute paths against the OS, not against CC's config root — `~/.claude/.credentials.json` resolves via real `$HOME`. Full isolation requires three layers:

1. **`$HOME` override** for capability/compliance/safety: launcher sets BOTH `CLAUDE_CONFIG_DIR=stub_home` AND `HOME=stub_home_root` (a fake `$HOME` whose `~/.claude/` IS stub_home, whose `~/.ssh/`, `~/.codex/`, `~/.gemini/`, `~/.aws/`, `~/.gnupg/` are absent or empty). Closes the model-tool-access loophole.
2. **Process-level sandbox** for implementation suite: `bwrap` (Linux) or `sandbox-exec` (macOS) profile denying read on credential-shaped paths. The credential symlink lives inside the test fixture's stub-HOME and is the ONLY credential-shaped file the process can see.
3. **Ongoing audit** during implementation suite as a defense-in-depth tripwire: Python `sys.addaudithook` records `open()` events ON the harness Python process. Important scope caveat: `sys.addaudithook` does NOT fire on syscalls in spawned subprocess children — the cc/codex/gemini binary's tool-call opens are NOT caught. The audit hook is therefore a SECONDARY defense (catches harness-internal regressions like a future bug where `runner.py` accidentally opens `.credentials.json`); the sandbox (mitigation #2) is the PRIMARY defense for the documented threat (model-driven credential read in subprocess). The synthetic credential canary fixture exercises the SANDBOX, not the audit hook.

Codex parallel: `CODEX_HOME=stub_home`. Gemini: no documented config-dir env override, but `$HOME` override + sandbox covers the credential-exfil path. Option 1 is loom's existing failure mode. Option 3 introduces operational coupling. Option 4 changes which auth path is exercised (would invalidate measurements).

**Sandbox tooling deprecation:** `sandbox-exec` is Apple-deprecated as of macOS 10.10 but functional. v1.1 follow-up: macOS `sandbox` framework via Rust shim. Phase 1 ships with `sandbox-exec` as documented deprecation risk.

## ADR-G — Versioning of JSONL schema and harness

**Options:**

1. Two versions: `harness_version` (semver) + `schema_version` (semver), independent.
2. One version covers both.
3. Schema version is a date.

**Recommendation: Option 1 — independent semvers.**

**Why:** Schema is contract with downstream tooling (aggregate.py, future dashboards). Harness is contract with operators. They evolve at different rates. Bugfix to gemini quota retry is harness patch (1.0.0 → 1.0.1) but doesn't change schema. Adding `attempts` field is schema minor (1.0.0 → 1.1.0). Renaming `state: "fail"` → `state: "failure"` is schema major (1.0.0 → 2.0.0) and almost certainly bad. Breaking semantics defined in `06-jsonl-schema-v1.md`.

## ADR-H — Retry semantics for INV-DET-1

**Options:**

1. Single attempt. Flake = test-author's problem.
2. Retry-once-on-fail. State `pass_after_retry` distinct.
3. Retry-N-times configurable.

**Recommendation: Option 2 — retry once on fail; state explicitly tagged.**

**Why:** One retry catches >80% of single-call flakes (loom's empirical observation in compliance suite) at 2× cost on failures only. State tagging lets aggregates flag retry-prone tests for rewriting. Option 1 too noisy. Option 3 overengineering for a setting with one obvious right value.

## ADR-I — Where the spec lives

**Options:**

1. `specs/08-coc-eval-harness.md` only.
2. `coc-eval/README.md` only.
3. Both: durable spec + thin README.

**Recommendation: Option 3 — durable spec at `specs/08-coc-eval-harness.md` + thin `coc-eval/README.md`.**

**Why:** Spec captures invariants that survive code rewrites. README orients new operators. README allowed to drift; spec is not. Both is canonical csq pattern (cf. `specs/01-cc-credential-architecture.md`).

## ADR-J — Loom harness retirement vs preservation

**Options:**

1. csq becomes sole owner; loom deletes its harness.
2. csq becomes sole multi-CLI evaluator; loom keeps harness as authoring-side validator (small, focused subset).
3. Both repos run independent harnesses indefinitely.

**Recommendation: Option 2 — with explicit drift-detection and shape-change protocols (R1-revised).**

**Why:** Loom has legitimate use for a tiny harness during artifact authoring (smoke-test that an emitted fixture loads). csq runs the multi-CLI parity matrix. Neither is wasted; clean ownership boundary in the paired loom-csq rule. Option 1 strips loom of self-sufficiency. Option 3 is the parallel-infrastructure failure the project memory warns against.

**R1 additions (per redteam AD-08):** The paired rule MUST contain:

1. **Shape-change protocol.** When loom changes the `.coc/` artifact shape (RULE_ID grammar, prompt strings, scoring patterns), csq's harness MUST regression-test against the new shape. csq is the schema authority for fixture content (RULE_ID grammar, prompt strings, scoring patterns) since csq's harness is the canonical evaluator. Loom is the authority for artifact-format details (slot composition, frontmatter shape, file-layout conventions). Disputes default to csq for content, loom for format.

2. **Pre-merge gate.** Either (a) csq runs harness against loom's emitted fixtures pre-merge in csq's CI, OR (b) loom CI runs csq's harness on its own emitted fixtures pre-merge. Pick one — write it down in the paired rule.

3. **Drift-detection cadence.** Quarterly CI job in csq runs `git diff loom/.claude/test-harness/fixtures csq/coc-eval/fixtures` with a whitelisted divergence list. Un-whitelisted drift fails the job and pages a maintainer.

Without a cadence, both repos evolve independently and the boundary erodes silently within months.
