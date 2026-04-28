# Red-Team Round 1 — Consolidated Findings

Three parallel redteam agents probed the analysis package for gaps. **50 above-LOW findings** total: 7 CRIT, 22 HIGH, 18 MED, 3 LOW. Per `rules/zero-tolerance.md` Rule 5, every above-LOW finding gets a concrete in-phase fix.

## Round 1 cohort

| Agent                | Lens                 | Findings                          |
| -------------------- | -------------------- | --------------------------------- |
| deep-analyst         | architecture/design  | 13 (4 CRIT, 5 HIGH, 3 MED, 1 LOW) |
| security-reviewer    | adversarial security | 18 (3 CRIT, 9 HIGH, 4 MED, 2 LOW) |
| requirements-analyst | operator/UX          | 19 (9 HIGH, 9 MED, 1 LOW)         |

## Critical-path summary

Three findings invalidate or significantly weaken round-0 mitigations:

1. **R1-CRIT-01 (security):** HIGH-02's `--allowed-tools` flag-allowlist mitigation is mechanically false. CC has no documented flag that allows Read while denying specific absolute paths. The credential-exfiltration concern is unresolved.
2. **R1-CRIT-02 (security):** Stub-HOME (ADR-F) only overrides `CLAUDE_CONFIG_DIR`, not `$HOME`. Models running with `--dangerously-skip-permissions` resolve `~/.claude/.credentials.json` via real `$HOME`. The whole stub-HOME defense is partial.
3. **R1-CRIT-03 (security):** Suite glob discovery (`importlib` of every `suites/*.py`) is an arbitrary-code-execution sink at harness invocation. Single-file PR planting `suites/_evil.py` runs at every `coc-eval/run.py` call.

These three demand architectural reframing before H1 lands. They are NOT "fix during port" — they reshape the launcher table contract and the harness loader.

## Architecture/design (deep-analyst) findings

### CRIT

- **AD-01** H3 cannot validate stub-HOME isolation; AC-16 canary lands two PRs late. Move canary to H3.
- **AD-02** Auth probe runs once per invocation; mid-run token expiry unhandled. Add INV-AUTH-3: re-probe between suites.
- **AD-03** ADR-C locks Phase 2 out of MiniMax-via-codex. Reframe as data-driven `profile_compatible_clis: list[str]`.
- **AD-04** Suite-ordering enforcement unverified across invocations. Add INV-RUN-7 (refuse start if `coc-env/` has untracked files outside scaffold whitelist) and AC-32.

### HIGH

- **AD-05** JSONL `score` shape is polymorphic union (`criteria` vs `tiers`). Make them parallel optional arrays.
- **AD-06** AC-23 negative-control credential canary is unfalsifiable as written. Replace with synthetic canary file containing fake-but-shaped token.
- **AD-07** Settings overlay deep-merge does not recursively strip dangerous keys. Replace strip-list with positive allowlist.
- **AD-08** Loom-csq boundary rule (ADR-J + H12) has no conflict-resolution clause. Add shape-change protocol + quarterly drift CI check.
- **AD-09** H7-before-H8 ordering is wrong; safety lacks the implementation-suite guards it depends on. **Swap H7 ↔ H8.**
- **AD-10** AC-24 35-min budget unsourced; CI Flow H blows through. Re-derive: 50min cc-only, 90min full multi-CLI.
- **AD-11** F07 fix mis-routed to H6; belongs in H8 (implementation-suite path).

### MED

- **AD-12** "Byte-for-byte" loom fixture port ships Kailash names through csq. Adapt content with substitution layer; per-fixture header comment.
- **AD-13** 13-PR sequence overloaded for "one phase". Acknowledge multi-session expectation; consider Phase 1.a (cc-only) vs Phase 1.b (codex/gemini).
- **AD-14** `state` enum precedence ordering unspecified; aggregator may double-classify. Add explicit ladder + AC-33.

### LOW

- **AD-15** INV-DET-3 quarantine threshold mentioned but no PR lands `flaky/` directory. Drop INV-DET-3 from Phase 1 OR add to H9.

## Adversarial security (security-reviewer) findings

### CRIT

- **R1-CRIT-01** HIGH-02 `--allowed-tools` flag-allowlist is non-existent. Replace with **process-level isolation** (bwrap on Linux, sandbox-exec on macOS) + `$HOME` override.
- **R1-CRIT-02** Stub-HOME does not isolate model tool access; symlink target IS the real file. Override **both** `CLAUDE_CONFIG_DIR` AND `$HOME` for capability/compliance/safety; pair with sandbox for implementation.
- **R1-CRIT-03** Suite glob discovery is an ACE sink. Replace `glob` with explicit `SUITE_MANIFEST` list. Add AC-12-bis.

### HIGH

- **R1-HIGH-01** `error_description` redaction is misframed; redactor is byte-pattern-based, not field-name-based. Word-boundary parity with Rust requires custom char-class lookahead/lookbehind, not naive `\b`. Add 25-fixture parity test (AC-20a).
- **R1-HIGH-02** Settings allowlist (HIGH-06) missed `mcpServers`, `hooks`, `statusLine.command`, `env.LD_PRELOAD`. Replace strip-list with positive allowlist `{env, model, permissions}` only.
- **R1-HIGH-03** Aggregate.py reaches GitHub UI via CI artifact; markdown-injection in test/fixture names unescaped. Add escape pass + AC-8a injection canary.
- **R1-HIGH-04** Run-id 6-char base36 collides under scripted invocation. Format: `<iso8601>-<pid>-<counter>-<rand6 from secrets.token_urlsafe>`.
- **R1-HIGH-05** Aggregate.py reading attacker-writable `results/` is a JSON-bomb DoS surface. Per-record byte cap, per-int digit cap, per-file size cap.
- **R1-HIGH-06** Subprocess timeout doesn't reap orphaned grandchildren; CC/codex/gemini fork sub-processes. Use `start_new_session=True` + `os.killpg`. Mark credential-symlink fd `O_CLOEXEC`.
- **R1-HIGH-07** Implementation suite has no ongoing credential-read monitoring; AC-23 is one-shot. Add `sys.addaudithook` (Python audit hook) OR sandbox the path via R1-CRIT-01.
- **R1-HIGH-08** CRIT-02 fixes profile NAME, not CONTENT. Pair with R1-HIGH-02; both must land together.
- **R1-HIGH-09** TOCTOU on credential symlink. Pre-spawn re-validation: `os.stat(target).st_ino == expected_ino`. Add INV-ISO-6.

### MED

- **R1-MED-01** Suite-ordering enforcement is convention not invariant. Add INV-PERM-1 runtime check; bypass canary AC-22a.
- **R1-MED-02** `cliVersion` 5s timeout fail-closed handling unspec'd; auth probe mtime heuristic too weak. Replace mtime check with real `claude --print "ping"` probe.
- **R1-MED-03** Token-budget circuit breaker missing. Add INV-RUN-7 + AC-24a.
- **R1-MED-04** `git clean -fdx` doesn't clean `.git/hooks/` or `core.hooksPath`. Tighten reset.

### LOW

- **R1-LOW-01** JSONL `cmd` field redundancy + injection vector. Drop `cmd`; use `cmd_template_id`.
- **R1-LOW-02** Schema versioning example shows both at 1.0.0; reinforces wrong "bumped together" intuition. Add comment in schema doc.

## Operator/UX (requirements-analyst) findings

### HIGH

- **UX-01** First-run with zero auth → exit 0 looks identical to success. Exit 78 with explicit banner.
- **UX-02** No --help output design; argparse default unusable. Spec the usage block.
- **UX-03** No live progress during 35-min run; freeze indistinguishable from progress. Add `--format pretty` with ETA + status line.
- **UX-04** Ctrl-C mid-run leaves `results/<run_id>/` indeterminate; no resume path. SIGINT handler writes `INTERRUPTED.json`; add `--resume <run_id>` flag (FR-13).
- **UX-08** Baselines for "expected pass-rate" live in AC text, not tooling. Encode as `coc-eval/baselines.json` data file; aggregate gates on it.
- **UX-09** CI "parity-with-main" is unspecified. Combine with UX-08 baseline gate.
- **UX-13** Spec the literal error messages for 5 common operator scenarios.
- **UX-15** Default JSONL stdout unreadable for humans. `--format pretty | jsonl | json`.
- **UX-18** 35-min budget doesn't account for retry stack-up under quota stress. Tier ACs: AC-24a (no-retry), AC-24b (one retry), AC-24c (gemini wall-clock cap with `skipped_budget`).
- **UX-21** README only created in H13 (last PR). Move to H1.

### MED

- **UX-05** Aggregate matrix unbounded; add `--top N`, `--regressions-only`, `--failed-only`.
- **UX-06** `--profile mm` failure modes need spec'd error messages + `--list-profiles` flag.
- **UX-07** No tag/category system for cross-suite test selection. Add `tags: list[str]` per test + `--tag` flag.
- **UX-10** Quarantine lifecycle unspecified. Add `quarantined: bool` per test + auto-quarantine CI job + new state `skipped_quarantined`.
- **UX-11** `Literal["cc", "codex", "gemini"]` forces architectural change for 4th CLI. Replace with `CliId = str` + registration mechanism.
- **UX-12** Compliance/safety tests cannot inspect filesystem effects post-run. Add `post_assertions: list[FsAssertion]`.
- **UX-14** Flow G references `--validate` flag not in FR. Add FR-16 (`run.py <suite> --validate`).
- **UX-17** Schema fwd-compat untested. Add `coc-eval/tests/test_schema_compat.py` with committed v1.0.0 fixture.
- **UX-19** "Latest run" semantics dangerous when CI + local collide. Add `--full` flag + partial-coverage banner.

### LOW

- **UX-20** Token-redaction destroys evidence for credential-canary failures. Add `<test>.evidence.log` path for `evidence_required: true` tests.

## Cross-finding patterns

Three meta-themes:

1. **Stub-HOME / sandbox concerns (R1-CRIT-01, R1-CRIT-02, R1-HIGH-07, R1-MED-01, AD-01).** The stub-HOME design as proposed is partial. Real isolation requires `$HOME` override AND process-level sandbox AND ongoing audit AND runtime invariants — not just `CLAUDE_CONFIG_DIR` override.

2. **Schema/contract drift (AD-05, AD-08, R1-HIGH-04, UX-11, UX-17).** The JSONL schema, Literal types, paired loom-csq rule, and version compat are all "future-proofing" gaps that compound into a hard-to-evolve baseline.

3. **Operator UX is undermade (UX-01, UX-02, UX-03, UX-04, UX-15, UX-21).** First-run experience is broken. README arrives last. No progress, no resume, no human-readable mode. Phase 1 ships a CI tool, not a developer tool.

## Round 2 scope

Per `feedback_redteam_efficiency` memory: round 1 = 3 parallel agents; round 2 = 1 focused agent on residuals.

**Recommended round 2 single-agent focus:**

1. Verify the H7 ↔ H8 swap doesn't break a dependency missed.
2. Re-validate the stub-HOME architecture after `$HOME`-override + sandbox edits land in 05-launcher-table-contract.
3. Re-examine the JSONL schema after `score.criteria` / `score.tiers` parallel-arrays rewrite + state precedence ladder.

Round 2 entry criterion: round 1 fixes applied to analysis package files; spec re-flowed to incorporate them. Round 2 exit criterion: zero CRIT + zero HIGH net.

## Findings → analysis-package edits required

Mapping of findings to specific files needing updates before this analyze phase closes:

- `01-analysis/05-launcher-table-contract.md` — R1-CRIT-02 ($HOME override), R1-CRIT-01 (sandbox), R1-MED-01 (INV-PERM-1), UX-11 (CliId)
- `01-analysis/06-jsonl-schema-v1.md` — AD-05 (parallel arrays), R1-HIGH-04 (run-id format), R1-HIGH-01 (redact word-boundary), R1-HIGH-03 (aggregator escape), R1-HIGH-05 (DoS hardening), AD-14 (state precedence ladder), R1-LOW-01 (drop cmd), UX-07 (tags), UX-12 (fs_assert kind)
- `01-analysis/04-nfr-and-invariants.md` — INV-AUTH-3, INV-PERM-1, INV-ISO-6, INV-RUN-7 (token budget), INV-RUN-3 update (process-group kill)
- `01-analysis/07-adrs.md` — ADR-C reframe (data-driven profile compatibility), ADR-J update (drift protocol), ADR-F update (HOME + sandbox)
- `01-analysis/08-acceptance-criteria.md` — Add AC-32 through AC-49 (~18 new ACs)
- `01-analysis/09-security-review.md` — Major rewrite of CRIT-02 mitigation, HIGH-02 (drop flag-allowlist, add HOME+sandbox), HIGH-06 (positive allowlist), new CRIT-03 (glob ACE), new HIGHs
- `02-plans/01-implementation-plan.md` — Swap H7 ↔ H8, move AC-16 canary to H3, move F07 to H8, add SUITE_MANIFEST to H1, README to H1
- `03-user-flows/01-operator-flows.md` — UX-13 error messages, UX-15 format flag, UX-04 resume flow, UX-16 run_id printing
