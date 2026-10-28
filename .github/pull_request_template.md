<!--
PR template for `terrene-foundation/csq`.

Two sections are CONTENT-DENSITY-ENFORCED on every PR that touches the
capability layer or the bench (per `.github/workflows/csq-pr-template-check.yml`
+ `.github/scripts/check-pr-template.py`):

  - ## Harness delta
  - ## Latency bench delta

For PRs that don't touch those paths, leave the sections in place but write
`N/A — <reason>` (≥ 20 chars total) under each. Empty sections fail the gate.

Origin: PR-CA9 plan tasks T25 + T26 (R2/B35 + R2/B36 + R2/B37).
-->

## Summary

[1-3 bullet points — what changed and why.]

## Test plan

- [ ] Unit tests pass
- [ ] Integration tests pass (cargo test --workspace; pytest coc-eval/tests)
- [ ] Manual testing completed (if user-facing)

## Related issues

Fixes #<issue> (or: `(no issue)` for internal post-mortems)

## Harness delta

<!--
Required for any PR that touches:
- `csq-core/src/coc/`, `csq-core/src/capability_layer/`, `csq-core/src/audit/`
- `csq-core/src/providers/*/probe.rs`, `csq/src/cli/commands/run.rs`
- `coc-eval/bench/`, `coc-eval/baselines.json`, `coc-eval/tests/`
- `specs/09-*.md`, `specs/10-*.md`
- `csq-core/src/daemon/coc_cache_sweeper.rs`

For unrelated PRs (rule prose, doc fixes, README updates), write
`N/A — <reason>` (e.g. `N/A — README typo fix`).
-->

| Harness component        | Touched? | Notes |
| ------------------------ | -------- | ----- |
| Capability-layer driver  | no       | —     |
| Stage instrumentation    | no       | —     |
| Parse cache              | no       | —     |
| Daemon coc_cache_sweeper | no       | —     |
| Bench harness (Python)   | no       | —     |
| Stub binaries            | no       | —     |

## Latency bench delta

<!--
Required for any PR that touches the same paths as Harness delta. The
expected shape comes from `python3 coc-eval/bench/end_to_end.py
--synthetic-only --pr-template --cli cc --fixtures coc-env --n-trials 5`.
For unrelated PRs, write `N/A — <reason>` (e.g. `N/A — pure docs change`).
-->

| CLI | Fixture | Layer median (ms) | Bare median (ms) | Ratio | Upper CI |
| --- | ------- | ----------------- | ---------------- | ----- | -------- |
| —   | —       | —                 | —                | —     | —        |

🤖 Generated with [Claude Code](https://claude.com/claude-code)
