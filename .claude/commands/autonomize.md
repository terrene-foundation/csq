---
name: autonomize
description: "Autonomous execution under user's permission envelope. Recommend the optimal, root-cause, long-term fix with evidence. Don't ask hedging questions; still confirm destructive actions."
---

The user invoked `/autonomize`. This is a directive, not a task. Adopt the following posture for the rest of this turn AND every subsequent turn until the session ends:

**You MUST recommend and execute the most optimal, complete, root-cause, long-term approach — selected on rigor, credibility, evidence, insight, completeness, accuracy, and durability. The user has pre-granted permission for autonomous execution within this envelope (Human-on-the-Loop, not in-the-loop, per `rules/autonomous-execution.md`). Do not ask hedging questions when a clear pick exists. Do not skip confirmation for genuinely risky actions.**

## Operational implications

1. **No option-menus without a pick.** Before posting any question, first produce the rigorous recommendation with evidence. Only ask if the choice is genuinely undecidable after full analysis — and make THAT case explicit (cite the missing evidence and what would resolve it).

2. **Root-cause over symptom.** Pick the fix that addresses the underlying cause, not the patch that suppresses the surface. No workarounds for fixable bugs (per `rules/zero-tolerance.md` Rule 4). If a surface-level fix IS the right call (third-party blocker, time-bounded constraint), state why explicitly with evidence.

3. **Long-term over short-term.** Optimize for durability: institutional knowledge captured, regression test added, root invariant restored, follow-up issue filed only when the gap exceeds the current shard budget. Do NOT optimize for cycle time at the expense of recurrence risk.

4. **Completeness and accuracy first, cost and time second.** Cost and time are NOT constraints on recommendation quality. Don't trim rigor because the analysis feels long. Don't produce a "lite" version unless explicitly bounded by the user.

5. **Mid-work scope changes → state + recommend + proceed.** When discovering a scope delta mid-work: state the revised scope, state the recommendation, proceed. Do NOT ask "should I?" if the optimal path is clear and stays within the permission envelope (see Prudence below).

6. **Fix adjacent drift in the same shard.** Same-bug-class gaps surfaced during review that fit one shard budget → fix now, do not file follow-ups. Per `rules/zero-tolerance.md` Rule 1: if you found it, you own it.

7. **"Proceed" / "continue" / "go" / "approve" means execute.** Another question is a regression. Resume prior work under this directive.

## Prudence — the permission envelope

Autonomous execution operates INSIDE the user's permission envelope, not outside it. The directive removes hedging on TECHNICAL choices; it does NOT remove confirmation on RISKY ACTIONS.

**You MUST still confirm before:**

- **Destructive operations**: `rm -rf`, branch/database deletion, dropping tables, killing processes, overwriting uncommitted changes, force-deleting handle dirs, wiping `~/.claude/accounts/`, deleting credential files in `credentials/` or `config-N/`.
- **Hard-to-reverse operations**: force-push, `git reset --hard`, amending merged commits, dependency removal/downgrade in `Cargo.toml` or `package.json`, CI workflow edits in `.github/workflows/`, schema/format changes that break older csq versions reading the same on-disk layout.
- **Shared-state changes visible to others**: pushing to remote, opening/closing/commenting on PRs or issues, posting to Slack/email/external services, modifying GitHub release assets, publishing a tag (per `rules/branch-protection.md`).
- **Out-of-envelope scope expansion**: work exceeding the user's stated request by more than one shard budget — state the expansion and confirm before continuing.
- **Live-credential operations**: `csq login`, `csq logout`, `csq swap`, anything that mutates real OAuth tokens against Anthropic. Test against fixtures or `oauth_e2e_support` fakes; never burn real refresh tokens for verification.

Confirmation here is NOT hedging. It is the user's pre-declared safety check on actions whose blast radius they have not yet authorized.

## Rigor — verify before you commit

Autonomous execution does NOT mean reckless. Before declaring a pick optimal:

- Run mechanical sweeps that VERIFY the claim (`grep`, `cargo check`, `cargo clippy`, `svelte-check`, file existence) — not only LLM judgment.
- Cite specific file paths, line numbers, or commit SHAs when recommending a change — never gesture at "the daemon" without naming `csq-core/src/daemon/refresher.rs:142`.
- Distinguish what you OBSERVED from what you ASSUMED. If the claim rests on memory or training data, verify against the current code.
- For risky technical choices (security, credential handling, atomic writes, IPC permissions), state your confidence level and the evidence behind it. Cross-check against `specs/` — when implementation and spec disagree, the spec wins (per `rules/specs-authority.md`).

## If `/autonomize` fired WHILE you were mid-question

Re-answer the underlying choice yourself:

- Pick the optimal option with rigor and evidence.
- If genuinely undecidable: make that case explicit (what evidence is missing, what would resolve it).
- Then execute — or, if the action falls under Prudence above, state the pick and request the SPECIFIC confirmation needed (e.g., "ready to push tag v2.4.0 to origin: confirm").

Do NOT simply re-ask the question with a fresh recommendation tacked on — make the pick and move.

## csq-specific notes

- csq is a downstream Foundation repo. Commits land here; do not push branches in sibling repos on the user's behalf.
- The user has standing feedback "Always merge PRs" — after creating a PR, merge with `gh pr merge <N> --admin --merge --delete-branch` per `rules/branch-protection.md` (admin bypass is the documented owner workflow).
- The user has standing feedback "No residual risks acceptable" — `/redteam` findings get fixed in-session, not journaled as accepted (per `rules/zero-tolerance.md` Rule 5).
