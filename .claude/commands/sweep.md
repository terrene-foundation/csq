---
name: sweep
description: "Outstanding-work audit. Workspaces, GH issues, redteam-vs-specs gaps, on-disk hygiene. End-of-cycle gate before /wrapup."
---

## Purpose

A `/sweep` is the structural defense against "I think we're done." Before declaring a session converged or starting fresh work, surface every class of outstanding item: in-flight todos, open GH issues, spec-vs-code gaps, stale workspace state, on-disk leftovers from past sessions, and process-hygiene gaps.

Distinct from `/redteam` (scopes to ONE workspace's spec compliance) — `/sweep` is repo-wide.

## Execution Model

Autonomous — runs every sweep sequentially, accumulates findings into a single report. The agent MAY fix trivial gaps inline (per `rules/zero-tolerance.md` Rule 1: if you found it, you own it) but MUST surface every finding with its disposition (FIX-NOW / FILE-ISSUE / DEFER-WITH-REASON / FALSE-POSITIVE).

## Workflow

Run all 7 sweeps. Aggregate findings into a single report at the end with severity (CRIT / HIGH / MED / LOW), disposition, and pointer (file:line, PR#, issue#).

### Sweep 1: Active todos across all workspaces

```bash
find workspaces/*/todos/active/ -name "*.md" 2>/dev/null
```

Read frontmatter (`status`, `priority`). Group by workspace. Surface stale (>7d) workspaces' todos with explicit "is this still relevant?" flag.

### Sweep 2: Pending journal entries (auto-generated, awaiting promotion)

```bash
find workspaces/*/journal/.pending/ -name "*.md" 2>/dev/null
find journal/.pending/ -name "*.md" 2>/dev/null
```

Per the project's journal conventions: high-value commit body → promote, bare merge → discard, already-codified → discard with note.

### Sweep 3: GitHub open issues — current repo

```bash
gh issue list --repo terrene-foundation/csq --state open --limit 50 \
  --json number,title,labels,createdAt,updatedAt,comments
```

Categorize: **Stale** (no activity ≥30d), **Closeable** (delivered code in main per `rules/git.md` § Atomic Commits), **Genuinely actionable**.

### Sweep 4: Open PRs and stale feature branches

```bash
gh pr list --repo terrene-foundation/csq --state open --limit 50 \
  --json number,title,headRefName,isDraft,createdAt,statusCheckRollup
git branch -r --no-merged origin/main 2>&1 | grep -v "HEAD ->"
```

Surface: drafts >7d, PRs with red CI (never merge red — fix in same branch per `rules/git.md`), remote branches without PR (orphan work). Note: per user feedback "Always merge PRs", any PR sitting open with green CI is itself a finding.

### Sweep 5: Spec-vs-code gaps (per workspace)

`/redteam` re-derived as a repo-wide sweep. The csq specs in `specs/01-…` through `specs/07-…` are normative — implementation MUST match (per `rules/specs-authority.md`).

For each active workspace under `workspaces/`:

1. Read `02-plans/` and `todos/completed/` for what was promised.
2. For each spec MUST clause cited in those plans, grep production source (`csq-core/src/`, `csq-cli/src/`, `csq-desktop/src-tauri/src/`, `csq-desktop/src/`) for the implementation symbol.
3. Verify the contract holds — symbol exists, code path is wired, no stub return.

Categorize findings:

- **Orphan** — spec promises symbol; source has none.
- **Drift** — spec says X; source does Y.
- **Coverage gap** — symbol exists; no Tier 2 wiring test in `csq-core/tests/` or `csq-desktop/src/lib/__tests__/`.
- **Stub** — `todo!()`, `unimplemented!()`, `// TODO`, `// FIXME`, `panic!("not yet")` in production paths (BLOCKED per `rules/zero-tolerance.md` Rule 2 and `rules/no-stubs.md`).

Roll up: per workspace, count findings by category. Workspaces with ≥3 unresolved gaps → flag as candidates for a follow-up `/redteam` round.

### Sweep 6: On-disk hygiene (csq-specific)

csq's runtime layout under `~/.claude/accounts/` accumulates handle dirs and lock files when terminals exit uncleanly. Sweep these:

```bash
# Stale handle dirs — term-<pid> dirs whose PID is no longer alive
ls -1 ~/.claude/accounts/ 2>/dev/null | grep -E '^term-[0-9]+$' | while read d; do
  pid="${d#term-}"
  kill -0 "$pid" 2>/dev/null || echo "stale: ~/.claude/accounts/$d"
done

# Stale per-account login locks (from the OAuth race flow)
ls -1 ~/.claude/accounts/.login-*.lock 2>/dev/null | while read f; do
  age_seconds=$(( $(date +%s) - $(stat -f %m "$f" 2>/dev/null || stat -c %Y "$f" 2>/dev/null || echo 0) ))
  [ "$age_seconds" -gt 3600 ] && echo "stale (>1h): $f"
done

# Stale workspace session notes
find workspaces/*/.session-notes -mtime +30 2>/dev/null
git worktree list                                                  # orphan worktrees
find workspaces/*/journal/.pending/*.md -mtime +14 2>/dev/null     # stale .pending
```

Surface each stale entry with disposition. Stale handle dirs are safe to delete (the symlink layer means each handle dir is independent per spec 02 INV-02). Stale login locks belong to a process that died mid-OAuth and can be removed.

### Sweep 7: Build artifact + benchmark hygiene

```bash
# Build artifact size
du -sh target/ csq-desktop/src-tauri/target/ csq-desktop/node_modules/ 2>/dev/null

# Stale benchmark results — bench-results-*.json at repo root
ls -la bench-results-*.json bench-log-*.txt 2>/dev/null

# coc-eval result accumulation
du -sh coc-eval/results/ 2>/dev/null
ls -1 coc-eval/results/ 2>/dev/null | wc -l
```

Surface: any `target/` >5GB (run `cargo sweep -t 14` per the user's "Rust build infra" memory), any `bench-results-*.json` from a previous benchmark cycle that's no longer cited, any `coc-eval/results/` directory growing beyond a session's needs.

### Sweep 8: Process hygiene (uncommitted, divergence, zero-tolerance)

```bash
git status --short
git rev-list --left-right --count origin/main...HEAD 2>/dev/null
grep -rEn 'TODO|FIXME|HACK|XXX|todo!\(\)|unimplemented!\(\)' \
  --include='*.rs' --include='*.ts' --include='*.svelte' --include='*.js' \
  --exclude-dir=node_modules --exclude-dir=target \
  csq-core csq-cli csq-desktop/src csq-desktop/src-tauri/src 2>/dev/null | head -20
```

Surface: uncommitted changes, branch ahead/behind origin/main, new stub markers in production code (BLOCKED per `rules/zero-tolerance.md` Rule 2 and `rules/no-stubs.md`).

## Output

Write findings to `workspaces/<project>/04-validate/sweep-<date>.md` (when a workspace context is active) OR `SWEEP-<date>.md` at repo root. Each finding: `[SEVERITY] [Sweep N] <title>` + Location + Disposition + Evidence + Why-this-matters + Action-taken-if-FIX-NOW. End with cross-cutting observations and 2-5 ranked recommended next-session items.

## Closure

Before reporting `/sweep` complete:

1. ALL Sweep 1-8 outputs accumulated.
2. Trivial fixes applied inline (`rules/zero-tolerance.md` Rule 1); reclassified `FIXED` with commit SHA.
3. Non-trivial fixes filed as workspace todos OR GH issues with delivered-code references.
4. Report committed (`git add` + `git commit`).
5. Optional: human authorization for the recommended next-session scope.

The report is the deliverable. The agent does NOT decide what to do next — that's a human call.
