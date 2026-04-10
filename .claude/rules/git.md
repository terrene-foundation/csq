---
name: git
description: Git workflow rules — conventional commits, atomic commits, branch naming, PR descriptions, no secrets in history.
---

# Git Workflow Rules

Applies to all git operations in claude-squad.

## MUST Rules

### 1. Conventional Commits

Format: `type(scope): description` where type is one of `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`.

```
feat(auth): add OAuth2 support
fix(api): resolve rate limiting issue
refactor(workflow): simplify node connection logic
```

**Why:** Non-conventional commits break automated changelog generation and make `git log --oneline` useless for release notes.

### 2. Atomic Commits

One logical change per commit. Tests and implementation land together. Each commit builds and passes tests.

```
❌ "WIP", "fix stuff", "update files"
❌ Multiple unrelated changes in one commit
✅ feat(rotation): add token refresh + unit tests
```

**Why:** Mixed commits are impossible to revert cleanly, and "WIP" commits that don't build poison `git bisect`.

### 3. Branch Naming

Format: `type/description` (e.g. `feat/add-auth`, `fix/api-timeout`).

**Why:** Consistent branch names let CI pattern-match against ref types and keep `git branch --list` readable.

### 4. PR Description

Every PR MUST include: Summary (what and why), Test plan (how to verify), Related issues (links like `Fixes #123`).

```markdown
## Summary

[1-3 bullet points]

## Test plan

- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Related issues

Fixes #123
```

**Why:** Without issue links PRs disconnect from their motivation, breaking traceability and preventing automatic issue closure on merge.

## MUST NOT Rules

### 1. No Direct Push to Main

MUST NOT push directly to `main`. All changes go through PRs. Owner bypass is `gh pr merge <N> --admin --merge --delete-branch`, not direct push.

**Why:** Direct push bypasses CI checks and code review, allowing broken or unreviewed code to reach the release branch.

### 2. No Force Push to Main

MUST NOT force-push to `main`. Force push on a shared branch rewrites history everyone has already pulled.

**Why:** Force pushes discard other contributors' work silently; once the reflog expires, the lost commits are unrecoverable.

### 3. No Secrets in Commits

MUST NOT commit API keys, passwords, tokens, private keys, or `.env` files — not even in history. If a secret lands, the fix is key rotation plus history rewrite.

**Why:** Once committed, secrets persist in git history forever and are exposed to anyone with repo access, including future contributors who weren't around when the leak happened.

### 4. No Large Binaries

Single file >10MB or total repo >1GB is BLOCKED. Use Git LFS or external storage.

**Why:** Git never forgets — a 100MB file committed once permanently bloats every clone forever, even after deletion.

## Pre-Commit Checklist

Before every commit:

- Code review (intermediate-reviewer)
- Security review (security-reviewer) — see `agents.md` Rule 2
- Tests pass, linting passes
- No secrets in diff
- Commit message follows convention

## Exceptions

Require explicit user approval, PR documentation, and team notification for force operations.
