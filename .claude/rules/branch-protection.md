---
name: branch-protection
description: Branch protection rules — no direct push to main, no force push, PR workflow for all protected repos.
---

# Branch Protection Rules

## Scope

These rules apply to ALL git operations in the claude-squad repository.

## Protected Repositories

| Repository                        | Branch | Protection Level    |
| --------------------------------- | ------ | ------------------- |
| `terrene-foundation/claude-squad` | `main` | Full (admin bypass) |

## Protection Settings

All repositories enforce:

- **1 approving review** required for PRs (admin can bypass)
- **Dismiss stale reviews** on new pushes
- **Status checks must pass** (strict mode)
- **No force pushes** to main
- **No branch deletion** for main
- **Conversation resolution required**
- **Enforce admins: OFF** — repo admins can merge without reviews

## Workflow

### For the repo owner (admin)

1. Create feature branch: `git checkout -b type/description`
2. Commit changes on the branch
3. Push branch: `git push -u origin type/description`
4. Create PR: `gh pr create --title "..." --body "..."`
5. Review the diff (Claude Code assists with review)
6. Merge with admin bypass: `gh pr merge <N> --admin --merge --delete-branch`

### For contributors (non-admin)

1. Fork the repository
2. Create feature branch
3. Submit PR
4. Wait for 1 approving review from a maintainer
5. CI must pass before merge

## Claude Code Integration

Claude Code creates branches and PRs. The owner reviews and merges:

```bash
# Claude Code creates the PR
git checkout -b feat/my-feature
# ... make changes ...
git push -u origin feat/my-feature
gh pr create --title "feat: my feature" --body "..."

# Owner merges after vetting with Claude Code
gh pr merge <N> --admin --merge --delete-branch
```

## MUST NOT Rules

### 1. No Direct Push to Main

All changes to main MUST go through a PR. Direct pushes are rejected by GitHub.

**Why:** Direct push bypasses CI checks and code review, allowing broken or unreviewed code to reach the release branch.

### 2. No Force Push

Force pushes to main are blocked. No exceptions.

**Why:** Force push on a shared branch rewrites history everyone has already pulled, silently discarding other contributors' work.

### 3. No Disabling Protection

Branch protection settings MUST NOT be weakened without explicit owner approval and documentation of the reason.

**Why:** Once protection is removed, every subsequent bypass becomes invisible — there's no audit trail showing the rules were briefly turned off, and re-enabling requires explicit intent that's easy to forget.

## Rationale

These repositories are open source (Apache 2.0, Terrene Foundation). Branch protection ensures:

- All changes are traceable via PRs
- CI validates every change before merge
- Contributors follow the same process as maintainers
- Admin bypass allows the owner to move fast while maintaining the audit trail
