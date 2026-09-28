# `.githooks/` — version-controlled git hooks

This directory holds hooks that must **ship with the repo**. A hook dropped into
`.git/hooks/` is not tracked, does not survive a clone or a fresh worktree, and
disappears without a trace the first time someone re-clones — which is how the
repo reached a state where a complete, correct push guard was invoked by nothing
and 354 commits landed on the CI-free `dev` trunk with no gate firing.

## Install (once per clone — this line is not version-controlled)

```bash
cd /Users/example/repos/dev/csq
git config --local core.hooksPath .githooks
```

Verify it took:

```bash
git config --local core.hooksPath      # -> .githooks
```

### Why `--local` and not `--global`

- **Blast radius.** `core.hooksPath` is a machine-wide policy switch when set
  globally. The hook in this directory is repo-specific by construction: it looks
  for `.csq-dev-preflight.json` and gates a ref named `dev`. Applied globally it
  would put a csq-shaped gate in front of every repository on this machine,
  including the community fork, loom, and kailash — a one-line config write with
  unbounded scope. `--global` is the wrong instrument for a repo-local policy.
- **`--local` is the only scope that means "this repo".** It writes to
  `.git/config` for this checkout alone.

### Why the one-liner is not itself version-controlled

`.git/config` is a **protected path** in this repo. `scripts/ci/dev-preflight.mjs`'s
own header cites loom#1470: the git admin subtree can re-point a guard's repo
identity, and its hook scripts run arbitrary code on checkout. Tooling here does
not write into it. So the hook **directory** ships and the **pointer** is a manual
step — the honest cost of that boundary. If you want it automatic, the supported
shape is a provisioning script run by the operator, not a tool writing to
`.git/config` on its own.

### The value that was in place before this

Measured 2026-09-20, `core.hooksPath` was:

```
/Users/example/repos/csq/.git/hooks
```

That is **a different repository** (the community fork), and its hook directory
held zero non-sample hooks. So this repo's hooks were being looked for in another
repo's admin subtree and found nowhere. That is a pre-existing condition, recorded
here so it is not silently overwritten without a decision — replacing it is the
maintainer's call.

## What the hook gates, and what it does not

`.githooks/pre-push` delegates its verdict to `scripts/verify/dev-push-guard.sh`
and gates **pushes that write `refs/heads/dev` only**.

| push | gated? | why |
| --- | --- | --- |
| `refs/heads/dev` | **yes** | the trunk is CI-free by construction — nothing downstream catches a bad push to it |
| feature branches, tags | no | these get CI through a PR, which `dev` does not have. A hook firing on them is a false alarm that trains the operator to override it |
| `refs/heads/main` | no | already BLOCKED by branch protection and `git.md` MUST NOT #1, and it runs CI |
| deletion of `dev` | **blocked** | a receipt cannot vouch for a deletion |

This split exists because the pre-push hook is the only layer that knows *which
ref* is being pushed; `dev-push-guard.sh` reads a receipt bound to **HEAD**, not to
a ref, so it structurally cannot make that dispatch itself. Verdicts stay in the
guard; only the dispatch lives here.

## Outcome contract (three, never two)

| exit | meaning |
| --- | --- |
| `0` | allow — a preflight receipt names exactly HEAD and no gate in it REFUSES |
| `1` | **block** — determinate: no receipt, a stale receipt, a RED/UNDETERMINED gate recorded in it, a deletion, or a push of a commit the HEAD-bound receipt cannot name |
| `2` | **block** — UNDETERMINED: the guard could not measure (unreadable or malformed receipt, no verified `python3`, HEAD unresolvable), or it exited something unrecognised |

`2` is never folded into `0`. A guard that reads "I could not check" as "cleared"
reports green in exactly the case it exists to catch. Git aborts the push on any
non-zero status; the two codes are kept distinct so the operator's scrollback still
says which kind of refusal they hit.

## Test

```bash
bash scripts/tests/githooks-pre-push.test.sh    # 0 pass · 1 fail · 2 cannot measure
```

The self-test lives at exactly that path because `scripts/ci/dev-preflight.mjs`
globs `scripts/tests/*.test.sh` — a test anywhere else would never run.

## Deliberate bypass

```bash
git push --no-verify origin dev
```

`--no-verify` skips this hook. It is the documented escape hatch for a deliberate
decision, not a routine one: the whole reason this hook exists is that `dev` has no
CI behind it, so a bypassed push is unguarded end to end.
