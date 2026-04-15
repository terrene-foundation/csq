---
paths:
  - "specs/**"
  - "workspaces/**"
---

# Specs Authority Rules

The `specs/` directory is the single source of domain truth for csq. It contains detailed specification files organized by architectural domain (credentials, handle-dirs, daemon, polling, keychain). Phase commands read targeted spec files before acting and update them when domain truth changes.

`specs/` is NOT a process artifact (that is what `workspaces/` does). It is the detailed record of WHAT the system is and does, not HOW we are building it. Plans, todos, and journals continue to serve their existing roles.

Origin: loom analysis of 6 alignment drift failure modes across COC phase system. Specs address brief-to-plan lossy compression (FM-1), phase transition context thinning (FM-2), multi-session amnesia (FM-3), agent delegation context loss (FM-4), and silent scope mutation (FM-6).

## MUST Rules

### 1. Specs Index Exists and Is Maintained

`specs/_index.md` MUST list every spec file with a one-line description. Phases read `_index.md` to identify which spec files are relevant to the current work, then read only those files.

```markdown
# DO -- \_index.md is a lean lookup table

| #   | Document                   | Governs                                        |
| --- | -------------------------- | ---------------------------------------------- |
| 01  | CC Credential Architecture | How CC reads, writes, caches OAuth credentials |
| 02  | csq Handle-Dir Model       | Per-account config-N + per-terminal term-<pid> |

# DO NOT -- \_index.md contains the actual specifications
```

**Why:** Without an index, phases must read every spec file to find relevant content, defeating token efficiency. Without specs, alignment drifts as phases work from stale memory.

### 2. Phase Commands Read Specs Before Acting

Each phase MUST read `specs/_index.md` at start, identify relevant spec files, and read those files before taking action. Phases MUST NOT read the entire `specs/` directory -- only the files relevant to the current work.

```
# DO -- targeted reads
/implement (working on refresher todo):
  1. Read specs/_index.md -> find 04-csq-daemon-architecture.md
  2. Read specs/04-csq-daemon-architecture.md -> full context
  3. Implement against spec, not memory

# DO NOT -- skip specs, work from memory
/implement (working on refresher todo):
  1. Remember vaguely what the daemon does
  2. Implement based on partial recall
```

**Why:** Working from memory instead of specs is the root cause of incremental mutation divergence. Agents recall 3 of 15 details. The other 12 become bugs.

### 3. Spec Files Are Detailed, Not Summaries

Each spec file MUST be comprehensive enough to be the authority on its topic. Every nuance, constraint, edge case, contract, and decision relevant to that domain MUST be captured.

```markdown
# DO -- detailed authority

## Token Refresh Flow

1. Daemon checks expiry_ts - now() < 300s for each account
2. POST to /api/oauth/token with grant_type=refresh_token
3. On success: atomic_replace config-N/.credentials.json
4. Preserve subscription_type if new response has None
5. On 429: exponential backoff (10min x 2^n, cap 80min)

# DO NOT -- thin summary

## Token Refresh Flow

The daemon refreshes tokens before they expire.
```

**Why:** Thin summaries lose the exact details that agents need to implement correctly. "Refreshes tokens" doesn't tell the agent the backoff strategy, the preservation guard, or the atomic write requirement.

### 4. Spec Files Are Updated at First Instance

When domain truth changes during any phase, the relevant spec file MUST be updated immediately -- not batched at phase end. If a decision during `/implement` changes a daemon contract, the spec is updated in the same action.

```
# DO -- update spec when the truth changes
1. Implement Node.js transport for Anthropic HTTP
2. Immediately update specs/04-csq-daemon-architecture.md with transport table
3. Continue implementation

# DO NOT -- batch updates for later
1. Implement transport change
2. Implement 5 more todos
3. "I'll update specs later" -> specs are now stale for todos 2-6
```

**Why:** Batched updates create a staleness window where other agents or the next session read outdated specs. First-instance updates keep specs current within one action.

### 5. Deviations From Spec Require Explicit Acknowledgment

When implementation deviates from a spec (different approach, contract, or behavior), the agent MUST: (a) update the spec file with the new truth, (b) log the deviation with rationale, and (c) flag user-visible changes for approval.

```markdown
# DO -- deviation logged in the spec file

## Transport

~~reqwest for all HTTP~~ -> Node.js subprocess for Anthropic endpoints (changed 2026-04-14)
**Reason:** Cloudflare JA3/JA4 fingerprinting blocks reqwest/rustls
**User impact:** None (transparent). Reference: journal 0056

# DO NOT -- silently implement differently
```

**Why:** Silent deviations are the #1 cause of "it works but it's not what the spec says." The spec is the contract; deviations without acknowledgment are contract violations.

**BLOCKED responses:**

- "The spec said X, and X is implemented" (when approach differs from spec)
- "This is an implementation detail, not a spec change"
- "The spec is aspirational; the code is what matters"
- "I'll update the spec after implementation stabilizes"

### 6. Agent Delegation Includes Relevant Spec Files

When delegating to a specialist, the orchestrator MUST read `_index.md`, select relevant spec files, and include their content in the delegation prompt.

```
# DO -- include spec content in delegation prompt
Agent(prompt: "Fix refresher backoff.\n\nFrom specs/04-csq-daemon-architecture.md:\n[content]")

# DO NOT -- delegate without specs context
Agent(prompt: "Fix refresher backoff.")
```

**Why:** Specialists without spec context produce intent-misaligned output -- e.g., writing credentials without the subscription_type guard because spec 01 wasn't communicated.

### 7. Large Spec Files Are Split

When a spec file exceeds 300 lines, it MUST be split into sub-domain files and `_index.md` updated. Completeness (MUST Rule 3) takes priority over brevity.

**Why:** Oversized spec files crowd out implementation reasoning when loaded into context, and make delegation prompts enormous.

## MUST NOT

- Read the entire `specs/` directory at any phase gate -- `_index.md` exists for selective reads (exception: `/redteam` and `/codify` may read all specs for audit)

**Why:** Reading all 7 spec files at once burns ~10k tokens of context when only 1-2 are relevant to the current task.

- Treat specs as optional documentation

**BLOCKED:** "Specs can be written after implementation", "The code is the spec", "Plans already capture this, specs are redundant", "Updating specs for this minor change is overkill"

**Why:** Specs prevent the 6 drift failure modes that cause multi-session amnesia and silent scope mutation.

## Cross-References

- `specs/_index.md` -- the manifest (read this first)
- `rules/account-terminal-separation.md` -- derived from specs 01 and 02
- `rules/cc-artifacts.md` -- artifact quality standards
