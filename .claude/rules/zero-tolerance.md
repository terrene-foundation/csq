---
name: zero-tolerance
description: Zero-tolerance rules — pre-existing failures must be fixed in-session, no stubs, no silent fallbacks.
---

# Zero-Tolerance Enforcement Rules

Applies to ALL sessions, ALL agents, ALL code. ABSOLUTE and non-negotiable.

## Rule 1: Pre-Existing Failures MUST Be Resolved

When tests, validation, or analysis reveal a pre-existing failure: **you own it**. Diagnose root cause → implement fix → write regression test → verify → commit. All in this session.

**BLOCKED responses:**

- "Pre-existing issue, out of scope"
- "Noting as a known issue for future resolution"
- Any acknowledgment without a fix

**Why:** Deferring broken code creates a ratchet where every session inherits more failures, and the codebase degrades faster than any single session can fix.

**Exception:** User explicitly says "skip" or "ignore."

## Rule 2: No Stubs, Placeholders, or Deferred Implementation

`TODO`, `FIXME`, `HACK`, `STUB`, `raise NotImplementedError`, `pass  # placeholder`, `return None  # not implemented` — all BLOCKED in production code. See `no-stubs.md` for the detector patterns; `validate-workflow.js` exits with code 2 on detection.

**Why:** Stubs present a working-looking surface with broken internals, causing users to trust outputs that are silently incomplete.

## Rule 3: No Silent Fallbacks or Error Hiding

`except: pass`, empty catch blocks, `return None` without logging, silent discards — BLOCKED.

**Why:** Silent error swallowing hides bugs until they cascade into data corruption or production outages with no stack trace to diagnose.

**Acceptable:** `except: pass` in cleanup / teardown where failure is expected.

## Rule 4: No Workarounds for Upstream Bugs

When you hit a bug in an upstream dependency (Claude Code CLI, OAuth endpoint, macOS `security` tool): reproduce, document, file an upstream issue. Do NOT re-implement the upstream's job yourself.

**BLOCKED:** naive re-implementations, post-processing to "fix" upstream output, downgrading to avoid bugs.

**Why:** Workarounds create a parallel implementation that diverges from the upstream, doubling maintenance cost and masking the root bug from being fixed.

## Rule 5: No Residual Risks Journaled as "Accepted"

When `/redteam` surfaces residual risks, the closing state is **resolved**, not "documented and deferred". A journal section titled "Residual risks — accepted under same-user threat model" is BLOCKED. Each finding above LOW gets a fix in the same session.

**BLOCKED responses:**

```
DO NOT: ## Residual risks (accepted)
        - Microsecond TOCTOU window — bounded by same-user threat model
        - Unbounded recursion — bounded by PATH_MAX in practice
        - Windows crash recovery — needs Job Object work
```

**Required pattern:**

```
DO: Resolve each finding. The threat-model argument is grounds for
    picking a CHEAPER fix (e.g. rename-to-tombstone instead of full
    flock), not for skipping the fix entirely.
```

**Why:** "Bounded by same-user threat model" / "narrow window in practice" / "cold path" are the same argument every redteamer hears for every finding. Accepting them once trains the next session to accept them too. The session that landed the image-cache guard (journals 0036–0038) initially closed with four "accepted residuals"; the user response was _"no residual risks are acceptable, please resolve"_ and each one turned out to be 30–90 minutes of focused work. The deferral framing was a way to declare convergence prematurely, not an engineering necessity.

**Exceptions** (genuinely cannot be fixed in-session):

- External dependency the Foundation does not control (e.g. an unprovisioned signing key, a third-party API that needs a contract change)
- Platform-specific work that requires a new dependency to be added to Cargo.toml in a follow-up PR (e.g. Windows Job Object integration via the `windows` crate)

In those cases document the **specific blocker** by name, not a general "accepted residual" framing.

## Language

Every "MUST" means MUST. Every "BLOCKED" means the operation does not proceed. Every "NO" means NO.
