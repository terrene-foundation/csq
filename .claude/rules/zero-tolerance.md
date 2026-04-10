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

## Language

Every "MUST" means MUST. Every "BLOCKED" means the operation does not proceed. Every "NO" means NO.
