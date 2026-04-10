---
paths:
  - ".claude/**"
---

# No Stubs, TODOs, or Simulated Data

## Scope

These rules apply to ALL production code (non-test files).

## MUST NOT Rules

### 1. No Stubs or Placeholders

Production code MUST NOT contain:

- `TODO`, `FIXME`, `HACK`, `STUB`, `XXX` markers
- `raise NotImplementedError` (implement the method)
- `pass # placeholder` or `pass # stub`
- `return None # not implemented`
- Empty function/method bodies that should have logic

**Why:** Stubs present a working-looking surface with broken internals, causing users to trust outputs that are silently incomplete and to waste cycles debugging "why the feature doesn't behave as documented."

### 2. No Simulated or Fake Data

Production code SHOULD NOT contain:

- `simulated_data`, `fake_response`, `dummy_value`
- Hardcoded mock responses pretending to be real API calls
- `return {"status": "ok"}` as a placeholder for real logic
- Test fixtures masquerading as production defaults

**Frontend mock data is a stub.** The following patterns in JS/TS/TSX/JSX production code are stubs:

- Constants named `MOCK_*`, `FAKE_*`, `DUMMY_*`, `SAMPLE_*` (e.g., `MOCK_USERS`, `SAMPLE_DATA`)
- Functions named `generate*()` or `mock*()` that produce synthetic/random data instead of calling APIs (e.g., `generateHourlyOccupancy()`, `mockTransactions()`)
- Hardcoded arrays/objects serving as page data where an API call should exist
- `Math.random()` used to generate display data (occupancy rates, transaction counts, etc.)

**Why**: Frontend mock data is invisible to Python stub detection but has the same effect — users see fake data presented as real. A page with `generateHourlyOccupancy()` is as broken as a backend endpoint with `raise NotImplementedError`.

### 3. No Silent Fallbacks

Production code MUST NOT silently swallow errors:

- `except: pass` (bare except with pass)
- `catch(e) {}` (empty catch block)
- `except Exception: return None` without logging

**Acceptable**: `except: pass` in hooks/cleanup code where failure is expected.

**Why:** Silent error swallowing hides bugs until they cascade into data corruption or production outages with no stack trace to diagnose — by the time symptoms surface, the root cause is invisible.

### 4. Avoid Deferred Implementation

When implementing a feature:

- Aim to implement ALL methods fully, not just the happy path
- If an endpoint exists, it must return real data
- If a service is referenced, it must be functional
- Never leave "will implement later" comments

**Why:** Half-implemented features present a working UI with broken backend, causing users to trust outputs that are silently incomplete or wrong — worse than a broken UI because the break is invisible.

## Enforcement

- **PostToolUse hook**: `validate-workflow.js` **BLOCKS** (exit code 2) stub patterns in production Python AND JS/TS code. In JS/TS: detects `MOCK_*/FAKE_*/DUMMY_*/SAMPLE_*` constants, `mock*()` function declarations, data-producing `generate*Data/List/Records/Stats()` calls, and `Math.random()` display data. This is NOT a warning — it stops the operation.
- **UserPromptSubmit hook**: Injects zero-tolerance reminder every turn
- **Red-team agents**: Scan for violations during validation rounds. If a stub is found, the red team MUST fix it — not report it.
- **Spec coverage audit**: `/redteam` step 1 reads plans and verifies each item exists with real data flowing — catches mock data that survived implementation.

## Why This Matters

Stubs and TODOs accumulate silently. Each one is a hidden failure point:

- Users encounter `NotImplementedError` in production
- Silent fallbacks mask real bugs
- Simulated data gives false confidence in demos
- TODOs never get done without active tracking

## Exceptions

Test files (`test_*`, `*_test.*`, `*.test.*`, `*.spec.*`, `__tests__/`) are excluded from stub detection.

**Exceptions may be made for iterative development where TODOs are actively tracked.** Previous versions of this rule allowed stubs with "explicit user approval." Users iterating on projects may use TODOs when actively tracked. If you cannot implement something, ask the user what the behavior should be, then implement it. If the user says "remove it entirely," delete the function — do NOT leave a stub.

See also: `rules/zero-tolerance.md` (Absolute Rule 2)
