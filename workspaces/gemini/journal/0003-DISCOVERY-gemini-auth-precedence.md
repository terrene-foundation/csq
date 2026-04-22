---
type: DISCOVERY
date: 2026-04-22
created_at: 2026-04-22T05:35:00Z
author: co-authored
session_id: 2026-04-22-gemini-pr-g0
session_turn: 10
project: gemini
topic: OPEN-G01 resolution — GEMINI_CLI_HOME settings.json isolates fully from user-level ~/.gemini, no fallback observed
phase: analyze
tags: [gemini, auth, isolation, precedence, OPEN-G01, pr-g0]
---

# Discovery — OPEN-G01: Gemini CLI auth precedence is handle-dir-dominant

## Context

`workspaces/gemini/02-plans/01-implementation-plan.md` lists OPEN-G01 as a PR-gating precondition for PR-G0: "empirically verify whether user-level `~/.gemini/settings.json` beats `GEMINI_CLI_HOME/.gemini/settings.json` when both exist." The worry case: csq pre-seeds the handle-dir with `selectedType=gemini-api-key`, but a user who is also signed in at the machine level (common developer setup, `selectedType=oauth-personal` + `~/.gemini/oauth_creds.json`) quietly bleeds their OAuth token into csq-spawned sessions. If this happened, PR-G2a's drift detector would need to either actively rename `~/.gemini/oauth_creds.json` at spawn time or refuse provisioning entirely.

The resolution branch matters: the "active rename / refuse provisioning" path was the pessimistic default in the plan, and it materially complicates the user-experience story (csq mutates the user's home directory to enforce isolation). A clean-isolation finding downgrades the drift detector to a cheap re-assertion.

## Probe

Environment: macOS 25.3.0 (Darwin), `gemini-cli` 0.38.2 via Homebrew (`/opt/homebrew/bin/gemini`), Node.js runtime.

User-level state (unchanged throughout the probe, created by a real `gemini` sign-in with `jack@terrene.foundation`):

| Path                         | Contents                                                  |
| ---------------------------- | --------------------------------------------------------- |
| `~/.gemini/settings.json`    | `{"security":{"auth":{"selectedType":"oauth-personal"}}}` |
| `~/.gemini/oauth_creds.json` | Valid (access_token, refresh_token, expiry_date, …)       |

Three probe scenarios, all using a single prompt `gemini -p "say only the word: ping" -o json`:

### Probe A — handle-dir settings wins if present

```
GEMINI_CLI_HOME=/tmp/gemini-isolated
/tmp/gemini-isolated/.gemini/settings.json = {"security":{"auth":{"selectedType":"gemini-api-key"}}}
GEMINI_API_KEY=AIzaSyInvalidForTesting123BogusKey (bogus)
```

**Result:** `400 INVALID_ARGUMENT` with `reason: "API_KEY_INVALID"`, `domain: "googleapis.com"`, `service: "generativelanguage.googleapis.com"`. The CLI attempted an API-key call with the bogus env value — OAuth was NOT attempted despite the user-level oauth_creds being valid.

### Probe B — handle-dir with no settings.json does NOT fall back to user-level

```
GEMINI_CLI_HOME=/tmp/gemini-iso-empty
/tmp/gemini-iso-empty/.gemini/      (directory exists, no settings.json inside)
GEMINI_API_KEY unset
```

**Result:** exit code 41, error message:

> Please set an Auth method in your /tmp/gemini-iso-empty/.gemini/settings.json or specify one of the following environment variables before running: GEMINI_API_KEY, GOOGLE_GENAI_USE_VERTEXAI, GOOGLE_GENAI_USE_GCA

The CLI explicitly named the handle-dir's settings.json path. User-level `~/.gemini/settings.json` was ignored entirely — no fall-through, no OAuth attempt.

### Probe C — no isolation, user-level auth works

(Baseline run from earlier in the session, `gemini -p "…" -o json` with default env — succeeds with a full response via the user-level OAuth path, confirming the oauth_creds.json is actually valid and would have been used if the CLI were configured to use it.)

## Discovery

`GEMINI_CLI_HOME` fully isolates the `settings.json` resolution path. When set, the CLI reads `$GEMINI_CLI_HOME/.gemini/settings.json` and does NOT fall back to `~/.gemini/settings.json` on a miss. This holds in three regimes:

- handle-dir has a conflicting `selectedType` → handle-dir wins (Probe A)
- handle-dir has no settings.json at all → the CLI errors at the handle-dir path rather than falling through (Probe B)
- no isolation envelope → user-level OAuth works normally (Probe C baseline)

In csq's deployment, every spawn goes through `GEMINI_CLI_HOME=term-<pid>/` with a pre-seeded `settings.json` containing `selectedType=gemini-api-key` (spec 07 §7.2.3). The user's `~/.gemini/oauth_creds.json` is a no-op for those spawns.

## Why this matters

1. **PR-G2a drift detector simplifies to "re-assert selectedType" only.** The original plan's branch for "user-level wins → active rename / refuse provisioning" does not fire. `reassert_api_key_selected_type(handle_dir)` needs only to re-verify the handle-dir's settings.json on every spawn — if it has drifted (e.g. gemini-cli wrote something else during an interactive session), re-seed. No touching the user's home directory.

2. **User's personal Gemini CLI keeps working.** A user who runs `gemini` standalone (outside csq, no `GEMINI_CLI_HOME`) still hits their user-level `~/.gemini` and signs in with their personal OAuth. csq does not interfere with that path.

3. **EP4 ToS-guard's concern shifts.** The 7-layer ToS guard was partially motivated by the fear of OAuth-from-user-level bleeding through. This finding removes that specific vector. EP4 still defends against explicit user misconfiguration (user provisions csq slot with AI Studio key but later flips handle-dir settings to oauth-personal), but the "silent bleed from ~/.gemini" failure mode is not reachable.

4. **oauth_creds.json residue modal (PR-G5) stays.** Even though isolation holds for fresh spawns, csq still wants to surface a UX warning when a user has a stale `~/.gemini/oauth_creds.json` around — some workflows (user runs `gemini` directly, then later tries csq) would leave leftover oauth tokens in `~/.gemini` that deserve a cleanup prompt. This is a UX concern, not a correctness one.

## Limits of this probe

- **gemini-cli 0.38.2 specifically.** Google has shipped multiple breaking auth-path changes in the last year; csq's EP4 whitelist is already pinned to the minor release (plan §PR-G2a). A future gemini-cli release could reintroduce user-level fallback. Regression test: the "handle-dir-with-empty-settings errors with handle-dir path" probe must pass on every whitelisted minor release.
- **Didn't test oauth-personal in the handle-dir.** Only api-key-in-handle-dir vs oauth-at-user-level. The reverse case (handle-dir says oauth-personal with no creds; user-level has oauth-personal with valid creds) was not probed because csq's design never writes oauth-personal into handle-dirs. If that invariant ever slips, the fall-through question reopens.
- **Didn't test Vertex SA paths.** `GOOGLE_GENAI_USE_VERTEXAI` is a separate auth mode; not exercised. Vertex branching arrives in PR-G4 UX (AddAccountModal's second tab).

## Decision impact

- **Spec 07 §7.2.3:** existing text is consistent with this finding; no changes needed beyond what PR-G0 already added (§7.2.3.1 event-delivery contract).
- **PR-G2a drift detector scope:** reduce from "rename oauth_creds or refuse provisioning" to "re-assert selectedType before every spawn." Plan §PR-G2a FR-G-CORE-04 simplifies.
- **Risk analysis §4 GG-drift-1:** downgrade severity; the user-level bleed scenario is empirically unreachable on 0.38.2.

## For Discussion

1. **Probe B's error message names the handle-dir path explicitly — is that guaranteed by gemini-cli's contract, or is it a happy accident of the current error-message template?** If Google rephrases the error to something like "Please set auth in the appropriate settings.json," the regression test loses its failure signal. What's the contract-strength fallback? (Possible: parse stack frames or inspect which settings file was stat'd. More fragile.)

2. **If `GEMINI_CLI_HOME` isolation had NOT held, what would the cheapest mitigation have been — active rename of `~/.gemini/oauth_creds.json` at spawn time (reversible, destructive to user's standalone workflow during csq sessions) or a one-time consent dialog asking the user to delete their user-level oauth before using csq (non-destructive, adds a friction gate)?** The plan implicitly assumed active rename; the consent-gate alternative wasn't considered.

3. **The test matrix only covers gemini-cli 0.38.2. EP4's versioned whitelist (plan §PR-G2a) pins to minor releases, but OPEN-G01's resolution is an inferred property of the same whitelist — should the regression test live in the EP4 whitelist-tuning suite (i.e. every whitelist bump re-runs the isolation probe) or in a separate "auth-precedence regression" bucket?**

## Cross-references

- Spec 07 §7.2.3 — per-surface Gemini layout (authoritative for settings.json location)
- Spec 07 §7.2.3.1 — event-delivery contract (added in this PR; not load-bearing for this finding)
- `workspaces/gemini/02-plans/01-implementation-plan.md` §PR-G2a FR-G-CORE-04 — drift detector scope
- `workspaces/gemini/01-analysis/01-research/04-risk-analysis.md` §4 GG-drift-1 — severity downgrade candidate
- Journal 0001 — API-key-only surface decision (provides the context for "why handle-dir always has selectedType=gemini-api-key")
- Journal 0002 — silent-downgrade detection (orthogonal; lives in response-shape not auth-path)
- Upstream: `google-gemini/gemini-cli` 0.38.2 behavior (probe target)
