---
type: DECISION
date: 2026-04-22
created_at: 2026-04-22T00:00:00Z
author: co-authored
session_id: 2026-04-22-gemini-analyze
session_turn: 20
project: gemini
topic: Gemini ships as API-key-only surface; OAuth subscription rerouting is rejected
phase: analyze
tags: [gemini, api-key, tos, google, surface, scope]
---

# Decision — Gemini API-key-only surface

## Context

Three auth modes are technically possible for routing Google Gemini into a csq-managed terminal:

1. **AI Studio API key** (AIza...) — flat, long-lived, pay-as-you-go.
2. **Vertex service account JSON** — standard GCP enterprise auth, used with `GOOGLE_APPLICATION_CREDENTIALS`.
3. **Gemini CLI OAuth device-auth** — the subscription-backed path (personal Google account → Gemini Advanced / Google AI Pro / Code Assist).

The OAuth path is the most user-valuable in a multi-account rotation scenario (it maps a subscription's quota to a slot). But Google's published ToS at `google-gemini/gemini-cli/docs/resources/tos-privacy.md` explicitly prohibits third-party software from accessing Gemini CLI backend services via OAuth. Enforcement is active in 2026: gemini-cli discussion #20632 and #22970 document 403 bans, Form-based reinstatement on first offense, permanent ban on second.

## Decision

csq ships Gemini as an API-key-only surface. Two auth modes are supported:

1. AI Studio API key via `csq setkey gemini --slot N` (paste).
2. Vertex service account JSON via `csq setkey gemini --slot N --vertex-sa-json <path>`.

OAuth subscription rerouting is NOT supported. The UI never surfaces an OAuth option, even if `~/.gemini/oauth_creds.json` already exists from the user's standalone gemini-cli setup. On first provisioning, csq detects prior OAuth residue and shows an explicit ToS-ban disclosure modal that requires acknowledgment before proceeding (ADR-G12).

The architecture goes further: csq ENFORCES the ban defensively across seven layers (EP1–EP7 in workspaces/gemini/01-analysis/01-research/04-risk-analysis.md §6):

- EP1 — `security.auth.selectedType` drift-detector at every spawn (ADR-G04)
- EP2 — user-level settings shield at install/provision
- EP3 — spawn env sanitation (strip `GEMINI_OAUTH_*`, `GOOGLE_OAUTH_*` on AI-Studio-mode slots)
- EP4 — response-body sentinel kills child if OAuth-flow markers appear in output
- EP5 — UI never renders an OAuth option
- EP6 — spawn refuses if `oauth_creds.json` is in the handle dir ancestry chain
- EP7 — defense-in-depth against any future gemini-cli A/B-test auth flipping (GrowthBook-class)

## Alternatives considered

1. **OAuth with a disclosure modal** (the pattern Codex uses for its ToS-ambiguous case via ADR-C08) — rejected. OpenAI's ToS is ambiguous on multi-account subscription use; Google's is explicit and actively enforced. The precedent from Codex does not transfer.
2. **Proxy Gemini OAuth through a Foundation-hosted relay** — rejected. Shifts the ToS violation from the user to the Foundation; does not eliminate it.
3. **Ship OAuth with a "you've been warned" toggle** — rejected. Acceptance of risk ≠ acceptance of ToS violation. Users will get banned; the Foundation will be blamed.
4. **Don't ship Gemini at all** — rejected. API-key path is entirely legitimate and valuable for users who want single-pane multi-key quota awareness.

## Consequences

- **Users lose the rotation-across-subscriptions value prop.** A user with a Google AI Pro subscription + a free Google account cannot pool their quotas through csq. They must use AI Studio keys (pay-as-you-go) or Vertex (enterprise).
- **API-key-only simplifies the implementation significantly.** No refresh subsystem, no daemon prerequisite (ADR-G09), no per-account mutex lattice, no credential mode-flip dance. Gemini reuses ~80% of Codex's abstraction; the 20% that differs is mostly ToS enforcement and the counter+429 quota path.
- **ToS enforcement is a first-class feature.** Seven defense layers span provisioning UI, spawn path, runtime response parsing. The drift detector (ADR-G04) is a per-spawn cost; measured in NFR-G01 at ~10-15ms budget.
- **If Google relaxes ToS** (unlikely in a horizon shorter than years), csq's posture is reversible. ADR-G01 explicitly notes re-evaluation on a written ToS change. The UI's OAuth-never-rendered stance is the most expensive decision to reverse (modal design, state machine extension); the rest of the stack would accept OAuth with minimal change.
- **Honest quota display is load-bearing.** Google exposes no public quota endpoint for AI Studio keys. csq's counter + 429 parse is the limit of what's possible — and the UI refuses to synthesize percentages when data is absent (ADR-G05). This is a discipline, not a constraint — but it's distinguishing.

## For Discussion

1. The ToS ban is the single largest scope cut in the Gemini surface. Is csq's value prop strong enough WITHOUT subscription rotation, or does the absence make Gemini feel like a second-class slot compared to Claude and Codex? (Value prop per 06-product-positioning: single-pane visibility, encrypted key storage, drift-detection, downgrade surfacing.)
2. Seven enforcement layers (EP1–EP7) feel like a lot for "just don't use OAuth." Is there a simpler reduction that gives equivalent defense — e.g., collapse EP1 + EP3 + EP6 into one `pre_spawn_tos_assert(slot)` function that all spawns pass through? This is an implementation question; spec already mandates the behavior regardless of factoring.
3. The response-body OAuth sentinel (EP4) requires wrapping gemini's child process I/O. This adds latency and complexity to every Gemini spawn. Is it worth it given that EP1–EP3 already make OAuth-mode execution nearly impossible to reach? Risk: if a future gemini-cli release changes how `selectedType` is honored OR adds a new auth-flipping mechanism, EP4 is the last-line defense. Keep or drop?

## References

- ADR-G01, ADR-G04, ADR-G12 in workspaces/gemini/01-analysis/01-research/03-architecture-decision-records.md
- 04-risk-analysis.md §6 EP1-EP7
- `google-gemini/gemini-cli/docs/resources/tos-privacy.md` — the authoritative ToS text
- gemini-cli discussion #20632, #22970 — enforcement precedent
- gemini-cli #21744 — `.env` discovery short-circuit (orthogonal but related)
- spec 07 §7.2.3 (Gemini layout), §7.3.4 (Gemini provisioning sequence)
