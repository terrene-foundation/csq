---
type: DISCOVERY
date: 2026-04-22
created_at: 2026-04-22T00:00:00Z
author: agent
session_id: 2026-04-22-gemini-analyze
session_turn: 20
project: gemini
topic: Silent model downgrade on preview tiers is the Gemini-specific failure class, and detection requires per-response modelVersion capture
phase: analyze
tags: [gemini, downgrade, preview, modelversion, growthbook-class]
---

# Discovery — Silent-downgrade detection for Gemini preview tiers

## Context

Google's Gemini API exhibits a silent downgrade pattern: when a user selects a preview model (e.g., `gemini-3-pro-preview`) and the account's tier does not actually have preview access, the API responds successfully with a fallback model (typically `gemini-2.5-pro`) — no error, no warning header, no user-visible signal. Conversation continues with the fallback; output quality degrades without explanation.

This is structurally identical to an existing csq-tracked failure class: the GrowthBook `tengu_auto_mode_config` A/B flag in `.claude.json` that silently forces Sonnet on Claude accounts regardless of user selection (memory: `discovery_growthbook_model_override.md`). Both failures share the pattern "user asks for X, system silently delivers Y, UI claims X is in use."

## Discovery

Detection requires parsing `modelVersion` from the RESPONSE (not the request). Gemini's `generateContent` REST endpoint and `streamGenerateContent` SSE endpoint both return the effective model in the response payload — typically inside `usageMetadata` or as a top-level `modelVersion` field. Exact field location per endpoint is OPEN-G02 (workspaces/gemini/01-analysis/01-research/04-risk-analysis.md §4 GG3), pending live verification.

Once captured, csq stores BOTH the selected model (what the user asked for via `csq models switch`) AND the effective model (what Google actually delivered). When they differ, the AccountCard shows a downgrade badge (amber, `Selected: gemini-3-pro-preview · Effective: gemini-2.5-pro`). Flapping is debounced via a 3-mismatches-in-5-minutes latch (ADR-G06); below that threshold, occasional drift is shown as-observed without latching.

The mechanism intentionally does NOT pause the slot or block further requests. Users who explicitly opted into a preview model understand they may get the fallback; csq's job is to make that visible, not to enforce the selection.

## Why this matters

1. **This is the Gemini-specific showstopper.** Without downgrade detection, a user who switches their slot to `gemini-3-pro-preview` to get better coding output but doesn't actually have preview access will pay for pro-preview rate-limit slots while receiving 2.5-pro quality. They would only discover this by noticing quality regression across sessions. The same failure is silent in standalone gemini-cli today.

2. **The abstraction extends to every surface.** Claude has GrowthBook flags. Codex's `wham/usage` might grow a similar override mechanism. Gemini has preview-tier fallback. The pattern is: "model selection is a request; effective model is a response property; trust the response, not the request." csq's quota.json v2 schema already supports this via `selected_model` + `effective_model` fields.

3. **Response-side capture is also the ToS-guard signal.** The same response-parsing wrapper that captures `modelVersion` can detect OAuth-flow markers (EP4 in the ToS enforcement surface). One code path, two defenses.

## Detection mechanics

1. **csq-cli wraps gemini's stdout/stderr** during spawn (already needed for 429 parse and EP4 ToS sentinel).
2. **Parser runs on each response chunk** (REST or SSE). First chunk almost always carries `modelVersion`; for safety, also parse `usageMetadata` on final chunk of SSE.
3. **Event emitted to daemon:** `gemini_effective_model_observed { slot, selected, effective, is_downgrade }`.
4. **Daemon writes quota.json[N]** with `selected_model`, `effective_model`, `effective_model_first_seen_at`, `mismatch_count_today`.
5. **UI reads quota.json:** if `is_downgrade`, render the badge.
6. **Debounce:** latch `is_downgrade = true` only after 3 mismatches in 5 minutes; reset to false after 5 minutes of matches.
7. **Log once per day:** `error_kind = "gemini_preview_downgrade"` at first detection; re-emit daily for persistence.

## Follow-up actions

- **Resolve OPEN-G02** before PR-G3 ships. Method: capture a real response from each endpoint (REST + SSE) against a tier WITHOUT preview access (probably free tier with `gemini-3-pro-preview` selected). Record exact field names and position. Pin in spec 05 §5.8.
- **Integration test:** mock gemini responses, assert `effective_model` is extracted correctly from both REST and SSE shapes.
- **Cross-surface consistency:** the same `selected_model` / `effective_model` fields should work for Codex's `wham/usage` (if OpenAI exposes effective model) and for Claude's GrowthBook-overridden case. Consider whether quota.json v2 should lift these fields to the surface-agnostic layer now, or leave them surface-specific until a second use case lands.

## For Discussion

1. The 3-mismatches-in-5-minutes debounce is a guess. If the fallback alternates rapidly (F10 in risk analysis — `gemini-3-pro-preview` → `gemini-3-pro-preview-04` → `gemini-2.5-pro` same day), is the right debounce "latch on first, release on N consecutive matches" instead? Depends on empirical flapping frequency, which we don't have. Ship the 3/5-minute rule with a config knob; revise on observed data.
2. Should csq's downgrade detection extend upstream to gemini-cli itself (a PR to surface `modelVersion` as user-visible output)? This is more expensive than solving it in csq, but benefits every user. Alternative: file an issue with the data we collect and let Google decide.
3. If OPEN-G02 reveals that `modelVersion` is NOT in every response shape (e.g., absent in SSE unless `usageMetadata` is requested), csq needs either an additional request flag (changes gemini-cli invocation) or a best-effort approach that only catches the REST path. How aggressive should csq be about modifying the gemini invocation to guarantee capture?

## References

- ADR-G06 in workspaces/gemini/01-analysis/01-research/03-architecture-decision-records.md
- 04-risk-analysis.md §4 GG3 (OPEN-G02), §1 F2/F10, §8 (silent-downgrade UX)
- memory: `discovery_growthbook_model_override.md` — analog on Claude side
- quota.json v2 schema: spec 07 §7.4 (to be extended with selected/effective fields via spec 05 §5.8)
