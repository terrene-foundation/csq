---
type: DISCOVERY
date: 2026-04-22
created_at: 2026-04-22T05:40:00Z
author: co-authored
session_id: 2026-04-22-gemini-pr-g0
session_turn: 14
project: gemini
topic: OPEN-G02 resolution — effective-model capture point is gemini-cli's init event, not raw generateContent modelVersion; .env in CWD IS loaded by gemini-cli so csq must pre-spawn scan
phase: analyze
tags: [gemini, response-shape, env-precedence, OPEN-G02, pr-g0, effective-model]
---

# Discovery — OPEN-G02: Response shape + env-precedence for Gemini

## Context

`workspaces/gemini/02-plans/01-implementation-plan.md` lists OPEN-G02 as a PR-gating precondition for PR-G0. Two unresolved questions:

1. **Where does the effective-model signal live in the response?** The silent-downgrade detection (journal 0002) depends on capturing `modelVersion` from the runtime response — `usageMetadata`, top-level `modelVersion`, or somewhere else. Location differs between REST `generateContent` and SSE `streamGenerateContent`; csq's capture path must pin one or both.
2. **Does a `.env` in the spawn CWD override csq's `Command::env`-injected `GEMINI_API_KEY`?** Upstream issue `google-gemini/gemini-cli#21744` documents a discovery chain `$CWD → ancestors → $GEMINI_CLI_HOME → $HOME`; csq spec 07 §7.2.3 already cites this. Empirical verification against the shipped 0.38.2 was missing.

Both questions gate PR-G2a (capture module) and PR-G3 (daemon consumer). If the answer to #1 changed csq's capture approach, PR-G2a's code layout changed. If the answer to #2 shifted the threat model, PR-G2a's pre-spawn scan (EP2/EP3/EP6) changed.

## Probe — response shape

Environment: macOS 25.3.0 (Darwin), `gemini-cli` 0.38.2, valid user-level OAuth (`selectedType=oauth-personal`).

### Probe 1 — `-o json` (aggregated, non-streaming)

`gemini -p "say only the word: ping" -o json`:

```json
{
  "session_id": "00dc1161-…",
  "response": "ping",
  "stats": {
    "models": {
      "gemini-3-flash-preview": {
        "api":    {"totalRequests": 1, "totalErrors": 0, "totalLatencyMs": 6406},
        "tokens": {"input": 8577, "prompt": 8577, "candidates": 1, "total": 8896, "cached": 0, "thoughts": 318, "tool": 0},
        "roles":  {"main": { … }}
      }
    },
    "tools": { … },
    "files": { … }
  }
}
```

**Key finding:** the effective model surfaces as the **key** of `stats.models.<model>`, not as a `modelVersion` field. gemini-cli has already parsed the underlying Google API's `modelVersion` per-response and aggregated into this per-model bucket. A session that hits two different models (e.g. a pro call plus a flash fallback) would show two keys under `stats.models`.

### Probe 2 — `-o stream-json` (NDJSON per-event)

`gemini -p "say only: ping" -o stream-json` emits four newline-delimited JSON objects:

```json
{"type":"init",   "timestamp":"…","session_id":"…","model":"gemini-3-flash-preview"}
{"type":"message","timestamp":"…","role":"user",     "content":"say only: ping"}
{"type":"message","timestamp":"…","role":"assistant","content":"ping","delta":true}
{"type":"result", "timestamp":"…","status":"success","stats":{"total_tokens":8697,"input_tokens":8223,"output_tokens":1,"cached":0,"input":8223,"duration_ms":15305,"tool_calls":0,"models":{"gemini-3-flash-preview":{…}}}}
```

**Key finding:** the `init` event carries a top-level `model` field — this is the effective model for the whole session, emitted before the first generation token. The `result` event repeats the same model key under `stats.models`.

### Probe 3 — error response shape (`-o json`)

With bogus API key, `-o json` returns:

```json
{
  "session_id": "c401e424-…",
  "error": {
    "type": "Error",
    "message": "{\"error\":{\"message\":\"{\\n  \\\"error\\\": {\\n    \\\"code\\\": 400,\\n    \\\"message\\\": \\\"API key not valid…\\\",\\n    \\\"status\\\": \\\"INVALID_ARGUMENT\\\",\\n    \\\"details\\\": [\\n      {\\n        \\\"@type\\\": \\\"type.googleapis.com/google.rpc.ErrorInfo\\\",\\n        \\\"reason\\\": \\\"API_KEY_INVALID\\\",\\n        \\\"domain\\\": \\\"googleapis.com\\\",\\n        \\\"metadata\\\": {\\n          \\\"service\\\": \\\"generativelanguage.googleapis.com\\\"\\n        }\\n      },\\n      {\\n        \\\"@type\\\": \\\"type.googleapis.com/google.rpc.LocalizedMessage\\\",\\n        \\\"locale\\\": \\\"en-US\\\",\\n        \\\"message\\\": \\\"API key not valid…\\\"\\n      }\\n    ]\\n  }\\n}\"}}",
    "code": 400
  }
}
```

**Key finding:** gemini-cli double-wraps the Google API error. The outer shape is gemini-cli's `{type, message, code}`. The `message` field is a stringified JSON containing the Google API envelope `{error: {code, message, status, details: [...]}}`. For 429 `RESOURCE_EXHAUSTED`, the `details` array will contain additional entries (`QuotaFailure` + `RetryInfo`) per spec 05 §5.8's placeholder shape — this probe confirms the envelope is consistent with the Google API standard error response.

## Probe — env precedence

### Probe 4 — `.env` in CWD is loaded when shell env is unset

```
/tmp/gemini-env-probe/.env  =  "GEMINI_API_KEY=AIzaFromEnvFileBogus000000000000000000000\n"
cd /tmp/gemini-env-probe && unset GEMINI_API_KEY && GEMINI_CLI_HOME=<api-key-handle> gemini -p "ping" -o json
```

**Result:** same `API_KEY_INVALID` error as Probe 3 — gemini-cli issued the API call with the bogus `AIza…` value. Since no shell `GEMINI_API_KEY` was set, the value must have come from `/tmp/gemini-env-probe/.env`. This confirms the dotenv loader is active in 0.38.2 and loads `.env` from CWD into the process environment before the API-key lookup runs.

### Why shell env "probably" wins, but we don't want to rely on that

Standard dotenv semantics: a variable that is already present in the process environment is NOT overridden by a `.env` file. Under that contract, `Command::env("GEMINI_API_KEY", real_key)` from csq would beat a stray `.env` in the user's CWD.

Problem: the contract is a library-level convention, not a platform guarantee, and gemini-cli bundles its own loader (Node.js dotenv in the Vite bundle). A patch release that flips `override: true` in the loader would silently invert the precedence. csq cannot rely on this.

Csq's safer design (spec 07 §7.2.3 already states and PR-G2a implements as EP2/EP3/EP6):

- Pre-spawn scan of the gemini-cli discovery chain `$CWD → ancestors → $GEMINI_CLI_HOME → $HOME`.
- If any `.env` in that chain contains `GEMINI_API_KEY` (grep-level, not dotenv-parsed — handles quoted + unquoted), **refuse to spawn** with an actionable error naming the offending file.
- User remediation: delete or move the `.env`; csq re-tries.

This shifts the invariant from "hope dotenv doesn't override" to "guarantee no .env with GEMINI_API_KEY exists in the discovery chain at spawn time." Deterministic; does not depend on upstream library behaviour.

## Implications for PR-G2a capture module

Given the probes:

1. **Primary effective-model source: stream-json `init.model`.** Parse the first `init` line from gemini-cli's stdout; emit `effective_model_observed` event with `selected = handle_dir.settings.json.model.name`, `effective = init.model`. Simple, low-latency, bounded parse cost.

2. **Fallback effective-model source: `stats.models.<key>` in `-o json` or `result.stats.models`.** For invocations that don't use stream-json, parse the final JSON and extract the first (and usually only) key under `stats.models`. Multiple keys indicate mid-session model switch — emit multiple events, let the daemon's debouncer (3-in-5-minute latch, ADR-G06) handle.

3. **Error surfacing: parse gemini-cli's outer `error.message` as nested JSON to extract Google's `details[]`.** 429 detection triggers on `details[*].reason == "RESOURCE_EXHAUSTED"`; retry-delay from `details[*]['@type' == "type.googleapis.com/google.rpc.RetryInfo"].retryDelay`. Matches spec 05 §5.8 placeholder shape.

4. **Csq-cli wraps gemini-cli with `-o stream-json` by default.** Text output is unusable for capture; `-o json` forces aggregation to end-of-session (no streaming); `-o stream-json` gives per-event timing which is what the quota counter needs. This adds a UX constraint — interactive gemini sessions inside csq see stream-json formatted output, not the familiar TUI — flagged for PR-G2a design review.

## Why this matters

1. **Effective-model capture is trivially cheap.** Single JSON.parse of the first stdout line. No regex-on-stderr gymnastics. The plan's §PR-G2a `capture.rs` module can lean hard on gemini-cli's own pre-parsed shape.

2. **The 429 parser has a confirmed envelope to target.** Spec 05 §5.8 listed the 429 shape as "PLACEHOLDER, TO BE VERIFIED." This probe verifies the envelope structure (code/status/details) matches Google's standard API error shape. The specific 429 details array (QuotaFailure + RetryInfo) is a Google-wide convention documented in `google.rpc.*` protobufs and was not re-verified end-to-end against a real 429 — that waits on actual rate-limiting, either in load-testing during PR-G3 or post-merge.

3. **`.env` is a real attack surface, not hypothetical.** Probe 4 demonstrates a bogus `.env` in the user's CWD reaching the API in 0.38.2. Any user who runs csq from a project directory that happens to have a `.env` with `GEMINI_API_KEY` would be silently pwned — csq's spec-mandated `Command::env` does NOT protect against the `.env` that gets loaded into the process env at module-init time. EP2/EP3/EP6 pre-spawn scan is the correct mitigation and this probe re-justifies it.

4. **Model-router makes internal API calls BEFORE the user's turn.** The Probe 1 error stack shows `NumericalClassifierStrategy.route` → `ModelRouterService.route` firing before `GeminiClient.processTurn`. This means a single user prompt issues AT LEAST two upstream API calls: routing + generation. The csq counter in spec 05 §5.8 counts "spawns," not "API calls" (ADR-G05) — this is intentional, because the inner call count is gemini-cli-version-dependent and would make the counter noisy. The finding confirms the decision to count at the csq-cli spawn boundary, not at the underlying API boundary.

## Limits of this probe

- **429 shape is assumed, not observed.** No actual rate-limiting hit. The envelope consistency (via Probe 3's 400 error sharing the same `details` shape) is strong circumstantial evidence. A live 429 capture (natural traffic post-v2.2 launch, or a scripted quota-exhaustion test) remains a follow-up.
- **SSE streaming not probed directly.** `-o stream-json` is gemini-cli's wrapper format; the underlying `streamGenerateContent` SSE shape was not inspected. If a future csq feature needs to bypass gemini-cli (unlikely — the delegation-to-CC / delegation-to-Gemini-CLI principle in memory/`feedback_delegate_to_reference_client.md` argues against it), this gap reopens.
- **Dotenv override behaviour not empirically tested.** We confirmed `.env` is loaded when shell env is absent; we did NOT verify whether shell env beats `.env` when both are set. Design is defensive (pre-spawn scan) regardless.
- **gemini-cli 0.38.2 specifically.** Same caveat as OPEN-G01 — EP4 whitelist pinning catches future drift.

## Decision impact

- **Spec 05 §5.8 429 shape:** promote from "PLACEHOLDER, TO BE VERIFIED" to "SHAPE-CONSISTENT-WITH-GOOGLE-API-STANDARD, specific 429-only fields pending live capture." Next revision of §5.8 (not PR-G0; deferred to first real 429 in production).
- **Spec 05 §5.8.1 (added in this PR) captures the stream-json event shape by reference.** The NDJSON durability log uses csq-internal event kinds (`counter_increment`, `rate_limited`, `effective_model_observed`, `tos_guard_tripped`); gemini-cli's `init`/`message`/`result` types are inputs to the emitter, not the log format.
- **PR-G2a capture.rs design:** `-o stream-json` is the primary capture format. Parser reads line-by-line from a tokio LinesStream, matches on `type`, emits csq events. `-o json` handled as a fallback for commands that don't stream.
- **EP2/EP3/EP6 pre-spawn scan:** unchanged from plan; justification reinforced.
- **Risk analysis §4 GG3 (modelVersion location):** RESOLVED — location is gemini-cli's stream-json `init.model` field. Close GG3.

## For Discussion

1. **Wrapping gemini-cli with `-o stream-json` changes the interactive UX — users running `csq run N` on a Gemini slot see NDJSON output instead of gemini-cli's TUI. Is that acceptable for v2.2, or does PR-G2a need a user-facing reformatter (read stream-json, re-emit TUI-style)?** The latter adds ~200 LOC and a new failure mode (reformatter bugs swallow output). The former is a "beta" UX that changes once csq invests in the reformatter.

2. **The 429 envelope was verified indirectly via a 400 error sharing the same `details` shape. If a future Google API change splits 400 and 429 into different envelopes (unlikely per Google's `google.rpc` protobuf convention, but not impossible), the parser silently misses 429s. How much spec-level investment is warranted in a positive 429 capture now — a scripted exhaustion probe against a throwaway API key, or accept the risk and let the circuit-breaker catch schema drift post-launch?**

3. **If `.env` loading in 0.38.2 had NOT been confirmed — i.e. the dotenv loader had been removed or disabled in the shipped CLI — would csq's EP2/EP3/EP6 pre-spawn scan still be justified, or would it be dead-weight compensation for a fixed bug?** The answer shapes whether EP2/EP3/EP6 is a forever-invariant or a version-gated guard. (Current lean: forever-invariant, because users may run pre-0.38.2 builds via legacy npm installs.)

## Cross-references

- Spec 05 §5.8 — Gemini counter + 429 parse (placeholder shape, this probe verifies envelope consistency)
- Spec 05 §5.8.1 — CLI-durable NDJSON event log (added in this PR; consumes these event sources)
- Spec 07 §7.2.3 — per-surface Gemini layout (`.env` discovery chain citation)
- Spec 07 §7.2.3.1 — event-delivery contract (added in this PR; governs how these events reach the daemon)
- `workspaces/gemini/02-plans/01-implementation-plan.md` §PR-G2a — capture module scope
- `workspaces/gemini/01-analysis/01-research/04-risk-analysis.md` §4 GG3 — RESOLVED here
- Journal 0002 — silent-downgrade detection (load-bearing consumer of effective-model signal)
- Journal 0003 — auth precedence (same-session paired probe)
- Upstream: `google-gemini/gemini-cli#21744` (.env discovery chain, probe target)
- Memory: `feedback_delegate_to_reference_client.md` — justifies capture-via-cli-wrapper rather than re-implementing Google API client
