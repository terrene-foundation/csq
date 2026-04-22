---
type: DECISION
date: 2026-04-23
created_at: 2026-04-23T02:30:00Z
author: co-authored
session_id: 2026-04-23-codex-pr-c5
session_turn: 12
project: codex
topic: PR-C5 — daemon usage_poller Codex module (wham/usage parser, per-account circuit breaker 5→15m→80m, PII-scrubbed raw+drift captures at 0o600, committed PII-redacted golden fixture, surface dispatch into run_loop).
phase: implement
tags:
  [
    codex,
    pr-c5,
    usage-poller,
    wham-usage,
    circuit-breaker,
    pii-scrub,
    schema-drift,
    surface-dispatch,
  ]
---

# Decision — PR-C5: daemon Codex usage poller + circuit breaker + PII-scrubbed captures

## Context

Journal 0010 captured the live `GET chatgpt.com/backend-api/wham/usage` schema against a real plus-plan account, superseding the GAP state in journal 0008. Spec 05 §5.7 flipped PROPOSED → VERIFIED. PR-C4 landed the refresh side of the Codex daemon story — broker_codex_check, surface-dispatched refresher tick, startup reconciler, and the Windows named-pipe merge gate. PR-C5 closes the read side: poll wham/usage, parse the verified schema, map to csq's `AccountQuota`, and tolerate upstream drift without silently corrupting quota.json.

Spec contracts driving the design:

- Spec 05 §5.7 — verified wham/usage response shape. `used_percent` is 0–100 (not 0–1); `reset_at` is absolute Unix epoch; `user_id`/`account_id`/`email` are PII at the top level.
- Spec 07 §7.4.1 — `AccountQuota` v2 surface + kind fields; `extras: Option<Value>` escape hatch for plan_type.
- Spec 07 §7.7.4 OPEN-C04 — Node transport required (Cloudflare JA3/JA4 fingerprints reqwest responses). PR-C0.5 already wired `http::get_bearer_node`; PR-C5 reuses the same closure.
- Plan §PR-C5 — circuit breaker 5-fail → 15min → 80min cap; raw + drift capture at 0o600; `.gitignore` for raw paths; golden fixture with committed PII-absence assertion; "ships PROVISIONAL if journal 0008 not captured" — no longer applies because 0010 captured the schema; ships STABLE.

## Decision

Seven surgical pieces, one PR:

### 1. `csq-core/src/daemon/usage_poller/codex.rs` (NEW)

Sibling of `anthropic.rs` with five responsibilities: discovery (`discover_codex`) + credential load → per-account gate → HTTP poll via injected `HttpGetFn` closure → parse via existing `http::codex::parse_wham_response` (made `pub(crate)` in this PR) → write-path dispatch on outcome:

- **Success** (200 + schema-match): map `primary_window` → `AccountQuota.five_hour`, `secondary_window` → `seven_day`, `plan_type`/`allowed`/`limit_reached` → `extras`. Surface = `"codex"`, kind = `"utilization"`. Write raw body to `accounts/codex-wham-raw.json` (0o600, PII-redacted) for operator diagnosis.
- **Drift** (200 + parse fail, i.e. upstream schema changed): degrade to `kind = "unknown"` with empty windows; write raw body to `accounts/codex-wham-drift.json` (0o600, PII-redacted) so the next session can diff what changed.
- **Transport / 401 / 429 / non-200**: record failure on the per-account circuit breaker; emit a fixed-vocabulary `error_kind` tag; do NOT touch quota.json for this account.

Every new `{e}` formatter wraps the source error in `error::redact_tokens` before interpolation (security.md MUST Rule 8 / journal 0010 discipline).

### 2. `BreakerState` + `BreakerMap` — per-account circuit breaker

Independent of the Anthropic poller's 10-minute cooldown (`FAILURE_COOLDOWN` + `set_cooldown_with_backoff`) so the two surfaces cannot cross-contaminate. The breaker is DIAGNOSTIC, not rate-limiting:

- `CODEX_BREAKER_FAIL_THRESHOLD = 5` consecutive fails trips the breaker.
- `CODEX_BREAKER_BASE_COOLDOWN = 15 min` on first trip.
- Doubles on each subsequent consecutive failure (5→15m, 6→30m, 7→60m), capped at `CODEX_BREAKER_MAX_COOLDOWN = 80 min`.
- Any successful poll clears the state (counter + cooldown_until).

Six unit tests: default-closed, stays-closed-below-threshold, trips-at-threshold, doubling behaviour, cap behaviour, success-clears-state. `u32` fails counter is saturating; `1u64.checked_shl(over.min(16))` prevents integer overflow at very large `fails` counts (extreme-value test in `breaker_caps_at_max_cooldown` runs 100 consecutive failures without panicking).

### 3. PII-scrubbed golden fixture + committed assertion

`csq-core/tests/fixtures/codex/wham-usage-golden.json` — the journal 0010 response shape with PII values replaced by fixed sentinels (`REDACTED-user-id`, `REDACTED-account-id`, `REDACTED@example.invalid`). Two committed tests enforce this stays scrubbed:

- `golden_fixture_has_no_real_pii` — iterates every line, rejects any `acct_` prefix, rejects any `@`-bearing string except the `REDACTED@example.invalid` sentinel. Catches operator mistakes where a real raw capture is accidentally committed instead of the scrubbed version.
- `golden_fixture_parses_into_wham_snapshot` — asserts the fixture parses cleanly through the production `parse_wham_response`, preventing drift between the fixture and the pinned schema.

`csq-core/tests/fixtures/codex/scrub.sh` — `jq`-based PII scrubber for future live re-captures. Replaces `user_id`, `account_id`, `email`, `sub` (if present) with fixed sentinels. Chosen over embedding the scrub logic in Rust because operators running ad-hoc re-captures need a single pipe-friendly command.

### 4. PII redactor (`redact_pii_json`)

Two-pass redactor: (a) recursive JSON walk replacing `user_id`/`account_id`/`email`/`sub` at ANY nesting depth with the fixed sentinels; (b) token-pattern pass via existing `error::redact_tokens` as defense-in-depth against nested fields carrying JWTs or OAuth tokens. Falls back to token-only redaction when the body is not valid JSON — drift captures are ALLOWED to be non-JSON (that's partly what "drift" means), but the token redactor still fires. Four unit tests: top-level, nested, sub claim, non-JSON fallback.

### 5. Raw + drift capture write path

`accounts/codex-wham-raw.json` on success; `accounts/codex-wham-drift.json` on MalformedResponse {status: 200}. Both paths use `unique_tmp_path` + `secure_file` (0o600) + `atomic_replace` with cleanup-on-error at every step per security.md MUST Rule 5a (partial-failure cleanup — tmp file holding PII must not be left on disk when any subsequent step fails). `write_raw_capture_redacts_pii_and_sets_permissions` asserts both redaction and 0o600 on Unix.

### 6. `usage_poller/mod.rs` — surface dispatch

Three changes: add `pub mod codex;`, add `codex_breakers: codex::BreakerMap` to `RunLoopConfig` (initialized in `spawn_with_config`), call `codex::tick(&cfg.base_dir, &cfg.http_get, &cfg.codex_breakers)` immediately after `anthropic::tick` in the heartbeat body. The `http_get` closure is shared between Anthropic and Codex — both production wirings (`csq-cli/src/commands/daemon.rs`, `csq-desktop/src-tauri/src/daemon_supervisor.rs`) already use `http::get_bearer_node`, which is the Node subprocess transport Codex requires per OPEN-C04 and which is also safe for Anthropic. No new parameter on `spawn` / `spawn_usage_poller` — production call sites are untouched.

### 7. `.gitignore` — capture paths

`accounts/codex-wham-raw.json` and `accounts/codex-wham-drift.json` added. Even though both files are PII-redacted on write, the diffs would surface structural drift (e.g. "today's capture added a `team_plan_id` field") across sessions that belongs in operator notes, not commit history.

## Alternatives considered

**A. Introduce a sibling `HttpGetFnCodex` type alias parallel to refresher's `HttpPostFnCodex`.** Rejected. The refresher needs a Date-aware Node transport (`post_json_node_with_date`) that the Anthropic refresher branch does not use, so the sibling type carried real semantic weight. In the usage poller both surfaces use byte-identical `get_bearer_node`; introducing a sibling type alias with the same signature would be noise. If a future surface needs a distinct GET transport, the split becomes justified; today it is not.

**B. Ship PROVISIONAL per plan §PR-C5 "Ships PROVISIONAL if journal 0008 not captured".** Rejected. Journal 0010 captured the schema against a real plus-plan account mid-PR-C00 session; §5.7 flipped VERIFIED. The PROVISIONAL tag only exists for the pre-capture case. Shipping STABLE is aligned with plan H11 Path A.

**C. Use `anthropic.rs`'s existing cooldown/backoff pattern (`set_cooldown_with_backoff`, `FAILURE_COOLDOWN = 600s`).** Rejected. The existing pattern uses a per-call 10-minute cooldown that fires on any failure, single-tier. PR-C5's breaker wants two distinct signals: (a) "short transient — retry next tick" (below threshold, no cooldown, fails counter increments), and (b) "sustained failure — user must re-login" (at/above threshold, exponential cooldown). Shoehorning tier (a) into the existing system would either require re-shaping `FAILURE_COOLDOWN` globally (breaks Anthropic) or adding per-surface cooldown constants (more plumbing than a dedicated state struct).

**D. Rely on `fetch_wham_with_http` from `http::codex`.** Rejected for the poller-specific path. `fetch_wham_with_http` is `FnOnce`-parameterized for test ergonomics and returns only the typed `Result<WhamSnapshot, CodexHttpError>` — the raw body is discarded. The poller needs the raw bytes for the raw + drift capture files. Exposing `parse_wham_response` as `pub(crate)` and calling it alongside the retained body bytes is minimal and keeps the existing test surface intact.

**E. Hard-code the PII redaction set rather than recursing.** Rejected. The journal 0010 capture showed PII only at the top level, but future OpenAI response shapes could embed it nested (e.g. `code_review_rate_limit.account_id`). Recursive replacement is ~15 more lines of Rust and costs nothing measurable at runtime.

**F. Emit raw-body captures only on drift, not on success.** Rejected on operator-diagnosis grounds. When a user reports "my Codex quota looks wrong", the most useful artifact is the last raw body the daemon successfully parsed. Drift-only would leave the operator blind during the "it parsed but the numbers look wrong" failure mode. Both files are 0o600 and git-ignored, so the surface-area cost is negligible.

**G. Write `plan_type` to a reserved `AccountQuota` field rather than `extras`.** Rejected. Spec 07 §7.4.1 already carves `extras: Option<Value>` as the escape hatch for surface-specific data. Adding `plan_type` as a reserved field would force a schema bump (PR-C6) we don't need yet, and would commit csq to a plan_type field shape we've only observed for one value (`"plus"`). `extras.plan_type` is round-trip-preserved and leaves the option open.

## Consequences

- `quota.json` now carries live 5h + 7d Codex utilization after each 5-minute poll cycle. Dashboard Accounts tab shows real percentages for Codex slots without UI changes — existing `five_hour_pct()` / `seven_day_pct()` accessors work unchanged for any surface.
- Schema-drift failure mode is now observable. If OpenAI ships a new wham/usage field that breaks the parser, quota for that account degrades to `kind: "unknown"` (`five_hour_pct()` returns 0.0) and `accounts/codex-wham-drift.json` holds the redacted body. csq keeps polling — the breaker increments fails, trips at 5, backs off — giving the operator a bounded diagnostic window.
- Repeated poll failures cap at 80-minute cooldown rather than hammering upstream. Two-codex-slots-down scenario (e.g. both user accounts logged out) burns ~5 polls \* 30s timeout = 2.5 minutes of wall time in the worst case before breakers fire; subsequent ticks skip those slots cheaply.
- Raw-body capture provides an audit trail for the "my quota looks wrong" bug class. Operators can `cat accounts/codex-wham-raw.json | jq .` and see the last PII-redacted success body without waiting for the next tick. Drift capture provides the same for schema-drift events.
- Tests: csq-core 851 → 871 (+20 new in `usage_poller::codex`). Existing 851 remain green (see Oversight).
- `http::codex::parse_wham_response` is now `pub(crate)`. This is a visibility widening, not a public API change.
- No change to `csq-cli` / `csq-desktop` call sites — `spawn_usage_poller` signature unchanged.

## For Discussion

1. **The circuit breaker's 15-min base + 80-min cap was chosen from the plan without a measured calibration against actual OpenAI 429 cadence or the distribution of transient vs sustained failures in `http::codex` probes during the v2.1 bring-up. If the observed failure distribution in post-launch telemetry shows transient flakes cluster below 5 failures but real outages exceed 80 minutes, should the cap float upward (e.g. 240 min) to reduce reconnection spam during a real outage, or hold at 80 min and rely on the operator to notice and run `codex login`?** (Lean: hold at 80 min. The breaker exists to bound wasted cycles, not to prevent eventual recovery; 80 min is short enough that an operator who returns after lunch sees a stale quota but a daemon that is still alive and retrying, which is better than a daemon that appears frozen.)

2. **We reused the shared `HttpGetFn` closure across Anthropic and Codex rather than introducing a sibling `HttpGetFnCodex` alias. If a future v2.2 surface (say, a hypothetical Anthropic-direct endpoint that CANNOT use the Node bridge) needs a distinct transport for Anthropic only, does today's shared-closure design block that cleanly — i.e. is the refactor "add a second parameter and thread it through" or does it ripple into `anthropic.rs`'s test fixtures and expected-mock harnesses?** (Lean: clean refactor. `HttpGetFn` is already `Arc<dyn Fn>`; adding a second parameter is mechanical. The Codex-only design choice in this PR does not close any doors.)

3. **The raw-body capture writes on every successful poll, overwriting the previous capture. If OpenAI changes the wham/usage shape during a week when no operator runs `codex login` or inspects logs, the capture will still show the NEW shape on the next poll — but the drift-capture path only fires when the parser rejects the body. Is there a case for an additional "shape-diff since last capture" trigger that also captures the raw body when any new top-level key appears even if the parser succeeds (with the existing 4 PII keys continuing to redact), or is that feature creep into observability work that belongs in a later PR?** (Lean: defer. Shape-diff requires maintaining a "last seen schema" on disk and a cheap diff algorithm; both are non-trivial for ~1 future field added per year. The drift-capture trigger covers the case where the new field breaks parsing; the success-capture covers the case where the operator notices "these numbers look wrong" and wants to read the raw. The un-covered middle — "parser accepts new fields silently but operator never looks" — is a monitoring problem, not a poller problem.)

## Cross-references

- `workspaces/codex/journal/0010-DISCOVERY-wham-usage-live-schema-captured.md` — verified schema (supersedes 0008 GAP); the parser implements against this capture.
- `workspaces/codex/journal/0016-DECISION-pr-c4-daemon-codex-refresher-startup-reconciler-windows-h2.md` — refresh side; PR-C5 reads the canonical `credentials/codex-<N>.json` that PR-C4 maintains.
- `workspaces/codex/journal/0007-DECISION-codex-transport-via-node-subprocess.md` — OPEN-C04 transport; the poller reuses `http::get_bearer_node`.
- `workspaces/codex/journal/0009-DISCOVERY-codex-oauth-error-body-no-echo.md` — error-body echo defense-in-depth; every new `{e}` formatter on the Codex branch wraps in `redact_tokens`.
- `workspaces/codex/02-plans/01-implementation-plan.md` §PR-C5 — closes this plan item.
- `specs/05-quota-polling-contracts.md` §5.7 — VERIFIED schema.
- `specs/07-provider-surface-dispatch.md` §7.4.1 — surface + kind + extras fields on AccountQuota.
- `csq-core/src/http/codex.rs::{parse_wham_response, WhamSnapshot, WHAM_USAGE_URL}` — the parser + types + URL PR-C5 consumes; `parse_wham_response` visibility widened to `pub(crate)`.
- `csq-core/src/daemon/usage_poller/codex.rs` — NEW module.
- `csq-core/src/daemon/usage_poller/mod.rs` — dispatch wiring.
- `csq-core/tests/fixtures/codex/{wham-usage-golden.json, scrub.sh}` — committed fixture + scrub tool.
- `.gitignore` — new entries for raw + drift capture paths.
- `.claude/rules/security.md` MUST Rule 4 (atomic writes), Rule 5 (0o600 permissions), Rule 5a (tmp-file cleanup on partial failure), Rule 8 (no `{e}` near OAuth code without `redact_tokens`) — all honored end-to-end.
- `.claude/rules/zero-tolerance.md` Rule 5 (no residual findings) — no deferred items from this PR.
