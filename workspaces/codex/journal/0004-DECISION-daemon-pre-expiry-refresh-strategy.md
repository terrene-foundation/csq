---
type: DECISION
date: 2026-04-22
created_at: 2026-04-22T00:00:00Z
author: co-authored
session_id: 2026-04-22-codex-open-c01-resolved
session_turn: 20
project: codex
topic: Resolve OPEN-C01 via daemon pre-expiry scheduled refresh; keep INV-P01/P02 with re-framing
phase: analyze
tags: [oauth, refresh, invariant, codex, open-c01, resolved]
---

# Decision — Daemon pre-expiry refresh strategy for Codex

## Context

Journal 0003 flagged OPEN-C01 (spec 07 §7.7.1): whether `cli_auth_credentials_store = "file"` disables codex's in-process OAuth refresh. Direct source read of openai/codex main branch (shallow clone, 2026-04-22) delivered a HIGH-confidence answer: **NO — the store-mode flag only selects a write destination; refresh behavior is unconditional.**

Supporting citations from the source read:

- `codex-rs/login/src/auth/storage.rs:319-332` — the `cli_auth_credentials_store` enum only picks a backend (`FileAuthStorage` | `KeyringAuthStorage` | `AutoAuthStorage` | `EphemeralAuthStorage`). No refresh logic flows through this enum.
- `codex-rs/login/src/auth/manager.rs:1376-1389` — `AuthManager::auth()` is called on every HTTP call path (`core/src/client.rs:692`, `session/turn.rs:1237`, etc.) and unconditionally invokes `self.refresh_token()` if `is_stale_for_proactive_refresh(&auth)` returns true.
- `codex-rs/login/src/auth/manager.rs:1863-1883` — `is_stale_for_proactive_refresh` returns true when the access-token JWT's `exp` claim is `<= Utc::now()` OR when `auth_dot_json.last_refresh` is more than 8 days old. **There is no pre-expiry leeway window; codex refreshes ON expiry, not before.**
- `codex-rs/login/src/auth/manager.rs:1745-1750` — in-process refresh is serialized by a single `refresh_lock` (scoped to one `AuthManager`), so concurrent calls within ONE codex process are safe. Sibling codex processes sharing a symlink to the same `auth.json` have no cross-process coordination — exactly the openai/codex#10332 failure mode.
- Grep of `codex-rs/` for `DISABLE_REFRESH|READONLY|NO_REFRESH|skip_refresh`: zero hits. No escape-hatch env var exists.

## Decision

Keep INV-P01 (daemon sole refresher) and INV-P02 (daemon hard prerequisite for Codex slots), but re-frame both to acknowledge codex's on-expiry in-process refresh:

**INV-P01 (re-framed):** The daemon is the _scheduled pre-expiry_ refresher for Codex tokens. Daemon refresh MUST complete at least 2 hours before JWT expiry (matching the Anthropic window in spec 04 INV-06). Codex's in-process refresh is a fallback that the daemon prevents from ever firing by keeping the token fresh.

**INV-P02 (unchanged in posture, refined in rationale):** `csq run <codex-slot>` refuses to spawn if the daemon is not running. Rationale: without the daemon refreshing pre-expiry, codex will eventually hit its on-expiry threshold and refresh in-process, reproducing the cross-process race.

**Contingency (option 2 from the verification report):** if codex's refresh threshold ever tightens (e.g., from on-expiry to pre-expiry), making it hard for the daemon to consistently beat it, csq can interpose via `CODEX_REFRESH_TOKEN_URL_OVERRIDE` (cited at `codex-rs/login/src/auth/manager.rs:99`) — point codex at a daemon-local HTTP endpoint that serializes refreshes. Full protection; medium implementation cost. Captured as a follow-up track, not shipped in PR1.

**Upstream track:** file a feature request for `CODEX_SKIP_INPROCESS_REFRESH=1` (or equivalent). Long lead time; does not gate our PR1.

## Alternatives considered

1. **Ship daemon-only with no pre-expiry margin** — rejected. If daemon refresh happens AT expiry (same threshold as codex), the race is not eliminated; it's just moved.
2. **Interpose via CODEX_REFRESH_TOKEN_URL_OVERRIDE in PR1** — rejected for PR1 scope. Medium cost (implement OAuth token-grant surface in the daemon, proxy to OpenAI), and unnecessary if option 1 works. Keep as contingency.
3. **Upstream patch** — correct long-term move, but lead time is measured in months. Filed as a separate track.
4. **Abandon Codex integration** — not considered; the mitigation is implementable today.

## Consequences

- **Spec 07 INV-P01 is re-framed** to explicitly call out the scheduled-pre-expiry model. Updated in spec 07 v1.0.2.
- **Spec 07 §7.7.1 OPEN-C01 is marked RESOLVED** with citation block pointing to this journal entry.
- **Spec 04 (daemon architecture) INV-06** already requires 2h-before-expiry refresh for Anthropic; Codex reuses the same refresher subsystem with the same window. Implementation cost for this invariant: zero beyond the surface-dispatch already planned for PR3.
- **Clock-skew risk (F13 in 04-risk-analysis.md):** becomes load-bearing. If the user's clock drifts > 2h ahead of OpenAI's, the daemon will miss its refresh window and codex's in-process refresh will fire. Mitigation: daemon emits `clock_skew_detected` warning when local time differs from HTTP Date header by > 5 min.
- **Integration test (MUST exist before PR1 merges):** spawn two codex processes against a test account, simulate a daemon refresh, assert neither codex process's in-process refresh path is entered. Run under `strace` or similar to confirm no extra refresh POSTs.
- **Observability:** daemon logs `codex_prerefresh_scheduled { slot, expires_at, refresh_at }` on every schedule; `codex_prerefresh_completed` or `codex_prerefresh_failed` on outcome. If `codex_inprocess_refresh_suspected` ever fires (detected via auth.json last_refresh delta not matching daemon's write log), it's a P0 alert.

## For Discussion

1. The 2-hour safety margin matches Anthropic. Is 2 hours correct for Codex, or should the margin be larger given codex's on-expiry trigger? A wider margin (4+ hours) reduces clock-skew risk at the cost of more refresh requests. The Anthropic case is governed by ~5-hour token lifetimes; what is Codex's access-token lifetime from the source read (check `last_refresh` cadence)?
2. If the `CODEX_REFRESH_TOKEN_URL_OVERRIDE` contingency becomes necessary, the daemon gains a local HTTP listener on the refresh path. That's a new attack surface (covered in spec 04 security layers) but also a new failure domain. Is this cost warranted for the tail risk, or is filing the upstream patch enough?
3. The clock-skew mitigation logs a warning but does not fail the spawn. Should `csq run <codex-slot>` hard-refuse if clock skew is > 5 min, similar to how INV-P02 refuses if daemon is down? Trade-off: false positives on NTP-less machines (containers) vs. silent corruption on clock-skewed hosts.

## References

- spec 07 §7.7.1 OPEN-C01 (resolved)
- spec 07 INV-P01, INV-P02 (re-framed)
- spec 04 INV-06 (Anthropic 2h-before-expiry precedent)
- journal 0003 (the original gap)
- openai/codex source read report (this session, 2026-04-22)
- openai/codex#10332 (the race being mitigated)
