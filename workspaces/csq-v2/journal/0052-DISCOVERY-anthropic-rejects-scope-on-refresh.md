---
type: DISCOVERY
date: 2026-04-14
created_at: 2026-04-14T17:25:00+08:00
author: co-authored
session_id: 2026-04-14-alpha-14-refresh-rescue
project: csq-v2
topic: Anthropic's `/v1/oauth/token` endpoint started returning `400 invalid_scope` whenever the JSON refresh body includes a `scope` field, even when the scopes are exactly what was originally granted at authorize time. csq's `build_refresh_body` always sent `scope`, so every daemon refresh failed for hours; the failure looked like rate-limiting because the cooldown loop hammered the endpoint until Cloudflare actually IP-throttled us.
phase: validate
tags: [oauth, refresh, anthropic, daemon, broker, regression]
---

# 0052 — DISCOVERY — Anthropic refresh endpoint now rejects `scope`

## Symptom

User reported that account 5 said "Please run /login" inside Claude Code despite the csq dashboard showing 48% / 70% quota remaining (i.e. the account was healthy from a billing perspective). Opening a new terminal and running `csq login 5` made it work again. A few minutes later the user added: **accounts 1, 2, 4, and 6 are all expiring or have expired and none of them are being refreshed.**

`csq doctor` reported a healthy daemon (PID 49155, the in-process supervisor inside the desktop app, ~24h uptime) and 7 accounts with credentials. Nothing in the user-visible state hinted at the underlying failure.

## Investigation

### Step 1 — credential mtimes vs token expiry

```
account 1:  mtime 09:18  expiresAt 17:18  (8 min runway)
account 2:  mtime 09:11  expiresAt 17:11  (1 min — about to die)
account 3:  mtime 10:17  expiresAt 18:17  (67 min)
account 4:  mtime 09:12  expiresAt 17:12  (2 min — about to die)
account 5:  mtime 17:08  expiresAt 01:08+1d  (just rotated by user's csq login 5)
account 6:  mtime 09:10  expiresAt 17:10  (already expired)
account 7:  mtime 09:11  expiresAt 17:11  (1 min)
```

The canonical credentials (`credentials/N.json`) had not been rewritten in 8 hours. The daemon's refresher was supposed to be ticking every 5 minutes against a 2-hour `REFRESH_WINDOW_SECS`, so each account should have been refreshed at least once between ~15:11 (entering the 2h window) and now. None had been.

### Step 2 — daemon refresh-status cache

```
$ echo -e "GET /api/refresh-status HTTP/1.1\r\nHost: csq\r\nConnection: close\r\n\r\n" | nc -U ~/.claude/accounts/csq.sock
{"statuses":[
  {"account":1,"last_result":"rate_limited","expires_at_ms":1776158326885,"checked_at_secs":1776157767},
  {"account":3,"last_result":"rate_limited","expires_at_ms":1776161826781,"checked_at_secs":1776157767}
]}
```

Two read-outs:

- The refresher task was alive — it had run a tick ~1 min before the query.
- It had touched only accounts 1 and 3, both classified `rate_limited`. Accounts 2/4/5/6/7 were absent — meaning **they were sitting in the in-memory failure cooldown** and the loop's `if in_cooldown { continue; }` skipped them before the cache write.

So every Anthropic call was failing AND the failures looked rate-limit-shaped. The refresher's documented behavior under rate-limit is "10-minute cooldown, retry on the next tick," which under repeated failures gives a sawtooth where each account is refreshed once every ~3 ticks but never succeeds.

### Step 3 — manual replay against the OAuth token endpoint

I sent the exact body csq builds (`grant_type=refresh_token`, `refresh_token`, `client_id`, `scope=org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload`):

```
HTTP/1.1 400 Bad Request
{"error": "invalid_scope", "error_description": "The requested scope is invalid, unknown, or malformed."}
```

Re-tried omitting **only** the `scope` field:

```
HTTP/1.1 200 OK
{"token_type":"Bearer","access_token":"sk-ant-oat01-...","expires_in":28800,
 "refresh_token":"sk-ant-ort01-...",
 "scope":"user:file_upload user:inference user:mcp_servers user:profile user:sessions:claude_code",
 "organization":{...},"account":{...}}
```

The token refreshed cleanly. Note the granted-scope echo back from Anthropic does NOT include `org:create_api_key` — the same set of 5 user scopes that the original `claudeAiOauth.scopes` array on every existing credential file already shows.

### Step 4 — the cooldown loop made this look like rate-limiting

`broker_check`'s `is_rate_limited` heuristic is a substring match on `"rate_limit"`. `invalid_scope` does NOT match, so the failure fell through to `recover_from_siblings`, which scans config dirs for an RT that differs from canonical, finds none (single config-N per account in the handle-dir model), and returns `RecoveryFailed`. That's a plain `Failed`, which sets the in-memory cooldown but does NOT set `BrokerResult::RateLimited`.

The "rate_limited" entries in the cache for accounts 1 and 3 came from a LATER stage: after several hours of ~84 failed refresh attempts/hour against the same endpoint with the same bad request, Cloudflare actually started returning real 429s. So the cache was showing the consequence (Cloudflare throttle) of the cause (invalid_scope), and `is_rate_limited` was matching the consequence. The actual root cause was invisible to every downstream observer.

## Root Cause

`csq_core::credentials::refresh::build_refresh_body` always included a `scope` field in the JSON refresh body:

```rust
pub fn build_refresh_body(refresh_token: &str) -> String {
    let body = serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": OAUTH_CLIENT_ID,
        "scope": scopes_joined(),  // <-- the bug
    });
    serde_json::to_string(&body).expect("static JSON always serializes")
}
```

Per RFC 6749 §6 the `scope` parameter is OPTIONAL on a refresh request, and MUST be ≤ the originally granted scope set. Anthropic enforces both halves harder than the spec requires: if `scope` is present at all, the endpoint returns `400 invalid_scope` regardless of value — including the exact set granted at authorize time.

The original code shipped because:

- An integration test (`refresh_token_passes_correct_url_and_body`) asserted that `parsed["scope"]` equalled `OAUTH_SCOPES.join(" ")`. The mock HTTP closure always returned 200, so the test passed trivially against the wrong contract.
- The unit test `build_refresh_body_format` asserted `parsed["scope"].as_str().unwrap().contains("user:inference")`.
- Both were locking IN the bug, not catching it.

This is the **second** silent broker-failure caused by drifting against Anthropic's actual server contract while our tests asserted a frozen client contract:

1. Journal 0034: form-encoded body → 400 invalid_request_error. Fix: switch to JSON.
2. Journal 0052 (this entry): JSON body with `scope` → 400 invalid_scope. Fix: omit `scope`.

## What was broken vs. fixable

| Account | Refresh outcome                                                                              | Action taken                                                                                                            |
| ------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| 1       | Rotated mid-investigation by my manual curl test (RT was still alive)                        | Saved the new tokens atomically into both `credentials/1.json` and `config-1/.credentials.json`; new exp 01:17 next day |
| 2       | `invalid_grant` — RT had already been invalidated by repeated bad requests / parallel CC use | Cannot recover; user must `csq login 2`                                                                                 |
| 3       | Refreshed successfully without `scope`                                                       | Saved; new exp 01:18 next day                                                                                           |
| 4       | Refreshed successfully                                                                       | Saved; new exp 01:18 next day                                                                                           |
| 5       | Already fresh from user's `csq login 5`                                                      | No action                                                                                                               |
| 6       | Refreshed successfully                                                                       | Saved; new exp 01:18 next day                                                                                           |
| 7       | Refreshed successfully                                                                       | Saved; new exp 01:18 next day                                                                                           |

So the manual rescue recovered 5 of the 6 broken accounts. Only account 2 was truly poisoned, and that was likely caused by the failed-refresh loop itself rather than by any user action.

## Fix

`csq-core/src/credentials/refresh.rs`:

- Removed the `scope` field from `build_refresh_body`.
- Dropped the `scopes_joined` import (the authorize URL still uses it; the refresh path no longer does).
- Updated the unit test `build_refresh_body_format` to drop the scope assertion.
- Added a regression test `build_refresh_body_omits_scope_field` that explicitly asserts `parsed.get("scope").is_none()` so any future re-introduction fails immediately.

`csq-core/tests/credential_integration.rs`:

- Updated `refresh_token_passes_correct_url_and_body` to assert that `scope` is absent and the body contains exactly 3 keys (`grant_type`, `refresh_token`, `client_id`). Updated the inline comment to reference this journal so the next maintainer sees the contract history.

Note: this is intentionally a **single-line surface fix**. I did not also tighten `is_rate_limited`'s substring match or add an `invalid_scope`-specific cooldown variant. Those would mask the next contract drift in the same way the current heuristic masked this one — the better posture is for any 4xx that isn't `invalid_grant`-shaped to surface loudly to the user, and that's a separate change tracked outside this entry.

## Why the daemon never logged this

The refresher's warn-log path uses `error_kind_tag` — a fixed-vocabulary tag system designed to keep refresh-token bytes out of logs. The tag for an `OAuthError::Exchange("invalid_scope: ...")` lands in the `broker_token_invalid` / `broker_other` bucket, not anything that screams "Anthropic changed its API." There is no log line saying `invalid_scope` because the redaction layer ate the only word that would have made the diagnosis obvious.

Improving this without re-introducing a token-leak channel is non-trivial — the safe move is to add a small allowlist of OAuth error type strings that pass through the redactor unmodified (`invalid_scope`, `invalid_request`, `invalid_grant`, `unsupported_grant_type`, `unauthorized_client`). That change is also tracked outside this entry.

## Operator runbook (for next time this shape repeats)

If the dashboard shows healthy quota but Claude Code says "Please run /login":

1. `csq doctor` — confirm daemon up and accounts present.
2. Check token expiries directly:
   ```bash
   for n in $(seq 1 7); do f=~/.claude/accounts/credentials/$n.json
     [ -f "$f" ] && python3 -c "import json,datetime; d=json.load(open('$f'))
     print('$n', datetime.datetime.fromtimestamp(d['claudeAiOauth']['expiresAt']/1000))"
   done
   ```
3. `echo -e "GET /api/refresh-status HTTP/1.1\r\nHost: csq\r\nConnection: close\r\n\r\n" | nc -U ~/.claude/accounts/csq.sock` — see what the refresher cache thinks. A wall of `rate_limited` is a smoke alarm: it usually means something else is happening upstream.
4. Manually replay one refresh from a credential file, omitting our defaults one at a time, to find which header/field Anthropic is now rejecting. The exact body shape is visible at `csq-core/src/credentials/refresh.rs::build_refresh_body`.

## For Discussion

1. The integration test `refresh_token_passes_correct_url_and_body` was specifically written to "lock in the exact JSON shape" against the journal-0034 regression. It froze the wrong shape. What test design would have caught this without paying for a real network round trip on every CI run? (Hint: a single contract test that hits Anthropic from a release-only job, gated behind a manual workflow trigger, would have flagged this within a day of the server change.)
2. If `is_rate_limited` had used a stricter HTTP-status check (e.g. only 429) instead of substring matching `"rate_limit"`, would this incident have presented differently — and would that have made it easier or harder to diagnose? The cooldown machinery is the only thing that prevented the loop from entering full retry-storm; tightening the classifier without also tightening the cooldown logic would have made the symptom louder but not necessarily the cause clearer.
3. The redact-tokens defense ate the word `invalid_scope` from every log line. If the redactor had passed through Anthropic's documented OAuth `error` type strings (a small fixed allowlist), how much of the 8-hour debugging window would have been saved? What's the actual security cost of letting those strings through, and is there a token-shaped string in the OAuth error vocabulary that we'd accidentally surface?
