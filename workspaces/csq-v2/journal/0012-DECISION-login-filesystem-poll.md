---
type: DECISION
date: 2026-04-10
created_at: 2026-04-10T16:00:00Z
author: co-authored
session_id: m87c-cli-login-daemon-delegation
session_turn: 15
project: csq-v2
topic: CLI `csq login` polls canonical credential file, not /api/accounts
phase: implement
tags: [m8, m87c, cli, daemon, login, polling, discovery-cache]
---

# DECISION: `csq login` polls the filesystem, not `/api/accounts`

## Context

M8.7c rewrote `csq-cli/src/commands/login.rs` to delegate OAuth
logins to the running daemon:

1. `detect_daemon(base_dir)` → fail to direct shell-out if not healthy.
2. `GET /api/login/{N}` over the Unix socket → get Anthropic
   authorize URL from the daemon's `start_login`.
3. Open the URL in the default browser.
4. **Wait for the daemon's `/oauth/callback` handler to write the
   credential file.**
5. Run finalization (profile email, `.csq-account` marker,
   `broker_failed` clear).

Step 4 requires the CLI to notice when the daemon has finished the
exchange. The session notes offered two options:

> poll `/api/accounts` until the account appears (or add a new
> `GET /api/login-status/{N}` endpoint)

A third option — not in the session notes — surfaced during
implementation: **poll the canonical credential file directly on
the CLI's own filesystem**.

## Decision

Poll `{base_dir}/credentials/{N}.json` directly from the CLI using
`std::path::Path::exists` + `credentials::load` for validity.

- Poll interval: 750ms.
- Deadline: 5 minutes, matching the daemon's
  `OAuthStateStore::STATE_TTL`.
- The daemon's OAuth callback handler already writes this exact
  path via `credentials::save_canonical` in the `write_credentials`
  step of `oauth_callback::callback_handler` — the CLI is watching
  the same file the daemon writes.

## Alternatives considered

### Option A — Poll `/api/accounts` over the Unix socket

Would reuse the existing M8.5 read route. Rejected because:

1. **Discovery cache TTL (5s) becomes a floor on latency.** The
   `/api/accounts` handler caches the last filesystem scan for 5
   seconds to prevent statusline polling from DoS'ing the daemon
   (journal 0008-DECISION-cache-ownership-daemon-level.md,
   security review MED #1). A login that completes at t=0.5s
   would not be visible via `/api/accounts` until t=5.0s at worst,
   adding a jarring pause between "browser says success" and
   "CLI says success".
2. **Cache invalidation would require plumbing.** The OAuth
   callback handler would need to hold a reference to the
   discovery cache and call `.clear()` on success. The session
   notes list this as a nice-to-have follow-up; it's not wired
   yet. Polling the filesystem sidesteps the dependency entirely.
3. **HTTP overhead per poll.** Every poll is a round trip through
   the daemon's axum router — cheap (sub-millisecond) but
   unnecessary compared to a single `metadata` syscall.

### Option B — Add `GET /api/login-status/{N}`

A new endpoint that bypasses the discovery cache and returns
`pending | complete | expired` for a specific account. Rejected
because:

1. **More attack surface for zero benefit.** The information the
   CLI needs is already publicly observable via the credentials
   directory it owns.
2. **New routes require security review.** Every addition to the
   daemon router goes through a security reviewer pass per
   project policy. Avoiding a new route avoids the review burden
   on a purely cosmetic improvement.
3. **The daemon does not know more than the filesystem does.**
   The callback handler's only persistent side effect on success
   is `save_canonical` — there is no extra in-memory state the
   CLI could query that isn't already on disk.

### Option C — inotify / FSEvents file-watch instead of polling

Rejected because:

1. **New cross-platform dependency.** Would require `notify` or
   platform-specific crates, breaking the current "small, known
   dep surface" posture.
2. **750ms polling is imperceptible for a human-in-the-loop
   flow.** The user is reading a consent page in their browser,
   not micro-benchmarking the CLI.
3. **Adds failure modes.** Inotify can drop events under load;
   a polling loop is trivially correct.

## Consequences

### Positive

- **Zero additional daemon endpoints, zero additional cache
  plumbing.** The CLI uses only the existing `/api/login/{N}`
  route plus the filesystem it already owns.
- **Sub-second latency between daemon-write and CLI-notice**
  (bounded by the 750ms poll interval), vs up to 5s via
  `/api/accounts`.
- **Works even if the daemon's HTTP layer becomes temporarily
  unresponsive** after the exchange — the CLI only needed the
  daemon to run the PKCE exchange, not to serve the success signal.
- **No coupling to the daemon's router shape.** If the daemon's
  API surface is refactored later, this path keeps working.

### Negative

- **CLI now has a second way to detect a completed login** (the
  first being the direct path's "credentials captured from
  keychain/file" check). A future author reading `login.rs` sees
  two success detection strategies. Mitigation: both are
  documented in the file header, and the daemon path's comment
  explicitly references `canonical_path`.
- **Polling the filesystem cannot observe the "user denied
  consent" case directly** — the daemon's callback handler
  writes the failure HTML to the browser but does not signal the
  CLI. The CLI will hit its 5-minute deadline instead. This is
  acceptable because the state store's own 5-minute TTL is the
  same budget, and the user already has visual feedback in the
  browser. If we ever need faster failure propagation, the fix is
  to write a `{base_dir}/login-error-{N}.json` sentinel from the
  callback's failure branches and have the CLI watch for either
  the success file or the sentinel.
- **Polls the `credentials/` directory even if the user has
  cancelled the CLI with Ctrl-C** — actually no, Ctrl-C kills
  the thread. Not a concern.

## Implementation notes

- The daemon path runs only on Unix (`#[cfg(unix)]`). Windows
  CLI users will hit the direct shell-out fallback until M8.3
  (Windows named-pipe IPC) lands.
- `DAEMON_WAIT_CAP = 300s` is defined in `login.rs` and
  intentionally matches `crate::oauth::STATE_TTL` as a documented
  coincidence — if the TTL is ever lengthened, the CLI cap
  should follow. A test could pin this relationship, but the
  cap lives in the CLI crate and the TTL in the core crate,
  making the assertion awkward.
- Finalization (profile update, marker write, broker-failed
  clear) is shared between both paths via a single `finalize()`
  function. This keeps the daemon and direct paths
  behaviour-identical post-login.

## For Discussion

1. **Evidence check** — the security review for M8.5 MED #1
   justified the 5-second discovery cache TTL as the minimum to
   prevent statusline DoS. If a future session shortens the TTL
   to, say, 500ms, does Option A become attractive enough to
   collapse the two code paths?
2. **Counterfactual** — if the daemon's OAuth callback handler
   had NOT been willing to call `save_canonical` and had instead
   kept credentials in memory until a separate API call
   retrieved them, which option would we have chosen? Would
   "filesystem polling" still have been available, or would we
   have been forced to add the new endpoint?
3. **Invert the framing** — Option B was rejected partly because
   of the security review burden on new routes. If the project
   had zero security review overhead, would the explicit
   `login-status` endpoint be the better long-term design
   because it makes the state machine legible, even if polling
   achieves the same outcome?
