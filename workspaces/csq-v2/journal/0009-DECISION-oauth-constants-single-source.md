---
name: OAuth constants single source of truth
description: Why csq-core/src/oauth/constants.rs owns every Anthropic OAuth value and how this resolves finding L1 from v1.x security analysis
type: DECISION
date: 2026-04-10
created_at: 2026-04-10T00:00:00Z
author: co-authored
session_id: m87a
session_turn: 1
project: csq-v2
topic: OAuth PKCE module bootstrap (M8.7a)
phase: implement
tags: [oauth, security, constants, v1-parity, m8.7, finding-L1]
---

# OAuth Constants: Single Source of Truth

## Context

v1.x (Python) defined the Anthropic OAuth `CLIENT_ID`, `SCOPES`, and `TOKEN_URL` independently in three files:

1. `rotation-engine.py` (token refresh)
2. `dashboard/refresher.py` (background refresher)
3. `dashboard/oauth.py` (PKCE login flow)

The v1.x security analysis flagged this as **finding L1** — if Anthropic ever rotates the client_id or changes the token URL, three places must be edited in lockstep, and silent drift between them is unrecoverable. The analysis explicitly called for a single shared constant in the Rust rewrite.

v2.0's M8.4 (`credentials::refresh`) already defined `TOKEN_ENDPOINT` as one constant. When M8.7a (OAuth PKCE login) added the authorize URL, client_id, scopes, and default redirect port, we had the choice to:

1. **Spread them around** — put client_id / authorize URL / scopes next to the code that uses them.
2. **Consolidate them** — one module, one file, every OAuth constant in one place.

## Decision

Create `csq-core/src/oauth/constants.rs` as the **single source of truth** for every Anthropic OAuth value:

- `OAUTH_CLIENT_ID` (9d1c250a-e61b-44d9-88ed-5944d1962f5e)
- `OAUTH_SCOPES` (as `&[&str]`, not a pre-joined string)
- `OAUTH_AUTHORIZE_URL`
- `OAUTH_TOKEN_URL` — **re-exported from** `credentials::refresh::TOKEN_ENDPOINT` so there is still only one Rust constant backing it. A compile-time test asserts the two symbols refer to the same value.
- `DEFAULT_REDIRECT_PORT` (8420)
- `redirect_uri(port) -> String` — the builder, locked to `127.0.0.1` so there is no way to bind to `0.0.0.0` by accident (security finding S12)
- `scopes_joined() -> String` — computed from `OAUTH_SCOPES` on demand for the authorize URL's `scope=` param

Every other module in `csq-core/src/oauth/` imports from `constants.rs`. The module docstring explicitly lists the stability contract: if Anthropic rotates any value, this one file is the only place that needs to change.

## Why

**Rotation safety.** A future Anthropic client_id rotation is not hypothetical — OAuth apps do get re-registered. Centralization collapses a 3-file edit to a 1-file edit and removes the silent-drift failure mode.

**Test coherence.** Tests that need to assert "the authorize URL contains the right client_id" read the constant directly. If the constant changes, the test updates automatically. Without centralization, tests would hardcode a second copy of the value and go stale independently.

**Import discipline.** There is a single import path (`crate::oauth::constants::*`) that reviewers can grep for. Any module that references OAuth values via a string literal stands out in review as a probable bug.

**Compile-time pinning across modules.** The `token_url_matches_refresh_endpoint` test in `constants.rs` asserts `OAUTH_TOKEN_URL == credentials::refresh::TOKEN_ENDPOINT`. If a future refactor ever splits them, `cargo test` breaks immediately rather than a runtime 404 months later.

## Alternatives Considered

### Alt 1: Copy constants to each caller

Put `CLIENT_ID` in `login.rs`, `exchange.rs`, and `refresh.rs` independently — matching v1.x's structure.

**Rejected because:** This is literally the shape v1.x had and is the exact structure finding L1 called out as unsafe. Replicating it in Rust would be regression.

### Alt 2: Constants as `const fn` builders

Make `client_id()` / `authorize_url()` functions instead of `const` values, with no `const` exports. Allows computed variants (e.g., dev vs prod) if we ever needed them.

**Rejected because:** csq has exactly one target (Anthropic production) and no plausible reason for per-environment variation. A `const` is simpler to reason about and allows compile-time string matching in tests.

### Alt 3: Pull constants from a config file

Load the client_id from `~/.config/csq/oauth.toml` at startup.

**Rejected because:** The client_id is fixed by Anthropic's OAuth app registration, not by the user. A config file would invite users to edit it, which can only break things. Hardcoding is correct here.

## Consequences

- Any future OAuth endpoint change is a 1-file, 1-line edit.
- Tests that check URL structure read from the same constant the runtime uses — no drift possible.
- M8.7b's `/api/login/{N}` route and the `/oauth/callback` TCP listener both inherit this module. No duplicated client_id in network code.
- Future third-party OAuth providers (if csq ever supports them) get their own `providers/<name>/constants.rs` — the Anthropic module is not the generic abstraction, it's the Anthropic-specific one.

## Security Invariants Now Preserved By This Module

1. **`redirect_uri(port)`** hardcodes `127.0.0.1` — there is no path in the `oauth` module that can produce a `0.0.0.0` binding (finding S12).
2. **`OAUTH_TOKEN_URL`** is re-exported from the refresh endpoint constant — same URL, two flows, one truth.
3. **`OAUTH_SCOPES`** is a `&[&str]`, not a pre-joined string — consumers must either join with spaces (authorize URL query) or iterate (credentials file array). A string-only constant would have allowed a bug where the file stored `"user:profile user:inference"` as one scope.

## For Discussion

1. **If Anthropic ever added a per-environment client_id (dev vs prod), does this design handle it gracefully?** No — `OAUTH_CLIENT_ID` is `const`. A future shift would require the module to introduce a `pub fn client_id() -> &'static str` that branched on a build-time feature flag. The current design optimizes for the current reality (one environment) at the cost of a future refactor if that reality changes. Is that the right trade, or should we pre-invest in the function form now?

2. **The `token_url_matches_refresh_endpoint` test is a runtime assertion, not a compile-time guarantee.** Could we make it a compile-time invariant using `const` propagation, so a mismatch fails `cargo build` rather than `cargo test`? `const _: () = assert!(...)` works for some comparisons but not string equality across crates. Is this worth the effort, or is the runtime test sufficient given CI always runs it?

3. **v1.x hardcoded `DEFAULT_REDIRECT_PORT = 8420` because Anthropic's OAuth registration permits `http://127.0.0.1:8420/...` as a valid redirect URI.** If the port were user-configurable, every user would need to register their own port with Anthropic. But what if 8420 is in use on the user's machine (another csq, another app, Grafana)? The current design surfaces a clear error at daemon startup — but is that the right UX, or should the daemon refuse to start entirely? Should we add a `csq doctor` command that detects the conflict pre-emptively?
