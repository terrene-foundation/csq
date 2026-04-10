---
type: DECISION
date: 2026-04-10
created_at: 2026-04-10T20:15:00Z
author: agent
session_id: m8-http-client
session_turn: 30
project: csq-v2
topic: HTTP client selection — reqwest with rustls-tls-webpki-roots
phase: implement
tags: [m8, http, reqwest, rustls, security, dependencies]
---

# DECISION: Use reqwest with rustls-tls-webpki-roots for HTTP transport

## Context

M0-M7 built a library that is deliberately HTTP-agnostic. Both
`credentials::refresh::refresh_token` and `providers::validate::validate_key`
take an injected `http_post` closure so that unit tests can mock the
transport and the library itself carries no HTTP dependency. The
daemon (M8) and the CLI (`csq setkey`, eventually `csq refresh N`)
need a real HTTP implementation that satisfies those closure signatures.

Two signatures are in scope:

- `(url, body) -> Result<Vec<u8>, String>` for the OAuth token refresh
  (form-encoded POST to `https://platform.claude.com/v1/oauth/token`).
- `(url, headers, body) -> Result<(u16, String), String>` for provider
  key validation probes (`max_tokens=1` JSON POSTs to Anthropic and 3P
  endpoints).

Additionally, M8.2+ will need an async HTTP client for the daemon's
background refresher and usage poller.

## Options considered

### Option A: ureq

**Pros**: Truly synchronous (no tokio runtime spawned), smaller
dependency tree (~5 crates vs ~60), simpler model — a POST is just a
blocking syscall. Good fit for CLI paths.

**Cons**: No async story. The daemon would need a second HTTP stack
(`hyper` or `reqwest::Client`) for its background polling. Two HTTP
stacks doubles the supply-chain surface and forces two sets of TLS
configuration to stay in sync. ureq also bundles `rustls` with its own
root policy that differs subtly from reqwest's.

### Option B: reqwest with blocking + async

**Pros**: One HTTP stack for the whole project. `reqwest::blocking`
wraps the async client in a dedicated tokio runtime so CLI code can
call `post_form(url, body)` synchronously; daemon code can use
`reqwest::Client` with the same TLS config and feature set. Both
paths share the same error types, timeout behavior, and HTTPS-only
enforcement. Standard in the Rust ecosystem — well-audited, actively
maintained, widely deployed.

**Cons**: Heavier (~60 crates transitively). The first `csq setkey`
invocation pays a small tokio runtime startup cost (~5ms measured
locally). Subsequent calls reuse the `OnceLock`-cached client so there
is no per-call cost after warmup.

### Option C: write a hand-rolled HTTP/1.1 client

**Rejected**: zero-tolerance rule on workarounds. Re-implementing
HTTPS + TLS + certificate validation + redirect handling ourselves
is a security-critical wheel we should not reinvent. Every bug in our
TLS handshake is a potential MITM vector against credential refresh.

## Decision: Option B — reqwest with rustls-tls-webpki-roots

### Feature flags

```toml
reqwest = { version = "0.12", default-features = false, features = [
    "rustls-tls-webpki-roots",
    "blocking"
] }
```

- **`rustls-tls-webpki-roots`** (not `rustls-tls` or `native-tls`):
  rustls avoids the OpenSSL attack surface entirely (no dynamic OpenSSL
  linkage, no version-skew bugs). `webpki-roots` bundles Mozilla's CA
  root store inside the binary, so csq does NOT depend on the host's
  TLS cert store being populated or up-to-date. This matches the
  Foundation Independence rule (stdlib-plus-essentials philosophy
  carried over from v1.x Python) and the install-friction goal (csq
  works on a freshly installed box with no CA bundle configured).
- **`blocking`**: required by the CLI path (`csq setkey`,
  `csq refresh N` later). Internally spawns a small tokio runtime —
  acceptable; shared via `OnceLock`.
- **`default-features = false`**: omits `http2` default auto-pull,
  `charset`, `gzip`, `brotli`, `deflate`, `cookies`, `json`, etc.
  reqwest still pulls `http2` transitively via `hyper`, but we opt in
  to only what we actually use.

### Module layout

`csq-core/src/http.rs` exposes two free functions:

```rust
pub fn post_form(url: &str, body: &str) -> Result<Vec<u8>, String>;
pub fn post_json_probe(
    url: &str,
    headers: &[(String, String)],
    body: &str,
) -> Result<(u16, String), String>;
```

Both signatures match the closure contracts that `refresh_token` and
`validate_key` already expect. No public `reqwest` types leak out of
the module — callers only see `String` errors and primitive types.

A single `reqwest::blocking::Client` is cached behind `OnceLock` with:

- `timeout(10s)` — generous for CI and slow networks; OAuth exchange
  is well under 1s in practice.
- `connect_timeout(5s)` — fail fast on unreachable hosts.
- `https_only(true)` — reject `http://` URLs at request time. An
  attacker who poisoned `ANTHROPIC_BASE_URL` to a cleartext URL
  (combined with some other way to bypass the `strip_sensitive_env`
  fix) would still be blocked at the TLS layer.
- `redirect::Policy::limited(2)` — OAuth endpoints should never
  redirect; 2 is defensive slack.
- `user_agent("csq/{CARGO_PKG_VERSION}")` — makes csq traffic
  attributable in provider logs.

### Error sanitization

`sanitize_err(reqwest::Error)` strips the URL via `without_url()` and
classifies into four buckets (`timeout`, `connect`, `redirect`, other)
before stringifying. This prevents accidental leakage of URL-embedded
secrets into error messages — defense in depth, since form bodies are
not URL-embedded today but refactors could theoretically turn a POST
into a GET. Confirmed by the `sanitize_err_does_not_leak_bodies` unit
test, which passes a fake refresh token in the body to `192.0.2.1`
(TEST-NET-1 documentation space) and asserts the error message does
not contain the token substring.

## Consequences

- **Workspace dependency growth**: +~60 crates (reqwest, hyper, rustls,
  webpki, etc.). The full `cargo build` time on a warm cache went from
  ~3s to ~4s; incremental builds are unaffected.
- **Unblocks M8.1 (this PR)**: `csq setkey` now performs a real
  validation probe. The stub placeholder is removed.
- **Unblocks broker refresh**: `csq_core::http::post_form` satisfies
  the `refresh_token` closure contract. The daemon scaffold (M8.2)
  will pass it into `broker_check`.
- **Tightens broker concurrent test**: with real-transport
  characteristics no longer abstract, the re-read-inside-lock
  guarantee (C6 fix) means concurrent callers never double-refresh.
  `broker_concurrent_exactly_one_refresh` was loosened to `<=3` as a
  flakiness hedge during M4; it is now pinned to `==1`, which is what
  the lock protocol actually guarantees.
- **Daemon reuses the same crate**: M8.2 adds
  `reqwest::Client::new()` (async) for the background poller. The
  rustls config, timeouts, and User-Agent will be factored into a
  shared builder so both clients stay in sync.
- **Test coverage**: 6 new unit tests in `http.rs` cover client
  construction, HTTPS-only rejection, invalid URL handling, timeout
  classification, and error sanitization. Total workspace tests:
  232 → 238.

## Follow-up

- M8.2: add async reqwest client for the daemon refresher and poller.
  Factor shared builder into `http::client_builder()` so blocking
  and async clients share config.
- M8.2: wire `csq_core::http::post_form` into a `csq refresh N` CLI
  command that delegates to the daemon if running, else falls back
  to a direct `broker_check` call.
- Consider adding a `CSQ_HTTP_TIMEOUT` environment variable for
  debugging in environments with unusual network conditions.

## For Discussion

1. The `post_form` signature returns `Vec<u8>` while `post_json_probe`
   returns `(u16, String)`. This asymmetry is inherited from the two
   different closure contracts the library already established. Should
   we unify them (e.g., both return `(u16, Vec<u8>)`) and migrate the
   broker to use the unified shape in M8.2, or is the asymmetry a fair
   price for keeping the M0-M7 API stable?
2. Bundling `webpki-roots` means csq carries a snapshot of Mozilla's
   CA store. When that store rotates (CA added/removed), a stale csq
   binary may reject or accept certificates differently from the
   system. The alternative (`rustls-tls-native-roots`) reads the host
   store but fails on boxes without a populated store. Is the "works
   on empty box" property worth the stale-root risk?
3. The `sanitize_err` function strips URLs via `without_url()` but
   still formats the underlying reqwest error via `{}`. If reqwest
   ever adds a new error variant that quotes the request body in its
   `Display` impl, our sanitizer would silently leak. Should we
   instead classify into a finite enum and throw away the underlying
   error message entirely, trading diagnostics for defense-in-depth?
