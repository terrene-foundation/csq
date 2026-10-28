# Code Squad Q (csq) — Multi-Account Session Management

Tauri desktop app with a Svelte frontend and a Rust backend, plus a CLI. csq manages
several independently authenticated Claude Code accounts on one machine: it monitors
each account's quota, refreshes its OAuth tokens in the background, and lets any
terminal switch between accounts without disturbing the others.

This file is the orientation document for people — and coding agents — working in this
repository. It describes what the project IS. The authoritative behavioural contracts
live in `specs/`; where this file and a spec disagree, the spec wins.

## Absolute Directives

### 1. Credentials come from the environment, never from source

Every API key and OAuth token is read at runtime from the environment or from the
OAuth flow. No credential is ever hardcoded, committed, or written into a log line or
an error message. Response bodies from token endpoints can echo the token that was
submitted, so error text near the OAuth paths is redacted before it is formatted.

### 2. Implement, don't document

If you find a missing feature while working on something else, implement it. Filing it
as a known gap moves the cost to a future session that no longer has the context.

### 3. No stubs, no silent fallbacks

`TODO`, `unimplemented!()`, a swallowed error, a `return None` with no log — all of
these present a working surface over broken internals, and the user trusts the output.
A pre-existing failure you discover is yours to fix, not to report.

## Tech Stack

| Layer    | Technology                         |
| -------- | ---------------------------------- |
| Frontend | Svelte 5 (runes, component props)  |
| Desktop  | Tauri 2.x (Rust backend, WebView)  |
| State    | Rust backend state + Svelte stores |
| IPC      | Tauri commands (`invoke`)          |
| Styling  | CSS (plain, no framework)          |
| Build    | Cargo + Vite                       |

## Project Structure

A Cargo workspace. The binary crate is `csq/`; most of the logic lives in `csq-core/`.

```
csq/                         — binary crate (CLI + desktop app)
  src/
    cli/                    — CLI subcommands (`csq run`, `swap`, `status`, …)
    desktop/                — Tauri command handlers + desktop wiring
  ui/src/                   — Svelte 5 frontend
    lib/
      components/          — Reusable UI components
      stores/              — Svelte stores (runes-based)
      utils/               — Frontend utilities
csq-core/                    — core library (most logic lives here)
  src/
    accounts/  credentials/  oauth/     — identity, tokens, OAuth rotation
    daemon/                             — refresher, usage pollers, IPC server
    quota/                              — quota state + status rendering
    capability_layer/  coc/             — .coc/ translation + capability layer
    audit/                              — the hash-linked audit chain
    platform/  native/  http/  env/     — fs/keychain, native CLIs, transport
```

Other workspace crates:

| Crate         | Purpose                                                          |
| ------------- | ---------------------------------------------------------------- |
| `csq-sdk`     | Public wire contract — SDK envelope, error shape, payload types  |
| `csq-redact`  | Token redaction and `RedactedString`                             |
| `csq-merkle`  | RFC 6962 Merkle verifier leaf                                    |
| `csq-ledger`  | Transparency-log server                                          |

## The two entities: accounts and terminals

Nearly every subtle bug in this codebase has come from confusing these, so they are
worth stating plainly.

An **account** is an independently authenticated identity. It owns a permanent
directory that lives for as long as the account does, its own credentials, and its own
quota. It refreshes its own tokens and polls its own usage. It is the sole source of
truth for its own quota data.

A **terminal** is one running session, bound to an ephemeral handle directory whose
symlinks point at whichever account it is currently using. A terminal DISPLAYS quota;
it never WRITES it. Swapping accounts in one terminal repoints that terminal's
symlinks and leaves every sibling terminal untouched.

The rule that falls out of this: a quota write must take its account identity from the
poller that fetched the number, from a validated IPC payload, or from an explicit
account argument — never from "which account does this terminal seem to be on?" That
question has several answers and they disagree.

## Specifications

`specs/` is the authoritative record of system behaviour, indexed by
`specs/_index.md`. Read the index first and then only the documents relevant to the
change you are making; reading the whole tree is rarely the right move. When an
implementation decision changes a documented contract, update the spec in the same
change rather than batching it — a stale spec is worse than a missing one, because it
is trusted.

## Building and testing

```bash
cargo build --release -p csq --features cli --no-default-features   # the CLI
cargo test --workspace --features csq/test-utils                    # the test suite
cargo clippy --workspace --all-targets -- -D warnings               # lints
cargo fmt --all                                                     # formatting
```

Tests, clippy, and fmt all passing is necessary but not sufficient before calling a
user-facing change done: build the binary, install it, and run the actual command a
user would run. A green suite tells you the code is correct; it does not tell you the
artifact on disk is the one you fixed.

## Contributing

Changes go through pull requests. Commit messages follow Conventional Commits
(`type(scope): description`), one logical change per commit, with tests landing
alongside the code they cover. Anything touching credentials, the keychain, or the
OAuth paths deserves a security-focused read before it merges.
