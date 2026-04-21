# 01 — Codex Surface: Functional Requirements

Spec version: 0.1.0 | Status: DRAFT | Phase: /analyze

Derived from: briefs/01-vision.md, specs/07-provider-surface-dispatch.md, specs/02, specs/05, rules/account-terminal-separation.md.

Actors: **User** (owns ChatGPT subscription), **csq-cli** (process invoked in a terminal), **csq-core** (library: providers, daemon subsystems), **csq-desktop** (Tauri + Svelte UI), **Daemon** (long-running background process), **Codex CLI** (openai/codex native binary).

Observable outcomes follow given-when-then.

---

## 1. csq-cli surface additions

### FR-CLI-01 — Provision a Codex account

**As a** User
**I want** `csq login <N> --provider codex`
**So that** slot N becomes a Codex slot bound to my ChatGPT subscription.

Acceptance:

- Given slot N is empty or is already a Codex slot, when I run `csq login 4 --provider codex`, then csq creates `config-4/` (if absent), writes `.csq-account = "4"`, pre-seeds `config-4/config.toml` with `cli_auth_credentials_store = "file"` and a default `model` key BEFORE invoking `codex login` (INV-P03, spec 07 §7.3.3 step 2).
- Given the pre-seed is written, when csq shells out `CODEX_HOME=config-4 codex login --device-auth`, then the User completes device-auth in browser and `config-4/auth.json` appears.
- Given auth.json appears, when the daemon receives the login-complete signal, then daemon atomically renames it to `credentials/codex-4.json`, replaces `config-4/codex-auth.json` with a symlink to it, and sets mode 0400 outside refresh windows.
- Given `security find-generic-password -s com.openai.codex` returns a pre-existing entry on macOS, when `csq login --provider codex` runs, then csq prompts the User to purge the keychain entry and refuses to proceed until it is purged or explicitly kept (FR-DESK-05 below surfaces this from the desktop app).
- Given slot N was previously a Claude Code slot with live credentials, when the User runs `csq login 4 --provider codex`, then csq refuses with an actionable error: "slot 4 is a Claude Code slot; run `csq logout 4` first to repurpose".
- **Observability:** first-run emits `codex_login_seeded`, `codex_login_invoked`, `codex_login_complete`, `codex_login_daemon_registered` structured events (redacted per INV-P07).

### FR-CLI-02 — Run a Codex terminal

**As a** User
**I want** `csq run <N>` for a Codex slot
**So that** a terminal is spawned with the native `codex` CLI bound to slot N's identity.

Acceptance:

- Given slot N has surface `Codex` and the daemon is running, when I run `csq run 4`, then csq creates handle dir `term-<pid>/` that IS `CODEX_HOME`, symlinks `auth.json → credentials/codex-4.json`, `config.toml → config-4/config.toml`, `sessions → config-4/codex-sessions`, `history.jsonl → config-4/codex-history.jsonl`, writes `.live-pid`, strips `OPENAI_*` env vars, sets `CODEX_HOME=<abs-path>`, and execs `codex`.
- Given the daemon is NOT running, when I run `csq run 4` on a Codex slot, then csq refuses with: "daemon required for Codex slot — run `csq daemon start` (see ADR-C07)". Exit code 2. (INV-P02.)
- Given slot N does not exist, when I run `csq run 4`, then csq refuses with "account 4 not provisioned — run csq login 4 --provider codex".

### FR-CLI-03 — Cross-surface `csq swap`

**As a** User
**I want** `csq swap M` inside a Codex terminal where M is Claude
**So that** I can pivot to a different provider without closing the terminal.

Acceptance:

- Given current terminal is surface Codex and target M has surface ClaudeCode, when I run `csq swap 1`, then csq prints: "swap crosses surfaces (Codex → Claude Code). Conversation transcript will not transfer. Continue? [y/N]". On y, csq `exec`s `claude` in place with `CLAUDE_CONFIG_DIR=<new-handle-dir>`. On N, swap aborts with exit 1.
- Given `--yes` flag, when I run `csq swap 1 --yes`, then confirmation is bypassed.
- Given current and target share surface (Codex → Codex), when I run `csq swap 5`, then existing spec-02 INV-04 symlink-repoint behavior applies — no exec, no warning (INV-P05).
- **Observability:** cross-surface swap emits `swap_cross_surface {from, to, confirmed}` event.

### FR-CLI-04 — Model switch for a Codex slot

**As a** User
**I want** `csq models switch --slot <N> <model>`
**So that** slot N defaults to the chosen Codex model.

Acceptance:

- Given slot N is a Codex slot, when I run `csq models switch --slot 4 gpt-5-codex`, then csq rewrites top-level `model = "gpt-5-codex"` in `config-4/config.toml` via atomic replace, preserving other keys. (INV-P06, ModelConfigTarget::TomlModelKey.)
- Given the model name is not in the cached model list and `--force` is not set, when csq runs, then it refuses with "model 'gpt-5-codex-xyz' not in provider catalog — run `csq models list 4 --refresh` or pass --force".
- Given a running `codex` process on slot 4, when model is switched, then the running process continues on its in-session `/model` selection; the new default applies to the NEXT `codex` spawn.

### FR-CLI-05 — `csq setkey` is not applicable to Codex

**As a** User
**I want** clear behavior when I try to set an API key on a Codex slot
**So that** I don't accidentally mis-configure.

Acceptance:

- Given slot N has surface Codex, when I run `csq setkey --slot 4 <key>`, then csq refuses with exit 2: "Codex slots use OAuth device-auth, not API keys — run `csq login 4 --provider codex`".
- **Flag:** This is a hard refusal, not a no-op.

---

## 2. csq-core additions

### FR-CORE-01 — `providers::codex` module

Owns: login orchestration, config.toml pre-seed, auth.json relocation, keychain-residue probe, per-account refresh-lock registration. Exposes pure functions testable without a live daemon. Never writes quota data (rules rule 1).

Observable: integration test asserts pre-seed ordering (INV-P03); unit test asserts auth.json canonical path is `credentials/codex-<N>.json`, never inside `config-<N>` (ADR-C03).

### FR-CORE-02 — `daemon::usage_poller::codex` module

Polls `https://chatgpt.com/backend-api/wham/usage` with the account's access token. Versioned parser emits `QuotaKind::Utilization` on known schema, `QuotaKind::Unknown` on drift (ADR-C09). Respects per-call timeout (spec 05 §5.6). Writes `quota.json` with `surface: "codex"`, `kind`, `value`, `ts`, `schema_version: 2`. On repeated failure (N=5 consecutive, default), enters circuit-breaker cooldown; persists last-known-good raw response for bug reports.

### FR-CORE-03 — `daemon::refresher` Codex extension

Registers each Codex account under a `tokio::sync::Mutex<AccountN>` keyed by surface. Refresh path:

1. Acquire per-account mutex.
2. POST refresh to OpenAI token endpoint via the same JS-runtime transport used for Anthropic (inherits TLS-fingerprint workaround; see manifest §0.3).
3. On success, atomic_replace `credentials/codex-<N>.json` (mode 0600 during write, 0400 after) preserving any Codex-side backfilled metadata analogous to INV-07.
4. Handle dirs see the new token on next stat via symlink (INV-P01).
5. On 400/401 `invalid_grant`, mark account `LOGIN-NEEDED`, stop the poller for that slot, emit event for UI.

Never writes into handle dirs (no fanout copy — ADR and INV-P01).

### FR-CORE-04 — Token redaction extension

`error::redact_tokens` matches `sess-[A-Za-z0-9_-]{20,}`, Codex JWT shape (`eyJ…\.eyJ…\..+`), and existing Anthropic patterns. Unit test MUST assert a sample Codex error body with `sess-…` is redacted before being formatted. (INV-P07.)

---

## 3. csq-desktop additions

### FR-DESK-01 — AddAccountModal Codex card

Given the User opens AddAccountModal, when they pick "Codex (ChatGPT subscription)", then the modal shows the ToS disclosure (FR-DESK-03), a "Continue" button disabled until the disclosure checkbox is ticked, and on continue dispatches `csq login <N> --provider codex` with progress events surfaced live.

### FR-DESK-02 — ChangeModelModal Codex list fetch

Given the User opens ChangeModelModal for a Codex slot, when the modal mounts, then csq-core fetches `chatgpt.com/backend-api/codex/models` with 1.5s timeout. On success, list is cached at `accounts/codex-models.json` with `fetched_at` timestamp. On timeout/failure, on-disk cache is used and a "Cached Nm ago" staleness badge renders (ADR-C10). Model list MUST include at minimum: `gpt-5-codex`, `gpt-5.1-codex`, plus whatever the live endpoint returns.

### FR-DESK-03 — ToS disclosure modal (first Codex login only)

Given this machine has no record of prior Codex-ToS acceptance (file `accounts/codex-tos-accepted.json` absent), when the User initiates any Codex login, then a modal displays:

> OpenAI's published terms do not explicitly address multi-account use with third-party clients. Using csq against subscription-backed Codex accounts may carry account-suspension risk. csq discloses this; it does not indemnify.

On acceptance, csq writes `{accepted_at, csq_version, user_email_hash}` to `accounts/codex-tos-accepted.json`. Subsequent Codex logins skip the modal. (ADR-C08.)

### FR-DESK-04 — AccountCard Codex surface badge

Each AccountCard renders a surface badge: "Claude Code" (existing, invisible for backward compat) or "Codex" (new). Badge is keyboard-focusable and exposes the surface via `aria-label`.

### FR-DESK-05 — Keychain-residue probe

On first Codex login per machine, before device-auth runs, desktop surfaces any `com.openai.codex` keychain entries detected by csq-core with: "An existing `codex` CLI installation has stored credentials in your Keychain. csq manages tokens in files; leaving Keychain entries can cause login drift." Buttons: [Purge], [Keep and continue], [Cancel]. (ADR-C11.)

---

## 4. Persisted state (canonical paths)

| File                                                                    | Owner                            | Lifetime                                                                             |
| ----------------------------------------------------------------------- | -------------------------------- | ------------------------------------------------------------------------------------ |
| `accounts/credentials/codex-<N>.json`                                   | Daemon (refresher)               | Permanent; one per account; mode 0400 outside refresh                                |
| `accounts/config-<N>/codex-auth.json` (symlink)                         | csq-core (login)                 | Permanent symlink to above                                                           |
| `accounts/config-<N>/config.toml`                                       | csq-core (login, models switch)  | Permanent; daemon NEVER writes model key — only login + explicit `csq models switch` |
| `accounts/config-<N>/codex-sessions/`                                   | Codex CLI via handle-dir symlink | Permanent per-account                                                                |
| `accounts/config-<N>/codex-history.jsonl`                               | Codex CLI via handle-dir symlink | Permanent per-account                                                                |
| `accounts/term-<pid>/{auth.json, config.toml, sessions, history.jsonl}` | csq-cli (symlinks only)          | Ephemeral per-process                                                                |
| `accounts/codex-models.json`                                            | Desktop (model list cache)       | Replaceable, daemon-read-only                                                        |
| `accounts/codex-tos-accepted.json`                                      | Desktop                          | Permanent once written                                                               |
| `accounts/quota.json` (schema v2)                                       | Daemon (sole writer)             | Permanent                                                                            |

Handle-dir sweep (spec 02 §2.5) MUST NOT dereference symlinks — confirmed by INV-P04.

---

## 5. Cross-cutting non-functional

- **Performance:** `csq run <codex-slot>` cold-start to `codex` prompt < 800ms on M-series; no blocking network calls on this path.
- **Reliability:** Codex polling tolerates 3 consecutive wham/usage failures before degrading kind to Unknown; recovers automatically on next successful poll.
- **Security:** no Codex token ever crosses an event payload; redaction is verified by unit test (rules tauri-commands §1).
- **Platform:** macOS + Linux at ship; Windows deferred (ADR-C12). Ubuntu uses libsecret probe instead of macOS Keychain.
