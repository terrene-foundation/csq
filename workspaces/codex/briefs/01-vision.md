# csq × Codex — native-CLI provider surface

## Vision

Add Codex (OpenAI ChatGPT subscription) as a first-class provider surface in csq. Users who hold Plus, Pro, Business, or Enterprise ChatGPT subscriptions can provision a Codex account inside csq the same way they provision a Claude account today: `csq login <slot> --provider codex` seeds a permanent `config-<N>/` directory, the daemon owns token refresh, and `csq run <slot>` spawns the native `codex` binary with `CODEX_HOME` pointed at a per-terminal handle dir.

Codex is the first surface where csq operates across a CLI binary that is not Claude Code. It forces the introduction of a provider-surface dispatch layer (new spec 07) that the existing Anthropic/MiniMax/Z.AI/Ollama providers can also migrate to without behavior change.

## Why

- Users are paying for ChatGPT subscriptions and cannot rotate across multiple subscriptions inside a single workflow today.
- Routing Codex through a translation proxy into Claude Code loses prompt caching, extended thinking, tool-result images, and GPT-5-Codex's native harness fit. The native CLI is strictly better for Codex work.
- csq's value is multi-account rotation and quota awareness, not proxying. Generalizing the surface abstraction exposes that value across every CLI the user actually runs.

## Scope

1. `Surface` enum in `providers::catalog`: `ClaudeCode | Codex | Gemini`, parameterized `spawn_command`, `home_env_var`, `login_flow`, `quota_dispatch`, `model_config_key`.
2. Refactor Anthropic / MiniMax / Z.AI / Ollama to the new abstraction as `Surface::ClaudeCode` with zero behavior change.
3. New `providers::codex` module: login flow, config.toml pre-seed (`cli_auth_credentials_store = "file"` BEFORE first login), auth.json canonical location, per-account refresh lock.
4. New `daemon::usage_poller::codex` module: polls `https://chatgpt.com/backend-api/wham/usage`, versioned parser, schema-drift graceful degradation, circuit breaker on repeated failure.
5. New `daemon::refresher` extension: Codex OAuth refresh goes through the daemon's per-account `tokio::sync::Mutex` — handle-dir `auth.json` is ALWAYS a symlink to the canonical file in `credentials/codex-<N>.json`, NEVER a copy (breaks per openai/codex#15502).
6. `quota.json` v2: `{ account, surface, kind: "utilization"|"counter"|"unknown", value, ts, schema_version: 2 }`. One-shot v1→v2 migration in daemon startup.
7. Handle dir layout: `term-<pid>/` IS the `CODEX_HOME`; `auth.json` and `config.toml` are symlinks into `config-<N>/`; `sessions/` and `history.jsonl` symlink into `config-<N>/codex-sessions/` and `config-<N>/codex-history.jsonl` so conversation data survives handle-dir sweep.
8. Cross-surface `csq swap`: warn + `exec <new-binary>` in place. Same-surface swap keeps existing symlink-repoint behavior.
9. Desktop AddAccountModal gains a Codex card: first-run shows the ToS ambiguity notice, captures acceptance timestamp, then runs `codex login --device-auth` with `CODEX_HOME=config-<N>`.
10. ChangeModelModal fetches the live model list from `chatgpt.com/backend-api/codex/models` with 1.5s timeout + on-disk cache + staleness badge.

## Non-goals

- **No proxy-to-Claude-Code path for Codex.** We ship the native CLI only; the proxy option becomes a power-user topic handled by external projects (raine/claude-codex-proxy, CaddyGlow/ccproxy-api).
- **No Claude Code feature parity claim.** Codex surface does not attempt to replicate CC's agent system, COC workflow, or slash commands. Users get native codex UX.
- **No ChatGPT Team / Enterprise multi-seat pooling.** One ChatGPT login = one csq account. Admin/workspace accounts are out of scope.
- **No automated conversation migration** across surfaces. Cross-surface swap drops transcript; user is warned.
- **No Windows support at ship.** Codex relies on filesystem symlinks that require developer mode on Windows. Follow-up PR.

## Key constraints

1. **Daemon is a hard prerequisite for Codex slots.** `csq run N` refuses to spawn a Codex slot if the daemon is not running. Rationale: if the daemon is not the sole refresh writer, codex will refresh in-process through the symlink and corrupt our canonical file (openai/codex#10332 class of race).
2. **`cli_auth_credentials_store = "file"` is non-negotiable.** Written to `config-N/config.toml` BEFORE `codex login` is invoked, in that order, with an integration test asserting ordering. Prevents codex from escalating tokens to the macOS Keychain where they would contaminate across accounts.
3. **Keychain residue on upgrade.** If the user ran `codex` before installing csq, a `com.openai.codex` keychain entry exists. First-run for Codex probes for it and offers purge before proceeding.
4. **wham/usage endpoint is undocumented.** Parser is versioned. On schema drift, quota polling degrades to `kind: "unknown"` rather than silently lying. Raw last-known-good response is saved for bug reports.
5. **ToS ambiguity is disclosed.** First-run Codex modal shows a notice: OpenAI's published terms do not explicitly name third-party clients or multi-account rotation; using csq with subscription-backed accounts may carry suspension risk. Acceptance timestamp logged. This is disclosure, not indemnification.
6. **Token redaction covers Codex tokens** (`sess-*`, JWT shape) BEFORE any Codex log line ships. `error::redact_tokens` regex extended.

## Acceptance

- A user can `csq login 4 --provider codex`, complete device-auth in their browser, and see account 4 listed as a Codex slot in the desktop app.
- `csq run 4` launches the native `codex` CLI with the correct per-account identity.
- While `codex` is running, the daemon keeps `config-4/auth.json` fresh; the user does not experience `refresh_token was already used` errors across sibling terminals.
- The desktop dashboard shows account 4's remaining quota as an accurate number (from `wham/usage`), updating every 5 minutes.
- `csq swap 1` from inside a Codex terminal (where slot 1 is Claude) warns about transcript loss, confirms, then exec-replaces with `claude`.
- All existing Anthropic/MiniMax/Z.AI/Ollama behavior is byte-for-byte unchanged after the refactor.

## Dependencies

- Spec 07 (provider surface dispatch) drafted and in `specs/_index.md` before code lands.
- Spec 02 amended with INV-08 (per-surface persistent state carve-out).
- Spec 05 amended with §5.7 (Codex polling contract).

## Ships before

Gemini. Codex proves the abstraction end-to-end; Gemini reuses it with simpler auth (API-key only).

## References

- Research report (2026-04-21, this session) — Codex CLI verification against openai/codex main branch.
- Red team findings (2026-04-21, this session) — CRIT/HIGH items inform the constraints above.
- openai/codex#10332 — single-use refresh-token race across concurrent processes.
- openai/codex#15502 — copying auth.json between CODEX_HOMEs breaks refresh.
- Journal 0052 — Anthropic rejects scope on refresh (related OAuth-class bug).
- `.claude/rules/account-terminal-separation.md` — the constraint spine this integration must honor.
