# 00 csq Manifest

Spec version: 1.0.0 | Status: DRAFT | Governs: product scope, goals, non-goals, invariants summary

---

## 0.1 What csq is

**csq** (Code Session Quota, binary name `csq`, formerly `claude-squad`) is a Terrene Foundation open-source tool for managing multiple Claude Code accounts on one machine. It is a thin supporting layer around Anthropic's Claude Code CLI — it does not modify CC, it does not intercept CC's HTTP traffic, it does not embed CC source. It configures CC's environment so that one user running N concurrent terminals on M accounts gets per-terminal account control without cross-contamination.

Upstream dependency: Claude Code CLI (read-only observer, we cite its source for correctness proofs but never patch it). csq is installed as a single Rust binary; its core, CLI, and Tauri desktop app are the same binary with subcommand routing.

## 0.2 What csq does

1. **Maintains per-account canonical credentials** (`accounts/config-<N>/.credentials.json`), refreshed in the background by a long-running daemon.
2. **Provides per-terminal handle directories** (`accounts/term-<pid>/`) that let each running `claude` process pick an account independently and swap accounts in-flight without affecting sibling terminals.
3. **Polls Anthropic's OAuth usage endpoint** (and third-party provider endpoints) for quota data, stored in `accounts/quota.json`, surfaced in a statusline hook, a macOS system tray, and a Svelte desktop dashboard.
4. **Brokers OAuth token refresh** with a single-refresher-per-account lock so N concurrent terminals don't race on refresh-token rotation.
5. **Exposes a CLI** (`csq run`, `csq swap`, `csq login`, `csq status`, `csq statusline`) and a desktop app for monitoring and switching accounts.

## 0.3 What csq must not do

These are absolute scope boundaries. Violating any of them is a bug against this spec, not a feature:

- **csq must not modify Claude Code.** No patches, no binary rewrites, no LD_PRELOAD-style interception. csq is a cooperating outside party.
- **csq must not own chat history or session state.** CC's `history`, `sessions`, `projects`, `commands`, `skills`, `agents`, `rules`, `mcp`, `plugins`, `snippets`, `todos` all live in `~/.claude` and are shared via symlink from every handle dir. csq never writes into these. Reference: `csq-core/src/session/isolation.rs:12-15`.
- **csq must not require a terminal restart to swap accounts.** Swap is in-flight. The running `claude` process reloads credentials via CC's mtime check on its next API call. Reference: spec 01, section 1.4.
- **csq must not write quota data from the terminal side.** Quota is owned exclusively by the daemon's usage poller. CC's per-request `rate_limits` JSON is a terminal-scoped snapshot and must never be attributed to an account. Reference: `.claude/rules/account-terminal-separation.md` rules 1-4.
- **csq ships as a single Rust binary with no Python or jq runtime dependency.** Original ADR-001 stated "no Node at runtime" as well, but Cloudflare TLS fingerprinting on Anthropic endpoints forced a deviation: the OAuth refresher and usage poller shell out to a JS runtime (`node` or `bun`) for `platform.claude.com` / `api.anthropic.com` requests only. Third-party providers still use `reqwest`. The runtime is resolved via `csq-core::http::find_js_runtime` which walks `$PATH` first, then probes `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin`, `$HOME/.bun/bin`, and `$HOME/.volta/bin` so GUI-launched Tauri instances (which inherit only `/usr/bin:/bin:/usr/sbin:/sbin` on macOS) still find the runtime. Reference: journals `0056`, `0057`; ADR-001 in `workspaces/csq-v2/01-analysis/01-research/03-architecture-decision-records.md`.

## 0.4 Core invariants (derived from the detailed specs)

- **INV-01 config-N is permanent.** A directory named `config-<N>` is account N's canonical home forever. csq swap does NOT mutate it. Only login to account N and daemon refresh of account N write to `config-N/.credentials.json`. (Spec 02.)
- **INV-02 term-\<pid\> is ephemeral.** A handle dir lives exactly as long as the `claude` process that owns it. Created in `csq run`, deleted on process exit (or swept on the next daemon tick via `.live-pid` staleness check). (Spec 02, 03.)
- **INV-03 All identity derivation reads `.csq-account` marker.** Directory name is not identity. Code that derives "which account is this terminal on" MUST read the marker, never parse `config-N` or `term-<pid>` for a number. (Spec 02; `.claude/rules/account-terminal-separation.md` rule 5.)
- **INV-04 Swap is in-flight via file mtime.** `csq swap M` in terminal T atomically re-points term-T's symlinks from `config-<current>/*` to `config-<M>/*`. CC's next `fs.stat` on `.credentials.json` follows the symlink to the new target, sees a different mtime, clears its OAuth memoize, and the next API call uses account M. Terminal T swaps; other terminals unaffected. (Spec 01, 02.)
- **INV-05 Daemon is the sole writer of quota.json.** The usage poller polls Anthropic's `/api/oauth/usage` per account and writes the result. No other subsystem, no CLI path, no statusline hook writes quota data. (Spec 05; rules rule 1.)
- **INV-06 Daemon is the sole refresher of OAuth tokens.** Per-account `tokio::sync::Mutex` held across refresh. CC's own internal refresh is suppressed by keeping tokens fresh ahead of expiry (2-hour window). (Spec 04.)
- **INV-07 Subscription metadata is preserved on every credential write.** `subscriptionType` and `rateLimitTier` are not returned by Anthropic's token endpoint; CC backfills them into the live credentials on first API call. Any csq code that writes credentials MUST preserve these fields from the existing file. (Spec 01, 02.)

## 0.5 Non-goals

- **csq does not manage API-key-only accounts for Claude.** API keys are flat tokens without refresh semantics; the rotation and refresh systems do not apply. Third-party provider API keys (Z.AI, MiniMax) are handled separately under spec 05.
- **csq does not ship a vendored CC.** Users install CC via its own distribution channel. csq locates the `claude` binary via `PATH` and configures its environment.
- **csq does not attempt to bypass or override CC's own behavior.** When CC changes upstream, csq's specs and code follow — not the other way around.
- **csq does not guarantee behavior on forked or patched CC binaries.** All guarantees are against the official CC as shipped by Anthropic.

## 0.6 Reading order for new contributors

1. This manifest.
2. Spec 01 (`01-cc-credential-architecture.md`) — what CC does with credentials. **Load-bearing for everything else.**
3. Spec 02 (`02-csq-handle-dir-model.md`) — how csq organizes its own state on disk.
4. Spec 03 (`03-csq-session-lifecycle.md`) — the user-visible CLI surface.
5. Then branch into 04–06 as relevant to your task.

## Revisions

- 2026-04-12 — 1.0.0 — Initial draft, derived from CC 2.1.104 source read in the csq-v2 redesign session. Journal 0031 retracts journal 0029 Finding 4 which contradicted section 1.4 of spec 01.
- 2026-04-17 — 1.0.1 — Corrected the §0.3 "no Node at runtime" invariant to reflect the post-journal-0056 reality. Added runtime-resolution note covering PATH probe + absolute-path fallbacks for GUI-launched apps. Journal 0057.
