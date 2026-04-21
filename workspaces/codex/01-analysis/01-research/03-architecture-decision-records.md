# 03 — Codex Surface: Architecture Decision Records

Decision records for csq × Codex native-CLI provider surface. Status values: Accepted | Proposed | Superseded.

---

## ADR-C01 — Native `codex` CLI over translation proxy

**Status:** Accepted
**Context:** Alternative approach is to run `claude` and proxy Anthropic requests to OpenAI via projects like `raine/claude-codex-proxy` or `CaddyGlow/ccproxy-api`. Would not require a new surface.
**Decision:** Ship the native `codex` binary as surface `Surface::Codex`. Do not embed or recommend a proxy.
**Alternatives:**

1. Proxy-to-CC — loses prompt caching, extended thinking, tool-result images, GPT-5-Codex harness fit. Creates an indirection csq must maintain.
2. Hybrid (proxy for some, native for others) — doubles surface area and confuses users.
   **Consequences:** Introduces the `Surface` enum (spec 07) and per-surface on-disk layouts. Unlocks Gemini on the same abstraction. Users who want proxy-to-CC can use external projects; csq is surface-neutral, not proxy-neutral.

## ADR-C02 — Daemon as sole refresher for Codex `auth.json`

**Status:** Accepted
**Context:** `openai/codex#10332` documents a refresh-token single-use race when concurrent codex processes share the same `auth.json`. Each refresh rotates the refresh token server-side; the losing process sees `invalid_grant` and logs the user out.
**Decision:** Daemon's `refresher` subsystem holds a per-account `tokio::sync::Mutex` and is the only writer of `credentials/codex-<N>.json`. Codex processes read auth.json through a symlink; they NEVER write it in csq-managed terminals.
**Alternatives:**

1. Let codex refresh in-process — reproduces the documented race across sibling terminals.
2. Refresh per-handle-dir — needs fanout copies, which breaks per ADR-C03 / openai/codex#15502.
   **Consequences:** Makes daemon a hard prerequisite (ADR-C07). Preserves same-provider invariant already used for Anthropic (spec 04 INV-06).

## ADR-C03 — Canonical Codex credentials at `credentials/codex-<N>.json`, NOT inside `config-<N>`

**Status:** Accepted
**Context:** Spec 02 places Claude Code canonical tokens at `config-<N>/.credentials.json` with a mirror at `credentials/<N>.json`. For Codex we could mirror that shape.
**Decision:** Canonical file lives ONLY at `credentials/codex-<N>.json`. `config-<N>/codex-auth.json` is a symlink to it. Handle dirs symlink to the same canonical.
**Alternatives:**

1. Canonical inside `config-<N>` with mirror — duplicates the file, requires two-write atomicity and a second preservation guard.
2. Canonical in macOS Keychain — re-introduces keychain contamination class that `cli_auth_credentials_store = "file"` exists to prevent.
   **Consequences:** One atomic write per refresh. Symlink chain is shallow (handle-dir → credentials/). Fanout is a filesystem property, not code. Clean separation: `config-<N>` is user-editable state; `credentials/` is daemon-owned.

## ADR-C04 — Pre-seed `config.toml` BEFORE `codex login`

**Status:** Accepted
**Context:** `codex login` defaults to Keychain storage on macOS unless `cli_auth_credentials_store = "file"` is present in config.toml at login time. Writing config.toml AFTER login does not migrate the token out of Keychain.
**Decision:** csq writes `config-<N>/config.toml` with `cli_auth_credentials_store = "file"` and a default `model` key BEFORE shelling out to `codex login`. Integration test asserts ordering (INV-P03).
**Alternatives:**

1. Post-seed — token escapes into Keychain; violates ADR-C03.
2. Use Keychain everywhere — cross-account contamination on macOS, and no equivalent isolation on Linux.
   **Consequences:** Users see the config.toml populate instantly; no silent Keychain entries for csq-managed accounts. Pre-existing Keychain entries handled separately (ADR-C11).

## ADR-C05 — `codex-sessions/` and `codex-history.jsonl` persistent per-account

**Status:** Accepted
**Context:** Codex stores `sessions/` and `history.jsonl` inside `CODEX_HOME` by default. Spec 02 INV-02 makes handle dirs ephemeral; daemon sweep removes them.
**Decision:** Place these at `config-<N>/codex-sessions/` and `config-<N>/codex-history.jsonl`. Handle-dir entries `sessions` and `history.jsonl` are symlinks into those paths.
**Alternatives:**

1. Store inside handle dir — transcripts die with the terminal.
2. Store at `~/.codex-sessions/<N>/` (analogous to `~/.claude/sessions/`) — two different "shared item" discovery chains (`~/.claude/*` vs `~/.codex-*`) adds cognitive load with no upside.
   **Consequences:** Transcripts survive process crashes. INV-P04 explicitly forbids daemon sweep from dereferencing these symlinks.

## ADR-C06 — Cross-surface `csq swap` auto-exec-in-place with transcript-loss warning

**Status:** Accepted
**Context:** Same-surface swap repoints symlinks; the running binary picks up new state via fs.stat. Different-surface swap cannot: `codex` does not read `CLAUDE_CONFIG_DIR` and vice-versa.
**Decision:** Cross-surface swap prints a transcript-loss warning, prompts [y/N] (`--yes` bypasses), then `exec`s the target binary in place with the right home env var. Same-surface swap is unchanged.
**Alternatives:**

1. Hard-error on cross-surface swap — forces User to kill+relaunch, worse UX for 95% of cases.
2. Silent exec with no warning — transcript loss is surprising.
   **Consequences:** Exec is user-friendly. Users who script swap in CI should pass `--yes`. Any background state in the old surface is dropped by the exec (acceptable; sibling terminals unaffected).

## ADR-C07 — Daemon hard prerequisite for Codex slots

**Status:** Accepted
**Context:** ADR-C02 makes daemon the sole refresher. If daemon is down and the user spawns `codex`, codex will refresh in-process and corrupt the canonical file.
**Decision:** `csq run <codex-slot>` refuses to spawn when daemon is not running. Exit code 2. Error message: "daemon required for Codex slot — run `csq daemon start`". Desktop app surfaces a prominent banner + one-click daemon-start.
**Alternatives:**

1. Spawn codex anyway — reliably corrupts credentials (openai/codex#10332 class).
2. Auto-start the daemon from `csq run` — silent side effect; violates the principle that daemon start is a deliberate user action.
   **Consequences:** One extra step for first-time Codex users. Documented in the Codex onboarding path. Anthropic OAuth slots have the same requirement implicitly today (INV-06); this makes it explicit for Codex.

## ADR-C08 — ToS disclosure modal on first Codex login

**Status:** Accepted
**Context:** OpenAI ToS does not explicitly permit or prohibit multi-account subscription use with third-party clients. Foundation posture: disclose and let the user decide.
**Decision:** First-ever Codex login on this machine shows a ToS ambiguity notice. User must tick acceptance. Acceptance recorded to `accounts/codex-tos-accepted.json` with `{accepted_at, csq_version, user_email_hash}`.
**Alternatives:**

1. No disclosure — misaligned with Foundation independence framing (rules/independence.md).
2. Require a signed legal agreement — overbuilds for the risk.
   **Consequences:** Slight friction first time. Clear audit trail. csq does NOT indemnify — this is disclosure, not a shield.

## ADR-C09 — `wham/usage` schema versioning + graceful degradation

**Status:** Accepted
**Context:** The `wham/usage` endpoint is undocumented. OpenAI may change its response shape without notice.
**Decision:** Parser is versioned. Known shapes produce `QuotaKind::Utilization`. Unknown shapes degrade to `QuotaKind::Unknown` with raw last-known-good response persisted to `accounts/codex-wham-raw.json` for bug reports. Circuit breaker trips after 5 consecutive failures; polling resumes on success.
**Alternatives:**

1. Fail hard on schema drift — blocks all Codex quota reads.
2. Silently synthesize values — lies to the user; violates rules/account-terminal-separation.md rule 1.
   **Consequences:** UI must render a "quota unknown" badge gracefully. Bug reports carry the raw payload, accelerating parser updates.

## ADR-C10 — Live model list + 1.5s timeout + on-disk cache

**Status:** Accepted
**Context:** Codex model catalog shifts (`gpt-5-codex`, `gpt-5.1-codex`, future variants). Hardcoding dates quickly.
**Decision:** ChangeModelModal fetches `chatgpt.com/backend-api/codex/models` with 1.5s timeout. Success → cache at `accounts/codex-models.json`. Timeout/failure → use cache and show "Cached Nm ago" badge. Cold cache + failure → fall back to built-in minimal set (`gpt-5-codex`, `gpt-5.1-codex`).
**Alternatives:**

1. Poll daily in the daemon — wastes tokens and bandwidth.
2. Static list — bit-rots across releases.
   **Consequences:** Modal stays responsive even offline. Stale badge is visible and informs the user.

## ADR-C11 — Keychain residue probe + purge flow on first Codex login

**Status:** Accepted
**Context:** Users who ran `codex` before installing csq have tokens in macOS Keychain under `com.openai.codex`. With `cli_auth_credentials_store = "file"`, those entries are orphaned but visible; they can silently win over file credentials in some code paths.
**Decision:** First Codex login probes `security find-generic-password -s com.openai.codex`. If present, surface a desktop modal offering [Purge], [Keep and continue], [Cancel]. Log chosen action (non-sensitive). **Supersedes the "offer" framing:** if the user declines purge, csq refuses to provision the slot. Residue must be resolved before login proceeds (per zero-tolerance.md audit).
**Alternatives:**

1. Silently purge — destroys a standalone Codex setup the User may still rely on.
2. Ignore — leaves a credential drift hazard.
   **Consequences:** Clean first-run story. Linux uses libsecret probe via `secret-tool lookup service com.openai.codex` instead. Windows deferred (ADR-C12).

## ADR-C12 — No Windows support in first ship

**Status:** Accepted
**Context:** The handle-dir model relies on filesystem symlinks. Windows supports symlinks only in developer mode (or with elevated privileges). Existing csq has been macOS/Linux-first; Codex does not change that.
**Decision:** First Codex ship supports macOS and Linux only. `csq login --provider codex` on Windows refuses with exit 2: "Codex surface not yet supported on Windows — tracked in workspaces/codex/journal/".
**Alternatives:**

1. Use NTFS junctions — they don't behave like symlinks for file targets.
2. Copy-instead-of-symlink on Windows — breaks refresh (openai/codex#15502).
   **Consequences:** Explicit scope boundary. Future work item is to add a Windows handle-dir implementation (likely junction-for-dir + hardlink-for-file, with a different refresher strategy). Tracked as future, not rejected.

## ADR-C13 — Credential file mode-flip protected by per-account mutex

**Status:** Accepted (added post-risk-analysis; see journal 0001)
**Context:** Spec 07 §7.2.2 mandates `credentials/codex-<N>.json` is mode 0400 outside refresh windows. But `csq login N --provider codex` also needs to write this file (first login, re-login after `invalid_grant`). A 0400 file EACCESs on write.
**Decision:** All writers of `credentials/codex-<N>.json` acquire the per-account refresh mutex, flip mode to 0600, write, flip back to 0400, release. The mutex is the same `tokio::sync::Mutex` used by the daemon refresher (single mutex per account, shared by all writers).
**Alternatives:**

1. Keep file at 0600 always — drops a defense layer (any same-UID process can read).
2. Separate login vs refresh locks — deadlock risk.
   **Consequences:** Login path pulls the daemon mutex registry into csq-cli via IPC. Integration test asserts that two parallel `csq login 4 --provider codex` invocations serialize correctly.

## ADR-C14 — Per-account refresh mutex lifecycle tied to slot existence

**Status:** Accepted (added post-risk-analysis)
**Context:** Per-account `tokio::sync::Mutex` lives in a `DashMap<AccountNum, Arc<Mutex<()>>>`. If an account is deleted (`csq logout N`), the mutex must be pruned to avoid a minor leak and to prevent a stale lock from blocking a future `csq login N`.
**Decision:** `csq logout N` acquires the mutex (waiting for any refresh in progress), removes the credential file, then removes the entry from the DashMap. Subsequent `csq login N` allocates a fresh mutex.
**Consequences:** No memory leak. Logout serializes with refresh, which is the correct ordering.

## ADR-C15 — Verify `cli_auth_credentials_store = "file"` disables codex in-process refresh BEFORE spec 07 stabilizes

**Status:** Open (blocker for PR1)
**Context:** Risk G1 (workspaces/codex/01-analysis/01-research/04-risk-analysis.md) flags that our daemon-sole-refresher invariant depends on codex NOT refreshing in-process when `auth.json` is file-backed. Unverified against codex source.
**Decision:** Before PR1 lands, an investigation ticket MUST verify against openai/codex source what `cli_auth_credentials_store = "file"` actually controls. If it only redirects where tokens are stored (not whether in-process refresh happens), spec 07 INV-P01/P02 needs an alternate strategy: either a codex `CODEX_REFRESH_DISABLED` env var, a minimum-codex-version check that exits early on codex self-refresh, or an upstream patch.
**Consequences:** If the invariant does not hold, cross-terminal contention will reproduce openai/codex#10332 for csq users. This is a must-verify-not-an-assumption item before the first Codex PR lands.

## Status summary

ADR-C01 through C14 Accepted pending human approval at the /todos gate. ADR-C15 is Open (verification blocker on PR1). No superseded records.
