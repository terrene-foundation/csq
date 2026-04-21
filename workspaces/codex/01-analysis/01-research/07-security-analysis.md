---
type: RISK
date: 2026-04-21
created_at: 2026-04-21T00:00:00Z
author: agent
session_id: codex-analyze
session_turn: 7
project: codex-integration
topic: Security posture for csq × Codex native-CLI integration
phase: analyze
tags: [security, codex, oauth, keychain, threat-model, redaction]
---

# Codex Integration — Security Analysis

Authority: security-reviewer, /analyze phase. Scope: Codex surface only; the Claude Code surface is already covered by existing rules, specs 01/02/06, and journals 0006–0014, 0052.

---

## 1. Asset Inventory

| Asset                                                      | Class                    | Storage (canonical)                                                     | Storage (handle dir)                         | In-memory                                             | TTL                  | Rotation            | Redaction surface                                           |
| ---------------------------------------------------------- | ------------------------ | ----------------------------------------------------------------------- | -------------------------------------------- | ----------------------------------------------------- | -------------------- | ------------------- | ----------------------------------------------------------- |
| ChatGPT OAuth `access_token` (JWT)                         | **CRITICAL**             | `credentials/codex-<N>.json` (0400 outside refresh, 0600 during)        | Symlink ONLY, never a copy (spec 07 INV-P01) | `SecretString` in `tokio::sync::Mutex` during refresh | ~1h                  | Daemon refresher    | MUST be covered by `redact_tokens`                          |
| ChatGPT `refresh_token`                                    | **CRITICAL, single-use** | Same file as above                                                      | Same symlink                                 | Same                                                  | Long-lived, rotating | Refresher only      | MUST be covered                                             |
| `id_token` (OIDC JWT)                                      | **HIGH**                 | Same file                                                               | Same symlink                                 | Same                                                  | Same as access       | With refresh        | MUST be covered                                             |
| `wham/usage` response body                                 | MEDIUM                   | Parsed into `quota.json` v2; raw last-known-good cached for diagnostics | n/a                                          | Transient                                             | 5 min poll cycle     | n/a                 | Raw body may contain account id / email — redact before log |
| `state` token + PKCE verifier (device-auth flow)           | **HIGH (single-use)**    | In-memory only during `codex login` device-auth                         | n/a                                          | Parent `codex` process owns                           | One flow             | Per flow            | Structural defense only — no stable prefix                  |
| Pre-existing macOS keychain residue `com.openai.codex`     | HIGH                     | User's login keychain (pre-csq)                                         | n/a                                          | n/a                                                   | User-managed         | Prompt-driven purge | Never surface the value in logs                             |
| `config.toml` (`cli_auth_credentials_store = "file"`)      | LOW (integrity)          | `config-<N>/config.toml` (0600)                                         | Symlink                                      | n/a                                                   | Permanent            | n/a                 | Not secret, but tamper-detect-worthy                        |
| ChatGPT account identifier (email, plan) from `wham/usage` | MEDIUM PII               | `quota.json` (if stored)                                                | n/a                                          | n/a                                                   | Cached               | Poll                | Redact in logs                                              |

**Note on handle-dir storage:** `term-<pid>/auth.json` is ALWAYS a symlink into `credentials/codex-<N>.json`. The handle dir itself holds zero canonical secret bytes. This is load-bearing — openai/codex#15502 shows that any code path that _copies_ auth.json between CODEX_HOMEs breaks refresh.

---

## 2. Threat Model

| Attacker layer                                                                 | Can they reach Codex credentials today?                                                                                                                                                                                                                                                                                                                                                            | Residual                                                                                         |
| ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| **Same-UID process** reading handle-dir symlinks                               | Yes — symlinks resolve to `credentials/codex-<N>.json`. Mode 0400 outside refresh still allows same-UID read.                                                                                                                                                                                                                                                                                      | This is the baseline threat model csq already accepts (same as Anthropic).                       |
| **Different-UID process** (multi-user Mac, shared dev box)                     | Blocked by 0400/0600 file mode + per-user `~/.claude/accounts/`.                                                                                                                                                                                                                                                                                                                                   | SO_PEERCRED on daemon socket closes the IPC vector.                                              |
| **Same-user non-Codex process** (malicious MCP server in another CLI)          | Reads `credentials/codex-<N>.json` directly — not an IPC bypass; it's the same trust boundary.                                                                                                                                                                                                                                                                                                     | Out of scope per threat model. Keychain purge + file mode is the mitigation.                     |
| **Network-adjacent / localhost**                                               | Codex itself binds a localhost redirect during device-auth. Verified: `codex login --device-auth` uses device-code flow primarily, but the fallback `codex login` (web) binds an ephemeral loopback. csq does NOT run its own listener for Codex. The daemon's existing TCP route (127.0.0.1:8420) serves ONLY `/oauth/callback` for Anthropic with CSPRNG state; Codex MUST NOT share this route. | Codex handles its own callback; csq stays out of the network path.                               |
| **Adversarial browser during OAuth**                                           | Device-auth exchanges a short code, not a redirect. Lower browser-side risk than Anthropic's PKCE+redirect flow.                                                                                                                                                                                                                                                                                   | Still: the browser sees the ChatGPT session cookie — that cookie is OpenAI's concern, not csq's. |
| **Log aggregators / telemetry / crash reporters**                              | Rust panic handler + tracing layer both go through `redact_tokens`. Codex tokens (`sess-*`, JWT shape) NOT yet in the allowlist — **gap**.                                                                                                                                                                                                                                                         | PR1 must extend the redactor before first log line ships.                                        |
| **Subprocess env leakage** — codex runs shells, git, etc. on the user's behalf | Codex inherits csq's injected `CODEX_HOME` and forwards to its children. **Risk**: if csq injects any other secret into the env (e.g., an API key for future telemetry), codex's shell tools would see it.                                                                                                                                                                                         | csq MUST inject ONLY `CODEX_HOME` for Codex slots. No secret env vars.                           |

---

## 3. Defense Layers Per Asset

### 3.1 Filesystem

- **Mode**: `credentials/codex-<N>.json` is 0400 outside refresh windows, 0600 during (spec 07 §7.3.3 step 5). Implemented via `platform::fs::secure_file` (csq-core/src/platform/fs.rs:22). The 0400→0600→0400 transition needs a fresh helper; `secure_file` currently sets 0600 only. **Add `secure_file_readonly()` = 0o400** for the post-refresh transition.
- **Atomic replace**: spec 06 §6.4.1 and `platform::fs::atomic_replace` (csq-core/src/platform/fs.rs:41) are reused as-is. No Codex-specific work needed; the Codex write path MUST go through `cred_file` helpers identical to Anthropic (`csq-core/src/credentials/file.rs`).
- **flock**: the daemon's per-account `tokio::sync::Mutex` is in-process. The on-disk `refresh-lock` file pattern that Anthropic uses (journal reference in refresher.rs:19) MUST be reused for Codex — the codex CLI itself could refresh in-process if the daemon crashes mid-flow and a user spawns `codex` directly against `config-<N>`. INV-P02 (daemon is hard prerequisite) closes this but the flock is the belt to the daemon-gate suspender.

### 3.2 Keychain escalation defense — `cli_auth_credentials_store = "file"` enforcement

This is the thinnest defense line. The enforcement chain:

1. **Write order (spec 07 §7.3.3, INV-P03)**: `config.toml` is written BEFORE `codex login` spawns. Integration test must lock this ordering.
2. **Post-login tamper check**: after `codex login` returns, csq reads `config-<N>/config.toml` and asserts `cli_auth_credentials_store = "file"` is still present. If codex wrote a competing entry or the user hand-edited between steps, csq refuses and re-seeds.
3. **Daemon startup sweep**: on daemon start, for every Codex-surface account, re-read `config.toml` and re-assert the invariant. If a user opened the file in an editor and saved `cli_auth_credentials_store = "keychain"`, the daemon rewrites it back — with a WARN journal entry.
4. **Keychain residue probe (spec 07 §7.3.3 step 6)**: probes `security find-generic-password -s com.openai.codex` on first Codex login per machine. Offers purge. This closes the "user ran codex before csq" vector.

**What prevents a hand-edit between daemon ticks?** Nothing prevents the edit, but the next poller tick (≤5 min) restores the invariant. A user determined to use the keychain would have to kill the daemon — which INV-P02 also blocks (`csq run` refuses).

### 3.3 Redaction

**Current state** (`csq-core/src/error.rs:81`): `KNOWN_TOKEN_PREFIXES` covers only `sk-ant-oat01-` and `sk-ant-ort01-`. Codex tokens use `sess-*` and JWT shapes (`eyJ...` base64 triplet). Neither is caught today.

**PR1 requirement** — extend `KNOWN_TOKEN_PREFIXES` with:

- `sess-` (OpenAI session token prefix)
- JWT pattern: three base64url segments separated by `.` — regex `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`

**Test plan for the redactor extension:**

1. Unit: each new prefix round-trips through `redact_tokens` and outputs `[REDACTED]`. Golden values: `sess-abcdef1234567890abcdef`, a fake JWT whose payload decodes to `{"sub":"user_csq_test"}`.
2. Negative: short `sess-` (≤5 char body) is NOT redacted — avoids false positives on "session-id" strings.
3. Mixed: a single error body containing both an Anthropic `sk-ant-oat01-*` and a Codex `sess-*` redacts both independently (verifies non-greedy).
4. `error_description` field containing a JWT — redact the JWT but preserve the surrounding RFC 6749 error type (journal 0052 tightening proposal). Requires the `extract_oauth_error_type` re-insertion pass.
5. Fuzz: 10k random bytes through `redact_tokens`; assert no panic, bounded output length growth.

### 3.4 IPC

Unchanged from Anthropic — spec 04 + journal 0006 (three-layer socket hardening) + SO_PEERCRED / LOCAL_PEERCRED. Codex adds no new IPC routes; quota for Codex slots is served over the same Unix socket `/v1/state` / `/v1/quota` endpoints with `surface: "codex"` in the response.

### 3.5 Subprocess env isolation

**Finding**: Codex runs shell tools on the user's behalf (bash, git, `cargo`, etc.) and inherits the parent's environment by default. Blast radius of a malicious codex-invoked subprocess is: **full user-level access, plus whatever csq injected into codex's env**.

**Rule**: csq MUST inject ONLY `CODEX_HOME=<handle-dir>` into the codex child. Specifically:

- MUST NOT inject `CSQ_DAEMON_SOCKET` or `CSQ_*` into the codex child unless explicitly needed.
- MUST NOT inherit `ANTHROPIC_*` / `GEMINI_*` / `OPENAI_API_KEY` from the csq spawning environment into codex. A user with `OPENAI_API_KEY` in their shell would have codex's subprocesses leak it. `Command::env_clear()` + explicit re-add of PATH, HOME, SHELL, TERM, USER, LANG, LC\_\*, and `CODEX_HOME`.
- If telemetry env is ever added, it is csq-process-local, never exported to children.

**Existing Anthropic pattern**: the `claude` spawn path already uses a minimal env. The Codex spawn path MUST NOT regress this.

---

## 4. Token-in-Error-Message Risk (Journal 0007/0010 analog)

**Status: UNKNOWN for Codex endpoints. Investigation required before PR4 (quota poller) merges.**

Anthropic's `invalid_grant` response was observed echoing a refresh-token prefix into `error_description` (journal 0007). Codex hits a different endpoint family:

- OAuth refresh: `auth.openai.com/oauth/token` (device-auth flow for `--device-auth`; ChatGPT session-backed for the web flow).
- Usage poll: `chatgpt.com/backend-api/wham/usage`.

**Investigation steps (MUST complete before daemon refresher lands for Codex):**

1. Craft three deliberately-bad refresh requests against a sandbox Codex account:
   - Expired `refresh_token`.
   - Tampered `refresh_token` (last char flipped).
   - Valid `refresh_token` but wrong `client_id`.
2. Capture the full response body. Verify whether `error_description` or any other field echoes the submitted token.
3. If ANY echo is observed, the structural defense must hold: every error-body use in `csq-core/src/credentials/refresh.rs` (Codex path) MUST pass through `sanitize_body`, and the refresher MUST use `error_kind_tag` (csq-core/src/error.rs:260) for log lines, not `Display`.
4. Document findings in journal as `NNNN-DISCOVERY-codex-error-body-echo.md`.

Absent this investigation, treat the echo risk as PRESENT and route all Codex OAuth error formatting through `redact_tokens` as a prior.

---

## 5. Rule 9 Compliance — CRLF Validation

The Codex polling path SHOULD use a typed HTTP client. Two options, ranked:

1. **Preferred**: reuse `csq-core`'s existing HTTP transport (the Node.js subprocess transport from journal 0056, required for Anthropic Cloudflare JA3/JA4 bypass). ChatGPT endpoints ALSO sit behind Cloudflare, so the Node transport is likely mandatory — verify in investigation step 4.1. Node's `fetch` does its own header validation, so CRLF is structurally blocked.
2. **Fallback**: `reqwest` typed builder — no string interpolation; CRLF is rejected by `HeaderValue::from_str`.
3. **BLOCKED**: hand-rolled HTTP string interpolation into request lines. If any code path reaches this (e.g., a curl subprocess shortcut for debugging), it MUST validate `\r` and `\n` at runtime per rule 9, not `debug_assert!`.

If curl-subprocess is used for any Codex endpoint (same reason as Anthropic: Cloudflare fingerprinting), argument sanitization rules:

- Every string passed to `Command::arg` is a single argv token — no shell quoting, no `sh -c`.
- URL is constructed via `url::Url` parser, not `format!`.
- Headers are passed as `-H "Name: Value"` argv tokens; value MUST be `\r\n`-free (assert via `validate_path_and_query` analog).

---

## 6. Per-Account Isolation Invariants

**Codex keychain-entry hashing** (research finding): when `cli_auth_credentials_store` defaults to keychain, Codex derives a per-CODEX_HOME service name: `cli|<sha256(canonical CODEX_HOME)[:16]>` under `KEYRING_SERVICE = "Codex Auth"`. Two CODEX_HOMEs → two different entries. This is NOT our defense — we force file mode — but it means:

**If the file-mode invariant fails** (a user-edited `config.toml`, a codex version bump that changes default behavior), accounts would still be isolated by the per-hash service name. This is a belt to the file-mode suspender; it should be acknowledged, not relied on.

**What if a code path mutates CODEX_HOME mid-session?**

- `codex` does not support mid-session CODEX_HOME changes; it reads the env at startup.
- csq's `csq swap` within a Codex terminal is a cross-surface `exec` replacement (INV-P05) — the new process starts fresh.
- Same-surface Codex→Codex swap repoints the handle dir's `auth.json` symlink. The running codex process holds an open file descriptor? **Verify in research**: if codex caches the token in memory after first read, symlink repoint has zero effect until codex re-stats (matches CC's mtime reload pattern per spec 01 §1.4, but unconfirmed for codex). If codex does NOT re-stat, we need an IPC-to-codex kill signal — out of scope for v1, document in invariants.

**Per-account flock + 0400-outside-refresh isolation:**

- Two daemons (shouldn't happen — M8.1 single-daemon guarantee) racing the same account: flock serializes.
- Daemon + user-manual `codex` invocation: INV-P02 hard-refusal of `csq run` + a README note. If a user bypasses csq and runs bare `codex` pointing at `config-<N>/`, the daemon still refreshes; codex's in-process refresh would corrupt per openai/codex#10332. We cannot prevent the user running codex manually — we can document, and the flock provides partial safety.

---

## 7. Attack Tree — "Attacker gains token for account N"

```
ROOT: Attacker holds valid ChatGPT access+refresh token for account N
│
├── L1: Read credentials/codex-N.json directly
│    ├── Same-UID process (baseline threat, accepted)
│    │   Mitigation: same-UID trust model; 0400 out-of-window makes read race harder
│    │   Likelihood: HIGH if user runs malware; Impact: HIGH
│    └── Different-UID process
│        Mitigation: 0400/0600 file mode + ~/.claude/accounts/ dir mode
│        Likelihood: LOW; Impact: HIGH
│
├── L2: Steal during refresh race
│    ├── Two refreshers writing simultaneously
│    │   Mitigation: daemon per-account tokio::sync::Mutex + on-disk flock
│    │   Likelihood: LOW; Impact: HIGH (refresh-token invalidation)
│    └── TOCTOU on the 0400↔0600 transition (window: ~200ms)
│        Mitigation: write to tmp file at 0600, atomic_replace, then chmod 0400
│        Likelihood: LOW; Impact: MEDIUM
│
├── L3: Scrape from logs
│    ├── tracing layer logs error body with echoed token
│    │   Mitigation: redact_tokens extended for sess-*/JWT; error_kind_tag for log tags
│    │   Likelihood: MEDIUM pre-fix, LOW post-fix; Impact: HIGH
│    └── Crash reporter catches panic payload containing SecretString::expose_secret()
│        Mitigation: SecretString Display = [REDACTED]; no expose_secret() in error paths
│        Likelihood: LOW; Impact: HIGH
│
├── L4: Error-body echo (journal 0007 class)
│    ├── auth.openai.com echoes refresh_token in error_description
│    │   Mitigation: investigation step above; sanitize_body wraps every body use
│    │   Likelihood: UNKNOWN → treat as MEDIUM; Impact: HIGH
│    └── wham/usage echoes token in 4xx body
│        Mitigation: same redaction pipeline
│        Likelihood: LOW; Impact: HIGH
│
├── L5: Env leak to subprocess
│    ├── codex child process inherits csq env containing secret
│    │   Mitigation: Command::env_clear() + allowlist (§3.5)
│    │   Likelihood: MEDIUM if the code isn't careful; Impact: HIGH
│    └── codex passes CODEX_HOME to its own subprocess (git, etc.) which then reads auth.json
│        Mitigation: same-UID trust; codex's own responsibility, not ours
│        Likelihood: LOW; Impact: HIGH
│
├── L6: Keychain escalation
│    ├── cli_auth_credentials_store flipped to "keychain"
│    │   Mitigation: post-login assert + daemon-tick re-write
│    │   Likelihood: LOW (needs hand-edit); Impact: MEDIUM (tokens isolated per CODEX_HOME hash)
│    └── Pre-existing com.openai.codex keychain entry from before csq
│        Mitigation: first-run probe + purge modal (spec 07 §7.3.3 step 6)
│        Likelihood: MEDIUM on upgrade; Impact: MEDIUM
│
├── L7: IPC compromise
│    ├── Unix socket different-UID connect
│    │   Mitigation: SO_PEERCRED/LOCAL_PEERCRED (spec rule 7)
│    │   Likelihood: LOW; Impact: HIGH
│    └── TCP 8420 accepting Codex traffic
│        Mitigation: TCP route is ONLY /oauth/callback for Anthropic; Codex uses device-auth (no loopback listener needed)
│        Likelihood: LOW; Impact: HIGH
│
└── L8: Symlink-stat TOCTOU on handle dir
     ├── Attacker swaps term-<pid>/auth.json → attacker-controlled file between csq's check and codex's read
     │   Mitigation: handle-dir parent is 0700; attacker must be same-UID; already in baseline threat
     │   Likelihood: LOW; Impact: MEDIUM
     └── Daemon sweep of handle dirs dereferences symlinks and deletes codex-sessions/
         Mitigation: spec 07 INV-P04 — sweep MUST NOT deref
         Likelihood: MEDIUM if INV-P04 not tested; Impact: LOW (user data, not credentials)
```

---

## 8. Pre-Commit Security Gates Per PR

Per `zero-tolerance.md` rule 5 (no residual risks journaled as "accepted"), every finding above LOW in any of these gates MUST be fixed in the same PR that introduces it, not deferred.

**PR1 — Surface refactor (Anthropic → Surface::ClaudeCode)**

- Regression: existing `redact_tokens` tests unchanged and pass.
- No new assets; no new threat surface. Security gate: intermediate-reviewer only.

**PR2 — `providers::codex` module (login + config.toml pre-seed)**

- MUST: `redact_tokens` extended for `sess-*` + JWT, tests green.
- MUST: write-order test asserts `config.toml` written BEFORE `codex login` process spawn.
- MUST: post-login assert on `cli_auth_credentials_store = "file"`.
- MUST: `Command::env_clear()` + allowlist for codex child spawn.
- MUST: keychain residue probe implemented + modal wired.
- Gate: security-reviewer + tauri-platform-specialist.

**PR3 — Daemon refresher Codex path**

- MUST: complete §4 investigation + journal entry on error-body echo.
- MUST: all error formatting uses `sanitize_body` / `error_kind_tag`; zero `{e}` in log macros in the Codex path.
- MUST: per-account `tokio::sync::Mutex` + on-disk `refresh-lock` file.
- MUST: 0400↔0600 transition implemented via tmp-file atomic-replace, not in-place chmod.
- MUST: refresh failure goes through `OAuthError::Exchange` wrapper → `sanitize_body`, not raw.
- Gate: security-reviewer + rust-specialist.

**PR4 — Quota poller `wham/usage`**

- MUST: versioned parser; schema-drift degrades to `kind: "unknown"`, raw body cached after redaction.
- MUST: poll request uses typed HTTP builder (Node transport or `reqwest`), no string interpolation. If curl-subprocess, CRLF validation + argv separation verified.
- MUST: 429/5xx response bodies pass through `redact_tokens` before log.
- MUST: raw last-known-good cache file is 0600 and passes through `redact_tokens` before persist.
- Gate: security-reviewer + daemon-architecture skill consultation.

**PR5 — Desktop AddAccountModal + ChangeModelModal**

- MUST: no Codex credential fields on any `#[derive(Serialize)]` Tauri response (IPC payload audit per `tauri-commands.md` MUST rule 3).
- MUST: ToS acceptance timestamp is persisted locally, never sent off-box.
- MUST: ChangeModelModal's fetch of `chatgpt.com/backend-api/codex/models` uses the same typed transport; 1.5s timeout.
- Gate: security-reviewer + svelte-specialist.

**Convergence gate** — a separate `/redteam` round after PR3 ships, covering the complete Codex path end-to-end with fresh eyes. Findings above LOW are resolved in the same session per zero-tolerance.md rule 5.

---

## References

- csq-core/src/error.rs:44 — `extract_oauth_error_type` allowlist pattern to emulate for any Codex-specific type extraction
- csq-core/src/error.rs:81 — `KNOWN_TOKEN_PREFIXES` — extension point for `sess-` + JWT
- csq-core/src/error.rs:260 — `error_kind_tag` — use this for every Codex log line tag
- csq-core/src/platform/fs.rs:22 — `secure_file`; need `secure_file_readonly` sibling for 0400
- csq-core/src/platform/fs.rs:41 — `atomic_replace` reused as-is
- csq-core/src/daemon/refresher.rs:65 — refresher scaffold; Codex extension hooks here
- specs/06-keychain-integration.md §6.4 — write-path guards; reuse for Codex writes
- specs/07-provider-surface-dispatch.md §7.5 INV-P01..P07 — authoritative invariants
- rules/security.md MUST rules 2, 4, 5, 6, 7, 8, 9 — all apply to the Codex path unchanged
- Journal 0006 — three-layer socket hardening
- Journal 0007 — error-body token echo
- Journal 0010 — `redact_tokens` scope boundary (why PKCE verifiers rely on structural defense)
- Journal 0011 — OAuth dual-listener; Codex does NOT gain a new TCP route
- Journal 0052 — diagnostic redaction vs. defense balance; allowlist of RFC 6749 error-type strings

## For Discussion

1. **Error-body echo investigation**: §4 treats the risk as PRESENT until proven absent. Should PR3 block on completing the investigation, or is it acceptable to ship PR3 with structural defenses only (sanitize_body everywhere) and file the investigation as a follow-up in the same session? The tradeoff is tight scheduling vs. knowing whether we have a real leak.

2. **Counterfactual on cli_auth_credentials_store enforcement**: if we could not re-write `config.toml` on daemon tick (e.g., the user has the file open in an editor with a file lock), would the per-CODEX_HOME hash isolation in `KEYRING_SERVICE` be sufficient fallback? Spec 07 treats the file-mode invariant as non-negotiable (§7.0 rationale: prevents cross-account contamination). What contamination mode does the per-hash isolation leave open?

3. **Evidence for env_clear blast radius**: the analysis claims codex's subprocesses inherit the parent env. Before implementing `env_clear() + allowlist`, PR2 should spawn codex under a known env and inspect a child process's `/proc/<pid>/environ` (Linux) or equivalent macOS introspection. If codex already scrubs, our clearing is belt-and-suspenders; if it doesn't, this is the primary defense. Which is it?
