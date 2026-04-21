---
type: RISK
date: 2026-04-21
created_at: 2026-04-21T00:00:00Z
author: agent
session_id: gemini-analyze
session_turn: 7
project: gemini-integration
topic: Security posture for csq × Gemini native-CLI integration (API-key only)
phase: analyze
tags: [security, gemini, api-key, vertex, threat-model, redaction, tos]
---

# Gemini Integration — Security Analysis

Authority: security-reviewer, `/analyze` phase. Scope: Gemini surface only (API-key only, OAuth explicitly out of scope per Google ToS; see brief 01-vision §Non-goals). Pair document: `workspaces/codex/01-analysis/01-research/07-security-analysis.md`.

---

## 1. Asset Inventory

| Asset                                                                                       | Class                    | Canonical storage                                                                                           | Handle dir                              | In-memory                                               | TTL                                                   | Rotation                                      | Redaction                                                            |
| ------------------------------------------------------------------------------------------- | ------------------------ | ----------------------------------------------------------------------------------------------------------- | --------------------------------------- | ------------------------------------------------------- | ----------------------------------------------------- | --------------------------------------------- | -------------------------------------------------------------------- |
| AI Studio API key (`AIza[0-9A-Za-z_-]{35}`)                                                 | **CRITICAL**             | `config-<N>/gemini-key.enc` (0600, encrypted at rest)                                                       | Not present — injected via env at spawn | `SecretString`; decrypted only in the daemon spawn path | Long-lived until user rotates in Google Cloud console | User-driven; csq does not refresh             | MUST extend `redact_tokens`                                          |
| Vertex service-account JSON (RSA PRIVATE KEY + `client_email` + `project_id`)               | **CRITICAL**             | `config-<N>/vertex-sa.enc` (0600) — csq copies + encrypts content at provision time; never a path reference | Not present                             | `SecretString` wrapper around the decrypted JSON bytes  | Long-lived                                            | User rotates via gcloud; csq prompts re-paste | MUST extend redaction                                                |
| `GEMINI_API_KEY` in child-process env                                                       | **CRITICAL** (transient) | n/a — process-env only                                                                                      | Set on gemini child                     | Lives in kernel env page until gemini exits             | Duration of child process                             | n/a                                           | Never logged; `env_clear()` guards siblings                          |
| `config-<N>/.gemini/settings.json` (`security.auth.selectedType = "gemini-api-key"`)        | LOW (integrity)          | `config-<N>/.gemini/settings.json` (0644 OK; no secret content)                                             | Symlinked                               | n/a                                                     | Permanent                                             | Daemon re-asserts invariant                   | Not secret but tamper-detect-worthy                                  |
| `effective-model` response payload                                                          | MEDIUM                   | `quota.json` v2 `surface: "gemini"` record                                                                  | n/a                                     | Transient                                               | Poll cycle                                            | n/a                                           | JSON body may contain request IDs / account tags — redact before log |
| 429 `RESOURCE_EXHAUSTED` body (`quotaMetric`, `retryDelay`)                                 | MEDIUM (fingerprint)     | Parsed to `quota.json`; raw last-known-good cached (redacted)                                               | n/a                                     | Transient                                               | Poll cycle                                            | n/a                                           | Redact before persist to raw-cache                                   |
| Pre-existing `~/.gemini/oauth_creds.json` (OAuth residue from user running bare gemini-cli) | HIGH (ToS trap)          | User's home; pre-csq                                                                                        | n/a                                     | n/a                                                     | User-managed                                          | Probe + refuse / purge modal                  | Presence is diagnostic; value never logged                           |

**Load-bearing: no refresh surface.** API keys are flat and long-lived; there is no `/oauth/token` endpoint for csq to hit, no refresh-token single-use race (openai/codex#10332 class), and no keychain escalation vector analogous to the Codex `cli_auth_credentials_store` problem. The entire "in-process vs. daemon refresher" invariant lattice from INV-P01/P02 (spec 07) is a no-op for Gemini. Correspondingly, every defense is concentrated on **at-rest protection + process-env hygiene + ToS enforcement**.

---

## 2. Threat Model

| Attacker layer                                                | Reachability of Gemini key today                                                                                                                                                                                                                                                                                                                        | Residual                                                                                                                                       |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Same-UID process reading `config-<N>/gemini-key.enc`          | **File is encrypted.** Reader must also retrieve the wrapping key (macOS Keychain service `Terrene csq Gemini` / Linux libsecret collection / Windows DPAPI user scope). Same-UID can call the OS unlock API the same way csq does → effectively equivalent to 0600 plaintext on same-UID trust model.                                                  | Baseline same-UID trust; keychain wrap adds friction (malware must call `SecItemCopyMatching`), does not block a determined same-UID attacker. |
| Different-UID process (multi-user Mac / shared dev box)       | Blocked at TWO layers: file mode 0600 AND macOS Keychain ACL bound to the writing app's code-signature + login keychain of the writing user. Different-UID cannot unwrap.                                                                                                                                                                               | Strong.                                                                                                                                        |
| Gemini child spawning a shell tool (bash, grep, node via MCP) | Child inherits `GEMINI_API_KEY` unless gemini-cli explicitly scrubs before fork. **Assumed NOT scrubbed** — no documented scrub in gemini-cli source, and shell tools need an env to function. MUST mitigate in csq by keeping env allowlist minimal so the blast radius = one key, not a bag of secrets.                                               | MEDIUM residual; accepted as same-UID baseline unless shell subprocess can be observed exfiltrating.                                           |
| `.env` discovery bypassing csq injection                      | gemini-cli walks `$CWD → ancestors → $GEMINI_CLI_HOME → $HOME` and short-circuits on the first `.env` found (gemini-cli#21744). If the user's `$CWD` contains an old `.env` with `GEMINI_API_KEY=AIza<old>`, that wins over csq's process-env injection — **UNVERIFIED**, see §4.                                                                       | High-impact if precedence inverts; must verify.                                                                                                |
| Log aggregators / crash reporters / tracing                   | `redact_tokens` today has zero coverage for `AIza*` or PEM blocks. Any `warn!("{e}")` in the Gemini path currently leaks on first error.                                                                                                                                                                                                                | Blocks PR until §5 extension lands.                                                                                                            |
| Adversarial `~/.gemini/oauth_creds.json`                      | A file placed by a prior bare gemini-cli session (user-installed) could trick setup code into the OAuth path and get the slot permanently ToS-banned. Also: if a malicious process on same-UID writes `oauth_creds.json` into `config-<N>/.gemini/`, and gemini-cli prefers OAuth over api-key when both are present, we have a silent cross-auth flip. | MUST detect + refuse; see §6.                                                                                                                  |
| Clipboard scraping during paste                               | User pastes `AIza...` into the AddAccountModal → Tauri IPC channel → Rust state. Clipboard managers persist entries.                                                                                                                                                                                                                                    | Out of csq's control; document in UI copy ("clear clipboard after paste").                                                                     |
| Memory dump during spawn                                      | Key is briefly plaintext `SecretString` in the spawn code path; immediately handed to `Command.env(...)` which writes into the kernel env page. Post-spawn the parent drops the `SecretString`; child holds it in its own process memory.                                                                                                               | Same-UID trust; `SecretString` zeroes on drop in parent.                                                                                       |

---

## 3. Defense Layers Per Asset

### 3.1 Filesystem

- `config-<N>/gemini-key.enc` and `config-<N>/vertex-sa.enc`: 0600 via `platform::fs::secure_file` (`csq-core/src/platform/fs.rs:22`).
- Writes are atomic via `platform::fs::atomic_replace` (`csq-core/src/platform/fs.rs:41`). Required by `rules/security.md` MUST rule 4.
- `.gemini/settings.json`: 0644 acceptable (no secret content), but atomic_replace still used to prevent torn pre-seed on crash.
- `gemini-state/` persistent dir (spec 07 §7.2.3): 0700; contains `shell_history` which MAY contain user-typed secrets → must be mode-locked and NOT ingested by csq's diagnostic collector.

### 3.2 Encryption-at-rest (the new primitive Gemini introduces)

| Platform | Mechanism                                                                                                                               | Service/Account/Scope                                  | Library                                                                                                      |
| -------- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| macOS    | Generic password item in user's login keychain, wrapping a 256-bit AES-GCM data key. File content = `nonce(12) ‖ ciphertext ‖ tag(16)`. | service=`Terrene csq Gemini`, account=`csq-gemini-<N>` | `security-framework` crate (same as spec 01 §1.7 native migration; NO shell-out to `security` for this path) |
| Linux    | libsecret collection `Login`, schema `foundation.terrene.csq.Gemini`, attribute `account=<N>`. Data key wraps the file.                 | libsecret schema attr                                  | `secret-service` crate                                                                                       |
| Windows  | DPAPI user scope (`CryptProtectData` with `CRYPTPROTECT_UI_FORBIDDEN`). Data key wraps. No separate credential store entry needed.      | User scope                                             | `win32-security` / `windows` crate                                                                           |

Citations required at implementation time; shape above is the target contract. Any drift documented in a journal entry + spec 06 amendment.

**Why wrap the file with a keychain-held key rather than store the key directly in the keychain?** The AI Studio key can exceed sensible secret sizes if pasted as a JSON blob (Vertex service-account case: ~2.3 KB with PEM). Keychain items have size limits and sync quirks. Wrapping gives us: (a) small fixed-size data key in the keychain, (b) arbitrary-size ciphertext on disk, (c) atomic replace semantics on ciphertext rotation, (d) one keychain entry per slot, not one per field.

### 3.3 Process-env hygiene — `Command::env_clear()` + allowlist

The gemini child spawn MUST call `Command::env_clear()` and re-add ONLY:

| Var                                     | Why                                                                       |
| --------------------------------------- | ------------------------------------------------------------------------- |
| `PATH`                                  | Binary resolution                                                         |
| `HOME`                                  | User-dir resolution for anything gemini touches outside `GEMINI_CLI_HOME` |
| `USER`, `LOGNAME`                       | Git commit author, shell prompts                                          |
| `SHELL`                                 | Gemini shell-tool invocation (bash)                                       |
| `TERM`                                  | TTY rendering                                                             |
| `LANG`, `LC_ALL`, `LC_*`                | Locale                                                                    |
| `TZ`                                    | Time                                                                      |
| `GEMINI_CLI_HOME`                       | csq's isolation primitive — MUST be set to the handle dir                 |
| `GEMINI_API_KEY`                        | The secret itself — injected only for this child                          |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | Corporate proxy support (opt-in pass-through)                             |
| `SSL_CERT_FILE`, `SSL_CERT_DIR`         | Corporate TLS roots                                                       |
| `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`     | Linux standard dirs (pass-through; gemini-cli may honor)                  |

**Forbidden pass-throughs (common foot-guns):**

- `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME` — sibling-provider secrets leaking into a gemini tool subprocess.
- `CSQ_*` — daemon socket path, internal tokens.
- `AWS_*`, `GCP_*`, `GOOGLE_APPLICATION_CREDENTIALS` — the Vertex JSON path env. **Important**: do NOT set `GOOGLE_APPLICATION_CREDENTIALS` for Vertex slots; Vertex auth is via explicit library init with decrypted JSON bytes, not env. Setting this env would make the Vertex JSON visible to every child tool.
- `TELEMETRY_*`, `SENTRY_*`, `DD_*`.

### 3.4 Vertex service-account handling

- Vertex JSON MUST NOT be stored by path reference anywhere in csq state (`settings.json`, `profiles.json`, daemon state). User moves/deletes the file and slot breaks silently.
- User pastes or file-selects the JSON; csq **reads, validates shape, encrypts, stores at `config-<N>/vertex-sa.enc`, then unlinks any staging copy**.
- Validation: JSON parses; required keys present (`type == "service_account"`, `private_key` PEM block, `client_email`, `project_id`); `private_key` PEM header exactly `-----BEGIN PRIVATE KEY-----`.
- At spawn: decrypt, materialize a `tempfile::NamedTempFile` at 0600 under `$TMPDIR` (not in the handle dir — handle dir can be inspected by gemini's own tools), set a Vertex-specific env var that gemini-cli honors (if applicable per Vertex mode docs), then delete temp file after spawn. **Verification needed** on whether gemini-cli can consume Vertex creds from in-memory env vs. requires a file path. If file-path only, this temp-file-at-0600 is the compromise.

### 3.5 OAuth lockout enforcement

Per ToS: "third-party software MUST NOT access Gemini CLI's backend services via OAuth." Active 403 enforcement in 2026. Violation → Google Form recertification → permanent ban on second offense.

Three enforcement layers:

1. **Pre-seed** `security.auth.selectedType = "gemini-api-key"` in `config-<N>/.gemini/settings.json` BEFORE first spawn (spec 07 INV-P03). Integration test asserts ordering.
2. **Residue probe**: at `csq login N --provider gemini`, check for `~/.gemini/oauth_creds.json` AND `config-<N>/.gemini/oauth_creds.json`. If either exists, modal asks user to confirm purge before csq provisions API-key mode. User-level residue is offered purge; csq-dir residue is auto-purged (we own it).
3. **Daemon tick re-assertion**: on every poll cycle for Gemini accounts, re-read `settings.json` and assert `selectedType == "gemini-api-key"`. If a user or rogue tool flipped it (or dropped a fresh `oauth_creds.json` into `config-<N>/.gemini/`), rewrite the setting and delete the oauth file with a WARN journal entry.

### 3.6 gemini-cli auth precedence — OPEN QUESTION

**OPEN-G01 (PR-gating):** If both `security.auth.selectedType = "gemini-api-key"` AND `~/.gemini/oauth_creds.json` exist, what does gemini-cli prefer? Two outcomes possible:

- Setting wins → our enforcement chain is sufficient.
- Presence of creds file wins → our enforcement chain is security theater; we need to actively delete user-home oauth files, which is an unacceptable user-data-destroying action.

**Verification method:** construct a test rig with both present; run `gemini -p "ping" --output-format json`; inspect the request auth header (API key → `x-goog-api-key`; OAuth → `Authorization: Bearer`). Journal as `NNNN-DISCOVERY-gemini-auth-precedence.md`. Resolution is a blocker for PR2 (provider module).

---

## 4. `.env` Short-Circuit Defense

**OPEN-G02 (PR-gating):** gemini-cli#21744 confirms `.env` discovery walks `$CWD → ancestors → $GEMINI_CLI_HOME → $HOME` and short-circuits on first hit. Unknown: whether an env var set directly on the process (`Command::env("GEMINI_API_KEY", ...)`) takes precedence over a discovered `.env` file's `GEMINI_API_KEY=` line.

If `.env` wins, csq's process-env injection is a **false sense of security**: a stale `$HOME/.env` containing `GEMINI_API_KEY=AIza<oldkey>` would override the per-slot key csq injected, causing slot 5 to authenticate as slot 2 silently. Cross-slot contamination at the quota level.

**Verification method:** `GEMINI_CLI_HOME=/tmp/x GEMINI_API_KEY=AIza<newkey> gemini -p "whoami" --output-format json` with `/tmp/.env` containing a different key; inspect `modelVersion`/auth header. Journal as `NNNN-DISCOVERY-gemini-env-precedence.md`. Must complete before PR2 ships.

**Defensive posture until verified:** at spawn, csq scans `$CWD`, each ancestor up to `$HOME`, and `$HOME` for a `.env` containing a `GEMINI_API_KEY` line. If found, **warn the user** via modal (desktop) / stderr (CLI) and offer to (a) rename the file out of the way for the session, (b) proceed anyway, (c) abort. Never delete the user's `.env` silently.

---

## 5. Redaction Scope

**Current state** (`csq-core/src/error.rs:81`): `KNOWN_TOKEN_PREFIXES = ["sk-ant-oat01-", "sk-ant-ort01-"]`. Generic `sk-*` with ≥20-char body is also caught. Long-hex (≥32) is caught.

**Gemini extension:**

1. `AIza[0-9A-Za-z_-]{35}` — fixed length AI Studio key. Add `"AIza"` to `KNOWN_TOKEN_PREFIXES` with a 35-char exact body length requirement (not the generic ≥20 rule; `AIza` keys have deterministic length and we want to catch them in any context).
2. PEM private-key block — multi-line region between `-----BEGIN PRIVATE KEY-----` and `-----END PRIVATE KEY-----` (also `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `OPENSSH PRIVATE KEY` as belt-and-suspenders). Replace the whole region with `[REDACTED PEM KEY]`. Multi-line regex; `(?s)` flag; non-greedy match so two blocks in one string are redacted independently.
3. `client_email` shape — `<name>@<project>.iam.gserviceaccount.com`. Medium-PII but not a secret on its own; redact to `[REDACTED SA EMAIL]` when appearing next to a PEM block in the same error body, preserve elsewhere (diagnostic value for "which service account failed").

**Test plan for the extended redactor** (extends the PR1 Codex extension; both lands together or Gemini extension lands separately in Gemini PR2):

1. Unit: `redact_tokens("key=AIzaSyB-1234567890abcdefghij_KLMNOPQRSTUV")` → contains `[REDACTED]`, original key absent.
2. Unit: redact_tokens of a representative Vertex SA JSON (with a synthetic PEM block) → PEM region replaced, `client_email` preserved (different line), `project_id` preserved, other JSON structure intact.
3. Unit: a single error body containing an Anthropic `sk-ant-oat01-*` AND a Gemini `AIza*` AND a Codex JWT — all three redacted independently, no order dependency, no regex-overlap eating siblings.
4. Unit: short string `"AIza"` alone (no body) NOT redacted — false-positive guard on log tags.
5. Unit: `error_description` field containing an `AIza*` — key redacted, surrounding RFC 6749 error type (`invalid_request`) preserved via `extract_oauth_error_type` re-insertion (journal 0052). For Gemini specifically, Google uses `errorMessage`/`code` fields (gRPC-style), NOT RFC 6749 `error`. Add a parallel allowlist for Google error codes (`RESOURCE_EXHAUSTED`, `PERMISSION_DENIED`, `INVALID_ARGUMENT`, `UNAUTHENTICATED`) with the same `&'static str` discipline as `OAUTH_ERROR_TYPES` (`csq-core/src/error.rs:17`).
6. Fuzz: 10k random bytes through extended `redact_tokens`; bounded output; no panics.
7. Golden file: a captured (sanitized) real 429 `RESOURCE_EXHAUSTED` body round-trips through `sanitize_body` with no key leakage.

---

## 6. ToS Enforcement Hardening

Three pathways that could accidentally enable OAuth routing under csq's management:

1. **User pastes OAuth JSON thinking it's an API key.** OAuth creds have shape `{"access_token":..., "refresh_token":..., "expiry":...}`. API key is `AIza...`. Vertex JSON has `"type":"service_account"`. Detect all three shapes at paste time; refuse OAuth shape with a modal explaining ToS. `providers::gemini::capture::classify_paste()` is the single entry point; pasted text never reaches the encrypted store without classification.
2. **Pre-existing `~/.gemini/oauth_creds.json`** from a bare gemini-cli run. §3.5 point 2 handles this: probe + modal + purge.
3. **gemini-cli precedence when selected-type=api-key but oauth file exists.** OPEN-G01 above. If precedence inverts, we MUST delete the oauth file (in csq-owned dirs) OR refuse provisioning (for user-home oauth files, with a clear explanation and a user action to delete manually).

Additional: `csq setkey gemini` CLI command MUST print a one-line ToS reminder on first use per machine: "Gemini integration uses API keys only. OAuth subscription rerouting is prohibited by Google ToS and will result in account suspension." Acceptance captured as a timestamp in local `profiles.json`; never sent off-box.

---

## 7. Attack Tree — "Attacker gains active Gemini API key for slot N"

```
ROOT: Attacker holds valid AIza* for account N (or Vertex SA private key)
│
├── L1: Read config-<N>/gemini-key.enc directly
│    ├── Same-UID process
│    │   Mitigation: encrypted-at-rest; attacker must also call keychain unlock
│    │   Likelihood: MEDIUM if malware present; Impact: HIGH
│    └── Different-UID process
│        Mitigation: 0600 + keychain ACL bound to our code-sig + user login keychain
│        Likelihood: LOW; Impact: HIGH
│
├── L2: Snoop child-process env
│    ├── Same-UID process reads /proc/<gemini-pid>/environ
│    │   Mitigation: 0700 on /proc entry (kernel default for same-UID); no csq defense beyond same-UID trust
│    │   Likelihood: MEDIUM; Impact: HIGH
│    └── Gemini-spawned shell tool leaks env via `env | tee /tmp/x`
│        Mitigation: env_clear + allowlist reduces blast radius to ONE key; user-visible
│        Likelihood: LOW (needs hostile MCP server); Impact: HIGH
│
├── L3: Scrape from logs
│    ├── tracing layer logs error with AIza* echoed in body
│    │   Mitigation: §5 redactor extension; blocks PR until landed
│    │   Likelihood: MEDIUM pre-fix, LOW post-fix; Impact: HIGH
│    └── Crash reporter catches SecretString::expose_secret() in panic payload
│        Mitigation: SecretString Display = [REDACTED]; expose_secret() only at spawn; no panic path touches it
│        Likelihood: LOW; Impact: HIGH
│
├── L4: .env precedence inversion
│    ├── $HOME/.env with stale GEMINI_API_KEY overrides csq injection (OPEN-G02)
│    │   Mitigation: pre-spawn .env scan + modal; abort if unverified
│    │   Likelihood: MEDIUM until verified; Impact: HIGH (wrong-slot auth, quota contamination)
│    └── $CWD/.env written by malicious project
│        Mitigation: same pre-spawn scan covers $CWD
│        Likelihood: LOW; Impact: HIGH
│
├── L5: CI log / aggregator leak
│    ├── `csq run` in CI with verbose tracing + key in backtrace
│    │   Mitigation: default log level INFO; redactor on all error paths; no expose_secret in Debug
│    │   Likelihood: LOW; Impact: HIGH
│    └── `csq setkey` echoes key in shell history
│        Mitigation: read key from stdin (`--stdin` flag), never argv; refuse argv form
│        Likelihood: MEDIUM if user passes via argv; Impact: HIGH
│
├── L6: OAuth lockout bypass (ToS violation path)
│    ├── Pre-existing ~/.gemini/oauth_creds.json trips gemini-cli into OAuth mode despite selectedType
│    │   Mitigation: residue probe + modal; daemon re-assertion tick
│    │   Likelihood: MEDIUM on upgrade from bare gemini-cli users; Impact: HIGH (account ban, data loss)
│    └── Malicious process writes oauth_creds.json into config-<N>/.gemini/
│        Mitigation: daemon tick detects + deletes; settings.json re-asserted
│        Likelihood: LOW; Impact: HIGH
│
├── L7: Clipboard scrape during paste
│    ├── OS clipboard manager persists the paste
│    │   Mitigation: Out of csq control; UI copy reminds user
│    │   Likelihood: MEDIUM; Impact: HIGH
│    └── Malicious browser extension on the Google Cloud console page
│        Mitigation: out of scope
│        Likelihood: LOW; Impact: HIGH
│
└── L8: Vertex-specific
     ├── GOOGLE_APPLICATION_CREDENTIALS set in parent env leaks SA JSON path to gemini subprocesses
     │   Mitigation: env allowlist excludes it; if Vertex mode requires the env, temp file at 0600 in $TMPDIR, deleted immediately post-spawn
     │   Likelihood: LOW; Impact: HIGH
     └── SA JSON stored as path reference, user moves file
         Mitigation: csq copies+encrypts content at provision; never a path reference
         Likelihood: LOW; Impact: MEDIUM (UX failure, not key leak)
```

---

## 8. Pre-Commit Security Gates Per PR

Gemini PR sequence (lands after Codex, per brief §Ships after):

**PR-G1 — providers::gemini module (capture + encrypt + pre-seed)**

- MUST: `redact_tokens` extended for `AIza*` (35-char body) + multiline PEM block + Google error-code allowlist; unit tests green per §5.
- MUST: `classify_paste` rejects OAuth-shape JSON at the entry point with a ToS-explaining modal.
- MUST: residue probe for `~/.gemini/oauth_creds.json` and `config-<N>/.gemini/oauth_creds.json`; modal wired; user-home path requires explicit user action.
- MUST: `settings.json` pre-seed BEFORE first spawn, integration test asserts ordering (spec 07 INV-P03).
- MUST: encryption-at-rest implemented per §3.2 for the active platform; `gemini-key.enc` and `vertex-sa.enc` mode 0600 via `secure_file`; atomic_replace on write.
- MUST: OPEN-G01 (auth precedence) resolved and journaled; OPEN-G02 (.env precedence) resolved and journaled. PR blocks on both.
- MUST: `csq setkey gemini` reads from stdin; argv form refused.
- Gate: security-reviewer + rust-specialist + tauri-platform-specialist.

**PR-G2 — Spawn path (env_clear + allowlist + key injection)**

- MUST: `Command::env_clear()` at the Gemini spawn site; allowlist per §3.3 explicit in code; test asserts `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_APPLICATION_CREDENTIALS`, `CSQ_*` do NOT reach child.
- MUST: pre-spawn `.env` scan for `GEMINI_API_KEY` in `$CWD` ancestors and `$HOME`; modal/stderr warning; abort path.
- MUST: child-env introspection test on macOS + Linux (read `/proc/<pid>/environ` on Linux; `ps -E` equivalent on macOS) confirming only allowlisted vars present.
- MUST: Vertex temp-file path (if required) uses `$TMPDIR` at 0600 and deletes after spawn; integration test with deliberately-delayed spawn to verify unlink happens.
- MUST: no `{e}`/`{body}` in Gemini-path log macros; all error formatting via `sanitize_body` / `error_kind_tag` (`csq-core/src/error.rs:55`, `:260`).
- Gate: security-reviewer + rust-specialist.

**PR-G3 — Daemon usage poller (counter + 429 parse)**

- MUST: 429 `RESOURCE_EXHAUSTED` body parsed with versioned parser; schema drift → `kind: "unknown"`, raw body persisted ONLY after `redact_tokens`.
- MUST: poll path uses typed HTTP (Node transport or reqwest); no string interpolation into request lines; CRLF validation per `rules/security.md` MUST rule 9.
- MUST: counter state (`quota.json` v2 Gemini records) persisted via `atomic_replace`; monotonicity check on write (spec 02 / existing quota invariants).
- MUST: `daemon::poller::gemini` does NOT read the API key; spawn-side injects and poll uses scoped state only. If poll needs the key (for a test call), acquires it through the same decrypt path as spawn, not through a persistent cache.
- Gate: security-reviewer + daemon-architecture skill consultation.

**PR-G4 — Desktop AddAccountModal + ChangeModelModal**

- MUST: no secret fields on any `#[derive(Serialize)]` Tauri response (`rules/tauri-commands.md` MUST rule 3). `AccountView` audit: `gemini_key_present: bool` OK; `gemini_key_preview: String` FORBIDDEN.
- MUST: modal uses native secure input (password field), explicit "clear clipboard" reminder on paste completion.
- MUST: ToS acceptance timestamp persisted in local `profiles.json`, never IPC-emitted.
- MUST: ChangeModelModal + effective-model downgrade badge — response body parsed server-side (Rust), only `{selected, effective, is_downgrade}` surfaced to renderer.
- Gate: security-reviewer + svelte-specialist + tauri-platform-specialist.

**Convergence gate:** a `/redteam` pass after PR-G3 covering the complete Gemini path end-to-end (paste → encrypt → spawn → 429 parse). Every finding above LOW is resolved in the same session per `zero-tolerance.md` rule 5. No residuals journaled as "accepted."

---

## References

- `workspaces/gemini/briefs/01-vision.md` — API-key-only scope, ToS ban risk, `.env` short-circuit
- `specs/07-provider-surface-dispatch.md` §7.2.3, §7.3.4, INV-P03 — per-surface layout + pre-seed ordering
- `specs/06-keychain-integration.md` — extension pattern for Gemini encrypted store
- `csq-core/src/error.rs:17` `OAUTH_ERROR_TYPES` — `&'static str` allowlist pattern to clone for Google error codes
- `csq-core/src/error.rs:55` `sanitize_body`, `:81` `KNOWN_TOKEN_PREFIXES`, `:260` `error_kind_tag` (referenced from Codex analysis)
- `csq-core/src/platform/fs.rs:22` `secure_file`, `:41` `atomic_replace`
- `rules/security.md` MUST rules 1, 2, 3, 4, 5, 6, 7, 9 — apply unchanged to Gemini path
- `rules/account-terminal-separation.md` rule 1 — daemon-sole-writer for quota (Gemini counter mode included)
- `rules/tauri-commands.md` MUST rule 3 — no secrets in IPC payloads
- Journal 0006 — three-layer IPC hardening (Gemini adds no new routes)
- Journal 0007 / 0010 — error-body echo class (Gemini has its own echo surface per §5.5)
- Journal 0052 — RFC 6749 error-type re-insertion; Gemini needs a parallel Google error-code allowlist
- `google-gemini/gemini-cli#21744` — `.env` short-circuit
- Google Cloud Gemini API ToS §6 — third-party OAuth prohibition (active 2026)
- `discovery_growthbook_model_override.md` (user memory) — silent model downgrade class; applies to Gemini via effective-model badge

## For Discussion

1. **Encryption-at-rest wrap-vs-store:** §3.2 chose "keychain holds a data key that wraps on-disk ciphertext" over "keychain holds the secret directly." The argued reasons are size (Vertex JSON can exceed small-item limits) and atomic rotation. If Vertex support were deferred to PR-G5, would direct keychain storage be simpler and still meet the threat model — and does that argue for shipping AI-Studio-only first and Vertex later as a separate data-plane?

2. **Counterfactual on OPEN-G02:** if verification shows `.env` DOES override process-env in gemini-cli, the §4 defensive posture (scan + warn + abort) is the only safe option. What user experience does this degrade — specifically, how often do users have a project-local `.env` with unrelated `GEMINI_API_KEY` lines (from Firebase Studio, Google AI Studio samples, etc.), and does the abort path create an unusable modal-storm?

3. **Evidence for env-allowlist completeness:** §3.3 lists 13 allowlisted vars. A real-world gemini-cli session invokes tools (git, MCP servers, shell) that may silently need something we pruned. Before PR-G2 ships, run a representative session under the allowlist and observe which tool invocations fail. The finding either confirms the allowlist or expands it with rationale per entry. Which tools are the likely marginal cases (git on non-POSIX locales? rustup with `CARGO_HOME` unset?)?
