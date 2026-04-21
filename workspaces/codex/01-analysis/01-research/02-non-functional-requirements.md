# 02 — Codex Surface: Non-Functional Requirements

Phase: /analyze | Date: 2026-04-21

Performance, reliability, security, compatibility, observability, and maintainability constraints for the Codex surface. Partners with 01-functional-requirements.md; every FR MUST satisfy every applicable NFR.

## NFR-C01 — Cold-start performance

- `csq run <codex-slot>` from invocation to `codex` prompt MUST be < 800ms on M-series macOS (p99).
- Measured: wall-clock from user-press-Enter to first byte on codex stdout.
- Hard budget breakdown:
  - Handle-dir create + symlink set: < 50ms
  - Daemon health probe (unix socket `Ping`): < 20ms
  - Codex binary `exec`: < 100ms cold (kernel), near-instant warm
  - Remainder is codex-owned
- **Prohibited on this path:** any network call (wham/usage, models.json fetch, keychain probe). Those run on background tasks, not on `csq run`.
- Test: integration bench that spawns a Codex handle dir 100× and asserts p99.

## NFR-C02 — Daemon refresh freshness

- Codex access tokens MUST refresh ≥ 2 hours before expiry (same window as Anthropic per spec 04 INV-06).
- Measured: `min(expiry - now)` across all active Codex accounts, sampled every 5 minutes.
- Violation threshold: if refresh lag > expiry - 2h for any account, daemon logs `error_kind = "codex_refresh_lag"` and supervisor surfaces a tray warning.
- Per-call timeout per spec 05 §5.6: 30s, aborted and cooldown-retried.

## NFR-C03 — Quota polling cadence

- `wham/usage` polled every 5 minutes per active Codex account (same cadence as Anthropic).
- Circuit breaker: 5 consecutive failures → cooldown = 15 min, doubling to cap 80 min (inherits spec 05 §5.6 pattern).
- Schema-drift detection MUST trigger within one poll tick; UI MUST render `kind: "unknown"` within 30s of the first drift detection (statusline reads fresh `quota.json`).
- Raw-response capture for bug reports: last known good + last drift response persisted to `accounts/codex-wham-raw.json` and `accounts/codex-wham-drift.json` respectively. Each capped at 64 KB; redactor runs before write.

## NFR-C04 — Security

- **No plaintext tokens in logs.** Covered by INV-P07 + FR-CORE-04. Unit test asserts redaction on sample `sess-*` token and Codex JWT shape.
- **No tokens in IPC events.** Rule: tauri-commands.md MUST Rule 3 + 7.1 events-to-renderer never contain tokens, refresh_tokens, id_tokens, or wham/usage response body. Only derived fields (utilization %, timestamps, counts, surface tag).
- **Canonical file mode.** `credentials/codex-<N>.json` is 0400 outside refresh windows, 0600 during refresh, enforced by the mutex dance (ADR-C13). Startup reconciler flips any 0600 file back to 0400 if no refresh is in progress.
- **Per-user base dir.** All csq state lives under `$HOME/.claude/accounts/` (or `CSQ_BASE_DIR`), 0700, per-user only.
- **Daemon socket.** Unix socket 0600 in per-user dir; SO_PEERCRED / LOCAL_PEERCRED check rejects non-UID callers (unchanged from spec 04).
- **Subprocess env isolation.** `codex` spawn uses `Command::env_clear()` + explicit allowlist: `PATH`, `HOME`, `USER`, `LANG`, `TERM`, `CODEX_HOME`, plus user-configured pass-through (e.g., `HTTPS_PROXY`). Tokens are NEVER in env; they live in `auth.json` reached via symlink.
- **Keychain escalation prevention.** Enforced by pre-seeded `cli_auth_credentials_store = "file"` (ADR-C04). Daemon detects and refuses if user flips this value post-install (drift detection, F4).

## NFR-C05 — Reliability

- **Single-writer invariant for `credentials/codex-<N>.json`:** daemon-owned. Any second writer (login path) acquires the same per-account mutex (ADR-C13). Two concurrent `csq login N --provider codex` invocations MUST serialize, not corrupt.
- **Handle-dir sweep safety:** `remove_dir_all(term-<pid>/)` MUST NOT traverse symlinks. Integration test pins this against Rust stdlib semantics + platform APFS/ext4/btrfs. If a future Rust release changes semantics, CI catches it.
- **Atomic migration:** `quota.json` v1→v2 migration is idempotent + crash-safe. Write temp + rename; bump `schema_version` in same atomic operation.
- **Poller supervisor:** codex poller run under the same supervisor as Anthropic and 3P (spec 05 §5.6). Heartbeat every tick; missing heartbeat for 3× expected interval = force-restart.

## NFR-C06 — Observability

- Structured events emitted via tracing subscriber (unchanged from csq-core conventions, post journal 0017):
  - `codex_login_seeded`, `codex_login_invoked`, `codex_login_complete`, `codex_login_failed { error_kind }`
  - `codex_refresh_attempted`, `codex_refresh_succeeded`, `codex_refresh_failed { error_kind }`
  - `codex_usage_polled`, `codex_usage_schema_drift { schema_hash, sample_keys }`
  - `swap_cross_surface { from_surface, to_surface, confirmed }`
  - `keychain_residue_detected { provider, action }`
- `error_kind_tag` enum extended with Codex-specific values — closed enum, no dynamic strings (prevents log injection).
- Log level DEBUG for normal operation; INFO for state changes; WARN for retryable failures; ERROR for user-visible failures.
- **No redaction gaps in error paths:** every `format!("... {e} ...")` near Codex code goes through `error::redact_tokens` (extended for `sess-*` and JWT).

## NFR-C07 — Compatibility

- **csq version compatibility:** new `quota.json` schema v2 is a one-way migration. Downgrading csq below the Codex-ship version breaks quota reads. Document in release notes; no backward-compat shim.
- **Codex CLI version:** csq MUST probe `codex --version` at first spawn. Minimum version constant `CODEX_MIN_VERSION` in `providers/codex/mod.rs`. Below minimum → refuse with actionable upgrade message.
- **Platform:** macOS (Apple Silicon + Intel), Linux x86_64 + aarch64. Windows explicitly out (ADR-C12).
- **Python runtime:** not used by Codex path (zero-dependency invariant preserved per §0.3).
- **JS runtime (node/bun) dependency:** Codex HTTPS paths (auth.openai.com refresh, chatgpt.com/backend-api/\*) MUST be tested against Cloudflare fingerprinting. If reqwest/rustls is blocked (same class as Anthropic per journal 0056), we reuse the existing JS-runtime subprocess transport. If reqwest works for these endpoints, we document that and use the typed HTTP client. **This is a must-verify-before-PR3 item.**

## NFR-C08 — Maintainability

- **Spec as source of truth:** spec 07 governs surface dispatch. Any deviation during implementation MUST update spec 07 in the same commit (rules/specs-authority.md Rule 4).
- **Surface enum exhaustiveness:** all `match Surface { ... }` blocks MUST handle every variant; Clippy `match_same_arms` allowed only with rationale comment.
- **Test coverage floor:** PR1 regression test set is load-bearing per 04-risk-analysis §3 (five named tests). PR2-7 each add at least one integration test covering the per-PR failure mode from §1 of that doc.
- **No provider id string matching in new code.** After PR1, any code switching on `provider.id == "codex"` is a code smell — use `surface == Surface::Codex` instead. Lint rule (grep) enforced in CI.

## NFR-C09 — Error recovery

- **Login timeout:** device-auth flow has a 10-minute ceiling (ADR-C11 / G8). On timeout, csq cleans `config-<N>/`, removes partial state, and surfaces an actionable error.
- **Daemon-down path:** if user runs `csq run <codex-slot>` with daemon down, csq refuses with one-command recovery (`csq daemon start`). Exit code 2. Desktop app surfaces a banner with a click-to-start button (FR-DESK-01 prerequisite).
- **Broken symlink path:** daemon startup integrity check: for every `config-<N>/codex-auth.json` symlink that does not resolve, mark account `LOGIN-NEEDED` and surface event. User sees actionable re-login prompt. (F3.)
- **`refresh_token was already used` detection:** classify as `codex_invalid_grant`. Account state → `LOGIN-NEEDED`. UI shows re-login prompt. Mutex invariant prevents this internally; error path handles external corruption (F9).

## NFR-C10 — Observational budget

- Codex daemon refresh: 1 POST per account per ~5h (at expiry - 2h). For 10 Codex accounts: 2 requests/hour steady-state.
- Codex usage polling: 1 GET per active account per 5 min. For 10 Codex accounts: 120 requests/hour.
- Model list fetch: 1 per ChangeModelModal open. Cached 24h.
- Total network footprint steady-state: ~120 requests/hour/user (well within OpenAI's implicit tolerances for subscription clients).

## NFR-C11 — Documentation

- User-facing: release notes enumerate the Codex UX, ToS posture, daemon-requirement, and Windows-not-yet limitation.
- Developer-facing: spec 07 + workspaces/codex/01-analysis artifacts serve as the canonical reference. Journals document each landed decision.
- Desktop app includes an in-product help panel linking to the Codex onboarding section of the user docs.

## Cross-references

- FR document: `01-functional-requirements.md`
- ADRs: `03-architecture-decision-records.md`
- Risk analysis: `04-risk-analysis.md` (load-bearing for NFR-C04, -C05, -C09)
- Security analysis: `07-security-analysis.md`
- Spec: `specs/07-provider-surface-dispatch.md`
