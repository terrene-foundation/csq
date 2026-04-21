# csq v2.0.0 Stable — Security Audit

**Author:** security-reviewer agent (read-only)
**Date:** 2026-04-21
**Scope:** full Rust codebase (`csq-core/`, `csq-cli/`, `csq-desktop/`), v2.0.0-alpha.21 tag.
**Threat model:** same-user local attacker + hostile network + compromised GitHub Releases mirror.
**Related:** `workspaces/csq-v2/briefs/03-v2-stable-readiness.md`

---

## Executive Summary

1. **Security posture is stable-release-ready with one HIGH that needs attention and three MEDIUMs that should be resolved.** The foundations — atomic writes, subscription-preservation, 3-layer IPC, CRLF validation, error redaction, SecretString wrappers — are all in place and tested.
2. **Top risk: the csq-core `download_and_apply` updater path lacks the `is_placeholder_key()` gate.** The CLI wraps it correctly, but any future caller (a new Tauri command, a doctor subcommand, a test harness that slipped into release build) can invoke `csq_core::update::download_and_apply` directly and bypass the "placeholder key → refuse" check.
3. **Top mitigation already landed:** paste-code OAuth replaces the loopback TCP listener. The old 127.0.0.1:8420 route is gone from the runtime. No secrets route touches TCP.
4. **Subscription-contamination defense is correctly maintained in every credential write path audited** (`rotation::swap_to`, `credentials::refresh::merge_refresh`, `oauth::exchange::exchange_code` intentionally sets `None` because CC backfills, `credentials::file::save_canonical` preserves verbatim).
5. **Token redaction is structurally sound with one residual gap at an IPC error boundary** (M1 — defense-in-depth, not an active leak).

---

## CRITICAL (Must fix before stable)

**None.** No findings rise to CRITICAL severity for the v2.0.0 cut.

---

## HIGH (Should fix before merge)

### H1. `csq_core::update::download_and_apply` does not gate on `is_placeholder_key()`

**File:** `csq-core/src/update/mod.rs:68-70` and `csq-core/src/update/apply.rs:55-61`

**Attack scenario:** Today, the gate at `csq-cli/src/commands/update.rs:75` is the only placeholder check. The public `csq_core::update::download_and_apply` function it calls performs no such check itself. If a future caller — a desktop Tauri command, a new CLI subcommand, a `csq doctor --install-update` convenience, or an integration test accidentally promoted to `pub` — calls `download_and_apply` directly, they skip the gate. And because `#[cfg(test)]` overrides `RELEASE_PUBLIC_KEY_BYTES` with the seed-1 placeholder, if the gate is ever weakened during refactor, test coverage doesn't catch it.

**Blast radius:** anyone who signs a binary with the private key derivable from the seed-1 placeholder (trivially reproducible from the committed source) can trigger RCE as the current user on any csq install that reaches a downstream caller of `download_and_apply` without the CLI's gate.

**Fix recommendation:** move the `is_placeholder_key()` check to the top of `csq_core::update::apply::download_and_apply` itself, not the CLI wrapper. Every current and future caller then inherits the defense. Add a regression test asserting the check fires in `#[cfg(test)]` builds.

**Rule reference:** `rules/zero-tolerance.md` Rule 1. `rules/security.md` MUST Rule 1.

---

## MEDIUM (Fix in next iteration; blockers if trivial in-session)

### M1. `cancel_login` error path surfaces `OAuthError::Display` without redaction

**File:** `csq-desktop/src-tauri/src/commands.rs:860`

```rust
Err(e) => Err(format!("cancel failed: {e}")),
```

The three `OAuthError` variants that are pattern-matched (`StateMismatch`, `StateExpired`) are handled via `Ok(())`. The fallback `Err(e)` path passes `e` through `{e}` Display. Today `OAuthStateStore::consume` only returns those two variants, so the branch is structurally unreachable — but the compiler cannot prove that, and a future refactor that widens `consume`'s error type (e.g. to carry transport errors) can silently leak whatever is in `OAuthError::Exchange(s)` into the IPC response.

**Fix recommendation:** replace with `Err(format!("cancel failed: {}", error_kind_tag(&e)))` or exhaustively match all `OAuthError` variants. Use `#[deny(unreachable_patterns)]` locally to lock it in.

**Blast radius:** latent — depends on future refactor widening `OAuthError` surface.

**Rule reference:** `rules/security.md` MUST Rule 2; journal 0010.

### M2. Tauri capability grants `updater:default`, `autostart:default`, `process:default`, and `opener:default` to the renderer

**File:** `csq-desktop/src-tauri/capabilities/default.json:6-15`

All eight permission sets are granted to the main window. `process:default` typically allows `restart()`/`exit()` to be invoked from the renderer. `opener:default` lets the renderer open arbitrary URLs. `updater:default` lets the renderer invoke `check()` and potentially `downloadAndInstall()` via Tauri's bundled updater plugin.

The real risk: if the Svelte frontend or any future component mishandles user-supplied URLs and passes them to `opener`, they can be opened without user confirmation. This is lower than HIGH because the frontend currently only passes the cached `release_url` from the update manifest (trusted source). But the capability breadth is wider than the code uses.

**Fix recommendation:** narrow `opener:default` to `opener:allow-open-url` with an allowlist (`github.com`, `platform.claude.com`, `anthropic.com`). Narrow `process:default` to just what you actually need. Audit `updater:default` for whether it grants `downloadAndInstall` to the renderer — if it does and you rely on manual install until the Foundation key ships, the renderer could bypass that assumption.

**Blast radius:** depends on renderer trust. Tauri renderer is adversarial by convention.

**Rule reference:** `rules/tauri-commands.md` "Permissions" section.

### M3. Resurrection-log breadcrumb writes interpolated path without JSON escaping beyond quotes

**File:** `csq-core/src/daemon/refresher.rs:547-550`

Only double quotes are escaped. A path containing backslash, control characters (CR/LF), or other JSON-reserved sequences could corrupt the JSONL file so `jq` / `csq doctor` can't parse it. For `same-user` threat model this is non-exploitable — but the breadcrumb is billed as a forensic trail.

**Fix recommendation:** `serde_json::to_string(&Value::String(live_path.display().to_string()))` or serialize the whole object through serde_json.

**Blast radius:** forensic integrity only, not a leak.

---

## LOW (Consider fixing; informational)

- **L1.** `OAuthError::Http { body }` Display redacts but the `body` field is still `pub`. Today nothing constructs this variant. Remove the variant or privatize `body` via getter.
- **L2.** `credentials::file::save_canonical` mirror-write logs `error = %e`. No token material flows, but `{e}` is wider than needed. Prefer `error_kind = "mirror_write_failed"`.
- **L3.** `credentials::keychain::read` logs `service = %svc, error = %e`. Service name is not a secret but leaks which config dir the binary is probing. Tighten for consistency with refresher pattern.
- **L4.** `OAuthError::Exchange(recovery_err.to_string())` in broker/check.rs:154 walks the full CsqError Display chain. Mirror the `reason_tag` fixed-vocab pattern at line 144.
- **L5.** `http.rs::get_bearer_node` JSON-escapes headers via `serde_json::to_string(k).unwrap_or_default()` inside a JS template literal. Document the static-constant-only invariant.
- **L6.** `is_placeholder_key` compares full 32 bytes (no false-positive risk). Noted only for completeness.
- **L7.** `swap_account`, `rename_account`, `remove_account`, and several other Tauri commands accept `base_dir: String` without `canonicalize + starts_with(expected_base)` guard (unlike `swap_session` which has it). Same-user model makes this safe today, but recommend threading the guard everywhere for defense-in-depth.

---

## What a red-teamer would hit first — ranked

1. **Run `csq_core::update::download_and_apply` directly via a subcrate dep or rogue test.** H1 — fix structurally by moving the gate into core, not CLI.
2. **Pass a crafted `base_dir` through a Tauri command that doesn't canonicalize.** L7 — defense-in-depth gap.
3. **Attempt to poison the GrowthBook cache.** Not a csq bug per se, but if an attacker gets write access to `~/.claude/`, they can silently downgrade every csq-swapped terminal to Sonnet. Mitigation: document `csq doctor` should diff this cache.

---

## PASSED CHECKS (no findings)

- **Atomic writes:** every credential/quota/marker/settings write goes through `platform::fs::atomic_replace` + `secure_file` (0o600).
- **Subscription-metadata preservation:** correctly maintained across `swap_to`, `merge_refresh`, `save_canonical`.
- **AccountNum validation:** 187 occurrences across 38 files; no raw u16 reaches path construction.
- **CRLF injection on `daemon::client`:** runtime-checked at every public entry with regression tests.
- **3-layer Unix socket security:** umask 0o077 → bind → chmod 0o600 → `SO_PEERCRED`/`LOCAL_PEERCRED` → per-user directory.
- **No TCP credential routes:** 8420 fully retired.
- **No hardcoded tokens in source.**
- **`.gitignore` hygiene.**
- **No `shell=true`/`sh -c` interpolation in runtime code.**
- **SecretString zeroization** on `AccessToken`, `RefreshToken`, `CodeVerifier`.
- **OAuth state store:** CSPRNG, single-use, bounded (100), 10-min TTL.
- **PKCE:** SHA-256 → base64url-no-pad, verifier length 43 chars (RFC 7636 §4.1).
- **Redaction coverage:** `sk-ant-oat01-*` / `sk-ant-ort01-*` always; generic keys ≥20 chars; long hex ≥32.
- **Response body caps:** daemon 64 KiB, axum router 1 MiB.
- **Cooldown / backoff** in refresher: 10min × 2^n, cap 80min.
- **Peer UID check** tested on Linux + macOS.
- **Tauri CSP:** `connect-src` allowlisted; `freezePrototype: true`; no `unsafe-eval`.
- **Dependency versions:** reqwest 0.12.28, hyper 1.9.0, rustls 0.23.37, axum 0.8.8, tokio 1.51.1, ring 0.17.14 — current, no known open CVEs as of 2026-04. Recommend `cargo audit` in CI before cutting stable.

---

## Verdict

**Ready to cut v2.0.0 stable after H1 is closed.** M1–M3 are improvements that can land in 2.0.1 if blocked by schedule; L1–L7 are informational only.
