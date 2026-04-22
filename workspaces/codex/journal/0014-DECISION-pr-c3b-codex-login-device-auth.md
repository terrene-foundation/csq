---
type: DECISION
date: 2026-04-22
created_at: 2026-04-22T22:45:00Z
author: co-authored
session_id: 2026-04-22-codex-pr-c3b
session_turn: 14
project: codex
topic: PR-C3b — csq login --provider codex device-auth orchestrator + macOS keychain residue probe + FR-CLI-05 setkey hard-refuse. New module csq-core/src/providers/codex/{mod,surface,login,keychain}.rs consumes PR-C2b CredentialFile::Codex + PR-C3a discover_codex. Six security review findings (1 HIGH, 3 MEDIUM, 2 LOW) resolved inline per zero-tolerance Rule 5.
phase: implement
tags: [codex, pr-c3b, device-auth, keychain-residue, fr-cli-05, security-review]
---

# Decision — PR-C3b: Codex device-auth login + keychain residue probe + FR-CLI-05

## Context

Journal 0013 decomposed PR-C3 into C3a (discovery + handle-dir, shipped as PR #172) / C3b (this PR: login flow) / C3c (launch flow). PR-C3b implements the middle slice of spec 07 §7.3.3 — the ordered login sequence — and wires `--provider codex` into the CLI without touching the `csq run` launch path.

Spec §7.3.3 fixes seven ordered steps (mkdir config-<N>, write config.toml with `cli_auth_credentials_store = "file"` + `model`, shell out `codex login --device-auth` with `CODEX_HOME=config-<N>`, relocate auth.json to `credentials/codex-<N>.json`, flip 0o400, keychain residue probe on first Codex login, register with daemon refresher). Journal 0013 drew the PR boundary between steps 1-6 (PR-C3b) and step 7 + the daemon integration (PR-C4 refresher; PR-C3c launch).

## Decision

Ship `csq-core/src/providers/codex/{mod,surface,login,keychain}.rs` as the cohesive Codex provider module, wire `--provider {claude,codex}` into `csq login`, and hard-refuse `csq setkey --slot N` when N is already bound to Codex (FR-CLI-05). The orchestrator (`login.rs::perform`) is dependency-injected via `perform_with` so the write-order invariant (INV-P03: config.toml before spawn), the keychain decline path, and the probe-failed breadcrumb are all exercised without a real `codex` binary or a live keychain.

### Security review — H1/M1/M2/M3/L1/L2 resolved inline

Per `.claude/rules/zero-tolerance.md` Rule 5, no residual findings above LOW are journaled as "accepted". Six findings from the security-reviewer pass were resolved in the same session:

- **H1 (serde_json echo via `CredentialError::Corrupt.reason`)** — the `credentials::load(&auth_json)` path routed a serde error straight into an anyhow context that `csq-cli/src/main.rs` prints to stderr. serde's type-mismatch messages echo field values (`invalid type: string "<value>", expected …`), so a malformed codex-cli output could surface a JWT or `rt_*` refresh-token fragment. Fix: capture the error, route through `error::redact_tokens` into a fixed-vocabulary `tracing::warn!(error_kind=…)`, and return a user-facing anyhow error that drops the raw reason entirely. Same pattern applied to `save_canonical_for` failures. Regression test `malformed_auth_json_error_does_not_echo_tokens` feeds a `rt_AAAA…` value that serde would echo and asserts the anyhow chain is clean.

- **M1 (auth.json residue at codex-cli's umask mode + warn-not-error)** — codex writes `auth.json` at 0o644 (typical umask). The original cleanup was a best-effort `remove_file` + `tracing::warn!`. Fix: narrow the residue window by `secure_file(&auth_json)` BEFORE the remove (0o600), and on remove failure overwrite the file with zeros (best-effort shred) + elevate the log to `tracing::error!`.

- **M2 (prompt_yes_no blocks non-TTY callers / desktop reuse)** — `read_line` on a non-TTY stdin returns `Ok(0)` → trim `""` → default match arm → `Decline`. That is fail-closed on the CLI side (login aborts with an actionable "re-run in a terminal" message). Fix: expanded the `perform` doc comment to name the invariant and flag that the future desktop modal will NOT reuse this entry point (the Tauri command layer will capture the modal response first, then call `perform_with` with a pre-filled reader).

- **M3 (keychain `-s <svc>` arg wildcard bypass via test seam)** — `probe_residue_with` / `purge_residue_with` take `&str` service names. `security find-generic-password -s ""` matches the first generic-password entry in the keychain; a buggy future caller could trick the guard into classifying an unrelated item as Codex residue. Fix: added `validate_service_name` that requires non-empty + `com.*` prefix + ASCII alphanumeric/dot/dash/underscore. Invalid shape maps to `ProbeFailed` on probe and hard-errors on purge. Four new regression tests (empty, non-reverse-DNS, shell-metachar, purge-refuses-empty).

- **L1 (inherited env leaks CLAUDE_CONFIG_DIR into codex child)** — login-time env clear is PR-C3c scope, but the one cross-surface bleed most likely to be already set is `CLAUDE_CONFIG_DIR` (any csq-managed terminal has it). Fix: `.env_remove("CLAUDE_CONFIG_DIR")` on the `codex login` spawn so PR-C3c's allowlist does not have to re-prove this boundary.

- **L2 (FR-CLI-05 guard follows dangling symlinks)** — `Path::exists` on `credentials/codex-<N>.json` follows symlinks, so a dangling link reports not-bound and lets `csq setkey` proceed. Fix: swap to `std::fs::symlink_metadata(&path).is_ok()`; dangling links now refuse. Regression test `fr_cli_05_treats_dangling_symlink_as_bound` covers the case.

Total test delta: csq-core 783 → 818 (+35); csq-cli 111 → 116 (+5). Clippy clean; rustfmt clean.

## Alternatives considered

**A. Ship PR-C3 as one PR.** Rejected per journal 0013 — repeat of the PR-C2 monolithic anti-pattern; device-auth + process exec + env handling each deserve their own reviewable diff.

**B. Use a trait-based `LoginRig` for DI instead of 7 closure parameters on `perform_with`.** Rejected for PR-C3b. The closure list is heavy but localised to one module; a trait would add indirection and no consumer outside csq-core calls `perform_with`. PR-C3c or the desktop wire-up may refactor if a second consumer appears.

**C. Land the keychain residue probe as an extension of `csq-core/src/credentials/keychain.rs`.** Rejected. The existing module reads CC's keychain entries keyed by a SHA-256 hash of the config dir path — that is CC's own service-name shape, scoped to a Claude Code install. Codex writes a flat `com.openai.codex` service independent of config-dir hashing and tied to codex-cli, not csq. Putting Codex residue logic in the CC module would conflate two distinct security backends with different threat models and probe semantics. A narrow sibling module with its own `validate_service_name` keeps the failure surfaces independent.

**D. Defer the H1/M1/M2/M3/L1/L2 fixes to a follow-up PR-C3b.1.** Rejected per `zero-tolerance.md` Rule 5 — "no residual risks acceptable"; each finding above LOW is in-session work. L1 and L2 are LOW but the fixes are 1-3 lines apiece; resolving them now keeps the redteam ledger clean entering PR-C3c.

## Consequences

- PR-C3b ships `csq login --provider codex` as a usable path end-to-end up to the daemon-registration step. A freshly-logged-in Codex slot sits in `credentials/codex-<N>.json` at 0o400 with a 0o600 mirror at `config-<N>/codex-auth.json`, a `.csq-account` marker, and a profiles.json entry. codex-cli's own in-process refresh path is still load-bearing until PR-C4 lands `broker_codex_check` — acceptable because INV-P01 only becomes load-bearing when the daemon owns refresh cadence.
- FR-CLI-05 refuses the likeliest footgun (`csq setkey mm --slot <N>` on a Codex-bound slot) with an actionable exit 2 message. The check is filesystem-only (no credential read), cannot TOCTOU in a way that leaks tokens, and treats dangling symlinks as bound.
- The `perform_with` seam keeps every invariant testable: write-order (config.toml before spawn), decline fail-closed (spawn not reached), canonical 0o400 mode, probe-failed warn breadcrumb, malformed auth.json no-echo.
- PR-C3c can land on top without modifying PR-C3b: `launch_codex` consumes `create_handle_dir_codex` (PR-C3a) + the canonical file (PR-C3b) + the refresher chain (its own scope). PR-C4 consumes the canonical file + the Node transport (PR-C0.5) unchanged.
- If a future Codex provider variant (OpenAI API-key mode, non-ChatGPT) ever shows up, FR-CLI-05's `provider.surface == Surface::Codex` short-circuit already lets that through — no further wiring needed.

## For Discussion

1. **`perform_with` has seven generic parameters (R, W, P, U, S) plus &Path + AccountNum. The ergonomics are acceptable for one module but this is the second DI-heavy function in csq-core (after `daemon::refresher::tick`). At three, does the pattern deserve extraction into a `LoginRig` / `RefresherRig` trait in a shared module, or is each closure set different enough that a trait would impose false uniformity?** (Lean: wait for the third case. Closure-based DI is explicit about the dependency graph; a trait hides it behind method dispatch. Trait only wins if the rigs end up sharing methods.)

2. **M1's "overwrite with zeros then remove" best-effort shred uses `std::fs::write` which is not a cryptographic wipe — on a journaling filesystem or SSD with wear-levelling, the original bytes remain recoverable from physical media. Is this defense theatre on a desktop threat model, or is the token-residue window narrow enough that even a partial wipe meaningfully reduces attacker value? If the attacker already has user-level filesystem access, the 0o400 canonical is also readable.** (Lean: it is defence-in-depth, not a cryptographic guarantee. The `warn` → `error` log elevation is the more valuable half of the fix because it makes the rare-failure case observable in telemetry. The shred step is a cheap belt-and-suspenders that does not raise any false expectations as long as the comment says "best-effort".)

3. **If OPEN-C04 had resolved "reqwest OK" instead of "Node required" (counterfactual to journal 0007), PR-C0.5 would have been skipped and `csq-core/src/http/codex.rs` would not exist. Would PR-C3b have any dependency on that module today?** (Lean: No. PR-C3b only uses `credentials::load` / `save_canonical_for` + spec §7.3.3's shell-out to `codex login --device-auth`. The `http::codex` module is consumed by PR-C4 (refresher) and PR-C5 (wham/usage), not by login. This is a clean layering property — login orchestration is independent of HTTP transport.)

## Cross-references

- `workspaces/codex/journal/0013-DECISION-pr-c3-decomposition-discovery-first.md` (decomposition precedent; this PR is the middle slice)
- `workspaces/codex/journal/0011-DECISION-pr-c1-scope-deferrals.md` (three items deferred from PR-C1 — discover_codex + create_handle_dir_codex + refresher filter; two shipped in PR-C3a, the third deferred to PR-C3c/C4)
- `specs/07-provider-surface-dispatch.md` §7.3.3 (authoritative login sequence), §7.5 INV-P01/INV-P03/INV-P08/INV-P09 (refresh cadence, pre-seed ordering, mode-flip coordination, per-account mutex lifecycle)
- `csq-core/src/http/codex.rs` (PR-C0.5 Node transport — consumed by PR-C4, NOT by PR-C3b)
- `csq-core/src/credentials/mod.rs` (`CredentialFile::Codex` / `CodexCredentialFile` / `CodexTokensFile` — PR-C2b; consumed by PR-C3b)
- `csq-core/src/credentials/file.rs::save_canonical_for` (PR-C2a/PR-C2b; PR-C3b's step-4 relocator)
- `csq-core/src/accounts/discovery.rs::discover_codex` (PR-C3a; reads what PR-C3b wrote)
- `.claude/rules/security.md` (error-body redaction, atomic writes, 0o400 canonical mode) + `.claude/rules/zero-tolerance.md` Rule 5 (no residual findings)
