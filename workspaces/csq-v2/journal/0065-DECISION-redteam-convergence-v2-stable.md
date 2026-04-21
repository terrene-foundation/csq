---
type: DECISION
date: 2026-04-21
created_at: 2026-04-22T00:40:00+08:00
author: co-authored
session_id: 2026-04-21-stable-v2-readiness
session_turn: 60
project: csq-v2
topic: red-team convergence report on PR #148 surfaced B1 (L2 docs mismatch), B2 (tmp-file leak on secure_file failure), B3 (updater:default not narrowed); all three resolved in-session; v2.0.0 cleared to ship
phase: redteam
tags:
  [
    redteam,
    v2-stable,
    convergence,
    release-gate,
    updater,
    secure-file,
    tmp-leak,
    cryptographic-verification,
  ]
---

# 0065 — DECISION: red-team convergence for v2.0.0; ship cleared

**Source:** intermediate-reviewer agent run against PR #148 (`fix/v2-stable-blockers`).
**Input:** `workspaces/csq-v2/01-analysis/04-05`, `workspaces/csq-v2/02-plans/04`, journals 0061-0064, `git diff main..fix/v2-stable-blockers`.
**Output:** this decision journal + three code commits resolving the three above-LOW findings.

## The findings

The red-team agent walked every /analyze fix site and surfaced three blockers the initial three-agent /analyze pass had missed. All three are defense-in-depth gaps introduced by the fix-in-session work, not new bugs in the underlying system.

### B1 — L2 release-notes language vs `verify.rs` production key state

**Symptom:** `docs/releases/v2.0.0.md` L2 said "gated behind the Foundation's production release-signing key; until that key is provisioned, install 2.0.1+ manually". `csq-core/src/update/verify.rs:77-81` has a non-placeholder 32-byte key committed in `3af4f3e` ("provision Foundation Ed25519 release key + CI signing pipeline"). `is_placeholder_key()` returns `false` in production builds.

**Resolution:** confirmed cryptographically. Downloaded `SHA256SUMS` and `SHA256SUMS.sig` from the alpha.21 release and verified against the committed `RELEASE_PUBLIC_KEY_BYTES` using ed25519-dalek. Signature OK — the committed key IS the Foundation's real signing pubkey, and the private component exists as the `RELEASE_SIGNING_KEY` GitHub secret. L2 language softened to "has not been exercised against a real cross-version release on a fresh install" instead of "until the key is provisioned" (already pushed as `499d131`).

**Why this was missed in /analyze:** session-notes memory (`discovery_csq_update_blocked_by_key`) was stale — it said the key is a placeholder. That memory predates `3af4f3e` by 8 days. Stale memory seeded the brief, the brief seeded the release checklist, and only a red-team cross-check surfaced the mismatch. Action: correct the memory so future sessions don't re-derive the same mistake.

### B2 — tmp file leak on `secure_file` failure

**Symptom:** the P1-4 fix propagated `secure_file` errors from `providers::settings::save_settings` and `third_party::{bind,unbind}_provider_to_slot`. But `std::fs::write(&tmp, ...)` above each `secure_file` call creates the tmp file at umask-default permissions (typically `0o644`) with the API token in cleartext. On `secure_file` failure, the Err propagates but leaves the tmp file on disk — defeating the fail-closed intent the comment explicitly claimed. Same for `atomic_replace` failures.

**Resolution:** rewrote each failure branch in all three sites (`providers/settings.rs:222-246`, `third_party.rs:225-243`, `third_party.rs:373-395`) to `let _ = std::fs::remove_file(&tmp);` before returning the error. The Ok path continues to rely on `atomic_replace` consuming `tmp`.

**Why this was missed in /analyze:** deep-analyst audited the `secure_file(&tmp).ok()` → propagate change at the pattern level and confirmed the symmetry with the OAuth credential write path. Neither the analyst nor the security-reviewer traced the partial-failure cleanup. Red-team caught it by asking "what does the tmp file look like when we return Err?".

### B3 — `updater:default` capability not narrowed

**Symptom:** the M2 fix narrowed `opener:default`, `autostart:default`, `process:default` to explicit per-command grants. `updater:default` was left in place. The default updater permission grants `allow-check`, `allow-download`, `allow-install`, `allow-download-and-install` — a superset of what `UpdateBanner.svelte` actually calls (`check()` and `downloadAndInstall(...)`).

**Resolution:** replaced `updater:default` with `updater:allow-check` + `updater:allow-download-and-install` in `capabilities/default.json`. Dropping `allow-install` and `allow-download` removes two renderer-reachable code paths that were never used. Signature verification against the Tauri minisign pubkey in `tauri.conf.json:29` is unaffected.

**Why this was missed in /analyze:** M2 was scoped by the security-reviewer to "the three permissions that grant broad surfaces" (opener, process, autostart). Updater was inspected but treated as needed-as-is because the UpdateBanner calls it. Red-team noticed that only 2 of the 4 updater subpermissions are actually used and flagged the leftover as inconsistent with the stated narrowing intent.

## Consequences

- PR #148 code now closes every finding the /analyze + /redteam passes surfaced. Zero above-LOW residuals.
- The `release_key_check` ad-hoc verifier (`/tmp/keycheck/verify.rs`) is kept in journal as the gold-value test pattern: rebuild it as an optional `cargo run --example release_key_check` in `csq-core` if future key rotations need a fast re-validation path.
- Three lessons:
  1. **Stale memory can seed /analyze.** `discovery_csq_update_blocked_by_key` pre-dated the key provisioning commit. Seeded the brief, the checklist, the release notes. Red-team was the only way to catch it. Rule candidate: briefs MUST cite the source-of-truth commit for every claim about the current code state.
  2. **Partial-failure cleanup is easy to skip when the pattern is "propagate the error".** The `?` operator is terse; it hides the question "what's in the filesystem when the error fires?". Rule candidate: every `?` that follows `std::fs::write` to a sensitive file path MUST delete the tmp file first.
  3. **`permission:default` sets are never fully audited at narrowing time.** It's easy to narrow 3-of-4 and forget the 4th. Rule candidate: a narrowing PR MUST grep for all `*:default` grants in `capabilities/*.json` and justify each one that remains.

## For Discussion

1. The B1 stale-memory chain (`discovery_csq_update_blocked_by_key` → brief → checklist → release notes L2) is a failure of session-knowledge hygiene, not of the /analyze phase itself. The deep-analyst, requirements-analyst, and security-reviewer all operated correctly given the inputs. Should memory entries carry a TTL or a "last-verified commit" field, so sessions can programmatically detect when an entry needs re-validation?
2. B2 (tmp-file leak) is the exact partial-failure shape journal 0038 called out in a different context ("residual risks accepted under same-user threat model"). We now have two independent incidents of "fail closed" meaning different things to different implementers. Is it worth a `rules/fail-closed.md` that spells out the cleanup contract?
3. The `release_key_check` verifier took 5 minutes to write and decisively resolved B1. Without it, the only alternative was "trust commit 3af4f3e" or "hold the release until the Foundation manually confirms". Is cryptographic spot-verification a general pattern we should bake into `csq doctor` or a pre-release CI step so every release captain can sanity-check independently?
