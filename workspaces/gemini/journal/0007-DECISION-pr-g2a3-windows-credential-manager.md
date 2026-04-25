---
type: DECISION
date: 2026-04-25
created_at: 2026-04-25T18:00:00Z
author: co-authored
session_id: 2026-04-25-gemini-pr-g2a3
session_turn: 50
project: gemini
topic: PR-G2a.3 Windows Credential Manager — design + LocalSystem refusal + security-review convergence
phase: implement
tags:
  [
    gemini,
    platform-secret,
    vault,
    windows,
    dpapi,
    credential-manager,
    security,
    pr-g2a3,
  ]
---

# Decision — PR-G2a.3 Windows Credential Manager backend

## Context

Last of the three platform-native `Vault` backends. PR-G2a (#192) shipped the trait + macOS Keychain. PR-G2a.2 (#193) shipped Linux Secret Service + opt-in AES-GCM file fallback. PR-G2a.3 lands `WindowsCredentialVault` wrapping the Win32 `Cred*` API via `windows-sys = "0.52"`.

With this PR the platform::secret module has full coverage: macOS Keychain, Linux Secret Service (+ file fallback), Windows Credential Manager / DPAPI. PR-G2b can now flip the const placeholder `SURFACE_GEMINI` to `Surface::Gemini.as_str()` and the Vault subsystem is feature-complete for the Gemini API key path.

## Decisions

### D1 — `CRED_PERSIST_LOCAL_MACHINE`, NOT `CRED_PERSIST_ENTERPRISE`

`CredWriteW` accepts three persistence modes:

- `CRED_PERSIST_SESSION` (1) — drops at logoff
- `CRED_PERSIST_LOCAL_MACHINE` (2) — survives logoff, stays on this machine, encrypted to user's DPAPI key
- `CRED_PERSIST_ENTERPRISE` (3) — also roams via Active Directory roaming-profile machinery

We chose `LOCAL_MACHINE`. Q7 in workspaces/gemini/journal/0005 flagged the iCloud Keychain "deleted entries may resurrect on the next sync" failure mode for macOS; `CRED_PERSIST_ENTERPRISE` has the equivalent risk on AD-joined Windows machines. By refusing the roaming flavor by construction we close the entire class of "user deleted, profile sync resurrected" bugs. Cost: a user logging into a different Windows machine on the same AD domain has to re-provision their Gemini API key — same posture as macOS without iCloud Keychain. Acceptable for csq's threat model.

### D2 — Refuse-to-operate as `LocalSystem` (Q5 in journal 0005)

DPAPI keys are derived from the user profile. A daemon launched as `LocalSystem` (e.g. by an enterprise admin installing csq as a Windows service) sees a SYSTEM-scoped DPAPI key, while a user-launched `csq-cli` sees the user's profile-scoped key. Credentials written by one are invisible to the other. The whole multi-account-rotation premise breaks because the daemon would never see what the user provisioned and vice versa.

`open_windows_default` checks the process token's user SID via `IsWellKnownSid(sid, WinLocalSystemSid)` and refuses with `BackendUnavailable` when it matches, naming the reason ("Re-launch csq under the target user account or use Task Scheduler with 'Run only when user is logged on'") so an admin can self-diagnose.

`LocalService` and `NetworkService` use per-account profile DPAPI scopes and are not subject to the same SYSTEM-binding mismatch. They are intentionally NOT refused — if a future deployment surfaces issues there the refusal can be widened.

### D3 — Fail-closed on token-query failure (security review M2)

An earlier draft used `is_running_as_local_system() -> bool` returning `false` on every error path. Security review M2 flagged that as fail-OPEN: a daemon with a corrupted or stripped token (no `TOKEN_QUERY` right) would be allowed to start under the wrong DPAPI scope.

Final design splits the API:

- `check_local_system_posture() -> Result<bool, SecretError>` — used by production dispatch; refuses with `BackendUnavailable` when the token cannot be queried.
- `is_running_as_local_system() -> bool` — convenience for display/log layers; downgrades the error path to `false`.

Production binaries (the Vault factory) use the Result form. The bool wrapper exists for tests and one-off diagnostics that explicitly do not want a fail-closed gate.

### D4 — `run_with_timeout` shared helper enforces `VAULT_OP_TIMEOUT` on every backend (security review M1)

The trait docstring on `mod.rs::Vault` said "all methods MUST honour `VAULT_OP_TIMEOUT`", but in practice only the Linux Secret Service backend was wrapping syscalls in `tokio::time::timeout`. macOS and Windows had no enforcement.

PR-G2a.3 adds `mod::run_with_timeout` — a sync helper that spawns a dedicated worker thread, hands it a `FnOnce`, and waits with `mpsc::Receiver::recv_timeout(VAULT_OP_TIMEOUT)`. macOS and Windows backends now wrap every syscall in this helper. On timeout the worker thread is left to run to completion (the syscall cannot be cancelled in user space); the trade-off "occasional thread detach vs daemon never hangs" is the right posture per `security.md` §6 ("fail-closed on Keychain/lock contention").

This is a shared helper, so the macOS backend is also fixed in this PR (was pre-existing, but per `zero-tolerance.md` Rule 1 in-session fix is mandatory once the gap was named).

### D5 — Validate surface tags at the Win32 boundary (security review H1, H2)

`CredEnumerateW` filter syntax treats `*`, `?`, and `,` as pattern metacharacters. An unvalidated surface containing one would broaden the filter beyond the csq namespace — today impossible because every surface is a `&'static str` constant, but a future contributor threading user data through is a foreseeable change.

`to_wide` rejects strings with interior NUL bytes (would silently truncate the wide string and rebind the call to a shorter slot identity — the Win32 analogue of classic shell-NUL bugs).

`validate_surface_for_windows` enforces ASCII alphanumeric + `-` + `_` only. Every Vault method calls it before any syscall.

### D6 — Cleartext blob held in `Zeroizing<Vec<u8>>` (security review M3)

`set` previously copied the secret into a plain `Vec<u8>` for the `CredWriteW` `CredentialBlob*` field. Plain Vec dropped without zeroization re-introduces the cleartext window that `secrecy::SecretString` was created to bound.

Switched to `Zeroizing<Vec<u8>>` which derefs to `Vec<u8>` (so `as_mut_ptr()` / `len()` still work as the Win32 ABI requires) and wipes the buffer on `Drop`. Same fix on the `get` path's intermediate copy.

### D7 — Non-UTF-8 secrets surface as `InvalidKey`, not `DecryptionFailed` (security review M4)

Earlier mapping: `String::from_utf8(blob).map_err(|_| DecryptionFailed)`. The `DecryptionFailed` variant doc says "stored secret is unrecoverable, prompt re-provisioning" — the wrong action when the actual cause is a foreign writer (some other app squatting on the same target name) or a future csq version storing binary data.

New mapping: `InvalidKey { reason: "stored Windows Credential Manager secret is not valid UTF-8" }`. Audit log carries the right tag (`vault_invalid_key` instead of `vault_decryption_failed`). Same fix on the macOS path — was pre-existing.

## Alternatives considered and rejected

### `keyring` crate instead of direct `windows-sys` calls

**Considered**: same as PR-G2a.2 — `keyring` provides cross-platform abstraction.

**Rejected**: the platform::secret module already uses `security-framework` directly on macOS and `secret-service` directly on Linux. Adding `keyring` for Windows only would split the abstraction. A future pass could unify all three under `keyring` if the audit-log invariants stay enforceable; out of scope for PR-G2a.3.

### `CredProtect` for blob-level encryption layer

**Considered**: Win32's `CredProtect` gives an explicit DPAPI envelope on the blob, separate from Credential Manager's at-rest storage encryption.

**Rejected**: `CRED_PERSIST_LOCAL_MACHINE` already encrypts the blob via DPAPI. `CredProtect` would add a second layer with a separate key — adds complexity without changing the threat model, and would not protect against the "daemon as SYSTEM has wrong DPAPI scope" failure mode that D2 actually addresses.

### Refuse `LocalService` + `NetworkService` too

**Considered**: be maximally defensive and refuse all three system identities.

**Rejected**: they have per-account DPAPI scopes (different from `LocalSystem`'s machine-scoped key), so a `csq` daemon launched as `LocalService` could plausibly do credential-rotation work for that service identity. Refusing all of them would break a hypothetical "csq as a multi-tenant service" deployment that journal 0005 doesn't rule out. Document the choice; widen if observed-in-practice issues surface.

## Security-review convergence

In-session red-team by `security-reviewer`:

- **CRITICAL**: 0
- **HIGH**: 2 — both fixed (H1 surface-tag injection into `CredEnumerateW` pattern, H2 interior-NUL truncation in `to_wide`)
- **MEDIUM**: 4 — all fixed (M1 `VAULT_OP_TIMEOUT` not enforced on macOS/Windows; M2 `is_running_as_local_system` fail-OPEN; M3 cleartext blob not zeroized; M4 misclassified UTF-8 failure)
- **LOW**: 4 — addressed (L1 + L2 structured warns on corrupt entries, L3 obviously-fake test fixture, L4 subsumed by M2 fix)

The `withdrawn` finding (M2 about token leak — the original review listed it then withdrew on second pass) is preserved in the audit trail by the journal record but did not require code changes.

PR-gate verdict after fixes: PASS (verified by code-level review against the original findings list — re-spawn deferred since each finding had a one-to-one mechanical fix).

Convergence cost: ~30 minutes for the 6 above-LOW + 4 LOW findings, including the cross-cutting `run_with_timeout` helper that touches macOS too.

## Consequences

1. Windows users get a proper native Vault backend. Per-user, per-machine, DPAPI-encrypted, no roaming.
2. csq daemon refuses to start under `LocalSystem` with a clear error message naming the workaround (Task Scheduler "run when logged on").
3. macOS Keychain syscalls now honour `VAULT_OP_TIMEOUT` — pre-existing gap closed via the new `run_with_timeout` shared helper.
4. Workspace test count: 1337 (unchanged on macOS — all new tests are `#[cfg(target_os = "windows")]`). Windows CI exercises the dispatch contract + the `to_wide` / `validate_surface` regressions; gated `#[ignore]` live tests run via `--include-ignored` on a Windows box before security sign-off.
5. New csq-core feature deps: `Win32_Security` + `Win32_Security_Credentials` added to the existing `windows-sys` block. No new transitive crates; `windows-sys` is already pulled in by Tauri + tokio on Windows.
6. `platform::secret` is now fully wired across all three platforms — PR-G2b can flip the `SURFACE_GEMINI` const placeholder to `Surface::Gemini.as_str()` without touching the backend layer.

## For Discussion

1. **Counterfactual**: if security-reviewer M1 had not fired, how long until a hung Keychain or Cred call would have shown up in production? Given the Vault is called from the daemon usage poller (~5s cycle), a real hang would have been very visible — but the gap was a contract violation regardless. The fix was cheap (one shared helper); the right posture is "honour the contract you wrote".

2. **Compare**: does the `run_with_timeout` helper need to live in mod.rs or could it be per-backend? Per-backend would duplicate the spawn+recv_timeout dance three times. Shared helper centralizes the trade-off ("worker thread may detach on timeout") so a future review can reason about it once.

3. **Evidence**: the LocalSystem refusal exists for a real failure mode (DPAPI scope mismatch) but cannot be exercised on a developer workstation that runs as a normal user. Live validation requires an enterprise CI harness or a manual smoke test on a Windows VM with `psexec -s`. Documented as an unverified-locally test path in the PR description.

## Cross-references

- workspaces/gemini/02-plans/01-implementation-plan.md PR-G2a.3 section
- workspaces/gemini/journal/0005 — design reconciliation (parent decision tree); Q5 (LocalSystem refusal) and Q7 (deleted-entry resurrection)
- workspaces/gemini/journal/0006 — PR-G2a.2 (Linux backends) sibling decision record
- csq-core/src/platform/secret/windows.rs — WindowsCredentialVault impl
- csq-core/src/platform/secret/mod.rs — `run_with_timeout` shared helper + dispatch
- csq-core/src/platform/secret/macos.rs — now uses `run_with_timeout` for VAULT_OP_TIMEOUT enforcement
- .claude/rules/security.md §6 — fail-closed on Keychain/lock contention
- .claude/rules/zero-tolerance.md Rule 1 + Rule 5 — pre-existing failures resolved + above-LOW in-session
