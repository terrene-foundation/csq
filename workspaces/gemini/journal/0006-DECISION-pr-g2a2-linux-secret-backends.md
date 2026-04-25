---
type: DECISION
date: 2026-04-25
created_at: 2026-04-25T16:30:00Z
author: co-authored
session_id: 2026-04-25-gemini-pr-g2a2
session_turn: 30
project: gemini
topic: PR-G2a.2 Linux Secret Service + AES-GCM file fallback — design choices and security-review convergence
phase: implement
tags:
  [
    gemini,
    platform-secret,
    vault,
    linux,
    security,
    pr-g2a2,
    aes-gcm,
    argon2id,
    secret-service,
    dbus,
  ]
---

# Decision — PR-G2a.2 Linux Secret Service + AES-GCM file fallback

## Context

PR-G2a (#192, merged 2026-04-25) shipped the `Vault` trait + macOS Keychain backend + in-memory test backend. Linux + Windows returned `BackendUnavailable`. PR-G2a.2 lands the two Linux backends:

1. **Primary**: `linux::SecretServiceVault` — wraps the `secret-service = "4"` crate (D-Bus to gnome-keyring / kwallet / KeePassXC).
2. **Opt-in fallback**: `file::FileVault` — AES-256-GCM with Argon2id KDF, gated by `CSQ_SECRET_BACKEND=file` plus `CSQ_SECRET_PASSPHRASE` (or `CSQ_SECRET_PASSPHRASE_FILE`).

Per workspaces/gemini/journal/0005 (the design-reconciliation entry), the security-reviewer's tighter posture won every conflict. This entry captures the implementation choices that flowed from those decisions and the in-session red-team convergence.

## Decisions

### D1 — File backend lives in a platform-independent module

`platform::secret::file::FileVault` is compiled on every platform even though `open_default_vault` only routes there from Linux. Two reasons:

1. The crypto contract (Argon2id + AES-256-GCM + AAD binding) is portable Rust; isolating it in a `#[cfg(target_os = "linux")]` module would block macOS / Windows from running the unit tests, leaving CI unable to catch crypto bugs before they hit a Linux user.
2. A future Windows fallback (PR-G2a.3 "if DPAPI is unavailable" branch — currently rejected per journal 0005 §2) could reuse this code without churn.

The dispatch layer (`mod.rs::open_native_default`) is responsible for the "Linux only" gating: macOS and Windows return `BackendUnavailable` with an explicit `"CSQ_SECRET_BACKEND=file is Linux-only"` reason rather than honouring the env override. This is the "no silent fallback" rule from journal 0005 §1.

### D2 — Passphrase from env, not interactive prompt

`FileVault::open` reads the passphrase from `CSQ_SECRET_PASSPHRASE` (literal value) or `CSQ_SECRET_PASSPHRASE_FILE` (path). It does NOT prompt on a TTY.

Rationale: the vault is called from non-interactive contexts (daemon hot path, Tauri commands, usage poller). A TTY prompt would either hang the daemon or require complex askpass-style indirection. The user has already opted into the file backend by setting `CSQ_SECRET_BACKEND=file` — at that point requiring a second env var is a tax of one shell line, not a usability cliff.

Empty passphrase is rejected (`BackendUnavailable`) so a fat-fingered `export CSQ_SECRET_PASSPHRASE=` does not silently derive against a known-trivial input.

### D3 — Master key cached in `FileVault`; cleartext re-decrypted every `get`

The Argon2id-derived 32-byte AES key is cached in `FileVault::master_key` for the lifetime of the process. Cleartext secrets are NOT cached — every `get` re-reads `vault-store.json` and runs a fresh AEAD decrypt.

Rationale: re-deriving on every call would block the daemon for ~700ms (Argon2id at m=64MiB, t=3, p=1). For the daemon hot path this is unacceptable. The trait docstring on `mod.rs::Vault` was updated this PR to explicitly distinguish "decrypted secret cleartext" (forbidden cache) from "derived KDF master keys" (permitted cache) — closing the M1 ambiguity flagged by security-reviewer.

The cached key is wrapped in `SecretBytes(Vec<u8>)` with `#[derive(Zeroize, ZeroizeOnDrop)]` so it is wiped from memory on `Drop`. `FileVault` has a manual `Debug` impl that renders the master key as `"<redacted>"` so panic messages, `dbg!()` output, and `Result::unwrap_err` formatting cannot leak it.

### D4 — AAD binds version + surface + account

AES-GCM associated data is `format!("v{}:{}:{}", CURRENT_VERSION, slot.surface, slot.account.get())`. Two protections:

1. **Slot-swap defence** (test `aad_binding_prevents_slot_swap`): a file-edit attacker who swaps the ciphertext between two slots invalidates both AEAD tags, surfacing as `DecryptionFailed` for both slots rather than a silent slot-identity swap.
2. **Version pinning** (security review M3): if a future PR changes the file format, the AAD shape changes, and any unmigrated entry surfaces as `DecryptionFailed` rather than silently decrypting under a stale schema. The file format `version` field is the canonical version; AAD pins to it.

Cost: zero on the v1 ship — there are no existing entries to migrate.

### D5 — Sync wrapper around `secret-service` async API uses dedicated worker thread

`linux::block_with_timeout` spawns a fresh OS thread per call, builds a `current_thread` tokio runtime inside, runs the future under `tokio::time::timeout(VAULT_OP_TIMEOUT, ...)`, and joins.

Earlier draft used `tokio::task::block_in_place` + `Handle::block_on` when an ambient runtime existed. Security review H2 flagged this as panic-prone: `block_in_place` panics if the ambient runtime is `current_thread` (the default for `#[tokio::test]` and several CLI sites). The dedicated-thread pattern sidesteps the runtime-flavor minefield entirely.

Cost: an OS thread spawn per vault op (~10us). The actual D-Bus call dominates this by 3+ orders of magnitude. csq calls the vault a small constant number of times per process so the absolute throughput cost is negligible.

### D6 — Refuse-on-disappearance for write paths; degrade-to-empty for read paths

Security review H1: an earlier draft of `read_file` synthesized an empty header on `ErrorKind::NotFound`, with `salt = ""`. If the file vanished between `FileVault::open` and a subsequent `set`, the synthesized header would be written out with the empty salt, while the in-process master key was still bound to the original salt. Every subsequent `get` would surface `DecryptionFailed` — silent permanent corruption.

Fix: split into `read_file` (returns `BackendUnavailable` on NotFound) and `read_file_or_empty` (synthesizes for query paths only). `set` and `delete` use `read_file` and refuse with an actionable message naming the vanished file. `get` and `list_slots` use `read_file_or_empty` so the trait's `NotFound` / empty-list contracts hold.

Three regression tests pinned the asymmetry:

- `set_refuses_when_file_vanished_after_open`
- `delete_refuses_when_file_vanished_after_open`
- `get_after_file_vanished_returns_not_found`

## Alternatives considered and rejected

### Linux-only file backend code

**Considered**: gate the entire `file.rs` module with `#[cfg(target_os = "linux")]` to make the "Linux-only" intent maximally explicit at the type level.

**Rejected**: would block macOS / Windows from running the crypto unit tests, hiding bugs until a Linux user hit them. The dispatch-layer guard is the actual security boundary; the file module being compileable everywhere is a CI ergonomics win with no security cost.

### `keyring` crate instead of `secret-service` directly

**Considered**: the `keyring` crate provides a cross-platform wrapper around macOS Keychain, Linux Secret Service, and Windows Credential Manager.

**Rejected**: csq already uses `security-framework` directly on macOS (`platform::secret::macos::MacosKeychainVault`) for finer control over keychain attributes and ACL prompts. Adding `keyring` for Linux only would split the abstraction and complicate the audit log scheme (which is per-backend in csq). Direct `secret-service` matches the existing pattern.

### Per-`get` Argon2 derivation (no cache)

**Considered**: re-derive the master key on every vault op so no cleartext-derived material lives across calls.

**Rejected**: ~700ms per call at production Argon2 cost; the daemon usage poller calls `get` for every account at every poll cycle (~5s). Pinning a CPU at 700ms per call would exceed the cycle budget on multi-account hosts. The trait's "no caching" contract was clarified to distinguish derived KDF keys (permitted cache) from cleartext secrets (forbidden cache).

## Consequences

1. Linux users with a working session-bus + Secret Service provider get the native backend with no setup. Includes most desktop distros and Ubuntu Server with `gnome-keyring-daemon --foreground`.
2. Linux users on headless boxes (CI runners, WSL with no systemd-user, minimal Docker images) can opt into the file backend with `CSQ_SECRET_BACKEND=file CSQ_SECRET_PASSPHRASE=<value>`. Single-line opt-in; no per-call prompt.
3. macOS / Windows reject `CSQ_SECRET_BACKEND=file` even with a passphrase set. The error message names the rejection reason so users do not waste time wondering why their override was ignored.
4. Workspace test count: 1310 → 1337 (+27 from PR-G2a.2). All on macOS — Linux Secret Service live tests are gated `#[ignore]` and run via `--include-ignored` on a Linux box before security sign-off (CI on Linux exercises the dispatch contract + the file backend).
5. New csq-core deps: `secret-service = "4"` (Linux-only target), `aes-gcm` / `argon2` / `zeroize` moved from macOS-only to top-level (the file backend code compiles on every platform now).

## Security-review convergence

In-session red-team by `security-reviewer`:

- **CRITICAL**: 0
- **HIGH**: 2 — both fixed (H1 synthesize-on-NotFound corruption, H2 `block_in_place` panic on current_thread)
- **MEDIUM**: 3 — all fixed (M1 trait docstring caching ambiguity, M2 defensive bind on `Crypto` variant, M3 AAD version pinning)
- **LOW**: 5 — deferred per zero-tolerance Rule 5's LOW threshold. None blocking.

PR-gate verdict after fixes: **PASS**.

Convergence cost: ~20 minutes of mechanical edits + 3 new regression tests. Below the journal 0065 reference budget for "M-CDX-3 cluster" (which was 90 minutes for similar finding density).

## For Discussion

1. **Counterfactual**: if security-reviewer H1 had not fired, how long until the synthesized-empty-salt corruption would have surfaced in production? Best guess: never, because `vault-store.json` is in `~/.claude/accounts/` which csq creates and no other tool touches. The bug required the user to manually `rm` the file mid-process. But the cost of the fix was ~5 lines and three regression tests — cheap insurance against a class of file-disappear bugs we did not enumerate.

2. **Compare**: the `keyring` crate's Linux backend uses essentially the same `secret-service` API + sync wrapper pattern. Why didn't we use `keyring`? See "Alternatives considered" above — the direct dependency keeps the audit log scheme per-backend and avoids splitting the macOS path that already uses `security-framework` directly. **Challenge**: would adopting `keyring` for both macOS and Linux simplify the codebase enough to justify the abstraction? Not for one-additional-platform; reconsider when Windows DPAPI lands in PR-G2a.3.

3. **Evidence**: the AAD-binding test (`aad_binding_prevents_slot_swap`) verifies that swapping ciphertext between two slots surfaces `DecryptionFailed` for both. Is this the strongest test of AAD? Arguably the more compelling test is "the original entry is decryptable in its original slot after a revert" — but that's a property of AES-GCM correctness rather than our binding choice. The slot-swap test is the right one for our threat model.

## Cross-references

- workspaces/gemini/02-plans/01-implementation-plan.md PR-G2a.2 section
- workspaces/gemini/journal/0005 — design reconciliation (parent decision)
- csq-core/src/platform/secret/file.rs — FileVault impl
- csq-core/src/platform/secret/linux.rs — SecretServiceVault + dispatch
- csq-core/src/platform/secret/mod.rs — `open_default_vault` per-platform routing
- .claude/rules/security.md §1, §2, §5, §5a — atomic writes, no secrets in logs, partial-failure cleanup
- .claude/rules/zero-tolerance.md Rule 5 — convergence threshold (above-LOW resolved in-session)
