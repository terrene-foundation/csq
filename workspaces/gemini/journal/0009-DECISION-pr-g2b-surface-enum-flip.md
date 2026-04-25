---
type: DECISION
date: 2026-04-25
created_at: 2026-04-25T22:30:00Z
author: agent
session_id: 2026-04-25-gemini-pr-g2b
session_turn: 12
project: gemini
topic: PR-G2b — flip platform::secret test-code literals to Surface::Gemini.as_str() via local const
phase: implement
tags: [gemini, surface, platform-secret, pr-g2b, decoupling]
---

# Decision — PR-G2b: flip `"gemini"` literals in `platform::secret` to `Surface::Gemini.as_str()`

## Context

PR-G2a (#192) shipped the `platform::secret` Vault scaffolding with `surface: &'static str` SlotKey field, intentionally using a const placeholder `"gemini"` so the PR could land before the `Surface::Gemini` enum variant existed. PR-G2a.2 (#193) and PR-G2a.3 (#194) added the Linux Secret Service + AES-GCM file fallback and Windows DPAPI / Credential Manager backends respectively, both copying the literal-string convention from PR-G2a's tests. PR-G1 (#195) shipped `Surface::Gemini` plus `Surface::as_str()` (a `pub const fn` returning `&'static str`) and aliased `crate::providers::gemini::SURFACE_GEMINI` to `Surface::Gemini.as_str()`.

PR-G2b is the cleanup: every literal `"gemini"` in `csq-core/src/platform/secret/{mod,audit,in_memory,file}.rs` test code should derive from the enum so a future Surface rename pivots the test fixtures automatically.

The capability-manifest audit listed in the PR-G2b plan reduces to a no-op because PR-G2b adds zero IPC commands — the audit applies to PR-G3 when the daemon NDJSON consumer ships.

## Decisions

### D1 — Local `const GEMINI: &str = Surface::Gemini.as_str()` per test module

Each of the four test modules (`mod`, `audit`, `in_memory`, `file`) declares its own `const GEMINI: &str = Surface::Gemini.as_str();` and uses `GEMINI` everywhere — both in struct-field initialization (`SlotKey { surface: GEMINI, .. }`) and in match patterns (`SecretError::NotFound { surface: GEMINI, .. }`). The two contexts both accept a `const &str`, so the same identifier covers both.

**Why per-module instead of a single shared const:**

- Test modules are leaf modules. A shared const elsewhere (e.g. in a `secret::test_support` mod) would invert the dependency — the production module would import test scaffolding.
- The repetition is cheap (5 lines × 4 files = 20 lines) and each declaration documents why the test code is allowed to know about `Surface::Gemini`.
- The four-module-local declarations remain green if a future refactor pulls one file into a different crate.

**Why not import `crate::providers::gemini::SURFACE_GEMINI`:**

- That const lives in `providers::gemini`, which sits ABOVE `platform::secret` in the module hierarchy. Importing it would invert layering.
- The `SURFACE_GEMINI` alias exists for `providers::gemini`'s own internal sites (spawn, capture, keyfile) — making `platform::secret` reach across to grab it would couple the two layers in a direction the architecture rejects.

### D2 — Production code keeps `surface: &'static str`, not `Surface`

The SlotKey field stays `&'static str`. Switching it to `Surface` would force `platform::secret` to import `crate::providers::catalog::Surface`, which is the layer-inversion described above. The contract under H8 in the implementation plan is that `platform::secret` is sole-owned by Gemini today but designed to be surface-agnostic — the type signature should reflect that.

The new contract test `gemini_const_matches_surface_enum_wire_name` (in `mod.rs::tests`) anchors the invariant: if `Surface::Gemini.as_str()` ever returns something other than `"gemini"`, the test fails AND every SlotKey-using test pivots through the const — but the persisted vault entries (`csq.gemini.<n>` keychain service names, `csq-surface=gemini` Linux attributes, `vault-audit.ndjson` `surface` field) DO NOT pivot. The test acts as the early-warning that a Surface rename is also a vault schema migration.

### D3 — `validate_surface_tag` test data NOT flipped

`csq-core/src/platform/secret/windows.rs:617` keeps `for ok in ["gemini", "gemini-test", "future_surface", "anthropic"]` as literal strings. The test exercises the Windows backend's surface-tag VALIDATOR — it tests "this string is accepted" not "this is the Gemini surface." Replacing `"gemini"` with `GEMINI` here would obscure the test's intent (it's no longer about validation, it's about specific values) and would not gain any pivot value (the validator's contract is independent of which surfaces actually exist).

## Alternatives considered

### A1 — Replace `surface: &'static str` with `surface: Surface`

Rejected. The field type would tie `platform::secret::SlotKey` to the catalog enum, inverting H8's layering. Every backend (`linux.rs`, `macos.rs`, `windows.rs`, `file.rs`) would gain a `Surface` import even though they only need the wire string. The contract test in D2 covers the only invariant we actually need (string identity).

### A2 — Use the existing `crate::providers::gemini::SURFACE_GEMINI` directly

Rejected per D1's layering argument. `providers::gemini` depends on `platform::secret`; the reverse would create a cycle (modulo the rust compiler accepting it as a use-statement, the architectural intent is that `platform` does not know which `providers` exist).

### A3 — Defer the cleanup until a second surface needs the vault

Rejected. The string drift problem is invisible until it bites — the only way to catch it is at compile time via the const. Deferring means the next session inherits a code base where renaming `Surface::Gemini` silently breaks tests with cryptic match-pattern failures. Cheaper to fix now (one PR, 30 minutes) than to forensically trace a confusing test failure later.

## Consequences

### Immediate

- 1344 → 1345 workspace tests (+1: `gemini_const_matches_surface_enum_wire_name`).
- Doc-comments updated in `mod.rs` (SlotKey + module), `audit.rs` (module + `AuditEntry::surface`), `linux.rs` (`ATTR_SURFACE`) to reflect that the wire string derives from `Surface::as_str()`, not a placeholder.
- All seven sites listed in the session notes (`audit.rs:303, in_memory.rs:116/147, mod.rs:399/417/450, file.rs:633/746`) plus four additional sites the session notes missed (`audit.rs:287/306/321/340/348, in_memory.rs:172/191, file.rs:690/713/734/1039`) flipped to `GEMINI`.
- No production code paths changed — backend logic, error variants, audit format, file format are all bit-identical to PR-G1.

### Long-term

- A future Surface rename (`Gemini` → `GeminiV2`) breaks `gemini_const_matches_surface_enum_wire_name` first, then every test using `GEMINI` recompiles cleanly with the new value. The persisted-data implications (keychain service names, Linux attributes, audit log) STAY broken — that's the point of D2's "early-warning" framing: the test failure is the signal that a vault schema migration is also needed.
- When PR-G3's NDJSON event log ships, its test code follows this same pattern (`const GEMINI: &str = Surface::Gemini.as_str();` in event-log test modules).

### Capability-manifest audit (H1)

PR-G2b adds zero new Tauri commands. `csq-desktop/src-tauri/capabilities/default.json` is bit-identical. The H1 audit defers to PR-G3 when `gemini_provision`, `gemini_switch_model`, `gemini_probe_tos_residue` and the daemon NDJSON IPC types land.

## Verification

- `cargo test --workspace` — 1345 passing (was 1344), 0 failing, 6 ignored.
- `cargo test --workspace --package csq-core platform::secret` — 50 passing including new `gemini_const_matches_surface_enum_wire_name`.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo fmt --all -- --check` — clean.
- `grep -n '"gemini"' csq-core/src/platform/secret/` — only doc-comments, the JSON-schema example in `file.rs:34`, the contract assertion `assert_eq!(GEMINI, "gemini")`, and the unrelated `validate_surface_tag` test data remain.

## For Discussion

1. **Layering trade-off — is the import direction the right call?** D1 forbids `platform::secret` from importing `crate::providers::gemini::SURFACE_GEMINI` to avoid layer inversion, but allows it to import `crate::providers::catalog::Surface`. Both are in `providers/`. What distinguishes `catalog` from `gemini` strongly enough to permit one import and reject the other — and would that distinction survive PR-G3 when `providers::gemini::capture` defines IPC types that `daemon::usage_poller::gemini` consumes?

2. **Counterfactual — if PR-G2a had landed AFTER PR-G1.** The whole "const placeholder → enum flip" sequence exists because PR-G2a needed to land before PR-G1 (to enable PR-G2a.2/G2a.3 parallel work on backends). If we had sequenced PR-G1 first, would `SlotKey.surface: Surface` have been the obvious default, and is there any structural reason the layering argument in D2 still wins regardless of sequence? Or did the temporal ordering retroactively justify a layering decision that would have gone the other way under different sequencing?

3. **Evidence question — when does the contract test actually save us?** `gemini_const_matches_surface_enum_wire_name` asserts `GEMINI == "gemini"` AND `GEMINI == Surface::Gemini.as_str()`. The first assertion is stronger than the second (it pins the literal). If `Surface::as_str()` ever returns `"gemini-v2"`, the test fails on assertion 1 — which is exactly the early-warning we want. But: are there any realistic scenarios where assertion 2 fires WITHOUT assertion 1 (i.e. drift between `as_str()` and the persisted format), and if so, should we add a separate test that reads the literal from the on-disk vault file format to anchor THAT contract independently?
