---
type: DECISION
date: 2026-04-25
created_at: 2026-04-25T23:30:00Z
author: agent
session_id: 2026-04-25-gemini-pr-g3
session_turn: 30
project: gemini
topic: PR-G3 — Gemini NDJSON event log + daemon consumer + live IPC route + redteam convergence
phase: implement
tags: [gemini, ndjson, daemon, consumer, ipc, redteam, pr-g3, durability]
---

# Decision — PR-G3: NDJSON event log + daemon consumer + live IPC route

## Context

PR-G2a (#192) shipped scaffolding with the logical `GeminiEvent` type but no on-disk durability path or daemon consumer. PR-G2a.2 (#193) and PR-G2a.3 (#194) shipped the platform-native `Vault` backends. PR-G1 (#195) shipped the `Surface::Gemini` enum variant. PR-G2b (#196) flipped the last `"gemini"` literals in `platform::secret` test code to `Surface::Gemini.as_str()`.

PR-G3 is the **load-bearing PR** of the Gemini sequence — it implements the C-CR2 design tenet: "single-writer-to-quota.json preserved via CLI-durable event log". The CLI never writes `quota.json` directly; it writes NDJSON events that outlive the CLI process; the daemon drains events on each poll tick and writes `quota.json` atomically. Events are durable across daemon-down windows (zero loss for `sync_data`-completed lines).

## Decisions

### D1 — `EventEnvelope` is the single shape across NDJSON + IPC

Earlier sketches proposed splitting on-disk shape from on-the-wire IPC shape. Rejected. A single `EventEnvelope { v, id, ts, slot, surface, kind, payload }` carries through both paths so the daemon's `id`-based dedup works uniformly. `serde(flatten)` lets the inner `EventKind` use `serde(tag = "kind", content = "payload")` and produce the spec-pinned wire form (spec 05 §5.8.1):

```json
{
  "v": 1,
  "id": "<26-char base32 UUIDv7>",
  "ts": "2026-04-25T22:30:00.123Z",
  "slot": 3,
  "surface": "gemini",
  "kind": "rate_limited",
  "payload": { "retry_delay_s": 3600, "quota_metric": "...", "cap": 250 }
}
```

### D2 — Hand-rolled UUIDv7, no `uuid` crate dependency

`csq-core/src/providers/gemini/event_id.rs` implements RFC 9562 §5.7 in ~80 lines using the existing `getrandom` workspace dependency. UUIDv7 IDs are NOT used as security identifiers — only as dedup keys. The `uuid` crate would add a build-graph hop for code that never changes; hand-rolled keeps the dep surface minimal per the spirit of `rules/independence.md` Rule 3 (even though that rule's letter targets the Python era).

The base32 encoding uses RFC 4648 alphabet (uppercase A-Z 2-7) without padding. 128 bits → 26 chars (5 bits per char, last char has 3 data bits + 2 zero-pad). Lex-comparison over base32 strings matches comparison over the underlying bytes, which is monotone in time because the timestamp sits at the high end of the layout.

### D3 — `GeminiConsumerState` is shared between live IPC and drainer

A single struct of three `Arc`-backed fields (applied-set, breaker map, quota mutex) is constructed once in the daemon lifecycle and cloned into both the `RouterState` (for the IPC route handler) and `spawn_usage_poller` (for the drainer's tick). Per spec 05 §5.8.1: "single-writer-to-quota.json invariant preserved across IPC path AND NDJSON drain path because both terminate at the same mutex."

The dedup `AppliedSet` is a bounded LRU at 16k entries (FIFO order). UUIDv7 monotonicity means an evicted ID is always older than every ID still present; older IDs cannot reappear (file-order dedup guarantees this). The bound prevents unbounded memory growth.

### D4 — Drainer: per-slot fcntl lock, non-blocking

`drain_slot` acquires `platform::lock::try_lock_file` on a sibling `gemini-events-<slot>.lock` file. On contention it returns `DrainError::LockContended` and the next tick retries — never blocks. Spec 05 §5.8.1 mandates this discipline.

The drainer reads the entire file content, parses each line into an `EventEnvelope`, filters out duplicates and unsupported `v`, applies under the quota mutex, then truncates the log on success. On any parse error, the file is renamed to `gemini-events-<slot>.corrupt.<unix_ms>.ndjson` for operator inspection and a fresh log starts on the next event.

### D5 — Midnight-LA reset task is a separate tokio task

Resetting `requests_today` to 0 at midnight America/Los_Angeles runs as its own task spawned alongside the usage poller. Sleeps until the next LA midnight, fires `apply_midnight_reset` under the quota mutex, repeats. Cancellation-aware via the shared shutdown token. ADR-G05 pins the timezone for DST-correctness; the implementation uses fixed -08:00 for the millis-until-midnight calculation, which can drift by 60 min on the two DST transition days per year — acceptable per the ADR's "best-effort daily reset" framing.

### D6 — H1 capability audit reduces to verification

PR-G3 adds zero `#[tauri::command]` definitions in `csq-desktop`. The `POST /api/gemini/event` route lives on the daemon's HTTP/JSON Unix-socket router, NOT in Tauri's IPC layer. `csq-desktop/src-tauri/capabilities/default.json` is bit-identical to PR-G2b. Per `rules/tauri-commands.md` "Permission Grant Shape", the audit's enumeration of every `:default` bundle has nothing new to enumerate. The audit defers to PR-G5 when `gemini_provision`, `gemini_switch_model`, `gemini_probe_tos_residue` Tauri commands ship.

## Redteam convergence (PR-G3 round 1)

`security-reviewer` flagged 3 HIGH + 3 MEDIUM that REQUIRED in-PR resolution per `rules/zero-tolerance.md` Rule 5 (no residual risks acceptable):

| ID  | Severity | Issue                                                                                                                              | Fix                                                                                                                                                                                                                                           |
| --- | -------- | ---------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| H1  | HIGH     | IPC handler did not validate `envelope.surface == "gemini"`; same-UID caller could clobber Anthropic quota row                     | Added explicit surface check returning `400 invalid_surface` (`server.rs`) + integration test `gemini_event_live_ipc_rejects_non_gemini_surface`                                                                                              |
| H2  | HIGH     | IPC accepted any `slot` 1..999 regardless of provisioning state                                                                    | Added structured `warn!` log (`gemini_event_first_time_slot`) when IPC creates a quota row for a previously-unseen slot. Discovery-cache integration deferred to PR-G4 (the Gemini CLI surface dispatch PR) where the natural plumbing exists |
| H3  | HIGH     | `parse_rfc3339_to_unix_secs` rejected `±HH:MM` offsets, breaking round-trip with `format_rfc3339_la`-produced `last_reset` strings | Widened parser to accept both `Z` and `±HH:MM` plus optional fractional seconds; added `parse_rfc3339_accepts_z_and_offsets` regression test                                                                                                  |
| M1  | MEDIUM   | NDJSON writer relied on `mode(0o600)` at open time; future code paths could regress                                                | Added `secure_file()` defensive call after each `append_event` (no-op on Windows)                                                                                                                                                             |
| M2  | MEDIUM   | Quarantine sibling inherited source perms via rename; manually-dropped logs at 0o644 stayed world-readable                         | Added `secure_file()` call after rename in `quarantine_log`                                                                                                                                                                                   |
| M3  | MEDIUM   | Same-UID caller could trip the schema-drift breaker via 5 IPC POSTs and force `kind=unknown`                                       | Introduced `EventSource { Drain, Ipc }` enum and `apply_event_with_source`. IPC drift events are observed (debug-logged) but do NOT increment the breaker. Two regression tests pin the gate                                                  |

L1 (`pub fn apply_event` exposed across crate boundary), L2 (UUIDv7 panic on getrandom failure), L3 (duplicated Hinnant `unix_to_civil`), and L4 (silent `compute_reset_at` parse-failure) are deferred to follow-up PRs (G4 / G5 / a separate refactor PR) — none are exploitable, all four cost more session time to fix cleanly than they save.

## Alternatives considered

### A1 — uuid crate instead of hand-rolled

Rejected per D2. Adds a build-graph hop for static code; the hand-rolled implementation is unit-tested for layout correctness (version nibble = 7, variant bits = 0b10, 80-bit random uniqueness across 10k samples, k-sortability after 5ms).

### A2 — Per-slot quota mutex instead of process-wide

Rejected for PR-G3. Per-slot would parallelize quota writes across slots, but at single-digit slot counts the overhead of a `HashMap<u16, Arc<Mutex<()>>>` outweighs the benefit. The process-wide mutex is correct (the only invariant is single-writer); per-slot is an optimization deferred to a future PR if profiling justifies it.

### A3 — Live IPC route as a Tauri command instead of an HTTP route

Rejected. The csq-cli emitter is the primary client and runs as a separate process from csq-desktop; routing through Tauri would require a daemon → Tauri bridge. The daemon's existing Unix-socket HTTP router (with 3-layer security) is the natural home for cross-process IPC.

## Consequences

### Tests

1344 → 1382 (+38 tests):

- 7 UUIDv7 (`event_id.rs`)
- 12 envelope + writer (`capture.rs`)
- 18 drainer + apply + redteam fixes (`gemini.rs`) — including `ipc_source_drift_does_not_trip_breaker`, `drain_source_drift_still_trips_breaker`, `parse_rfc3339_accepts_z_and_offsets`
- 4 live IPC integration tests (`tests/daemon_integration.rs`) — including `gemini_event_live_ipc_rejects_non_gemini_surface`

`cargo clippy --workspace --all-targets -- -D warnings` clean. `cargo fmt --all -- --check` clean.

### Spec touchpoints

PR-G0 froze the schemas this PR implements. No spec edits were needed in PR-G3 itself — the implementation matches the frozen contracts in spec 05 §5.8.1 (NDJSON layout + drain discipline) and spec 07 §7.2.3.1 (event-delivery contract: 50ms connect, drop-on-unavailable, NDJSON as durability floor).

### Wire-shape implications

The live IPC handler's response is `204 No Content` on accept-or-dedup, `400` with fixed-vocabulary `error` tag on bad input. No upstream-body echoes (rules/security.md §2). Future surfaces using the same NDJSON pattern can post to the same envelope shape — `surface` is the dispatch key.

## For Discussion

1. **H2 deferral — when does the discovery-cache integration become cheap?** The redteam reviewer suggested adding a "slot exists in discovered accounts" check on the IPC handler. We deferred to PR-G4 because the discovery cache is a `RouterState` field with a 5-second TTL — checking it from `gemini_event_handler` would require either re-running discovery synchronously (adds latency to a 50ms-budget path) or trusting a 5-second-stale view (which races account creation). PR-G4 ships the `csq setkey gemini` flow that creates the slot via the Vault before any IPC traffic. Is the structured-log alone (PR-G3 H2 fix) enough until then, or does the same-UID threat model demand a stricter check now? What evidence would change the call?

2. **Counterfactual — if UUIDv7 had needed a uuid-crate dep.** D2 chose hand-rolled because csq-core already has `getrandom`. If `getrandom` weren't already a dep, would adding `uuid` cleanly have been preferable to adding `getrandom` AND hand-rolling? The deeper question: at what point does a 1-feature-of-1-crate import beat a 100-line hand-rolled equivalent? Argon2 + aes-gcm + secret-service all argued for the dep on cryptographic-correctness grounds; UUIDv7 doesn't carry that argument.

3. **Evidence question — what does "drift event from IPC" actually mean?** M3 split events by source: drain-path drift trips the breaker, IPC-path drift is debug-logged only. The reviewer's threat model is a same-UID malicious caller. But the _legitimate_ question is: under what conditions would csq-cli emit a drift event AND the daemon receive it via IPC but not via NDJSON drain? The NDJSON write happens BEFORE the IPC POST in the emitter (spec 07 §7.2.3.1: "NDJSON is the durability floor, not a fallback"). So IPC drift events are always paired with an NDJSON drift event the drainer will later apply via the breaker-counting path. Does that mean M3's gate is over-conservative — i.e. the breaker is correctly tripped by the eventual drain regardless of the IPC short-circuit? Or does the dedup ledger prevent the drain event from re-applying after IPC already applied it (making the ledger the actual reason the gate matters)?
