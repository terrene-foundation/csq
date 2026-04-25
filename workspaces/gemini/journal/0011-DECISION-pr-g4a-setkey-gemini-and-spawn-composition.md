---
type: DECISION
date: 2026-04-26
created_at: 2026-04-26T00:05:00Z
author: agent
session_id: 2026-04-26-gemini-pr-g4a
session_turn: 25
project: gemini
topic: PR-G4a — setkey gemini + spawn_gemini end-to-end + run dispatch + H2 resolution
phase: implement
tags: [gemini, csq-cli, setkey, spawn, vault, ipc, h2, pr-g4a]
---

# Decision — PR-G4a: setkey gemini + spawn_gemini composition + H2 IPC slot guard

## Context

PR-G3 (#197) shipped the NDJSON event log + daemon HTTP consumer + live
IPC route, but with three deferrals that PR-G4 was scheduled to close:

1. **End-to-end `spawn_gemini`** — PR-G2a (#192) shipped `prepare_env` and
   `pre_spawn_dotenv_scan` as standalone helpers; the actual `exec
   gemini-cli` composition was intentionally left unfinished pending
   the Surface enum (PR-G1, #195).
2. **Slot provisioning** — `csq setkey gemini` did not exist; there was
   no path for an operator to bind a Gemini API key to a slot.
3. **H2 deferral** — PR-G3's IPC handler structured-logs
   `gemini_event_first_time_slot` for unprovisioned slots but does not
   refuse them. PR-G4 was the natural home for the binding marker that
   makes a hard slot-existence check viable.

PR-G4 in the implementation plan also covers `models switch` and
cross-surface `swap`. Splitting PR-G4 into G4a (provisioning + spawn) and
G4b (config mutability) follows the established Gemini cadence (G2a,
G2a.2, G2a.3, G1, G2b, G3 all separate PRs) and keeps the diff under one
review session.

## Decisions

### D1 — `credentials/gemini-<N>.json` is the binding marker

Three other surfaces use this exact pattern (`credentials/<N>.json`,
`credentials/codex-<N>.json`); PR-G1 already wired the path through
`canonical_path_for(_, _, Surface::Gemini)`. The marker carries
*metadata* — auth mode (api_key vs vertex_sa), the Vertex SA path when
applicable, the operator-selected model — and **never any secret
material**. The API key lives in the platform vault; the Vertex SA JSON
lives wherever the operator pointed `--vertex-sa-json`.

The marker is the single source of truth for "is slot N Gemini-bound".
Dispatch in `csq run`, the daemon IPC handler's H2 gate, and a future
`csq listkeys` enumeration all share the same `symlink_metadata`
syscall. No vault touch in any dispatch path — that protects the
50 ms-budget IPC handler (spec 07 §7.2.3.1) from a Keychain prompt
latency spike.

### D2 — `build_spawn_plan` is testable, `execute_plan` is not

The end-to-end `spawn_gemini` orchestrates five steps (dotenv scan, read
binding, drift detect, vault decrypt, env build); the sixth step is an
`exec(2)` that replaces the calling process. Splitting the function in
two — `build_spawn_plan` returns `SpawnPlan` data, `execute_plan` execs
the plan — keeps the composition layer fully unit-testable without a
TTY or `gemini-cli` on `PATH`. Eight new tests cover the
build-plan branches:

- happy path inserts `GEMINI_API_KEY` via vault read
- drift detector seeds `<handle_dir>/.gemini/settings.json` with the
  binding's model name
- Vertex SA mode inserts `GOOGLE_APPLICATION_CREDENTIALS` and re-validates
  the path at spawn time
- shadow `.env` in CWD refuses with `SpawnError::ShadowAuth`
- missing binding marker refuses with `SpawnError::Provision(Io
  NotFound)`
- vault entry missing for an api-key binding refuses with
  `SpawnError::Vault(NotFound)`
- Vertex SA file disappeared post-provisioning refuses with
  `SpawnError::Provision(VertexSaInvalid)`
- parent shell `ANTHROPIC_API_KEY` does NOT leak into the child env
  (allowlist regression)

### D3 — H2 resolution: hard 404 on unprovisioned IPC traffic

PR-G3 deferred this gate because no marker existed. PR-G4a's marker
makes the check trivial — one `symlink_metadata` syscall (the same
syscall the dispatch path uses) keeps the live IPC handler under its
50 ms budget. `gemini_event_handler` now returns `404 slot_not_provisioned`
for any slot without `credentials/gemini-<N>.json`.

The structured-log warning `gemini_event_first_time_slot` is preserved
because there is still a brief window between binding write and
quota.json row creation where the slot is bound but no row exists; the
warning is the diagnostic for that window.

### D4 — `csq login --provider gemini` refuses with FR-G-CLI-06 message

API keys are not OAuth tokens. The login command refuses with a pointer
to the right command. The fall-through error message also widens to
mention gemini in the supported-providers list so a user who guesses
"gemini" gets the right pointer.

### D5 — Slot conflict guard parity with FR-CLI-05

`csq setkey gemini --slot N` refuses if N is already bound to Codex or
Anthropic OAuth. Same posture as `setkey mm` per FR-CLI-05 — the user
must `csq logout N` first. Avoids the "now there are two surfaces
fighting over slot N" bug class.

### D6 — `Gemini` SetkeyCmd variant has no `--key` flag

FR-G-CLI-03 mandates stdin-only key entry. The cleanest enforcement is
to NOT define the `--key` flag at all on the `Gemini` clap variant.
Operators piping the key (`echo $K | csq setkey gemini --slot N`) hit
the existing `read_key_interactive` non-TTY path; interactive operators
hit the hidden-input branch. The `--vertex-sa-json` flag is the only
permitted argument that carries operator data, and SA paths are
non-secret (the file at the path is the secret).

## Consequences

### Tests

1382 → 1408 (+26 tests):

- 17 provisioning tests (`provisioning.rs`) — round-trip API-key + Vertex
  SA modes, 0o600 perms, dangling-symlink dispatch, oversized SA file
  rejection, schema-version refusal, unbind idempotence
- 8 spawn-plan composition tests (`spawn.rs`) — 5 happy-path + drift +
  parent-env-leak + 4 refusal branches
- 1 daemon integration test (`daemon_integration.rs`) — H2 unprovisioned
  slot returns 404 and does not mutate quota.json
- Existing 3 live-IPC happy-path tests updated to call
  `provision_gemini_slot` first (otherwise they would 404)

`cargo clippy --workspace --all-targets -- -D warnings` clean.
`cargo fmt --all -- --check` clean.

### Spec touchpoints

No spec edits required — the implementation matches the contracts
already pinned in spec 07 §7.2.3 (binding marker layout) and §7.5
(INV-P02 inverted for Gemini) and spec 05 §5.8.1 (event-delivery
contract).

### Wire-shape implications

The H2 gate adds a new fixed-vocabulary error tag
`slot_not_provisioned` (404). No upstream-body echoes per
rules/security.md §2. CLI clients seeing this tag should re-check
binding state before retrying.

### What's left (PR-G4b)

- `csq models switch --provider gemini --slot N <model>` —
  atomic rewrite of `model_name` in the binding marker, which
  the next spawn picks up via the drift detector's
  `reassert_api_key_selected_type(_, model_name)` path.
- `csq swap M` cross-surface from / to a Gemini slot — currently
  same-surface swap-by-symlink-repoint works through existing
  rotation::swap_to; cross-surface needs the exec-in-place path
  per INV-P05.

## For Discussion

1. **Vault delete on uninstall — who calls it?** PR-G4a's
   `provisioning::unbind` removes the binding marker but explicitly does
   NOT touch the vault. The intent was that `csq logout N` (or a future
   `csq rmkey gemini --slot N`) calls `vault.delete` separately so the
   audit log emits two distinct events. But PR-G4a does not yet wire
   either of those — the operator who uninstalls a Gemini slot today
   will leave the keychain entry orphaned. Is this acceptable until
   PR-G4b (which would add `csq logout N` Gemini support), or should
   PR-G4a have shipped the vault delete in `unbind` for safety? The
   counter-argument: silently deleting a vault entry on `unbind` makes
   `unbind` non-recoverable — operators who run it by mistake lose
   their key.

2. **Counterfactual — if the binding marker had been the vault entry
   itself.** A simpler design would have used `vault.list_slots(GEMINI)`
   as the dispatch signal and skipped the marker file entirely. We
   rejected this because (a) the dispatch path runs on every `csq run`
   and the macOS Keychain may prompt the user, (b) the daemon IPC
   handler's 50 ms latency budget cannot accommodate a vault lookup,
   and (c) Vertex SA mode has no vault entry — the path lives on disk.
   But suppose the daemon path didn't exist (e.g. PR-G4 had reverted
   the IPC route): would the marker still earn its complexity?
   Probably not — `Vault::list_slots` would suffice for `csq run`
   alone. The marker exists because the daemon IPC handler is the
   load-bearing latency-sensitive caller.

3. **Evidence question — does the H2 gate close the same-UID malicious
   POST vector?** Same-UID attackers can still write a binding marker
   themselves before posting an event (the marker file requires no
   credentials). So the gate stops "POSTing for a slot that does not
   exist", not "POSTing as a same-UID attacker". The protection chain
   is: the binding marker write path goes through `csq setkey gemini`,
   which calls `refuse_if_slot_bound_to_other_surface` first — so a
   malicious marker write would also have to clobber an existing
   Anthropic / Codex slot, which the legitimate operator would notice
   on their next `csq run`. Is that chain audit-evident enough? Or
   should the marker carry a HMAC over its content keyed off the
   user's vault (defence-in-depth)?
