# 05 — Codex Surface: Scope Matrix

Columns: **IN_SCOPE** (ships in the first Codex release), **OUT_OF_SCOPE** (won't ship, by policy or user direction), **FUTURE** (explicitly deferred, not rejected), **REJECTED** (considered and declined, with rationale).

---

## IN_SCOPE

| Feature                                                                         | Source                                | Rationale                                                                            |
| ------------------------------------------------------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------ |
| `Surface` enum + dispatch tables                                                | spec 07 §7.1                          | Foundation for Codex and Gemini; refactor of existing providers is behavior-neutral. |
| `csq login <N> --provider codex` with pre-seeded config.toml                    | FR-CLI-01, ADR-C04                    | The only login path that keeps tokens out of Keychain.                               |
| `csq run <N>` for Codex slots (handle-dir IS CODEX_HOME)                        | FR-CLI-02, spec 07 §7.2.2             | Core UX parity with Claude slots.                                                    |
| Daemon refresher Codex extension (sole writer)                                  | FR-CORE-03, ADR-C02, ADR-C07          | Prevents refresh-token race (openai/codex#10332).                                    |
| Canonical auth.json at `credentials/codex-<N>.json`; symlinks everywhere else   | ADR-C03                               | Simplifies fanout, matches handle-dir ephemerality.                                  |
| `codex-sessions/` + `codex-history.jsonl` persistent per-account                | ADR-C05, INV-P04                      | Conversation data survives handle-dir sweep.                                         |
| `daemon::usage_poller::codex` with versioned parser + circuit breaker           | FR-CORE-02, ADR-C09                   | Quota visibility with graceful drift handling.                                       |
| `quota.json` v2 + one-shot v1→v2 migration                                      | spec 07 §7.6.2                        | Surface + kind tagging; backward compatible.                                         |
| Cross-surface `csq swap` with warning + `exec` in place                         | FR-CLI-03, ADR-C06                    | Keeps same-terminal flow across providers.                                           |
| `csq models switch` writing TOML `model = "..."`                                | FR-CLI-04, INV-P06                    | Consistent with Claude `env.ANTHROPIC_MODEL` pattern.                                |
| `csq setkey` hard-refuses for Codex                                             | FR-CLI-05                             | Prevents mis-configuration; clear error.                                             |
| AddAccountModal Codex card                                                      | FR-DESK-01                            | Desktop parity for add-account flow.                                                 |
| ChangeModelModal live fetch + cache + staleness badge + bundled cold-start list | FR-DESK-02, ADR-C10                   | Accurate model list without daemon work; never-empty modal.                          |
| ToS disclosure modal (first-login-only) + acceptance log                        | FR-DESK-03, ADR-C08                   | Foundation liability posture.                                                        |
| AccountCard surface badge                                                       | FR-DESK-04                            | Users can see which slots are Codex at a glance.                                     |
| Keychain-residue probe + refuse-on-decline flow (macOS, Linux)                  | FR-DESK-05, ADR-C11                   | Clean upgrade path for existing `codex` users; no silent corruption.                 |
| Per-account refresh mutex with 0400↔0600 mode-flip dance                        | ADR-C13, R7                           | Prevents EACCES races between login and refresh.                                     |
| Token redaction covers `sess-*` and Codex JWT shape                             | INV-P07, FR-CORE-04                   | No leaked tokens in logs or error payloads.                                          |
| `.env` hygiene (no Codex secrets in `.env`)                                     | rules/security.md                     | All tokens in file store under `credentials/`.                                       |
| Pre-existing classifier audit for OpenAI error shapes                           | §6 risk analysis, journal 0052 lesson | Codex error bodies mapped to correct `error_kind_tag` before PR3 ships.              |

## OUT_OF_SCOPE

| Feature                                                                    | Rationale                                                                                                            |
| -------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Proxy-to-Claude-Code path for Codex                                        | ADR-C01: native is strictly better; proxy handled by external projects.                                              |
| ChatGPT Team / Enterprise multi-seat pooling                               | briefs/01-vision.md §Non-goals: one ChatGPT login = one csq slot. Admin/workspace accounts are out of scope.         |
| Automated conversation migration across surfaces                           | briefs/01-vision.md §Non-goals: cross-surface swap drops transcript by design; user is warned.                       |
| Gemini surface                                                             | Ships AFTER Codex; same abstraction reused. Deliberate sequencing (briefs §Ships before).                            |
| Windows at first ship                                                      | ADR-C12: symlinks require developer mode. Tracked as FUTURE.                                                         |
| Building our own device-auth implementation                                | Delegate to `codex login` (memory: "Delegate to CC, don't reimplement"). csq shells out; does not reimplement OAuth. |
| Claude Code feature parity (slash commands, COC workflow, agents) on Codex | briefs §Non-goals: users get native codex UX; csq is the surface router, not a feature-parity layer.                 |
| Auto-rotation across mixed surfaces                                        | G13: cross-surface auto-rotate has materially different UX. Ships disabled; refuse cross-surface candidates.         |

## FUTURE

| Feature                                                                    | Deferral Reason                                                                             |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Windows Codex support (NTFS junction + hardlink layout, revised refresher) | ADR-C12 blocker; requires a new code path and testing tier. Tracked post-ship.              |
| Richer model-list cache eviction (TTL tuning, per-account overrides)       | ADR-C10 ships with a simple fetch-or-cache; richer policy waits on observed cache-hit data. |
| Multi-device refresh coordination (beyond per-account mutex)               | Current per-account `tokio::sync::Mutex` is same-machine only; multi-device deferred.       |
| Codex `/wham/usage` per-model breakdown                                    | If OpenAI exposes per-model fields, expose in UI. Blocked on schema stability.              |
| Auto-daemon-start from `csq run`                                           | Deliberately NOT done (ADR-C07); revisit only if onboarding friction data argues for it.    |
| Linux libsecret purge for pre-existing `codex` entries (full UX)           | Probe ships; richer purge UX on Linux waits on platform-specific tooling validation.        |
| Cross-surface auto-rotation                                                | Gated on a second-pass UX design (what does rotation "mean" when surfaces differ?).         |

## REJECTED

| Proposal                                                                        | Rejection Rationale                                                                                                                                  |
| ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Copy `auth.json` into each handle dir (per-terminal credential copy)            | openai/codex#15502 — copies break refresh. Symlink-only is the only correct shape.                                                                   |
| Let `codex` refresh its own tokens in-process                                   | openai/codex#10332 — refresh-token single-use race guarantees cross-terminal `invalid_grant` on contention. Daemon-sole-refresher is non-negotiable. |
| Pre-seed `config.toml` AFTER `codex login`                                      | Token is already in Keychain by then; post-seed does not migrate. Breaks ADR-C04's point.                                                            |
| Store canonical auth.json inside `config-<N>/.credentials.json`                 | Collides namespace with Claude credentials; forces union-of-providers schema into one file and two atomicity windows.                                |
| Silent cross-surface swap (no warning)                                          | Transcript loss is surprising; violates rules/communication.md Rule 4 (explain impact).                                                              |
| Hard-error on cross-surface swap (no exec)                                      | Forces kill+relaunch workflow for a case with a clean fix; worse UX for 95% of uses.                                                                 |
| Static, built-in-only Codex model list                                          | Bit-rots within months. ADR-C10 handles drift via live fetch + cache.                                                                                |
| Fail hard on `wham/usage` schema drift                                          | Blocks all quota reads when OpenAI changes a field. ADR-C09 graceful-degrades with raw capture.                                                      |
| "Accept residuals under same-user threat model" framing for any redteam finding | rules/zero-tolerance.md Rule 5 + user-memory "No residual risks acceptable". Every finding gets resolved in-session.                                 |
| Skipping the ToS modal on upgrade paths                                         | Breaks the disclosure audit trail. ADR-C08 requires per-machine acceptance regardless of install history.                                            |
| Letting user decline keychain purge and proceed anyway                          | ADR-C11 update: residue must be resolved before login proceeds, to prevent silent credential drift.                                                  |

---

## Estimate

Effort (autonomous-execution model, rules/autonomous-execution.md):

- /todos + approval gate: 1 session
- /implement (PR1 refactor + PR2 providers::codex + PR3 daemon refresher + PR4 quota poller + PR5 desktop UI + PR6 quota.json migration): 3–5 sessions, parallel where possible
- /redteam convergence + fixes: 1–2 sessions
- /codify: 0.5 session

Total: ~5–8 autonomous sessions before ship. ADR-C15 verification (does `cli_auth_credentials_store = "file"` disable in-process refresh?) is a gating item on PR1.
