# Gemini Surface — Scope Matrix

Features vs ship state. Rationale cites ADR / spec / rule.

| Feature                                                                                     | State        | Rationale                                                                            |
| ------------------------------------------------------------------------------------------- | ------------ | ------------------------------------------------------------------------------------ |
| `csq setkey gemini --slot <N>` (AI Studio key paste)                                        | IN_SCOPE     | FR-G-CLI-01; primary onboarding path                                                 |
| Vertex SA JSON path as alt auth                                                             | IN_SCOPE     | ADR-G10; enterprise users                                                            |
| `csq run <N>` surface-aware spawn                                                           | IN_SCOPE     | FR-G-CLI-03; spec 07 §7.3.4                                                          |
| `csq models switch --slot <N> <model>`                                                      | IN_SCOPE     | FR-G-CLI-04; INV-P06 SettingsModelName                                               |
| Same-surface `csq swap` (Gemini ↔ Gemini)                                                   | IN_SCOPE     | spec 02 §2.3.3 symlink repoint                                                       |
| Cross-surface swap (Gemini ↔ CC / Codex)                                                    | IN_SCOPE     | ADR-G07 / ADR-C06 exec-in-place                                                      |
| `providers::gemini` module (seed + encrypt + probe)                                         | IN_SCOPE     | FR-G-CORE-01; spec 07 §7.3.4                                                         |
| `settings.json` pre-seed BEFORE first spawn                                                 | IN_SCOPE     | ADR-G04; INV-P03                                                                     |
| `settings.json` drift detector re-asserts on every spawn                                    | IN_SCOPE     | ADR-G04; FR-G-CORE-04; EP1 ToS guard                                                 |
| API key encrypted at rest (`gemini-key.enc`)                                                | IN_SCOPE     | ADR-G02                                                                              |
| `GEMINI_API_KEY` via process env (no `.env`)                                                | IN_SCOPE     | ADR-G03; gemini-cli#21744                                                            |
| Single `spawn_gemini(handle_dir, key)` helper + lint-ban on direct `Command::new("gemini")` | IN_SCOPE     | ADR-G03 hermeticity                                                                  |
| Client-side counter + America/Los_Angeles midnight reset                                    | IN_SCOPE     | ADR-G05; FR-G-CORE-02                                                                |
| 429 `RESOURCE_EXHAUSTED` parse (retryDelay / quotaMetric) + schema-drift tag                | IN_SCOPE     | ADR-G05                                                                              |
| Effective-model downgrade capture (per-response, debounced)                                 | IN_SCOPE     | ADR-G06                                                                              |
| AddAccountModal: Gemini card with 2 tabs (key, Vertex)                                      | IN_SCOPE     | FR-G-UI-01                                                                           |
| ToS-warning modal (OAuth-banned disclosure)                                                 | IN_SCOPE     | ADR-G01; required for legal clarity                                                  |
| `~/.gemini/oauth_creds.json` refuse-with-warning                                            | IN_SCOPE     | ADR-G12                                                                              |
| ChangeModelModal with static list + preview note                                            | IN_SCOPE     | ADR-G08; FR-G-UI-02                                                                  |
| AccountCard Gemini badge + downgrade badge                                                  | IN_SCOPE     | FR-G-UI-03                                                                           |
| "quota: n/a" when counter empty (no synthesized %)                                          | IN_SCOPE     | ADR-G05; `account-terminal-separation.md` rule 4                                     |
| `persistent shell_history + tmp/` via symlinks                                              | IN_SCOPE     | spec 07 INV-P04                                                                      |
| Token redaction (`AIza*`, Vertex PEM, `client_email`) in logs                               | IN_SCOPE     | INV-P07                                                                              |
| `quota.json` v2 schema (surface + kind tags)                                                | IN_SCOPE     | spec 07 §7.4                                                                         |
| Env allowlist at spawn (+ explicit forbidden: `GOOGLE_OAUTH_*`)                             | IN_SCOPE     | EP3 ToS guard                                                                        |
| `csq login --provider gemini`                                                               | REJECTED     | FR-G-CLI-06; API keys have no login flow; command refuses                            |
| OAuth subscription rerouting (any form)                                                     | REJECTED     | ADR-G01; ToS ban with active enforcement                                             |
| Proxying Gemini through claude binary                                                       | REJECTED     | vision §Why; degrades tool calls + caching + thinking mode                           |
| Synthetic utilization percentage when counter empty                                         | REJECTED     | ADR-G05; violates `account-terminal-separation.md` rule 4                            |
| Plaintext API key in `settings.json`                                                        | REJECTED     | ADR-G02; same-UID leak vector                                                        |
| `.env` file for `GEMINI_API_KEY` (anywhere)                                                 | REJECTED     | ADR-G03; gemini-cli#21744 short-circuit                                              |
| Reading `~/.gemini/oauth_creds.json` silently                                               | REJECTED     | ADR-G12; user must acknowledge                                                       |
| Daemon hard prerequisite for Gemini slot                                                    | REJECTED     | ADR-G09; flat keys, no refresh                                                       |
| Auto-purging stale OAuth creds                                                              | REJECTED     | ADR-G12; user may still use standalone gemini-cli                                    |
| Live fetch of Gemini model list                                                             | OUT_OF_SCOPE | ADR-G08; catalog stable, release-bumped                                              |
| Vertex project pinning / IAM scope mgmt                                                     | OUT_OF_SCOPE | vision §Non-goals; delegated to `gcloud`                                             |
| `cloudbilling.googleapis.com` integration                                                   | OUT_OF_SCOPE | ADR-G05; IAM scope not held                                                          |
| Windows support                                                                             | FUTURE       | ADR-G11; shares ADR-C12 rationale                                                    |
| `claude.ai`-style web-dashboard cookie scrape                                               | OUT_OF_SCOPE | fragile, ToS grey zone                                                               |
| In-session `/model` slash command interception                                              | OUT_OF_SCOPE | INV-P06; native command is unaffected                                                |
| Screen-reader accessibility audit for new modals                                            | FUTURE       | UIUX track; tracked separately                                                       |
| Tray menu Gemini shortcut                                                                   | FUTURE       | spec 02 §2.7 tray reconception is a separate workstream                              |
| Auto-rotation among Gemini slots                                                            | OUT_OF_SCOPE | ADR-G09; no quota cap to rotate against; INV-P11 is same-surface policy for CC/Codex |
| `csq-update`-style migration from a pre-Gemini version                                      | IN_SCOPE     | vision §Acceptance; existing accounts unchanged, new slot provisions cleanly         |
| Importing `~/.gemini/settings.json`                                                         | OUT_OF_SCOPE | csq owns `config-<N>/.gemini/settings.json`; user can copy fields manually           |
| Supporting OAuth if Google ever relaxes ToS                                                 | FUTURE       | Gated on written ToS change; re-evaluate at that time                                |
