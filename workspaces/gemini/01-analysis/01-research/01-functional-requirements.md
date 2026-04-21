# Gemini Surface — Functional Requirements

Spec version: 1.0.0 | Status: DRAFT
Derived from: workspaces/gemini/briefs/01-vision.md, specs/07 §7.2.3/§7.3.4/§7.4, specs/02 INV-01..06, specs/05 §5.5.

## Actors

- **User** — csq operator provisioning/using a Gemini slot
- **csq-cli** — terminal-facing binary
- **csq-daemon** — background refresher + usage poller
- **csq-desktop** — Tauri dashboard

## csq-cli

### FR-G-CLI-01 — Provision key: `csq setkey gemini --slot <N>`

**As a** user **I want to** paste an AI Studio API key (or Vertex SA JSON path) and have slot N validated in one step **so that** I can use Gemini without reading docs.
**Given** slot N is unallocated and key `$K` is valid;
**When** user runs `csq setkey gemini --slot N` and pastes `$K`;
**Then**

- `config-<N>/.gemini/settings.json` is written first with `security.auth.selectedType = "gemini-api-key"` and `model.name = "auto"` (spec 07 §7.3.4 step 2).
- `$K` is encrypted at rest in `config-<N>/gemini-key.enc` via platform-native secret layer (ADR-G02). Plaintext never touches disk.
- One probe call: `gemini -p "ping" -m gemini-2.5-flash-lite --output-format json`; exit 0 required.
- On success: slot registered with daemon usage poller (counter mode).
- On failure: clear error (`invalid key`, `network error`, `model unavailable`), no state written.
  **Refuse when** `~/.gemini/oauth_creds.json` exists — warn user that OAuth is ignored and prompt confirm (ADR-G12).

### FR-G-CLI-02 — Vertex alt-mode

**Input:** `--vertex-sa-json <path>` flag replaces API-key paste.
**Then** daemon stores the file path (not the JSON body) in `config-<N>/gemini-vertex-sa.path`; spawn sets `GOOGLE_APPLICATION_CREDENTIALS=<path>` plus `GEMINI_API_KEY=` unset (ADR-G10).

### FR-G-CLI-03 — `csq run <N>` surface-aware spawn

**Given** slot N has `surface = Gemini`;
**When** user runs `csq run N`;
**Then**

- Handle dir `term-<pid>/` created; `term-<pid>/.gemini/` populated per spec 07 §7.2.3.
- Child env: `GEMINI_CLI_HOME=<abs term-<pid>>` AND `GEMINI_API_KEY=<decrypted>` (ADR-G03). No `.env` written anywhere.
- `exec gemini` (unix).
- Daemon NOT required (ADR-G09 / INV-P02).

### FR-G-CLI-04 — `csq models switch --slot <N> <model>`

**Input:** alias (`auto|pro|flash|flash-lite`) or concrete id (`gemini-2.5-pro`, `gemini-3-pro-preview`).
**Then** writes `model.name` in `config-<N>/.gemini/settings.json` via atomic rename. `ModelConfigTarget::SettingsModelName` dispatch (spec 07 INV-P06).
**Preview warning:** if model ends in `-preview`, cli prints "preview tier may silently downgrade".

### FR-G-CLI-05 — Cross-surface swap

`csq swap M` from Gemini→ClaudeCode/Codex or inbound inherits ADR-C06 (warn + `--yes` + exec-in-place). Source handle dir removed before exec (INV-P10). No FR for same-surface Gemini↔Gemini swap: symlink repoint per spec 02 §2.3.3.

### FR-G-CLI-06 — No `csq login --provider gemini`

API keys have no login flow. Command MUST refuse with "gemini uses API keys; run `csq setkey gemini --slot N`".

## csq-core

### FR-G-CORE-01 — `providers::gemini` module

- Key capture (paste / Vertex SA path).
- Encrypt/decrypt via `platform::secret` (Keychain macOS, libsecret Linux).
- `seed_settings_json(account_num)` writes ordered JSON before any spawn (INV-P03).
- Surface entry: `surface: Gemini, spawn_command: "gemini", home_env_var: "GEMINI_CLI_HOME", home_subdir: Some(".gemini"), quota_kind: Counter, model_config: SettingsModelName`.

### FR-G-CORE-02 — `daemon::usage_poller::gemini`

**Counter mode (spec 05 §5.8 / ADR-G05):**

- Increment on every spawn; persist `quota.json.accounts.<N>.counter.requests_today`.
- Daily reset at midnight America/Los_Angeles (Google's AI Studio billing TZ; pinned explicitly to honor DST).
- 429 path: if a spawn's first response body contains `RESOURCE_EXHAUSTED`, parse `quotaMetric` + `retryDelay`; write `rate_limit_reset_at`; clear synthetic percentage.
- Effective-model capture: parse first response `modelVersion`; store `selected_model` + `effective_model`. If they differ, set `downgrade: true` (ADR-G06).
- No synthesized percentage in UI — card reads "quota: n/a" when counter is empty (vision §Non-goals #3).

### FR-G-CORE-03 — Token redaction

`error::redact_tokens` MUST match `AIza*` keys and Vertex SA JWT claims before any log line (spec 07 INV-P07).

### FR-G-CORE-04 — Settings drift detector (ToS guard)

On every `csq run <gemini-slot>`, before spawn, csq reads `config-<N>/.gemini/settings.json` and reasserts `security.auth.selectedType = "gemini-api-key"`. If the value differs, csq rewrites it and emits `error_kind = "gemini_settings_drift"`. Rationale: user-level `~/.gemini/settings.json` merge or user hand-edits could otherwise route OAuth subscription traffic through csq-managed gemini, violating Google ToS (see workspaces/gemini/01-analysis/01-research/04-risk-analysis.md §6 EP1).

## csq-desktop

### FR-G-UI-01 — AddAccountModal: Gemini card

- Two tabs: **AI Studio API key** (paste) | **Vertex service account** (file picker).
- OAuth option is NOT rendered. Even if `~/.gemini/oauth_creds.json` exists, UI surfaces an inline warning: "A prior gemini-cli OAuth session was detected; csq will not use it. Google ToS prohibits OAuth subscription access by third-party tools" (ADR-G01/G12).
- ToS-warning modal on first Gemini provisioning ever: explicit text that OAuth rerouting is banned, first violation triggers Google recertification, second is permanent ban. User must tick accept.

### FR-G-UI-02 — ChangeModelModal

- **Static** list (ADR-G08): `auto`, `gemini-3-pro-preview`, `gemini-2.5-pro`, `gemini-2.5-flash`, `gemini-2.5-flash-lite`.
- Preview-tier note below any `-preview` entry: "Your tier may silently return 2.5-pro. csq will flag the downgrade after first call."
- Save button calls `models switch` (FR-G-CLI-04).

### FR-G-UI-03 — AccountCard

- **Surface badge:** "Gemini" chip (distinct color).
- **Downgrade badge:** when `selected_model != effective_model`, show `selected → effective` with tooltip explaining preview access.
- **Quota view:** counter ("N requests today") OR 429 reset countdown OR "n/a" — never a synthesized utilization bar.

## Persisted state

| Path                                    | Writer                                                         | Purpose                            |
| --------------------------------------- | -------------------------------------------------------------- | ---------------------------------- |
| `config-<N>/.gemini/settings.json`      | core (seed), cli (model switch), cli (drift reassert on spawn) | pre-seeded auth + model (INV-P03)  |
| `config-<N>/gemini-key.enc`             | core                                                           | encrypted API key (ADR-G02)        |
| `config-<N>/gemini-vertex-sa.path`      | core                                                           | Vertex SA file path (ADR-G10)      |
| `config-<N>/gemini-state/shell_history` | gemini (via symlink)                                           | persistent shell history (INV-P04) |
| `config-<N>/gemini-state/tmp/`          | gemini (via symlink)                                           | persistent tmp                     |
| `quota.json.accounts.<N>`               | daemon poller only                                             | counter + 429 + effective model    |

## Observable outcomes — end-to-end

- **Happy path:** setkey → validates → run → gemini launches non-interactively → first reply → dashboard shows `gemini-2.5-pro` both selected/effective, counter=1.
- **Preview downgrade:** user picks `gemini-3-pro-preview` → run → first reply returns `gemini-2.5-pro` → card shows `3-preview → 2.5-pro` badge.
- **429:** counter=237 → 429 `RESOURCE_EXHAUSTED retryDelay=3600s` → card flips to "resets in 59m 58s", counter stops incrementing.
- **OAuth residue:** user has `~/.gemini/oauth_creds.json` → modal warns + requires acknowledge; csq provisions the slot; csq never touches that file; drift detector (FR-G-CORE-04) continues to reassert API-key mode on every spawn.
