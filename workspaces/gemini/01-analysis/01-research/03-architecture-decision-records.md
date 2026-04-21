# Gemini Surface — Architecture Decision Records

Decisions for csq × Gemini native-CLI integration. Status: Accepted | Proposed | Superseded.

---

## ADR-G01 — API-key only; no OAuth subscription rerouting

**Status:** Accepted
**Context:** Google's `gemini-cli/docs/resources/tos-privacy.md` explicitly prohibits third-party software accessing Gemini CLI backend services via OAuth, with active 403 enforcement in 2026. First violation → Google Form recertification; second → permanent account ban.
**Decision:** csq ships Gemini as API-key (AI Studio) or Vertex SA JSON only. OAuth is never surfaced in UI, never attempted by the CLI, never documented as an option.
**Alternatives rejected:**

1. OAuth with a disclosure modal (pattern used for Codex ADR-C08) — inapplicable: OpenAI ToS is ambiguous; Google's is explicit-and-enforced.
2. Proxy Gemini OAuth through a hosted relay — shifts the ToS violation to the Foundation and does not remove it.
   **Consequences:** No rotation value for subscription evasion (pay-as-you-go has no cap to evade); csq value prop is single-pane multi-key quota awareness, not quota multiplication.

## ADR-G02 — Platform-secret encryption at rest for the API key

**Status:** Accepted
**Context:** `settings.json` is world-readable within the user home; plaintext `GEMINI_API_KEY` there leaks to any same-UID process that crawls dotfiles.
**Decision:** Encrypt the API key into `config-<N>/gemini-key.enc` via macOS Keychain / libsecret / (future) Windows Credential Manager. Decrypt only at spawn time; inject into child env (ADR-G03). File mode `0o600`.
**Alternatives rejected:**

1. Plaintext in `settings.json` — standard gemini-cli pattern but inherits same-UID leak risk noted in `rules/security.md`.
2. `.env` file — forbidden by ADR-G03.
   **Consequences:** `providers::gemini` depends on `platform::secret`. First keychain write prompts on macOS (acceptable one-time UX).

## ADR-G03 — `GEMINI_API_KEY` via process env; never `.env`

**Status:** Accepted
**Context:** `google-gemini/gemini-cli#21744` demonstrates the `.env` discovery chain (`$CWD → ancestors → $GEMINI_CLI_HOME → $HOME`) short-circuits at the first file found. A stale `.env` in the user's `$CWD` silently wins over one we'd write into `GEMINI_CLI_HOME`.
**Decision:** csq sets `GEMINI_API_KEY` on the spawned child's environment. csq writes zero `.env` files. Spawn site is a single helper `spawn_gemini(handle_dir, key)`; direct `Command::new("gemini")` elsewhere is lint-banned.
**Alternatives rejected:** `.env` under `GEMINI_CLI_HOME` (vulnerable to short-circuit), `.env` under `config-<N>/` (same).
**Consequences:** API key lives in process memory for the child lifetime only; never in a filesystem location gemini-cli discovery can reach stale.

## ADR-G04 — `settings.json` pre-seeded BEFORE first `gemini` spawn + re-asserted on every spawn

**Status:** Accepted
**Context:** First-launch gemini TUI interactively prompts for auth type unless `security.auth.selectedType` is set. User-level `~/.gemini/settings.json` may merge with workspace-level settings; if user flips `selectedType` to `oauth-personal` outside csq, next spawn would route OAuth traffic (ToS violation).
**Decision:** `providers::gemini::seed_settings_json(N)` writes `{security.auth.selectedType: "gemini-api-key", model.name: "auto"}` into `config-<N>/.gemini/settings.json` as the FIRST step of provisioning, before the probe call. Additionally, EVERY `csq run <gemini-slot>` re-asserts this setting before spawn (FR-G-CORE-04); if drift detected, csq rewrites and logs `gemini_settings_drift`.
**Alternatives rejected:** One-time pre-seed only — insufficient; user hand-edits or user-settings merge can flip auth type post-install.
**Consequences:** Provisioning is non-interactive. Drift detector guarantees ToS posture at every spawn, not just at install time.

## ADR-G05 — No public quota endpoint; client-side counter + 429 parse

**Status:** Accepted
**Context:** AI Studio API keys have no `/usage`-style endpoint. Vertex exposes billing via `cloudbilling.googleapis.com` but requires project-level IAM that csq does not manage.
**Decision:** Daemon maintains a per-slot request counter (increment on spawn), resets at midnight America/Los_Angeles daily. Parse `RESOURCE_EXHAUSTED` response bodies for real rate-limit signal. `QuotaKind::Counter` in the surface dispatch table (spec 07 §7.4).
**Critical constraint:** UI NEVER synthesizes a percentage. `quota.json.accounts.<N>.counter` exists or doesn't; if not, the card reads "quota: n/a". Violates `account-terminal-separation.md` rule 4 to fabricate.
**Alternatives rejected:** Screen-scrape AI Studio web dashboard — fragile, cookie auth, ToS grey zone. Derive from billing API — requires Vertex-only, IAM scope we don't hold.

## ADR-G06 — Effective-model downgrade capture from response stream

**Status:** Accepted
**Context:** Preview models (e.g. `gemini-3-pro-preview`) silently return a fallback (`gemini-2.5-pro`) on tiers without preview access. Same failure class as the GrowthBook model override documented in memory (`discovery_growthbook_model_override.md`).
**Decision:** Daemon poller (or spawn-side hook) parses `modelVersion` from every response (first + subsequent), persists `selected_model` + `effective_model` + `effective_model_first_seen_at` + `mismatch_count_today` on `quota.json`. When they differ, AccountCard renders a downgrade badge; flapping is debounced (latch on 3 mismatches in 5 minutes).
**Consequences:** No silent downgrade. Users diagnosing "wrong model" see it on the card within one request.

## ADR-G07 — Cross-surface swap inherits ADR-C06

**Status:** Accepted
**Context:** A Gemini terminal swapped to Claude Code (or vice versa) can't transfer conversation — different binaries, different state dirs.
**Decision:** Inherit Codex ADR-C06 verbatim: warn, confirm (`--yes` bypasses), exec-in-place. Source handle-dir removed before exec (INV-P10). Auto-rotation refuses cross-surface candidates (INV-P11).
**Consequences:** Single swap UX across all surfaces; no Gemini-specific branch.

## ADR-G08 — Static model list with preview-tier note

**Status:** Accepted
**Context:** Codex uses live fetch + cache (ADR-C10) because the GPT-5-codex catalog shifts often. Gemini's catalog is smaller (pro/flash/flash-lite + preview variants) and more stable; preview access is tier-gated and ADR-G06 already handles silent downgrade.
**Decision:** `ChangeModelModal` ships with a hardcoded list: `auto`, `gemini-3-pro-preview`, `gemini-2.5-pro`, `gemini-2.5-flash`, `gemini-2.5-flash-lite`. Update cadence is release-bound (bump the constant on each csq release).
**Alternatives rejected:** Live fetch from `generativelanguage.googleapis.com/v1beta/models` — adds a network dependency in the modal critical path with no visible benefit; stale list is a `chore` PR.

## ADR-G09 — No daemon prerequisite for Gemini slots

**Status:** Accepted
**Context:** INV-P02 mandates the daemon for refreshable surfaces (Claude Code OAuth, Codex). Gemini API keys are flat and long-lived; no refresh logic exists.
**Decision:** `csq run N` for a Gemini slot works with the daemon stopped. The usage poller (counter) runs only when the daemon is up; when stopped, the counter is not incremented and the card reads stale. This is honest — no daemon, no quota signal.
**Consequences:** Lower friction for first-time Gemini users; matches csq's existing MM/Z.AI API-key slot behavior.

## ADR-G10 — Vertex service-account JSON as alternate auth mode

**Status:** Accepted
**Context:** Enterprise users authenticate to Gemini via Vertex service-account JSON, not AI Studio keys. Rejecting Vertex forces them onto AI Studio (personal billing), which is wrong.
**Decision:** AddAccountModal Vertex tab accepts a file path to an existing SA JSON. csq stores the PATH (not the body) in `config-<N>/gemini-vertex-sa.path`. Spawn sets `GOOGLE_APPLICATION_CREDENTIALS=<path>`; `GEMINI_API_KEY` is unset. Probe call uses same path. csq re-validates path exists at every spawn; if deleted/moved, spawn refuses with actionable error.
**Out of scope:** Vertex project pinning, IAM scope reduction, SA rotation — delegated to `gcloud`.
**Consequences:** csq never reads SA JSON contents; file remains wherever the user placed it.

## ADR-G11 — No Windows support in first ship

**Status:** Accepted
**Context:** Shares ADR-C12 rationale verbatim: handle-dir model requires filesystem symlinks; Windows symlinks need developer mode.
**Decision:** `csq setkey gemini` on Windows refuses with exit 2 and a message pointing to the follow-up tracking issue.
**Consequences:** macOS + Linux at first ship. Windows handle-dir strategy (junctions + hardlinks) deferred.

## ADR-G12 — Refuse-with-warning if `~/.gemini/oauth_creds.json` exists

**Status:** Accepted
**Context:** A user who has run standalone gemini-cli likely has `~/.gemini/oauth_creds.json` from a prior OAuth login. Because csq sets `GEMINI_CLI_HOME` to the handle dir, that file is ignored — but the user may assume csq is using it (their "Gemini Advanced" subscription). That belief is wrong and creates a support surface.
**Decision:** At provisioning time, if `~/.gemini/oauth_creds.json` exists, surface a desktop modal: "A prior Gemini OAuth session was detected. csq does not use it (Google ToS prohibits OAuth rerouting by third-party tools). You will be billed on your API key." User must tick acknowledge to proceed.
**Alternatives rejected:**

1. Silent — creates the misperception.
2. Auto-purge the file — destroys standalone gemini-cli setup the user may still rely on.
   **Consequences:** One-time friction per machine per user. Clear mental model. Zero surprise on the first bill.

---

## Status summary

ADR-G01 through G12 Accepted pending human approval at `/todos` gate. No open blockers: unlike Codex (ADR-C15 verified OPEN-C01), Gemini's invariants do not depend on unverified binary internals — the risk surface is ToS + key handling, both of which are decided here.
