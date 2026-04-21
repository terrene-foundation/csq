# csq × Gemini — native-CLI provider surface (API-key only)

## Vision

Add Gemini (Google) as a provider surface in csq using the native `gemini` CLI with `GEMINI_CLI_HOME` isolation. Ships **API-key only** — no OAuth subscription rerouting. Users provision a Gemini account by pasting an AI Studio key (or a Vertex service-account JSON); csq injects `GEMINI_API_KEY` into the spawned process environment per account. Each slot is a separate `config-<N>/.gemini/` seeded with `security.auth.selectedType = "gemini-api-key"` so first launch is non-interactive.

Gemini lands after Codex and inherits the provider-surface dispatch abstraction introduced with Codex (spec 07).

## Why

- Gemini 2.5 / 3 Pro is materially useful for coding workflows with 1M-token context; csq users have asked for it alongside Claude and Codex.
- The native `gemini` CLI is strictly better than a Gemini-through-proxy-into-CC path: tool-call translation, prompt caching, and thinking-mode passthrough all degrade or break when routed through a bridge.
- API-key AI Studio billing is pay-as-you-go and does not require any form of multi-account rotation to avoid a subscription cap — but users still want csq's single-pane quota awareness across all providers.

## Scope

1. New `providers::gemini` module: API-key capture and validation, `config-<N>/.gemini/settings.json` pre-seeding, per-slot handle-dir layout.
2. Handle dir layout: `term-<pid>/.gemini/` is the effective state dir (gemini-cli prepends `.gemini/` to whatever `GEMINI_CLI_HOME` points at). `settings.json` symlinks to `config-<N>/.gemini/settings.json`; `tmp/` and `shell_history` symlink into `config-<N>/gemini-state/` so persistent history survives handle-dir sweep.
3. API-key injection strategy: csq injects `GEMINI_API_KEY` directly into the spawned child process environment. **Never writes `.env` files** — `google-gemini/gemini-cli#21744` demonstrates the `.env` discovery chain short-circuits unpredictably under `GEMINI_CLI_HOME`.
4. New `daemon::usage_poller::gemini` module: no public quota endpoint; increment-on-spawn client-side counter per slot, daily reset at UTC-05:00, parse `RESOURCE_EXHAUSTED` bodies from 429 responses for real rate-limit signal.
5. Effective-model downgrade detection: after first successful request, capture response `modelVersion`; if `effective != selected`, store both in `quota.json` and show a downgrade badge on the AccountCard. (Mirrors the GrowthBook-model-override discovery lesson.)
6. Desktop AddAccountModal gains a Gemini card: key paste, validate via headless `gemini -p "ping" -m gemini-2.5-flash-lite --output-format json` probe (exit 0 = ok), save. No login flow — API-key only.
7. ChangeModelModal with static Gemini model list (aliases `auto`, `pro`, `flash`, `flash-lite` + concrete IDs), preview-access note when a preview model is selected.

## Non-goals

- **No OAuth subscription rerouting.** Google's `gemini-cli/docs/resources/tos-privacy.md` explicitly prohibits third-party software accessing Gemini CLI's backend services via OAuth, with active 403 enforcement in 2026. Shipping OAuth-subscription support would get csq users banned. First violation → Google Form recertification; second → permanent ban.
- **No automated quota polling endpoint integration.** There is no public endpoint for AI Studio keys; best-effort counter + 429 parse is the honest answer.
- **No UI fiction.** If no counter data is available, the AccountCard reads "quota: n/a", never a synthesized percentage. Statusline follows the same rule.
- **No Vertex service-account management** beyond accepting the JSON path. Full Vertex provisioning (project pinning, IAM scoping) is left to `gcloud`.
- **No Windows support at ship.** Symlinks require developer mode; deferred to a follow-up PR.

## Key constraints

1. **ToS-clean by default.** The Gemini card in AddAccountModal offers exactly two auth modes: (a) AI Studio API key, (b) Vertex service-account JSON path. OAuth is never an option surfaced in UI, even if the user has `~/.gemini/oauth_creds.json` from a prior gemini-cli session.
2. **`settings.json` pre-seed is ordered.** `config-<N>/.gemini/settings.json` is written with `security.auth.selectedType = "gemini-api-key"` BEFORE the first `gemini` invocation. Prevents the TUI from interactively asking the user to pick auth type on first launch.
3. **Process-env API key, never `.env`.** The spawn path sets `GEMINI_API_KEY` on the child process. If the user's `$CWD` or any ancestor contains a stale `.env`, gemini-cli's discovery chain short-circuits before reaching ours — so we skip the discovery chain entirely by putting the key in the env.
4. **Downgrade is surfaced, never hidden.** Any response that returns a model different from the one the user selected shows a badge. Silent downgrade from `gemini-3-pro-preview` to `gemini-2.5-pro` on tiers without preview access is the primary risk here.
5. **429 parse, not silent fail.** `RESOURCE_EXHAUSTED` bodies from `cloudcode-pa.googleapis.com` or `generativelanguage.googleapis.com` parsed for `quotaMetric` and `retryDelay`. When hit, the account card shows a real rate-limit reset, not a fabricated count.

## Acceptance

- A user can `csq setkey gemini --slot 5`, paste their AI Studio API key, and see slot 5 validated (one probe call) and provisioned.
- `csq run 5` launches the native `gemini` CLI; the `/model` interactive slash command, per-session model selection, and 1M-context workflows all work natively.
- After first request, the desktop dashboard shows both the selected and effective model for slot 5.
- When the user hits Gemini's 429, the card flips to a real rate-limit view parsed from the response body, not a synthesized utilization bar.
- Upgrading from a csq version without Gemini: existing accounts unchanged; slot 5 can be newly provisioned.

## Dependencies

- **Blocked on Codex workspace:** spec 07 (provider surface dispatch) and the refactor of Anthropic/MM/Z.AI/Ollama to `Surface::ClaudeCode` ship with Codex. Gemini is additive on top.
- Spec 02 INV-08 amendment (per-surface persistent state).
- Spec 05 §5.8 amendment (Gemini polling contract).

## Ships after

Codex.

## References

- Research report (2026-04-21, this session) — Gemini CLI verification.
- Red team findings (2026-04-21, this session).
- `google-gemini/gemini-cli/docs/resources/tos-privacy.md` — ToS text prohibiting third-party services.
- `google-gemini/gemini-cli#21744` — `.env` discovery short-circuit.
- `google-gemini/gemini-cli#21691` — OAuth refresh-token wipe (OAuth-only; not our path).
- Memory: `discovery_growthbook_model_override.md` — silent model override class of bug, directly relevant to downgrade detection.
