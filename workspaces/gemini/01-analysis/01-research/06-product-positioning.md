# 06 — Gemini Surface: Product Positioning

Phase: /analyze | Date: 2026-04-22

Applies the /analyze framework — value propositions, USPs, platform model, AAA framework, network effects — to csq × Gemini. Frames the Gemini slot on its own merits, not as a Codex clone.

## 1. Value propositions

csq-for-Gemini delivers three concrete outcomes:

1. **Single-pane multi-key quota awareness.** Users who hold multiple AI Studio API keys (different billing projects, dev/prod splits, team allocations) see per-key request counts and downgrade signals in the same dashboard as Claude and Codex. Without csq, users juggle keys by manually swapping `GEMINI_API_KEY` in shell state.
2. **Honest, non-fabricated quota display.** Google provides no public quota endpoint for AI Studio keys. csq's counter + 429 parse is the limit of what's available — and the UI refuses to fabricate percentages when data is absent. Users trust what they see.
3. **Silent-downgrade detection.** Preview models (Gemini 3 Pro preview) silently fall back to 2.5 Pro on tiers without access. csq parses `modelVersion` on every response and flags the downgrade on the AccountCard. Without csq, users discover quality regressions by noticing weaker output over several sessions.

## 2. Unique selling points

What distinguishes csq-for-Gemini from alternatives in April 2026:

- **Per-account encrypted at-rest key storage (ADR-G02).** Standard gemini-cli puts `GEMINI_API_KEY` in `.env` or shell state. csq encrypts per-account via platform-secret, decrypts only at spawn time into process env. Reduces same-UID leak surface meaningfully.
- **Drift-detector ToS guard (ADR-G04 / FR-G-CORE-04).** csq rewrites `security.auth.selectedType = "gemini-api-key"` on every spawn, preventing accidental OAuth rerouting even if the user hand-edits settings. This is a concrete defense that no other multi-account tool provides.
- **`.env`-short-circuit immunity (ADR-G03).** csq injects `GEMINI_API_KEY` via `Command::env` directly; never relies on gemini-cli's fragile discovery chain. A stale `.env` in the user's CWD cannot hijack csq-managed sessions.
- **Effective-model downgrade badge (ADR-G06).** csq parses `modelVersion` on every response — no other multi-account tool surfaces silent tier-downgrades.
- **Handle-dir per-terminal isolation.** Multiple terminals on the same Gemini slot share `gemini-state/` via symlink; crashes don't lose shell history.
- **Honest "quota: n/a" posture.** When no counter data exists, csq shows n/a. No synthesized percentages. This is a discipline, not a feature — but a distinguishing one.

**Critique / what USPs must NOT claim:**

- csq does NOT multiply Gemini quota. API keys are pay-as-you-go.
- csq does NOT make Gemini faster or smarter. Model runs as Google ships.
- csq does NOT enable OAuth subscription use. Google ToS forbids it; csq enforces the ban.

## 3. Platform model

- **Producers:** Users who provision Gemini API keys (or Vertex SAs) into csq slots. The asset is the encrypted key file + pre-seeded settings.
- **Consumers:** Same users, plus automation they orchestrate.
- **Partners:** `gemini` CLI (google-gemini/gemini-cli, external partner), Google AI Studio / Vertex API endpoints (external dependency).

Transaction: provision once, consume many times. Unlike Codex (where the daemon is load-bearing for refresh), Gemini's platform posture is "csq is the key-management and quota-surfacing layer; gemini-cli is the execution layer; Google is the billing partner." csq is deliberately thin here.

## 4. AAA framework

- **Automate (reduce operational cost):** key decryption on spawn, counter increment, 429 parse, effective-model capture, settings drift reassertion, ToS guard sentinel. All background, all deterministic.
- **Augment (reduce decision cost):** per-slot default model with preview warning, downgrade badge for informed model re-selection, 429 reset countdown so users know when to retry. Each is information the user would otherwise gather manually.
- **Amplify (reduce expertise cost):** users don't need to know gemini-cli's `.env` discovery chain (#21744), don't need to know about Google ToS enforcement on OAuth rerouting, don't need to parse `RESOURCE_EXHAUSTED` error bodies. csq hides all of it.

## 5. Network behaviors

- **Accessibility:** one-command provisioning (`csq setkey gemini --slot N`), one modal in the desktop app. Paste and go.
- **Engagement:** AccountCard shows counter + downgrade + rate-limit reset; users stay informed across sessions.
- **Personalization:** per-slot default model + preview warning; two Gemini keys can have entirely different defaults.
- **Connection:** narrow — to Google's AI Studio or Vertex endpoints, via gemini-cli.
- **Collaboration:** multiple terminals on the same slot share `gemini-state/` via symlinks; per-slot isolation across teams is per-machine csq install.

## 6. Product focus (80 / 15 / 5)

- **80% agnostic:** the Surface abstraction + handle-dir model + daemon IPC for quota writes + desktop provider catalog + AccountCard rendering + model-config dispatch + token redaction. All shared with Codex and the existing providers.
- **15% per-provider config:** AI-Studio-vs-Vertex detection, `GEMINI_CLI_HOME` quirk with `.gemini/` subdir, settings.json pre-seed contents, 429 body schema, `modelVersion` parse path.
- **5% Gemini customization:** drift detector rewriting `security.auth.selectedType`, ToS-ban-disclosure modal, `~/.gemini/oauth_creds.json` refuse-with-warning flow, response-body OAuth sentinel.

The spec-07 abstraction holds: Gemini reuses 80% of the machinery Codex built. The 5% Gemini-specific is ToS-enforcement surface — a cost Google's policy imposes, not a csq design flaw.

## 7. Where positioning could be wrong

- **If Google relaxes ToS** on third-party OAuth use, csq's API-key-only posture becomes conservative rather than necessary. ADR-G01 commits to re-evaluation on a written ToS change; low-probability, high-impact item.
- **If gemini-cli removes `security.auth.selectedType` honor** or changes the precedence in a future release, the drift detector becomes meaningless and the ToS guard collapses. This is a gemini-cli version risk tracked via NFR-G07 minimum-version check.
- **If Google adds a public quota endpoint**, the counter + 429 approach becomes the slower of two paths. Not a blocker; upgrade path is additive.

## 8. What we're NOT saying

- Claims of cost reduction (users pay Google; csq doesn't negotiate).
- Claims of speed improvement (csq is a thin wrapper).
- Claims of "Gemini Advanced subscription access" (that's the OAuth path; banned).
- Claims of multi-key billing consolidation (csq doesn't aggregate; it monitors).
- Comparison to commercial multi-account tools (independence.md).

## Cross-references

- Brief: `briefs/01-vision.md`
- Functional requirements: `01-functional-requirements.md`
- ADRs: `03-architecture-decision-records.md`
- Risk: `04-risk-analysis.md`
- Security: `07-security-analysis.md`
- Rules: independence.md, communication.md, autonomous-execution.md
