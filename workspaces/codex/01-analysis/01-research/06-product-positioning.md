# 06 — Codex Surface: Product Positioning

Phase: /analyze | Date: 2026-04-21

Applies the /analyze skill framework — value propositions, USPs, platform model, AAA framework, network effects — to csq × Codex. Grounds every product decision in the user job, not the engineering abstraction.

## 1. Value propositions

csq-for-Codex delivers four concrete outcomes:

1. **Multi-account rotation without token corruption.** Users who hold multiple ChatGPT subscriptions (personal + Plus, or Plus + Pro) can rotate across them without triggering OpenAI's `refresh_token was already used` race. csq's daemon-sole-refresher mutex solves at the tool level what vanilla `codex` does not address.
2. **Quota visibility across accounts in one pane.** Remaining `wham/usage` utilization is polled per-account and surfaced in the same desktop dashboard that already shows Claude and third-party quota. Users stop guessing which account has headroom.
3. **Per-terminal identity with no restart.** One running `codex` session on slot 4 can swap to slot 5 via `csq swap 5` — same-surface swap repoints symlinks atomically and codex picks up the new auth at the next API call. No kill-and-restart.
4. **Provider-agnostic desktop UX.** The same AddAccountModal, AccountCard, and ChangeModelModal used for Claude today learn Codex. Users don't learn a new tool; they gain a new slot type.

## 2. Unique selling points

These are what makes csq-for-Codex distinct from every alternative currently available (April 2026):

- **Daemon-managed OAuth refresh with single-flight-per-account mutex.** Vanilla codex doesn't guarantee cross-process refresh safety. Translation proxies (raine/claude-codex-proxy, CaddyGlow/ccproxy-api) handle refresh inside their own process and suffer similar contention if two instances run. csq's daemon is the one writer across every terminal on the machine — this is architecturally unique.
- **Native CLI preservation, not translation.** Competing approaches route Codex through an Anthropic-compatible proxy into `claude`, losing prompt caching, tool-result images, extended thinking, and GPT-5-Codex harness fit. csq runs `codex` natively.
- **Per-account keychain isolation.** `cli_auth_credentials_store = "file"` + per-account `config-<N>/config.toml` gives the user a file-based, ownership-clear credential store that survives OS keychain drift. Competing tools either rely on Keychain (and contaminate across accounts) or require manual token management.
- **Handle-dir ephemerality with persistent transcripts.** `term-<pid>` is swept on process exit; `codex-sessions/` and `codex-history.jsonl` live in `config-<N>/` persistent storage. Crashes don't lose work.
- **Surface-aware dispatch abstraction (spec 07).** One mental model covers Claude, MiniMax, Z.AI, Ollama, Codex, Gemini. Future providers extend the abstraction, not the tool.
- **ToS-honest disclosure.** Users are told clearly what legal posture they're entering. No competing tool does this; most silently assume the user has researched it themselves.

**Critique / what USPs must NOT claim:**

- csq does NOT "pool" or "share" subscriptions between users. It rotates accounts YOU own.
- csq does NOT guarantee ToS safety. OpenAI's policy is ambiguous; we disclose, we don't indemnify.
- csq does NOT make Codex faster or better per-request. The model runs as OpenAI ships it.

## 3. Platform model

Treating csq as a platform (producers / consumers / partners):

- **Producers:** Users who provision Codex accounts into csq. They create the asset (a logged-in `config-<N>/`) that other actors consume.
- **Consumers:** The same users, plus any automation they run (shell scripts, CI, agent workflows). They read the asset (run `codex` terminals bound to each slot).
- **Partners:** `codex` CLI (openai/codex, upstream partner — csq wraps but does not modify), the daemon (csq-internal infrastructure partner), the desktop dashboard (csq-internal experience partner), OpenAI's token + wham/usage endpoints (external dependency partner).

Transaction shape: the user provisions once, then consumes many times. The daemon is the persistent intermediary that makes provision→consume low-friction. Partner CLIs are untouched upstream; csq is a cooperative outsider (per spec 00 §0.3).

This matters because: every design decision that increases friction at either the provision step (login) or the consume step (`csq run`) erodes the platform value. The daemon-hard-prerequisite rule is a provision cost (one-time) that buys reliability at consume time (every time). Correct trade.

## 4. AAA framework

Where csq × Codex reduces cost:

- **Automate (reduce operational cost):** token refresh, usage polling, handle-dir lifecycle, keychain-residue detection, schema-drift circuit breaker. All background work the user never thinks about. Without csq, the user either runs vanilla codex (and hits refresh races across terminals) or manually juggles accounts (and wastes cognitive budget).
- **Augment (reduce decision cost):** per-slot default model, live quota visibility, cross-surface swap confirmation, ToS disclosure. Each is a decision the user would otherwise make with incomplete information; csq surfaces the needed context at decision time.
- **Amplify (reduce expertise cost):** the user does NOT need to know OAuth device-auth flow semantics, single-use refresh token rotation, OpenAI's wham/usage schema, or macOS Keychain service namespacing. csq abstracts all of these. A non-expert user gets the same reliability as an expert who manually wires it up.

Scale implication: adding a new provider surface (Codex today, Gemini next) extends all three axes proportionally. The surface abstraction is the amplifier — it lets one user's knowledge (setting up Codex once) transfer to every teammate who installs csq.

## 5. Network behaviors

Per the /analyze framework — accessibility, engagement, personalization, connection, collaboration:

- **Accessibility:** `csq login <N> --provider codex` is one command + one browser roundtrip. AddAccountModal is one Svelte card. The ToS disclosure is one checkbox. No file editing, no env var setup, no API key generation.
- **Engagement:** the AccountCard shows live quota, the tray shows status, the statusline inside `codex` itself shows remaining percentage. Users stay informed without polling mentally.
- **Personalization:** per-slot default model (TomlModelKey), per-slot approval mode (codex's native config), per-slot identity. Two Codex accounts on the same machine can have entirely different defaults without conflict.
- **Connection:** Codex slots connect to OpenAI's backend (the token + wham/usage endpoints) via the daemon's single HTTP path. No plugin system, no third-party connectors — the connection is direct and narrow.
- **Collaboration:** multiple terminals on the same Codex slot share codex-sessions/ and codex-history.jsonl via symlink, so a team-of-one can work across several terminals on one account without transcript fragmentation. For multi-user collaboration, csq is explicitly single-user per-machine (non-goal per independence.md); teams use their own accounts in their own csq installs.

## 6. Product focus (80 / 15 / 5)

Applying the /analyze rule:

- **80% agnostic (reusable across providers):** the Surface abstraction, handle-dir model, daemon infrastructure, quota.json v2 shape, cross-surface swap machinery, desktop provider-catalog fetch, AddAccountModal state machine, AccountCard rendering. Gemini will consume this directly. Future providers (Grok, Pi, anyone) will too.
- **15% self-service per-provider config:** Codex-specific login flow (device-auth + pre-seed), wham/usage parser, keychain-residue probe, ToS disclosure modal, Codex model list endpoint. Each of these is a parameterization of the agnostic layer, not a fork of it.
- **5% Codex customization:** `cli_auth_credentials_store = "file"` force-write, per-account 0400/0600 dance, circuit breaker for wham/usage schema drift. These are pure Codex quirks that won't apply to other surfaces.

The spec-07 design passes this test: the surface enum + dispatch tables are agnostic; per-surface modules hold the 15%; the 5% hides inside those modules. If a future provider needs <5% customization, it's a sign the abstraction is healthy. If it needs >15%, the abstraction is wrong and spec 07 needs revision.

## 7. Failure mode for product positioning

The ONE way the positioning above could be wrong:

- **If `cli_auth_credentials_store = "file"` does NOT disable codex's in-process refresh** (ADR-C15, risk G1), the "daemon-sole-refresher" USP is architectural fiction. csq would need to fork codex, patch it, or live with the same race vanilla codex has. Every value proposition above depends on this verification passing.

This single unknown is the load-bearing premise of the entire Codex integration. It MUST be resolved before PR1 ships.

## 8. What we're NOT saying

The positioning above deliberately avoids:

- Claims of speed improvement (csq is a wrapper; the model runs as-is).
- Claims of cost reduction (users pay OpenAI; csq doesn't negotiate).
- Claims of official OpenAI endorsement (there isn't one; ToS is ambiguous).
- Comparison to any commercial competitor (rules/independence.md).
- Claims of ToS safety (rules/independence.md).

## Cross-references

- Brief: `briefs/01-vision.md`
- Functional requirements: `01-functional-requirements.md`
- Risk analysis: `04-risk-analysis.md` — single-unknown ADR-C15
- Rules: independence.md, communication.md, autonomous-execution.md
