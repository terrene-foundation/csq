# Probe-Driven Verification

**Spec version:** 1.0.7

Operator-run live-wire verification of the (provider × auth-mode) contracts pinned in spec 05 (quota polling) and spec 07 (provider surface dispatch). Probes hit real provider endpoints with the slot's real credentials, parse the response, and assert each load-bearing field matches the contract.

Probes are an operator-side gate. They are NEVER run in CI. They exist because contract drift between code and remote endpoints is otherwise discovered only when a slot starts misreporting quota in production — by which point a release has already shipped.

## 11.0 Scope and non-goals

**In scope:**

- One verifier per (provider × auth-mode) cell. Output is a binary OK/FAIL plus a structured diagnostic record citing the spec § anchor that defines the contract.
- A `csq probe <slot>` subcommand that auto-detects the slot's provider + auth-mode, runs the matching probe against the live endpoint, and emits the diagnostic record on stdout.
- An operator runbook (§11.4) listing every probe + its prerequisites + its OK/FAIL examples, used as the **pre-tag gate** before a release.

**Out of scope:**

- Latency measurement.
- Synthetic-CI verification.
- Continuous polling. Probes are one-shot. The daemon's usage poller (spec 04) is what does continuous polling.
- Auto-remediation. A FAILing probe surfaces the gap; the operator decides whether to file an issue, update the spec, or block the release.

## 11.1 Probe matrix

Ten cells. Each row is exactly one (provider, auth-mode) pair the daemon's usage poller dispatches against today.

| #   | Surface    | Provider catalog id  | Auth mode         | Spec anchor    | Endpoint                                                                                                                      |
| --- | ---------- | -------------------- | ----------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| 01  | ClaudeCode | `claude` (Anthropic) | OAuth             | spec 05 §5.1   | `GET https://api.anthropic.com/api/oauth/usage`                                                                               |
| 02  | ClaudeCode | `claude` (Anthropic) | API key           | spec 05 §5.1   | `GET https://api.anthropic.com/api/oauth/usage` (same endpoint; different `Authorization`)                                    |
| 03  | Codex      | `codex` (OpenAI)     | OAuth             | spec 05 §5.7   | `GET https://chatgpt.com/backend-api/wham/usage`                                                                              |
| 04  | ClaudeCode | `minimax`            | Bearer (API key)  | spec 05 §5.3   | `GET https://platform.minimax.io/v1/api/openplatform/coding_plan/remains`                                                     |
| 05  | ClaudeCode | `zai`                | Bearer (API key)  | spec 05 §5.4   | `GET https://api.z.ai/api/monitor/usage/quota/limit`                                                                          |
| 06  | ClaudeCode | `deepseek`           | Bearer (API key)  | spec 05 §5.4a  | `POST https://api.deepseek.com/anthropic/v1/messages` (no quota body — the assertion is "no `anthropic-ratelimit-*` headers") |
| 07  | Gemini     | `gemini`             | API key           | spec 05 §5.8   | event-driven counter (probe asserts on local `quota.json` shape, not a remote endpoint)                                       |
| 08  | Gemini     | `gemini`             | Vertex SA         | spec 05 §5.8   | event-driven counter (same as ApiKey; probe asserts schema parity)                                                            |
| 09  | Gemini     | `gemini`             | Code Assist OAuth | spec 05 §5.8.2 | `POST https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist` then `:retrieveUserQuota`                                |
| 10  | (local)    | `ollama`             | keyless           | n/a (local)    | `GET http://127.0.0.1:11434/api/tags` (presence + reachability only)                                                          |

**Cells deliberately omitted from the matrix:**

- `claude.ai` web dashboard (§5.2) — cookie-only auth; csq cannot replay.
- A cell for "no Anthropic auth at all" — covered by `csq doctor` static-state checks.
- A cell for "Gemini direct generative-language API" — csq does not poll that surface; the daemon sees Gemini quota only via §5.8.1's event-driven NDJSON log (cells 07-08) or via §5.8.2's Code Assist OAuth path (cell 09).

## 11.2 Per-cell probe contracts

Each cell defines (a) prerequisite, (b) request, (c) pinned response assertions, (d) FAIL diagnostic.

### Cell 01 — Anthropic OAuth (Claude Max)

**Prerequisite:** slot N's `config-N/.credentials.json` has a non-expired `oauthAccount.accessToken`.

**Request:** per spec 05 §5.1. `User-Agent` MUST start with `curl/`; HTTP/1.1; no compression. Transport via the Node bridge (`csq-core/src/http/mod.rs` — `post_json_node` / `get_bearer_node`) — direct `reqwest` is body-stripped by Cloudflare.

**Assertions (in order):**

1. HTTP status is `200`.
2. Body parses as JSON object.
3. Body has both `five_hour` and `seven_day` keys, each an object.
4. Each window object has `utilization` (`f64`) AND `resets_at` (RFC3339 string).
5. **Load-bearing scale check:** `0.0 <= utilization <= 100.0`. (A value > 100 means a regression — historically a missing-multiply-by-100 inversion.)
6. `resets_at` parses as a UTC timestamp in the future (`> now()`).

**FAIL diagnostic:** emit `{cell: "anthropic-oauth", spec_anchor: "05§5.1", status, redacted_body_excerpt, failed_assertion: "<which of 1-6>"}`. Body excerpt is capped at 256 Unicode codepoints (chars) and routed through `error::redact_tokens` (redact-then-truncate order).

### Cell 02 — Anthropic API key (pending live evidence)

`sk-ant-api03-…` API keys are not known to authenticate against `/api/oauth/usage` — the endpoint name and `Anthropic-Beta: oauth-2025-04-20` header are OAuth-bound. Without live evidence that the OAuth usage endpoint accepts API keys, blindly probing API-key slots there would always 401 and emit a misleading "refresher bug" hint. Cell 02 therefore returns `Skipped` with a `provider-drift-investigation` hint until either (a) Anthropic publishes an API-key-compatible quota endpoint, or (b) live evidence is gathered showing `/api/oauth/usage` accepts `sk-ant-api03-…` tokens.

The probe distinguishes Cell 01 vs Cell 02 by access-token prefix per spec 01 §1.2 (`sk-ant-oat01-` is OAuth, `sk-ant-api03-` is API key). When the operator provisions an API-key slot, this cell will Skip — that is the expected behavior until the contract is validated.

### Cell 03 — Codex OAuth (ChatGPT plus/team)

**Prerequisite:** slot N has codex credentials at either `identities/<UUID>/credentials-codex.json` (resolved via `profiles.json::by_slot[N]` → `credentials_codex_path_for`) or the legacy `credentials/codex-<N>.json` fallback; daemon refresher has run at least once. The probe reads the SAME credential channel as the daemon's usage poller (`csq-core/src/daemon/usage_poller/codex.rs`) and the handle-dir spawn (`csq-core/src/session/handle_dir.rs`); it does NOT read `~/.codex/auth.json` (which is codex-cli's standalone state — csq-unmanaged). The diagnostic-daemon credential-channel parity is the structural invariant here: a diagnostic surface MUST read the same per-identity credential channel the daemon production paths use for that slot, never a user-global state file.

**Request:** per spec 05 §5.7. Node bridge required (Cloudflare body-stripping; same failure class as Anthropic).

**Assertions:**

1. HTTP status is `200`.
2. Body has `rate_limit.primary_window` AND `rate_limit.secondary_window`.
3. Each window has `used_percent` (`f64`, in `[0.0, 100.0]` — already a percent, not 0-1) AND `reset_at` (Unix epoch `u64`).
4. `plan_type` is one of `{plus, team, business}` OR a known new value (parser is tolerant; new values log a `codex_plan_type_observed` info line).
5. `clock_skew_warning` not raised: `abs(reset_at - now() - reset_after_seconds) <= 5` for both windows.
6. PII fields (`user_id`, `account_id`, `email`) are present in raw response BUT are dropped before any persistence path. The probe asserts "after-redaction" diagnostic does NOT contain those keys.

**FAIL diagnostic:** same shape as Cell 01.

### Cell 04 — MiniMax bearer

**Prerequisite:** slot N has a MiniMax API key (`provider.id == "minimax"`).

**Request:** per spec 05 §5.3.

**Assertions:**

1. HTTP `200`.
2. Body has `model_remains: []` (non-empty array).
3. At least one entry matches the configured model glob (`MiniMax-M*` for coding plan; configurable per slot).
4. **Remaining-vs-consumed semantic:** `current_interval_total_count >= current_interval_usage_count`. (The endpoint name is `/remains`; `usage_count` field is a misnomer for REMAINING. A value violating this inequality means the upstream changed the field's semantic.)
5. `start_time < end_time`, both `i64` Unix-millis.

**Known limit:** the `total >= usage_count` inequality holds trivially when `usage_count == 0`, so a silent semantic-flip (REMAINING → CONSUMED) on a fresh quota is undetectable from the probe alone. A canary write-side request would distinguish the two — but that adds a billable call to every probe and is rejected on cost grounds. The probe surfaces a soft hint when `total > 0 && usage_count == 0` flagging the slot as "ambiguous; semantic check requires a write-side observation" so the operator knows the assertion is weakly satisfied.

### Cell 05 — Z.AI bearer

**Prerequisite:** slot N has a Z.AI API key (`provider.id == "zai"`).

**Request:** per spec 05 §5.4.

**Assertions:**

1. HTTP `200`.
2. Body has `code: 200` AND `data.limits[]`.
3. `data.limits[]` contains at least one entry with `unit == 3` (5h window) AND at least one with `unit == 6` (7d window).
4. `percentage` is an integer in `[0, 100]` (not a fraction).
5. `nextResetTime` is `i64` Unix-millis in the future.
6. `level` is one of `{free, pro, max}`.

### Cell 06 — DeepSeek bearer (no-quota assertion)

**Prerequisite:** slot N has a DeepSeek API key (`provider.id == "deepseek"`).

**Request:** `POST` to `https://api.deepseek.com/anthropic/v1/messages` with `max_tokens: 1` and a one-character user message. Response body is irrelevant — the probe inspects HEADERS only.

**Assertions:**

1. HTTP `200` OR `400` (a malformed minimal request still proves reachability; both confirm the bridge is up).
2. **Negative assertion:** response carries NO `anthropic-ratelimit-requests-*` header AND NO `anthropic-ratelimit-tokens-*` header. (Per spec 05 §5.4a, the absence of these headers is the load-bearing fact — it's what makes csq's catalog mark `quota_kind = QuotaKind::Unknown` for DeepSeek slots.)
3. If headers DO appear, the probe FAILs with `deepseek_unexpected_quota_headers` — DeepSeek's bridge has changed and csq's `usage_poller::third_party.rs` skip-on-Unknown branch is now silently dropping useful data.

### Cell 07 — Gemini API key (event-driven, no remote probe)

**Prerequisite:** slot N has a Gemini ApiKey (`provider.id == "gemini"`, `auth_mode == ApiKey`).

**Request:** none. This cell asserts on local state.

**Assertions:**

1. `quota.json[N].surface == "gemini"` AND `kind == "counter"`.
2. `counter.requests_today: u64` is present and parses.
3. `counter.resets_at_tz == "America/Los_Angeles"` (pinned for DST-correctness).
4. If `rate_limit.active == true`, then `rate_limit.reset_at: Option<i64>` is `Some` with a Unix epoch in the future.
5. `selected_model`, `effective_model` are both present (may be equal — equality is the healthy case).

**FAIL diagnostic:** `{cell: "gemini-api-key", spec_anchor: "05§5.8", missing_field, observed_shape}`.

### Cell 08 — Gemini Vertex SA (event-driven, schema parity with Cell 07)

Identical to Cell 07. The probe additionally asserts that the slot's `provider.auth_mode == VertexSa` and that `~/.config/gcloud/application_default_credentials.json` exists and is `0o600`.

### Cell 09 — Gemini Code Assist OAuth

**Prerequisite:** slot N has a Code Assist OAuth slot (`provider.id == "gemini"`, `auth_mode == CodeAssistOAuth`); `~/.gemini/oauth_creds.json` exists; gemini-cli has run at least once (so the access token is fresh).

**Request:** per spec 05 §5.8.2. Two calls — `loadCodeAssist` then `retrieveUserQuota`. **Bearer token is re-read from disk between the two calls** (TOCTOU defense; gemini-cli may rotate the file mid-probe).

**Operator-state signals route to `Skipped`, not `Fail`** — a `Fail` should mean contract drift, not "operator hasn't bootstrapped yet". The following cases emit `Skipped` with a remediation hint:

- HTTP 401 from either call → token stale; run `gemini` once.
- `cloudaicompanionProject` empty/null → operator has no Code Assist project; open `gemini` to bootstrap.
- HTML body on a 200 response → Cloudflare interception or upstream maintenance; retry.

Genuine contract drift (bucket schema mismatch, out-of-range `remainingFraction`, etc.) still emits `Fail`.

**Assertions (loadCodeAssist):**

1. HTTP `200`.
2. Body has `cloudaicompanionProject: String` (non-empty, GCP project resource name).

**Assertions (retrieveUserQuota):**

3. HTTP `200`.
4. Body has `buckets: []` (non-empty array).
5. Each bucket has `modelId: String`, `tokenType ∈ {REQUESTS, INPUT_TOKENS, OUTPUT_TOKENS, ...}`, `remainingFraction: f64 in [0.0, 1.0]`, `remainingAmount: u64`, `resetTime: RFC3339 string`.
6. Probe runs the limiting-bucket aggregation locally and asserts result is `(used_percentage in [0.0, 100.0], resets_at in future)` — same code path as `code_assist_quota::aggregate_to_usage_window`, but executed in probe context to detect drift between the live response and the parser.

**FAIL diagnostic:** distinguishes between `loadCodeAssist_failed` and `retrieveUserQuota_failed` so the operator knows which call regressed. 401 specifically routes to `gemini_oauth_token_stale` — not a probe FAIL, an operator hint to run `gemini` once to refresh.

### Cell 10 — Ollama keyless

**Prerequisite:** Ollama is the local fallback for offline / no-account scenarios. Probe asserts daemon reachability only.

**Request:** `GET http://127.0.0.1:11434/api/tags` (no auth), with IPv6 fallback to `http://[::1]:11434/api/tags`. Ollama on macOS Sequoia binds `[::1]:11434` by default when launched via the menubar app; v4-only would soft-skip with `ollama_not_running` while Ollama is actually fine.

**Assertions:**

1. HTTP `200` (Ollama is up) OR connection-refused (Ollama is down — emit `ollama_not_running` as a soft FAIL; this is informational, not blocking).
2. If `200`, body has `models: []` (may be empty — empty is valid; no models pulled is a separate operator concern).

### Gemini corrupt binding (cross-cell — applies to Cells 07/08/09)

A Gemini slot whose binding marker (`credentials/gemini-<N>.json`) **exists** — so `is_gemini_bound_slot` is `true` and the daemon's IPC gate WILL admit a Gemini spawn for it — but whose marker **does not parse** (corrupt JSON, or a schema version newer than this binary's `BINDING_SCHEMA_VERSION`) is classified `Skipped` with `cell = "gemini-corrupt-binding"`, `failed_assertion = "prerequisite: gemini binding parses"`, prerequisite-class → **exit 64** (misconfiguration). The operator MUST reconfigure the slot (`csq logout <N>` then `csq login <N> --provider gemini`) — this is distinct from a Cell 02 `provider-drift` skip (upstream change) and from an operator-state-65 skip (a transient token refresh): re-running the probe yields the identical corrupt read. EACCES on the marker (an `Io` error other than `NotFound`) and a malformed / newer-schema marker (`Malformed`) classify identically — the remediation is the same; only the diagnostic wording's `kind:` tag differs. `csq probe` detects this with the `is_gemini_bound_slot(slot) && read_binding(slot).is_err()` predicate (`is_gemini_corrupt_bound`), the same predicate `csq doctor`'s `gemini_unreadable_slots` uses — `discover_gemini` (the listing path) strict-parses and silently drops corrupt markers, so the probe dispatcher and `probe_all_slots` scan markers directly rather than relying on discovery.

### Codex corrupt binding (cross-cell — applies to Cell 03)

A Codex slot whose per-slot credential file (`credentials/codex-<N>.json`) **exists** — so `is_codex_bound_slot` is `true` — but whose payload **does not parse** via `credentials::file::load` (corrupt JSON, IO error, or other `CredentialError` variant) is classified `Skipped` with `cell = "codex-corrupt-binding"`, `failed_assertion = "prerequisite: codex credential file parses"`, prerequisite-class → **exit 64** (misconfiguration). The operator MUST reconfigure the slot (`csq logout <N>` then `csq login <N> --provider codex`).

Without this classification the dispatcher's Step 5 codex-oauth fall-through would emit a green Cell 03 record reflecting the slot's identity-store credential — NOT the corrupt per-slot legacy file's existence — silently masking the corrupt legacy file. Step 3.5 (corrupt-binding) fires before Step 5 to surface the misconfiguration. The mis-attribution risk (multiple slots probing against the SHARED `~/.codex/auth.json`) is structurally resolved: the probe no longer reads `~/.codex/auth.json` for any slot.

`csq probe` detects this with the `is_codex_bound_slot(base, slot) && credentials::file::load(canonical_path_for(base, slot, Surface::Codex)).is_err()` predicate (`is_codex_corrupt_bound`, `csq-core/src/providers/codex/provisioning.rs`). `discover_codex` already includes the slot with `has_credentials=false`; the probe dispatcher reads the credential directly to short-circuit before reaching the silent mis-attribution path.

**C2 ambiguous-binding extension (presence-presence).** As of `1.0.3` the C2 guard at `probe_slot` Step 2 fires on `(is_gemini_bound_slot(base, slot) || is_codex_bound_slot(base, slot)) && anthropic_present` — **presence-presence** for both surfaces. A slot carrying artifacts for two surfaces is ambiguous regardless of parse status; the operator MUST reconcile via `csq logout <N>` then re-bind. This subsumes the corrupt-Codex + Anthropic case and additionally flags valid-Codex + valid-Anthropic (previously a silent green Codex probe).

### Codex wrong-variant binding (cross-cell — applies to Cell 03)

A Codex slot whose per-slot credential file (`credentials/codex-<N>.json`) **exists** — so `is_codex_bound_slot` is `true` — AND **parses successfully** via `credentials::file::load` — BUT the parsed `CredentialFile` **does NOT carry a Codex variant** (`cf.codex().is_none()`) is classified `Skipped` with `cell = "codex-wrong-variant-binding"`, `failed_assertion = "prerequisite: codex credential file is the Codex variant"`, prerequisite-class → **exit 64** (misconfiguration). The operator MUST reconfigure the slot (`csq logout <N>` then `csq login <N> --provider codex`).

**Distinction from "Codex corrupt binding".** Both classifications signal misconfiguration at the same Codex per-slot file. The dichotomy is at-parse-time:

| Parse outcome                               | Classification                | Operator remediation                                |
| ------------------------------------------- | ----------------------------- | --------------------------------------------------- |
| `load(...).is_err()` (corrupt JSON, IO err) | `codex-corrupt-binding`       | `csq logout <N>` + `csq login <N> --provider codex` |
| `load(...).is_ok() && cf.codex().is_none()` | `codex-wrong-variant-binding` | `csq logout <N>` + `csq login <N> --provider codex` |

Today's `CredentialFile` parser is `#[serde(untagged)]` with two variants (Anthropic + Codex; `csq-core/src/credentials/mod.rs`); a wrong-variant `Ok(cf)` at a Codex path therefore always means the operator pasted an Anthropic-shape `claudeAiOauth` payload at the Codex-prefixed path. The wrong-variant cell does NOT surface unknown-shape JSON; that case fails BOTH variant deserializers and routes to `codex-corrupt-binding` by parser design.

Without this classification the slot is silently `continue`'d at `discover_codex` (`csq-core/src/accounts/discovery.rs`) and absent from every downstream consumer — `csq probe --all`, `csq doctor`, daemon spawn paths. The operator who pasted Anthropic credentials at a Codex path sees nothing.

**Token-handling note.** A wrong-variant `codex-<N>.json` may carry real, live Anthropic OAuth tokens (the operator may have pasted production credentials). The probe MUST NOT log or surface the payload contents. The structural defense: the `SkipReason::WrongVariantBinding { surface, observed_kind: &'static str }` variant uses ONLY fixed-vocabulary tags (`"anthropic"`, `"codex"`) sourced from `CredentialFile::observed_variant_tag()` — never a raw payload field.

`csq probe` detects this with the `is_codex_bound_slot(base, slot) && credentials::file::load(canonical_path_for(base, slot, Surface::Codex)) == Ok(cf) && cf.codex().is_none()` predicate (`is_codex_wrong_variant_bound`, `csq-core/src/providers/codex/provisioning.rs`). **The `probe_all_slots` parallel scan over this predicate is LOAD-BEARING** (the only channel; `discover_codex` omits wrong-variant slots) — unlike the `is_codex_corrupt_bound` scan which is idempotent with `discover_codex`'s `Err(e)` branch emission (`has_credentials=false`).

## 11.3 `csq probe` CLI surface

```
csq probe <slot> [--json]
csq probe --all [--json]
```

`<slot>` is `1..999` per `AccountNum`. `--all` enumerates slots via `csq_core::accounts::discovery::discover_all` (Anthropic / Codex / 3P / Gemini), **unioned** with a direct `is_gemini_corrupt_bound` marker scan over `1..=MAX_ACCOUNTS` — the union recovers corrupt Gemini slots that `discover_gemini` strict-parses and drops, so they still appear in the report. The merged id set is sorted ascending and deduped.

**Behavior:**

- Read slot's `provider.id` + `auth_mode` from `<base>/credentials/gemini-<slot>.json` (the canonical Gemini binding path — see `csq_core::providers::gemini::provisioning::binding_path`; the legacy `<base>/providers/<slot>/binding.json` form is a dead path no code reads or writes).
- Look up the matching cell in §11.1.
- Execute the per-cell probe per §11.2.
- Emit one JSON record per slot on stdout (one line per slot when `--all` is given).
- Exit code:
  - `0` every probed slot is OK
  - `1` some slot FAILed an assertion (contract drift)
  - `64` slot has no provider binding, OR a Gemini binding marker that does not parse, OR a Codex credential file that does not parse, OR a Codex credential file that parses but carries a non-Codex variant (all misconfiguration — operator fixes slot config; see §11.2 "Gemini corrupt binding" / "Codex corrupt binding" / "Codex wrong-variant binding")
  - `65` slot is in transient operator state (stale OAuth token, empty project, HTML interception) — fix one-shot then retry. Distinct from `64` so the hint isn't misread as "wrong slot config."
  - `70` transient infra failure (DNS, TCP refused) — operator retries when network is healthy.

**Output schema:**

```json
{
  "schema_version": "1.0.0",
  "slot": 5,
  "cell": "gemini-code-assist-oauth",
  "spec_anchor": "05§5.8.2",
  "status": "ok", // "ok" | "fail" | "skipped"
  "endpoint": "cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota",
  "elapsed_ms": 412,
  "assertions_passed": 6,
  "assertions_total": 6,
  "diagnostic": null, // populated on "fail"
  "redacted_response_excerpt": null // populated on "fail", capped 256 Unicode codepoints (chars), redact_tokens applied first
}
```

On FAIL the `diagnostic` field is shaped as:

```json
{
  "failed_assertion": "Each window object has `utilization` (f64) AND `resets_at` (RFC3339 string)",
  "observed_shape": "{\"five_hour\": {\"utilization\": null, ...}}",
  "hint": "spec 05 §5.1 requires utilization to be a non-null number"
}
```

**Default (non-`--json`) output:** color-coded one-liner per cell:

```
✓ slot 1 (claude/oauth)        anthropic /api/oauth/usage  6/6 OK     (412 ms)
✓ slot 2 (codex/oauth)          chatgpt /backend-api/...    6/6 OK     (380 ms)
✗ slot 5 (gemini/code-assist)   loadCodeAssist              FAIL @ A2  (5 ms)
                                hint: 401 — run `gemini` once to refresh OAuth token
                                spec: 05§5.8.2
· slot 7 (gemini-corrupt-binding)  n/a                      SKIPPED    (0 ms)
                                failed: prerequisite: gemini binding parses
                                hint:   fix with `csq logout <N>` then `csq login <N> --provider gemini`
                                spec:   11§11.2
· slot 8 (codex-corrupt-binding)  n/a                          SKIPPED      (0 ms)
    failed: prerequisite: codex credential file parses
    hint:   fix with `csq logout 8` then `csq login 8 --provider codex`
    spec:   11§11.2
· slot 7 (codex-wrong-variant-binding)  n/a                  SKIPPED      (0 ms)
    failed: prerequisite: codex credential file is the Codex variant
    hint:   fix with `csq logout 7` then `csq login 7 --provider codex`
    spec:   11§11.2
```

A `gemini-corrupt-binding` record carries a populated `diagnostic` (a `Skipped` record, not a `Fail`); its `observed_shape` and `hint` are structurally path-free fixed-vocabulary (no `$HOME`/username); the `<N>` in the hint is a placeholder, the concrete slot is the record's `slot` field.

When a slot has no credential file at the canonical path (no `profiles.json::by_slot` UUID, OR UUID resolved but credential file absent / unparseable), the `Skipped` record's `observed_shape` is exactly the fixed literal `"missing"` (path-free; slot number is on `ProbeRecord.slot`). The unit-variant `SkipReason::NoCredentials` produces this literal on every branch — pinned by regression test.

## 11.4 Operator runbook

### When to run probes

1. **Pre-tag gate.** Before cutting any csq release that touches `csq-core/src/daemon/usage_poller/*`, `csq-core/src/providers/*/code_assist_quota.rs`, or `csq-core/src/http/*`. Run `csq probe --all` against your live slots; confirm every cell OK. Save the JSON output to the release notes.
2. **After a provider rebrand or endpoint migration.** Provider companies move endpoints without notice. Probes catch the migration before users notice quota stuck-at-zero.
3. **As part of pre-merge review for any quota-poller-adjacent change.** The reviewer should ask: "did you run probes? show me the OK output for the slots this change could affect."

### How to interpret OK / FAIL

- **All OK:** safe to tag.
- **FAIL on a cell whose code this change didn't touch:** upstream provider drift. File an issue with the redacted diagnostic, update the spec § anchor with the drift note, decide whether to ship the unrelated change while the drift is investigated.
- **FAIL on a cell this change DID touch:** block the tag. Fix the parser/assertion mismatch, re-run, confirm OK.
- **`gemini_oauth_token_stale` hint on Cell 09:** run `gemini` once interactively to refresh the OAuth token, then re-run the probe. Not a code regression.

### Code Assist OAuth manual-smoke gate

A release that touches the Gemini Code Assist OAuth path is gated on Cell 09 confirming a freshly provisioned OAuth-mode slot returns the contract response from `cloudcode-pa.googleapis.com`.

**Prerequisite:** gemini-cli v0.41.2+ has no non-interactive auth surface. The operator MUST run `gemini` interactively once BEFORE `csq login --provider gemini` — pick "Sign in with Google" in the first-run picker, complete the browser OAuth flow, quit gemini-cli. Otherwise `csq login` returns `GeminiOauthCredsNotFound` and the gate cannot fire.

```bash
gemini       # interactive: pick "Sign in with Google", complete browser
             # flow, then quit. Writes ~/.gemini/oauth_creds.json.
csq login 5 --provider gemini   # verify oauth_creds.json + write binding marker
csq daemon start                # must be running
sleep 30                        # one tick
csq probe 5 --json | jq -e '.status == "ok" and .assertions_passed == 6'
```

Exit code `0` means tag-ready. Save the full probe JSON next to the release-notes block.

NOTE: there is no `--auth code-assist-oauth` flag in the CLI. The simple `--provider gemini` routes to the Code Assist OAuth path (`csq/src/cli/commands/login.rs`).

## 11.5 CI prohibition

**Probes MUST NOT run in CI.** Probes require real provider credentials. CI runners have none. Any GitHub Actions workflow that invokes `csq probe` (with or without `--all`) is prohibited, enforced by author/reviewer audit.

The complementary surface in CI measures latency budgets against synthetic stub binaries — that gate measures latency, not response-shape contracts. The two gates are deliberately disjoint:

- **Latency gate (CI):** layer-on/layer-off latency ratio against synthetic stubs. CI-safe.
- **`csq probe` (operator):** live-wire response-shape contract verification. Operator-only.

## 11.6 Drift detection and spec correction loop

When a probe FAILs because the upstream provider changed (not because csq's parser regressed):

1. Capture the redacted response excerpt from the FAIL diagnostic.
2. File an issue tagged `provider-drift` with the spec § anchor and the excerpt.
3. Update the relevant spec 05 § with a `Revisions` entry citing the new shape and the probe-FAIL date.
4. Update the parser. Re-run the probe. Confirm OK.
5. The PR title MUST include `[provider-drift]` and reference the issue number.

Probes are the only mechanism csq has for closing this loop without waiting for a user bug report. Treat a FAIL as a successful early-warning, not a regression.

## 11.7 Implementation site

- CLI: `csq/src/cli/commands/probe.rs`.
- **CI runtime guard:** `csq/src/cli/commands/probe.rs::handle` MUST refuse to run when `CI` or `GITHUB_ACTIONS` env var is set. The absence-of-credentials defense in §11.5 is necessary but not sufficient: a Makefile target shared between local + CI could spawn `csq probe` with operator credentials in the runner image, OR a future contributor could mirror credentials into a fork's CI. The runtime guard is defense-in-depth.
- `--all` enumeration: `probe_all_slots` builds the slot id set from `discover_all` unioned with direct `is_gemini_corrupt_bound`, `is_codex_corrupt_bound`, AND `is_codex_wrong_variant_bound` marker scans. **The `is_codex_wrong_variant_bound` scan is LOAD-BEARING** — `discover_codex` `continue`s wrong-variant slots, so this scan is the only channel that surfaces a wrong-variant slot in `probe --all` output. The `is_codex_corrupt_bound` scan is defensively belt-and-braces (idempotent with `discover_codex`'s `Err(e)` branch). The `is_gemini_corrupt_bound` scan recovers corrupt Gemini markers `discover_gemini` drops. Ids are deduped + sorted ascending via a `BTreeSet`.
- Codex corrupt-binding predicate: `csq-core/src/providers/codex/provisioning.rs` (`is_codex_corrupt_bound`) — mirrors `csq-core/src/providers/gemini/provisioning.rs` (`is_gemini_corrupt_bound`).
- Codex wrong-variant-binding predicate: `csq-core/src/providers/codex/provisioning.rs` (`is_codex_wrong_variant_bound`) — alongside `is_codex_corrupt_bound` in the same file.
- Per-cell probe functions: `csq-core/src/probe/<cell>.rs` (one file per cell; small, per-spec-§ assertions).
- Shared probe runner: `csq-core/src/probe/mod.rs` — `probe_slot` resolves the slot's Gemini binding (read ONCE), runs the ordered dispatcher (C2-ambiguity → corrupt-binding → valid-Gemini → 3P/Codex/Anthropic fall-through), and emits the §11.3 schema record. `probe_all_slots` sorts ascending by slot id so the §11.3 default-output example matches the order operators see.
- Shared RFC3339 parser: `csq-core/src/probe/anthropic_oauth.rs::parse_iso8601_to_epoch` is `pub(super)` so `gemini_local` can use the exact-epoch comparison instead of a 365.25-day year approximation.
- Tests: each cell file ships a unit test against a pinned response fixture under `csq-core/tests/fixtures/probe/<cell>.json`. Fixture content is the redacted response excerpt from the most-recent successful operator probe (§11.6 step 1 captures both FAIL and post-fix OK). Coverage includes a Cell 01 zero-utilization carve-out (`ok_when_zero_utilization_carries_null_resets_at` + `fail_on_null_resets_at_when_utilization_nonzero`) and a dispatcher integration test (`dispatcher_returns_ambiguous_when_both_bindings_present`).

## 11.8 Cross-references

- `specs/05-quota-polling-contracts.md` — pinned response shapes the probes assert against.
- `specs/07-provider-surface-dispatch.md` §7.4.1 — `quota.json` schema v2 (probe output references `surface` + `kind` fields here).
- `specs/04-csq-daemon-architecture.md` — the daemon usage poller that does continuous polling; probes are the one-shot operator complement.
- `csq/src/cli/commands/doctor.rs` — the complementary static-state gate (no outbound HTTP); its `gemini_unreadable_slots` shares the `is_gemini_corrupt_bound` predicate with the probe.

## Revisions

- **1.0.0** — Initial spec. Locks the 10-cell matrix, the `csq probe` surface, the operator runbook, and the CI prohibition.
- **1.0.1** — §11.3 exit code 65 added (operator-state Skipped distinct from misconfiguration 64). §11.7 implementation site amended to cite the CI runtime guard, the discovery-sort, the shared RFC3339 parser, and new regression tests. No matrix changes; no contract changes.
- **1.0.2** — §11.2 adds the "Gemini corrupt binding" cross-cell note (`cell="gemini-corrupt-binding"`, prerequisite-class → exit 64). §11.3 documents the corrupt-binding outcome + default-output example, and corrects the `--all` description (it enumerates via `discover_all` ∪ the `is_gemini_corrupt_bound` scan). §11.7 corrects implementation paths and documents the `probe_all_slots` union. `SCHEMA_VERSION` unchanged at `1.0.0`.
- **1.0.3** — §11.2 adds the "Codex corrupt binding" cross-cell note: `is_codex_corrupt_bound` predicate, `cell="codex-corrupt-binding"`, prerequisite-class → exit 64. §11.2 documents the C2 ambiguous-binding extension to **presence-presence** across Gemini + Codex. §11.3 extends the exit-code `64` narrative + adds the `codex-corrupt-binding` default-output example. §11.7 updates `probe_all_slots` union description. `SCHEMA_VERSION` unchanged at `"1.0.0"`.
- **1.0.4** — §11.2 adds the "Codex wrong-variant binding" cross-cell note covering the parse-Ok-but-`cf.codex()`-is-None case. §11.3 extends the exit-code-64 narrative + adds the `codex-wrong-variant-binding` default-output example. §11.7 extends `probe_all_slots` union description with the new scan + notes its load-bearing nature. `SCHEMA_VERSION` unchanged at `"1.0.0"` — new `SkipReason::WrongVariantBinding { surface, observed_kind: &'static str }` shape + new `cell` value are data within the unchanged JSON shape.
- **1.0.5** — §11.2 Cell 03 prerequisite text replaced: probe reads per-identity creds via `resolve_slot_to_uuid → credentials_codex_path_for(base_dir, uuid)` with legacy `credentials/codex-<N>.json` fallback; no longer reads `~/.codex/auth.json`. `SCHEMA_VERSION` unchanged at `"1.0.0"`. Companion: spec 05 rev 1.4.1.
- **1.0.6** — §11.5 enforcement-channel correction: the probe-in-CI prohibition is enforced by author/reviewer audit. No matrix change; no contract change.
- **1.0.7** — §11.2 Node-bridge transport citation corrected to `csq-core/src/http/mod.rs` (`post_json_node` / `get_bearer_node`).
