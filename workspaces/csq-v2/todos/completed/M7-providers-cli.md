# M7: Provider Management & CLI Entry Point

Priority: P0 (Launch Blocker)
Effort: 3 autonomous sessions
Dependencies: M1 (Platform), M2 (Credentials)
Phase: 2, Stream 3

---

## M7-01: Build provider catalog

Define provider skeletons: claude (ANTHROPIC_API_KEY), mm (MiniMax M2.7), zai (Z.AI GLM), ollama (keyless). Each has: key_fields, auth_type, env vars, model defaults, base URL, timeout. Embed model catalog (from `model-catalog.json`).

- Scope: 10.2, 10.9
- Complexity: Moderate
- Acceptance:
  - [x] All 4 providers defined with correct defaults
  - [x] Model catalog deserializes from embedded JSON
  - [x] `get_provider("mm")` returns MiniMax config

## M7-02: Build csq setkey

Set API key for provider profile. Read key from arg or stdin (keeps out of shell history). Strip `\r` from Windows clipboard. Create/update `settings-<provider>.json` with skeleton on first use. Preserve existing fields. Set system prompt primers for non-Claude models. Key validation HTTP probe for bearer-token providers.

- Scope: 10.1, 10.3, 10.5
- Complexity: Complex
- Acceptance:
  - [x] Stdin reading works (key not in shell history)
  - [x] First use: skeleton created with correct env/model defaults
  - [x] Existing profile: fields preserved, key updated
  - [x] Key validation: 200 = valid, 401 = invalid, timeout = warning
  - [x] Non-Claude: system prompt primers set

## M7-03: Build key validation HTTP probe

Send `max_tokens=1` test request to provider endpoint with the provided key. Report: valid (200), invalid (401/403), unreachable (timeout/DNS). Used by setkey and could be used by doctor.

- Scope: 10.10
- Complexity: Moderate
- Acceptance:
  - [x] Mock server: correct request format
  - [x] 200: "valid"
  - [x] 401/403: "invalid key"
  - [x] Timeout: "unreachable" warning

## M7-04: Build JSON auto-repair for truncated profiles

Detect truncated `settings-*.json` (1-3 missing closing braces). Repair by appending braces. Atomic writeback.

- Scope: 10.11
- Complexity: Moderate
- Acceptance:
  - [x] `{"a": 1` repaired to `{"a": 1}`
  - [x] `{"a": {"b": 1}` repaired to `{"a": {"b": 1}}`
  - [x] Valid JSON: no modification

## M7-05: Build Ollama integration

`get_ollama_models()` — runs `ollama list`, parses output. Returns model names for model catalog.

- Scope: 10.8
- Complexity: Trivial
- Acceptance:
  - [x] Parses `ollama list` output correctly
  - [x] Ollama not installed: returns empty list, no error

## M7-06: Build csq listkeys and csq rmkey

`listkeys` — shows configured profiles: profile name, key status, fingerprint (first 8 + last 6 chars), file path. `rmkey` — removes a provider profile file.

- Scope: 10.3-10.4
- Complexity: Trivial
- Acceptance:
  - [x] Keys properly masked in output
  - [x] Missing profile: error message
  - [x] rmkey: file deleted

## M7-07: Build csq models (list, list-provider, switch)

List all models across providers. List models for a specific provider (including Ollama live query). Switch active model: update all 5 MODEL_KEYS in settings file. Reject unknown models.

- Scope: 10.5-10.7
- Complexity: Moderate
- Acceptance:
  - [x] List all: shows models grouped by provider
  - [x] List provider: includes Ollama live models
  - [x] Switch: all 5 model keys updated atomically
  - [x] Unknown model: rejected with suggestion

## M7-08: Build csq login (browser flow)

Opens browser via `claude auth login` with isolated `CLAUDE_CONFIG_DIR`. Post-login: capture email via `claude auth status --json`. Capture credentials from keychain (macOS) or file (fallback). Save canonical + mirror. Save profile. Clear broker-failure flag.

- Scope: 9.6
- Complexity: Complex
- Depends: M2-05 (keychain), M2-08 (canonical save)
- Acceptance:
  - [x] `claude auth login` invoked with correct `CLAUDE_CONFIG_DIR`
  - [x] Email captured and saved to profiles.json
  - [x] Credentials captured from keychain or file
  - [x] Broker-failure flag cleared

## M7-09: Build csq install (self-installing binary)

Create directories (`~/.claude/accounts/`, `credentials/`), set permissions (700). Configure `settings.json` statusline command: `csq statusline`. Detect and remove v1.x artifacts (statusline-command.sh, rotate.md, auto-rotate-hook.sh).

- Scope: 14.1-14.2, 14.5
- Complexity: Complex
- Acceptance:
  - [x] Directories created with correct permissions
  - [x] settings.json patched: statusline uses `csq statusline`
  - [x] v1.x artifacts: check for modifications before deleting, preserve as `.bak` if modified
  - [x] Idempotent: running twice is safe

## M7-10: Build csq update + auto_update_bg()

`csq update` — foreground: check GitHub releases, download new binary, verify checksum, atomic replace. `auto_update_bg()` — background version check on launch, silent update if new version available.

- Scope: 14.3-14.4
- Complexity: Moderate
- Acceptance:
  - [ ] Downloads correct platform binary from GitHub Releases
  - [ ] Checksum verified before replace
  - [ ] HTTPS-only downloads (no HTTP fallback)
  - [ ] Ed25519 signature verification on release binary (pinned public key)
  - [ ] Atomic binary replacement
  - [ ] Background update: no visible delay to user

## M7-11: Build clap routing and main.rs

`clap` derive API for all subcommands. No-args defaults to `run`. Numeric first arg = `run N`. All subcommands registered with help text. `--version` flag.

- Scope: 15.1-15.4
- Complexity: Moderate
- Acceptance:
  - [x] `csq` → `csq run` (default)
  - [x] `csq 3` → `csq run 3`
  - [x] `csq --help` shows all subcommands
  - [x] `csq --version` shows version
  - [x] Unknown subcommand: helpful error

## M7-12: End-to-end CLI parity tests

For each CLI command, create test fixtures with same input as v1.x. Verify identical output. Commands: status, statusline, swap, run, suggest, listkeys.

- Scope: Phase 2 test strategy
- Complexity: Moderate
- Acceptance:
  - [x] All parity tests pass
  - [x] Deterministic commands produce byte-identical output
