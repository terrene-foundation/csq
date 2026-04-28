# M3: Account Identity & Discovery

Priority: P0 (Launch Blocker)
Effort: 2 autonomous sessions
Dependencies: M2 (Credential Management)
Phase: 1, Stream C

---

## M3-01: Build which_account() with fallback chain

Three-step identity resolution: (1) read `.current-account` fast path, (2) extract N from `config-N` dir name, (3) run `claude auth status --json` and match email to profiles. Returns `AccountNum`.

- Scope: 3.1
- Complexity: Moderate
- Acceptance:
  - [x] Fast path: `.current-account` exists, returns immediately
  - [x] Dir name fallback: extracts N from `config-N`
  - [x] CC auth fallback: matches email to profiles.json
  - [x] All three paths tested independently

## M3-02: Build account markers (read/write)

`csq_account_marker(config_dir)` — reads `.csq-account`, validates range. `write_csq_account_marker(config_dir, account)` — atomic write. These are the durable identity markers.

- Scope: 3.2-3.3
- Complexity: Trivial
- Acceptance:
  - [x] Write + read back matches
  - [x] Invalid content handled (non-numeric, out of range)
  - [x] Atomic write (no partial content on crash)

## M3-03: Build token matching

`credentials_file_account(access_token)` — linear scan of `credentials/N.json` matching access token. `live_credentials_account(refresh_token)` — same but matches refresh token (race-proof ground truth). Shared `_match_token_to_account()` helper.

- Scope: 3.4-3.6
- Complexity: Moderate
- Acceptance:
  - [x] Access token match: correct account returned
  - [x] Refresh token match: correct account even after CC refreshes (new AT, same RT initially)
  - [x] No match: returns None, not error

## M3-04: Build snapshot_account() with PID caching

Triggered from statusline on every render. Cheap path: if `.live-pid` process is alive, no-op. Expensive path: walk process tree to find CC PID, read `.csq-account`, write `.current-account` + `.live-pid`.

- Scope: 3.7
- Complexity: Complex
- Depends: M1-06 (process detection), M3-02 (markers)
- Acceptance:
  - [x] First call: walks process tree, writes PID file
  - [x] Subsequent calls with same PID alive: no-op (<1ms)
  - [x] PID dies: next call re-snapshots

## M3-05: Build Anthropic account discovery

Scan `credentials/*.json` for numeric filenames. Read `claudeAiOauth.accessToken` from each. Cross-reference with `profiles.json` for email. Returns list of `AccountInfo`.

- Scope: 3.8-3.10
- Complexity: Moderate
- Acceptance:
  - [x] Discovers all accounts with valid credential files
  - [x] Missing profile: account discovered with "unknown" email
  - [x] Invalid JSON credential file: skipped with warning

## M3-06: Build 3P account discovery

Read `settings-zai.json`, `settings-mm.json` for `ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_BASE_URL`. Returns 3P `AccountInfo` entries.

- Scope: 3.11
- Complexity: Moderate
- Acceptance:
  - [x] Discovers Z.AI and MiniMax accounts from settings files
  - [x] Missing settings file: no error, empty list

## M3-07: Build manual account management

`load_manual_accounts()` — reads `dashboard-accounts.json`. `save_manual_account(info)` — appends to file, atomic write with `0o600`.

- Scope: 3.12-3.13
- Complexity: Trivial (load), Moderate (save)
- Acceptance:
  - [x] Load: reads accounts from file
  - [x] Save: appends without corrupting existing entries
  - [x] Atomic write on save

## M3-08: Build combined discovery with dedup

`discover_all_accounts()` — merges Anthropic + 3P + manual. Deduplicates by ID (first wins). Returns unified account list.

- Scope: 3.14
- Complexity: Trivial
- Acceptance:
  - [x] All three sources merged
  - [x] Duplicate IDs: first source wins
  - [x] Empty sources: no error

## M3-09: Build profiles.json management

`ProfilesFile` struct per GAP-7 resolution. Load, save, get_email, update account profile. Forward-compat with `#[serde(flatten)]`.

- Scope: 3.15-3.16, GAP-7
- Complexity: Trivial
- Acceptance:
  - [x] Round-trip preserves unknown fields
  - [x] Get email for missing account: returns None
  - [x] Save preserves other accounts' entries
