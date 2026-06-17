# 02 csq Handle-Dir Model

Spec version: 1.21.1 | Status: STABLE | Governs: on-disk layout, two-tier permanent state, handle dir lifecycle, swap semantics

---

## 2.0 Scope

This spec defines csq's authoritative on-disk layout: where accounts live, where running terminals live, which files are permanent, which are ephemeral, and how `csq swap` moves a terminal between accounts without affecting sibling terminals.

It depends entirely on spec 01 (Claude Code Credential Architecture). If spec 01 is wrong, this one is wrong. Read spec 01 first.

## 2.1 On-disk layout

Root directory: `$HOME/.claude/accounts/` (configurable via `CSQ_BASE_DIR`; default shown).

```
accounts/
│
│  ╔══════════════════════════════════════════════════════════════════════╗
│  ║ TIER 1 — CC-owned per-account dir (config-N/): permanent, CC writes  ║
│  ║          via subprocess login; csq does NOT delete these dirs.       ║
│  ╚══════════════════════════════════════════════════════════════════════╝
├── config-1/                 ← CC-owned permanent home for account 1
│   ├── .csq-account          ← marker, content: slot's UUID (or legacy "1")
│   ├── settings.json         ← account 1's CC settings (CC subprocess or user edits)
│   ├── .claude.json          ← account 1's CC app state (CC writes)
│   ├── .quota-cursor         ← stale-read dedupe cursor
│   └── [symlinks to ~/.claude/* for shared items]
│   ── note: the .credentials.json LIVE MIRROR in config-N/ is retired.
│      Older installs may still have it on disk; the file is no longer
│      written by any production path. See INV-01 + INV-05.
├── config-2/                 ← CC-owned permanent home for account 2
│   └── ...
├── config-N/                 ← one per account
│   └── ...
│
│  ╔══════════════════════════════════════════════════════════════════════╗
│  ║ TIER 2 — csq-owned per-identity dir (identities/<UUID>/): canonical  ║
│  ║          credentials, settings, identity record.                     ║
│  ╚══════════════════════════════════════════════════════════════════════╝
├── identities/<UUID>/        ← identity-keyed canonical state
│   ├── identity.json         ← immutable: {email, provider, created_at, key_id}
│   ├── credentials.json      ← Anthropic OAuth tokens (canonical target)
│   ├── credentials-codex.json← Codex OAuth tokens (canonical target)
│   └── settings.json         ← per-account settings overlay (canonical target)
│
├── credentials/              ← legacy-keyed compat path — RETIRED. The numeric
│   │                            mirror (N.json / codex-N.json) is no longer
│   │                            written or read by any production path. Leftover
│   │                            mirror files from earlier builds are PRUNED by a
│   │                            reconciler pass on every daemon start when the
│   │                            identity-keyed successor exists and parses; KEPT
│   │                            otherwise (see §INV-LEGACY-MIRROR below).
│   ├── (post-cleanup: empty for slots whose by_slot UUID resolves;
│   │     mirrors remain only for pure-legacy / half-mint slots)
│   └── gemini-<N>.json       ← LIVE: Gemini binding (gemini::provisioning::write_binding)
│
├── profiles.json             ← {by_slot, by_email, by_slot_label, by_slot_identity}
├── store-version             ← {"schema": N, "minted_at": ...} — gate sentinel
├── label-channel-migrated    ← sentinel: written by the one-shot label relocation pass
├── quota.json                ← daemon-owned quota cache (per-slot)
├── rotation.json             ← auto-rotation config
├── csq.sock                  ← daemon IPC Unix socket (0o600)
│
└── term-<pid>/               ← ephemeral handle dir, one per running `claude` process
    ├── .credentials.json  → ../identities/<UUID>/credentials.json    (symlink)
    ├── .csq-account       → ../config-<current>/.csq-account         (symlink)
    ├── settings.json      ← materialized file (deep-merged: ~/.claude/settings.json + config-<current>/settings.json)
    ├── .claude.json       → ../config-<current>/.claude.json         (symlink)
    ├── .live-pid          ← contains the PID, used for sweep
    └── [shared symlinks to ~/.claude/*]
```

### Two tiers of state

1. **Permanent tier — two sub-tiers:**
   - **CC-owned per-account dir (`config-N/`)**: Claude Code's own per-account configuration directory. csq does NOT write `.credentials.json`, `.csq-account`, `settings.json`, or `.claude.json` into this dir during normal operation — those writes happen via CC's subprocess on `csq login N` (CC's OAuth flow writes its own files) or by direct user edit. csq reads `config-N/.credentials.json` exactly once during `finalize_login` to seed `identities/<UUID>/credentials.json`. Production readers route through the identity-keyed path; `config-N/` is preserved for CC's own use.
   - **csq-owned per-identity dir (`identities/<UUID>/`)**: csq's permanent account state — `identity.json` (immutable: email, provider, created_at, key_id), `credentials.json` (Anthropic, daemon-refreshed), `credentials-codex.json` (Codex, daemon-refreshed), and `settings.json` (per-account overlay). Linked to slots via `profiles.json::by_slot[N] → UUID` and `by_email[email] → UUID`.
   - **Compat-reader path (`credentials/N.json`) — RETIRED + cleaned up**: the legacy-keyed numeric mirror is no longer written or read by any production path. `save_canonical_for` (`csq-core/src/credentials/file.rs`) returns `Err(CredentialError::NoCredentials)` when `profiles.json::by_slot` has no UUID for the slot (fail-closed). `probe_slot` (`csq-core/src/probe/mod.rs`) does not fall back to the numeric path for slots with no UUID — such slots are skipped with `prerequisite: not present`. Pre-retirement mirror files (`credentials/<N>.json` for Anthropic, `credentials/codex-<N>.json` for Codex) left over from earlier builds are PRUNED by a reconciler pass (`csq-core/src/accounts/legacy_mirror_cleanup.rs::prune_legacy_credential_mirrors`) on every daemon start, provided the successor at `identities/<UUID>/credentials.json` (Anthropic) or `identities/<UUID>/credentials-codex.json` (Codex) exists and parses. Mirrors are KEPT when no `by_slot[N]` UUID resolves (pure-legacy install whose mirror is still the live read source via the `refresh::check.rs` fallback), or when the identity-keyed successor is missing/corrupt — see §INV-LEGACY-MIRROR below. The Gemini binding `credentials/gemini-<N>.json` is LIVE (not legacy) and out of the cleanup pass's scope (`gemini::provisioning::write_binding`).
2. **Ephemeral tier (`term-<pid>`):** exists once per live CC process, lives exactly as long as that process. Created by `csq run`. Deleted on process exit. Contains symlinks, the `.live-pid` file, and the materialized `settings.json` (deep-merged from user global + account overlay).

### The shared items (both tiers)

Every directory that CC launches into MUST have symlinks for every entry of `session::isolation::SHARED_ITEMS` (`csq-core/src/session/isolation.rs` — 35 entries: `projects`, `sessions`, `history`, `commands`, `skills`, `agents`, `rules`, `mcp`, `plugins`, `todos`, plus CC-internal items like `statsig`, `checkpoints`, `__store.db`) pointing at `~/.claude/<item>`. The const in `isolation.rs` is authoritative. This is what preserves conversation history across swaps — CC writes history to the symlinked target, which is the same path regardless of which config or handle dir it launched in.

## 2.2 Invariants

**INV-01: Two-tier permanent state — CC-owned `config-N/` AND csq-owned `identities/<UUID>/`.**

csq's permanent account state is split across two directory trees, both of which are permanent and neither of which is deleted in any normal flow:

- **`config-N/` (CC-owned)**: continues to exist for every provisioned account. csq does NOT delete `config-N/` (CC writes there via subprocess login and may be invoked directly by the user). csq does NOT write `.credentials.json`, `.csq-account`, `settings.json`, or `.claude.json` into `config-<N>/` during normal operation. The only writers are: (1) Claude Code itself via `claude auth login --subprocess` during `csq login N` — CC's own OAuth flow writes `config-N/.credentials.json`, populates settings, and updates `.claude.json`; (2) direct user edits to `settings.json` or `.claude.json` (e.g. running `claude` legacy-style with `CLAUDE_CONFIG_DIR=config-<N>`). Directory name `config-N` encodes the account number and the name MUST match the `.csq-account` marker inside it.
- **`identities/<UUID>/` (csq-owned)**: csq's permanent per-identity directory. The daemon refresher, `csq login`, and identity-mint writes target this dir. Contains `identity.json` (immutable side: email, provider, created_at, key_id), `credentials.json` (Anthropic OAuth tokens), `credentials-codex.json` (Codex OAuth tokens), and `settings.json` (per-account overlay). Linked to slots via `profiles.json::by_slot[N] → UUID`.

`csq swap`, `csq run`, and any non-login flow MUST NOT write to `config-<N>/.credentials.json`, `config-<N>/.csq-account`, `config-<N>/settings.json`, or `config-<N>/.claude.json`.

**Write paths into `config-N`:**

1. **CC subprocess on `csq login N`** — `claude auth login --subprocess` writes `config-N/.credentials.json` as part of CC's own OAuth flow (csq does NOT write this file directly; CC's own keychain-and-file write is the source). csq then reads the fresh tokens from that file and seeds `identities/<UUID>/credentials.json` via the canonical write chokepoint. The legacy `config-N/.credentials.json` live mirror is read once by `finalize_login` and not written-to again by csq.
2. User edits — `settings.json`, `.claude.json` may be edited by CC running in that dir (via legacy launches) or by the user directly.

**Retired writers:** the daemon refresher, `csq swap` (handle-dir model), `rotation::swap_to`, broker fanout / pullsync / sibling-recovery, and `copy_credentials_for_session` no longer write `config-N/.credentials.json`. Token-refresh writes target `identities/<UUID>/credentials.json` (via `save_canonical_for`, the Anthropic write chokepoint; the Codex chokepoint targets `credentials-codex.json`). Handle dirs whose symlinks resolve to that identity automatically see the new content via the symlink layer; see INV-05 below.

**INV-02: `term-<pid>` is ephemeral and per-process.**

- Created atomically by `csq run N` before execing `claude`.
- The directory name is `term-<pid>` where PID is the csq CLI's own process ID at handle-dir creation time (NOT the `claude` process that comes next, which is either the exec target of csq or a child). The PID is captured BEFORE `exec`, so it is stable for the lifetime of the resulting `claude` process.
- Every file in `term-<pid>` is either a symlink to a `config-<current>/*` target, the `.live-pid` sentinel, or the materialized `settings.json` (the sole non-symlink content file — deep-merged from `~/.claude/settings.json` + `config-<current>/settings.json`).
- On `claude` process exit, csq (via a wrapper OR via daemon sweep) removes `term-<pid>`. See section 2.5.
- **No long-lived content beyond settings.json.** If csq ever writes other real data into a `term-<pid>` dir, it's a bug against this spec.

**INV-03: Identity derivation reads `.csq-account` through the symlink.**

- To determine which account a terminal is currently bound to, code MUST read the `.csq-account` file within its `CLAUDE_CONFIG_DIR` (which is the handle dir). The symlink resolves to the current `config-<N>/.csq-account`, returning the slot's identity.
- Code MUST NOT parse `config-N` or `term-<pid>` directory names for a number to determine account identity. The handle dir PID is not an account ID. The config dir N is the account identifier ONLY when reading permanent canonical state, never when reading live runtime state.
- **Marker content semantic:** the `.csq-account` marker file content is the slot's identity UUID (canonical UUID-v4 string form, e.g. `"550e8400-e29b-41d4-a716-446655440000"`) when `profiles.json::by_slot` carries a mapping. The filename `.csq-account` is unchanged (content flips, never the filename). Pure-legacy installs that have not yet reached daemon Pass 0 fall back to the decimal slot id contract via `markers::write_csq_account_legacy`; the reader is UUID-tolerant, so legacy and UUID content both round-trip through `markers::read_identity_marker`. The decimal-only reader `markers::read_csq_account` returns `Option<AccountNum>` (UUID content returns `None`); the accessor `markers::read_csq_account_uuid` returns `Option<IdentityId>` for callers that need slot-independent identity.
- **`.current-account` is a PERFORMANCE CACHE, not an authority.** Resolution code MUST resolve the slot from `.csq-account` (numeric content → slot directly; UUID content → `profiles::resolve_uuid_to_slot` reverse lookup over `by_slot` — the inverse of `resolve_slot_to_uuid`), and treat `config-N/.current-account` only as a cache that is VALIDATED against that authority and SELF-HEALED on mismatch. `snapshot_account` performs this: it always resolves the authority, and when the cached `config-N/.current-account` disagrees it rewrites `config-N/.current-account = N` (the canonical file, never the handle-dir symlink — `atomic_replace`/rename would replace the symlink with a regular file). `.live-pid` does NOT gate RESOLUTION; it only gates the expensive `find_cc_pid` process-tree walk. Under the handle-dir model `config-N/.current-account` MUST equal N or be absent; any foreign value is drift. Without this, a stale cache (a pre-handle-dir-migration leftover, or a value left by a binder that did not refresh it) could surface the wrong slot after `csq swap N`. Diagnosis + repair: `csq doctor` flags `CurrentAccountDrift`; `csq repair` rewrites it.

**INV-03b: Every binder refreshes the `.current-account` cache.**

Every operation that (re)binds a `config-N` to slot N — `csq run`, `csq swap` (same-surface ClaudeCode + Codex, after `repoint_handle_dir`), and `csq move FROM TO` (after the rename + `.csq-account` write) — MUST write `config-N/.current-account = N` via the atomic writer. Writes are idempotent same-value (the destination slot is the explicit command argument, never terminal-derived) so no additional lock is needed beyond `atomic_replace`. The cache write is non-fatal for `swap` (snapshot's authority-first self-heal is the structural backstop) and fatal for `move` (parity with the paired `.csq-account` write in the same dir). This prevents `csq move 6 7` from rewriting `config-7/.csq-account` while leaving `config-7/.current-account` holding the old slot id, which would re-create the swap-wrong-slot bug.

**INV-04: Swap is a symlink repoint, never a file rewrite.**

`csq move FROM TO` performs a `by_slot` swap step (in addition to the filesystem rename) under the same `ProfilesFileLock` window. Specifically:

- `profiles.json::by_slot[FROM]` ↔ `by_slot[TO]` are swapped so that UUIDs survive the slot renumber. The identity addressable at `by_slot[FROM]` before the move is addressable at `by_slot[TO]` after, with its UUID intact.
- `profiles.json::by_slot_label[FROM]` ↔ `by_slot_label[TO]` are ALSO swapped. User rename labels are slot-keyed; without this swap a `csq move 2 3` would leave the label for account 2 at the old slot key 2 while the identity UUID moved to slot 3 — the label would either be lost or point at the wrong slot on the next `get_email` call. Only the present entry is swapped; absent entries remain absent (asymmetric swap is correct).
- `by_email` is intentionally NOT updated — email→UUID is slot-independent.
- The `by_slot` swap and the `by_slot_label` swap are performed under a single `ProfilesFileLock` window, so a concurrent reader never observes a half-swapped state.
- Implementation: `profiles::swap_slot_mapping(_lock, base, from, to)` in `csq-core/src/accounts/profiles.rs`. This is the single canonical primitive; there is no duplicate private implementation.
- After a successful move, the calling layer fires `POST /api/slot-swap {"from": N, "to": M}` via `csq_core::daemon::notify_slot_swap` (the shared chokepoint in `csq-core/src/daemon/client.rs`). The daemon drops `RefreshStatus` cache entries for both slot numbers. This is fire-and-forget; connect failure does not fail the move.

- `csq swap M` run inside a handle-dir-bound terminal MUST:
  1. Look up the current handle dir from `CLAUDE_CONFIG_DIR`.
  2. Verify that path is a `term-<pid>` dir under the csq base.
  3. For each symlinked file in the handle dir (`.credentials.json`, `.csq-account`, `.claude.json`, and any additional symlinks the launch created), atomically replace the symlink to point at `../config-<M>/<same-filename>`.
  4. Re-materialize `settings.json` by deep-merging `~/.claude/settings.json` (user global) with `config-<M>/settings.json` (new account's slot overlay) and writing the result to the handle dir.
  5. Atomic replace uses rename-over (`std::fs::rename` of a new symlink onto the old one — not delete-then-create, which races).
- csq swap MUST NOT write to the underlying `config-<M>/*` files. Those are permanent. The swap is purely a pointer change in the handle dir.
- After the repoint, the next time CC in that terminal calls `fs.stat('.credentials.json')`, the stat follows the new symlink to `config-<M>/.credentials.json`, returns a DIFFERENT mtime from what CC saw before (almost certainly — it's a different file), and CC's `invalidateOAuthCacheIfDiskChanged` clears its memoize. The next API call uses account M. See spec 01 section 1.4.
- **Known caveat — mtime collision:** the "almost certainly" above is an empirical claim, not a guarantee csq enforces. CC's invalidation fires on `mtimeMs !== lastCredentialsMtimeMs` (strict inequality, spec 01 §1.4). If `config-<current>/.credentials.json` and `config-<M>/.credentials.json` happen to share an mtime — e.g. both refreshed within the same nanosecond by the daemon, both written via `cp -p` from a common source, or filesystem precision is clamped (HFS+, certain network FS) — CC will silently skip the reload and the swap appears to "not take effect" until something else perturbs the file.
- **mtime-collision fix:** `repoint_handle_dir` calls `platform::fs::bump_mtime_above` on `config-<M>/.credentials.json` BEFORE the atomic symlink rename, advancing its mtime strictly above the pre-swap target's mtime. CC's first stat after the rename then always returns an advanced mtime, so the strict-inequality reload check fires on the next API call. The pre-bump (rather than post-bump) eliminates the race window between rename and bump in which CC could stat the new target with the colliding mtime. Failure of the bump is non-fatal — the post-swap `INFO`-level trace surfaces it via `mtime_changed = false` and the `mtime_collision` `WARN` is the regression detector. The same shape applies to `repoint_handle_dir_codex` on `credentials/codex-<M>.json`.
- **Sibling-terminal narrowed invariant (consequence of the mtime-collision fix):** Other terminals (with their own `term-<otherPid>/.credentials.json` symlinks still pointing at `config-<current>`) are untouched in the swap-source case. **However**, sibling terminals already bound to `config-<M>` (the swap **target**) WILL see a fresh mtime on their next CC stat and trigger a one-time credential reload. The reload reads identical credential content (no semantic change) and is functionally harmless, but the invariant "other terminals are unaffected by a swap" is narrowed to "**other terminals' account bindings are unaffected**." Sibling terminals on the swap source are still untouched in every observable sense; sibling terminals on the swap target see one harmless reload.

**INV-05: Daemon refresh writes to `identities/<UUID>/credentials.json`.**

- On successful token refresh for slot N, the daemon resolves N → UUID via `profiles.json::by_slot[N]` and writes the new tokens to `identities/<UUID>/credentials.json` ONLY. The `credentials/N.json` legacy mirror write is retired. The live mirror at `config-<N>/.credentials.json` is NOT written (retired).
- Every `term-<pid>` handle dir whose `.credentials.json` symlink resolves to `identities/<UUID>/credentials.json` automatically sees the new content on its next `fs.stat`. No per-handle-dir write is needed.
- This is a property of the symlink layer — the daemon refresh targets exactly one filesystem location per identity; the handle dirs are just views.
- **Consequence:** the `broker::fanout::fan_out_credentials` function was deleted entirely (see `csq-core/src/broker/`). Per-handle-dir fanout is a filesystem side effect of writing the identity file once; no iteration is needed.

**INV-06: Subscription metadata preserved on every credential write.**

- As in spec 01 section 1.7: `subscriptionType` and `rateLimitTier` may be null in fresh OAuth responses. When writing new tokens to `identities/<UUID>/credentials.json` (the ONLY write target), csq MUST preserve the existing non-null values from the current file if the incoming tokens have null fields. The retired `credentials/N.json` compat path does not apply; the guard applies to the identity-keyed path only.
- This applies to `csq login` and daemon refresh. It does NOT apply to swap (swap never writes credentials at all — it only repoints symlinks).
- **Guard location:** the daemon refresh path in `csq-core/src/daemon/refresher.rs` (and wherever else credentials are written via `save_canonical_for`, the Anthropic write chokepoint). csq swap does NOT write credentials in the handle-dir model.

**INV-07: `identities/<UUID>/` is csq's canonical per-account state.**

The `accounts/identities/<UUID>/` subtree is csq's canonical per-account state. Production credentials writes target `identities/<UUID>/credentials.json` (Anthropic) and `identities/<UUID>/credentials-codex.json` (Codex); per-account settings overlay targets `identities/<UUID>/settings.json`. Production readers route through `profiles.json::by_slot[N] → UUID` with a pure-legacy fallback to `credentials/<N>.json` for installs whose `by_slot` is empty. The daemon `phase4_gate_check` refuses to start when any UUID-mapped slot lacks its identity-keyed credentials/settings/codex file — guaranteeing the identity-keyed path is always live in production.

The `identities/<UUID>/identity.json` files contain only the **immutable side**: `{email, provider, created_at, key_id}`. Tokens live in sibling `credentials.json` / `credentials-codex.json`; settings live in sibling `settings.json`; quota lives in `quota.json` keyed by slot.

The `accounts/store-version` sentinel (`{"schema": 1, "minted_at": ...}`) marks that the daemon has run Pass 0 (`identity_mint`). Its presence is the idempotency gate for all subsequent starts and is required by `phase4_gate_check`.

**`profiles.json` schema and backward compatibility.** The slot's identity (email, provider, surface) is carried by:

- `profiles.json::by_slot[N] → UUID` and `profiles.json::by_email[email] → UUID` — maps written by `mint_for_login` / daemon Pass 0.
- `identities/<UUID>/identity.json` — the canonical immutable identity record.

A legacy `profiles.json::accounts: { "N": {email, method, extra} }` map existed in older schema versions and has been removed from the production `ProfilesFile` struct (`csq-core/src/accounts/profiles.rs`). Older on-disk files containing `accounts: {...}` are absorbed into `ProfilesFile::extra` via `#[serde(flatten)]` — a backward-compat hatch that lets legacy payloads load without data loss. The legacy data is accessible to reconciler passes via `pub fn legacy_accounts_email_map(pf: &ProfilesFile) -> HashMap<String, String>`. Regression tests `profiles_load_tolerates_v1_accounts_field_via_flatten` and `profiles_round_trip_preserves_v1_accounts_via_extra` cover the backward-compat hatch.

**Identity mint uses the OAuth email, not the display label.** `mint_for_login` uses `account_info.oauth_email` (credential-derived email, not the user-chosen display label) as the `by_email` map key. This ensures `get_email` can find the slot by OAuth email in the `by_email` reverse-lookup path even after a user renames the account.

**Reader priority:** `ProfilesFile::get_email(N)` resolution order is:

1. `by_slot_label[N]` — user rename label; checked FIRST because it is the most-recently intentional user action.
2. `by_slot_identity[N]` — identity-class label for non-OAuth slots (3P API keys, Codex); checked SECOND so a user rename (step 1) always wins.
3. `by_slot[N] → UUID → reverse-search by_email` — OAuth-email fallback for post-mint slots whose `by_slot_label` and `by_slot_identity` are both absent (the normal OAuth case).

**`by_slot_identity` channel — non-OAuth slot identity.** An independent top-level `HashMap<String, String>` field on `ProfilesFile`, mirroring `by_slot_label`'s serde shape (`#[serde(default, skip_serializing_if = "HashMap::is_empty")]`). The map carries identity-class labels for slots whose identity is NOT recoverable from `by_slot[N] → UUID → by_email` (the OAuth chain) — 3P API-key binds and Codex OAuth slots. Label literal conventions:

- `"apikey:<provider_id>"` — 3P API-key slots (e.g. `"apikey:mm"`, `"apikey:zai"`, `"apikey:deepseek"`, `"apikey:ollama"`). Written by `accounts/third_party.rs::bind_provider_to_slot` in the same `ProfilesFileLock` window as the settings env-block fan-out, and by the daemon backfill reconciler for upgraded hosts.
- `"codex-<N>/<id-prefix>"` — Codex OAuth slots, where `<id-prefix>` is the first dash-block of `tokens.account_id` (e.g. `"codex-12/abc12345"`). Written by `providers/codex/login.rs::update_profile` (CLI path) on every successful `csq login --codex` AND by `providers/codex/desktop_login.rs::update_profile` on every successful desktop Codex login. Non-stable across re-login: re-running `csq login --codex` against the same Codex account produces a NEW `tokens.account_id` and therefore a NEW label (see spec 07 §7.2.2).
- `"gemini-<N>/<mode-class>"` — Gemini-bound slots, where `<mode-class>` ∈ `{apikey, vertex, codeassist}` derived from the `AuthMode` of the csq-owned `credentials/gemini-<N>.json` binding marker (`gemini-13/apikey`, `gemini-7/vertex`, `gemini-4/codeassist`). Produced by the SINGLE shared `providers::gemini::provisioning::gemini_identity_label(slot, &AuthMode)` consumed by BOTH the synchronous provision write (all 3 `provision_*` paths, under `ProfilesFileLock`, marker-FIRST/identity-LAST) AND the daemon backfill Gemini arm. The literal is a pure function of the binding marker — it NEVER reads the Vertex SA JSON, gemini-cli's `~/.gemini/oauth_creds.json`, or the platform vault. Identity-CLASS-stable always; identity-VALUE-stable WITHIN a mode; the value changes only on a deliberate operator mode re-provision (the inverse signal-interpretation of the Codex non-stable label — see spec 07 §7.2.3 vs §7.2.2).

**`by_slot_identity` role in safe `accounts`-field removal.** `by_slot_identity` is the channel that lets the legacy `accounts` field be removed safely. Before this channel existed, non-OAuth slots' identity ONLY lived in `accounts[N].email`; removing that field would orphan them. With `by_slot_identity` populated (synchronous writes on new binds + reconciler backfill for upgraded hosts), `accounts[N]` becomes information-recoverable for non-OAuth slots via `get_email` step 2. The accounts-prune reconciler (`accounts/profiles.rs::prune_redundant_accounts_entries`) removes any `accounts[N]` whose deletion is information-preserving.

**Daemon backfill pass:** `pass_rn1_e_backfill_by_slot_identity` runs in `startup_reconciler::run_reconciler`. Non-sentinel-gated (pure function of disk state; second run no-op). Walks the legacy `accounts` data and, for entries whose `email` prefix-matches `"apikey:"` or `"codex-"`, writes `by_slot_identity[N] = email.clone()`. For entries with empty `email`, derives the identity from `settings.json::env::ANTHROPIC_BASE_URL` via `accounts::discovery::provider_from_base_url`. Skips slots whose `by_slot[N]` is present (OAuth — handled by the accounts-prune pass) and slots whose `by_slot_identity[N]` already exists (idempotency + preserves explicit synchronous writes). **Gemini arm:** Gemini slots have NO `accounts[N]` entry, so the accounts walk structurally skips them. The pass then reuses `accounts::discovery::discover_gemini` (already hardened: symlink reject, `.json` filter, `gemini-` prefix, `1..=999`, leading-zero canonicalization, `AccountNum::try_from`, `read_binding` error-branch). For each Gemini slot it re-reads the marker for the raw `AuthMode`, derives the literal via the shared `gemini_identity_label`, and **overwrites on mode-mismatch** (a slot re-provisioned in a new mode then crashed before the synchronous write self-heals on the next reconcile) while still skipping byte-equal values (idempotent). Non-fatal: `error_kind = "by_slot_identity_backfill_failed"` log; daemon continues. Counter: `ReconcileSummary::by_slot_identity_backfilled`.

**One-time label relocation:** On first daemon start after upgrade to a build containing the `by_slot_label` channel, the reconciler runs `pass_rn1_d5_label_relocation`. For every slot in the legacy `accounts` data whose `email` differs from the slot's OAuth email (i.e., it is a user rename label, not an address), the pass copies it into `by_slot_label[N]` — unless `by_slot_label[N]` is already present (idempotent; a later user rename takes precedence). After the pass completes successfully, the `label-channel-migrated` sentinel file is written atomically. Subsequent daemon starts skip the pass on sentinel detection (fast no-op). Failure of the pass is non-fatal — the daemon starts normally; the next daemon start retries. The sentinel write uses the `unique_tmp_path → write → atomic_replace` pipeline with tmp-cleanup on every failure branch (per the credential-write security discipline in spec 06).

**Login-path label capture:** The one-shot relocation pass covers slots that already had a `by_slot[N]` UUID when it ran. It does NOT cover the **pure-legacy unminted-with-rename-label** case: a slot with a user rename label in `accounts[N].email` but no `by_slot[N]` UUID at relocation time. The relocation pass's second arm only _records_ these as `UnrecoverableNoBySlot` outcomes (read-only) so `csq doctor` can warn by name; it cannot relocate them (no UUID anchor). `csq doctor` instructs the operator to "log in again to mint UUIDs". Without a complementary capture rule, that instruction would silence the warning WITHOUT preserving the label — minting `by_slot[N]` makes the `unrecoverable_label_slots` predicate (`!by_slot.contains(N)`) stop matching, so the warning clears even though the label was never copied; a later `accounts` deletion would then silently drop it. The one-shot relocation pass cannot recover this — it is sentinel-gated and never re-fires once `label-channel-migrated` exists. Therefore `mint_for_login` (the `csq login N` mint path) captures the label directly: after `add_identity_mapping` mints `by_slot[N]`, if `accounts[N].email` is non-empty and differs from the authoritative OAuth email (the `email` arg in both raw and `normalize_email`-d forms; OAuth-sourced) and `by_slot_label[N]` is absent, it is copied into `by_slot_label[N]` via `set_slot_label` under the same `ProfilesFileLock`. Rename detection is identical to the relocation pass's first arm; the `by_slot_label[N]`-absent guard preserves a later explicit rename. Non-fatal: a capture failure logs `error_kind = "label_capture_failed"` (token-redacted) and does not block login. This makes the `csq doctor` operator instruction true rather than weakening the doctor text to match a deficient implementation.

**INV-LEGACY-MIRROR: Legacy canonical credential mirror cleanup.** When the WRITER to `credentials/<N>.json` (Anthropic) and `credentials/codex-<N>.json` (Codex) was retired — refreshes now write only to the identity-keyed `identities/<UUID>/credentials.json` / `credentials-codex.json` paths — pre-retirement mirror files were left on disk; nothing brought existing files to absent. Consequence: `csq doctor`'s `detect_legacy_canonical_anthropic` + `detect_legacy_canonical_codex` (`csq/src/cli/commands/doctor.rs`) fire while the files remain. `prune_legacy_credential_mirrors` (idempotent reconciler pass, `csq-core/src/accounts/legacy_mirror_cleanup.rs`, wired into `startup_reconciler::run_reconciler`) walks `<base>/credentials/`, filename-matches the Anthropic + Codex shapes via the same `strip_prefix`/`strip_suffix` + `u16::parse` discipline the detectors use (rejects `gemini-<N>.json`, sentinel files, and non-decimal stems), and for each match evaluates the predicate. **Removal arm:** `profiles.json::by_slot[N]` resolves to `Some(UUID)` AND `identities/<UUID>/credentials.json` (Anthropic) or `identities/<UUID>/credentials-codex.json` (Codex) exists AND parses successfully via `credentials::load`. **Keep arms** (each with a `KeptReason` taxonomy entry on `LegacyMirrorPruneReport`): `NoBySlotMapping` (pure-legacy install — the mirror is the live read source via the `refresh::check.rs` fallback; deleting would brick the slot), `IdentityFileMissing` (half-mint state — the gate refuses daemon start in this configuration), `IdentityFileCorrupt` (successor parse failure — refuse to delete the only readable bytes), `IoError` (per-file delete failure → pass continues batch; file retried next start). Path reconstruction MUST use `canonical_path_for(base, AccountNum::try_from(N)?, surface)` rather than joining the raw `read_dir` filename — `AccountNum::try_from` is the structural defense against any non-decimal slot id that slipped past the filename matcher. The pass uses `ProfilesFileLock` ONLY to load the `profiles.json` snapshot; the per-file deletions execute lock-free (anti-pattern: do not extend the lock to wrap the deletion loop). NOT sentinel-gated (pure function of disk state; second run is a no-op) so a host that later mints a `by_slot[N]` UUID via `csq login N` gets its mirror pruned on the next daemon start. Non-fatal: lock contention / load error logs `error_kind ∈ {profiles_lock_contention, legacy_mirror_prune_failed}` and the daemon continues. Gemini bindings (`credentials/gemini-<N>.json`) are out of scope — they are the LIVE Gemini surface (`gemini::provisioning::write_binding`), not retired-writer legacy.

**INV-ORPHAN-IDENTITY-GC: Orphan-identity directory GC.** `csq logout N` (and a renumber that drops the last reference to a UUID) removes the slot's `by_slot`/`by_email`/`by_slot_identity` entries, its canonical credential files, and its `config-N/` dir — but historically left the csq-owned `identities/<UUID>/` directory on disk. Consequence: `csq doctor`'s `audit_coexistence` reports `INCONSISTENT: OrphanIdentity(<UUID>)` and dead credential dirs accumulate. Two coordinated fixes:

**(1) GC pass** `prune_orphan_identities` (`csq-core/src/accounts/orphan_identity_gc.rs`, wired into `startup_reconciler::run_reconciler` as the FINAL pass, after the legacy-mirror cleanup). It deletes every `identities/<UUID>/` whose directory name parses as an `IdentityId` AND whose UUID is referenced by NEITHER `by_slot` NOR `by_email` (the reachable set is `by_slot.values() ∪ by_email.values()` as `HashSet<IdentityId>`, never string-compared). `by_email` is in the set because mint re-adopts by email (reuse-eligible → KEEP). `by_slot_identity` values are LABELS (`"apikey:mm"`, `"codex-12/3bf322e8"`), NOT UUIDs, and are NOT consulted — a live Codex slot is reachable because `mint_for_codex_login` writes `by_slot[N] = UUID` (a critical safety invariant).

**(2) Logout source-fix** (`accounts::logout::logout_account`): after the profiles-map removal is durably saved under `ProfilesFileLock`, the now-orphaned UUID's dir is `remove_dir_all`'d — ordering: map-removal BEFORE dir-delete, so a crash leaves an unreferenced orphan (the GC collects it) NEVER a `by_slot` row pointing at a deleted dir. A shared UUID (another slot still references it) is preserved via the `by_slot ∪ by_email` re-check (the sibling-slot guard). `move_account` needs NO change — it keeps the UUID in `by_slot` under the new slot.

**Whole-pass fail-closed guards (KEEP everything):** profiles absent/unreadable/unparseable; `by_slot` AND `by_email` both empty (fresh/pre-mint install); on-disk `store-version` schema GREATER than this build's `STORE_VERSION_SCHEMA_CURRENT` (version-skew — a newer daemon may key identities through a channel riding in `ProfilesFile::extra`). **Live-handle-dir guard (defense-in-depth):** before deleting, scan `term-*` handle dirs; if any LIVE (`is_pid_alive`) dir's `.credentials.json` / `.credentials-codex.json` symlink resolves into the candidate, KEEP (`LiveHandleDir`). Per-dir keep taxonomy on `OrphanIdentityGcReport`: `ReferencedBySlot`, `ReferencedByEmail`, `LiveHandleDir`, `IoError` (`remove_dir_all` failure → keep + retry next tick; `NotFound` → success no-op). **Lock posture (load-bearing):** the wrapper holds `ProfilesFileLock` across the WHOLE pass — snapshot, `identities/` enumeration, AND deletion — and MUST NOT be refactored to release-after-snapshot. Because this pass deletes in the LIVE-MINT `identities/` namespace, holding the lock serializes against a concurrent `csq login` mint (which writes its mapping FIRST under the same lock then creates the dir), closing the TOCTOU where a stale snapshot + a freshly-minted dir race to a wrongful delete. NOT sentinel-gated (the orphan is born by a future logout). New `ReconcileSummary::orphan_identity_gc` field.

**Accounts prune to the empty-map target.** Every production _writer_ of `accounts[N]` emits `accounts: {}`, but nothing brought an already-**populated** map (from a host that ran an older build) to that target. Consequence: `csq doctor`'s `detect_v1_accounts_field` fires on `accounts.len() > 0`, so the deprecation gate could never clear on any upgraded host, and the terminal field deletion was structurally unreachable. `prune_redundant_accounts_entries` (an idempotent reconciler pass, `csq-core/src/accounts/profiles.rs`, wired into `startup_reconciler::run_reconciler` after `pass_rn1_d5_label_relocation` so genuine renames are already in `by_slot_label`) removes every `accounts[N]` whose deletion is **information-preserving** — i.e. leaves `get_email(N)` unchanged. Removal predicate (ANY of): (1) `accounts[N].email` empty; (2) `by_slot_label[N]` present (a relocated/captured rename — `get_email` step 1 wins); (3) `by_email` reverse-lookup equals `accounts[N].email` (mirrors `get_email` step 3 verbatim — the credential file would silently never fire because daemon-refreshed hosts don't have `oauthAccount.emailAddress`); OR (4) `by_slot_identity[N]` equals `accounts[N].email` (the identity channel mirrors what `get_email` step 2 would return after this entry is removed — closes the gap for non-OAuth slots whose `by_slot[N]` is absent). Otherwise the entry is a genuine rename with NO recovery channel (`UnrecoverableNoBySlot`) and is **kept** (the gate correctly holds open — there is real un-relocated data). The pass is NOT sentinel-gated (pure function of disk state; second run is a no-op) so a host that later resolves an unrecoverable entry via `csq login N` gets it pruned on the next daemon start. Non-fatal: lock contention / load error logs `error_kind ∈ {profiles_lock_contention, accounts_prune_failed}` and the daemon continues.

**Production writer audit (`accounts` field):**

The audit primitive for the deprecation is:

```bash
grep -rn 'profiles\.accounts\.insert\|accounts\.insert' csq-core/src csq/src --include='*.rs' | grep -v '#\[cfg(test)\]'
```

Every production hit MUST be one of: (a) the downgrade compat seam in `accounts/move_slot.rs::move_profiles_entry` (the `Some(entry) => { ... file.accounts.insert(to_key, entry); }` relocation), OR (b) inside a `#[cfg(test)]` block. The user-rename path (`update_email`) now writes `by_slot_label` (via `set_slot_label`) and MUST NOT appear in this audit.

**Cross-reference:** `specs/04-csq-daemon-architecture.md` §4.2.9 describes the Pass 0 algorithm, sentinel state machine, and reconciler scope in detail.

## 2.3 Directory-level operations

### 2.3.1 Account provisioning: `csq login N`

1. Create `config-<N>/` if it doesn't exist. Populate with symlinks via `session::isolate_config_dir`.
2. Run OAuth flow (CC's `claude auth login` delegated inside the config dir — see spec 03).
3. On success, capture tokens from `config-<N>/.credentials.json`.
4. Update `profiles.json` with account label.
5. Run `identity_mint::mint_for_login` to seed `profiles.json::by_slot[N] = <UUID>` and `identities/<UUID>/identity.json`, and write the canonical `identities/<UUID>/credentials.json`.
6. Write `.csq-account` marker. **Marker content semantic:** the marker content is the slot's identity UUID via `markers::write_csq_account(config_dir, uuid)` when `profiles::resolve_slot_to_uuid(base, N)` returns `Some(uuid)` (the post-mint normal case); pure-legacy installs where mint failed or was skipped fall back to `markers::write_csq_account_legacy(config_dir, account)` which writes the decimal slot id. The filename `.csq-account` is invariant (content flips only). The reader (`markers::read_identity_marker`) accepts both formats; the accessor `markers::read_csq_account_uuid` returns the UUID directly when the file carries UUID content.
7. Signal daemon to start refresh + usage polling for account N.

### 2.3.2 Terminal launch: `csq run N`

1. Verify `config-<N>` exists and has valid credentials.
2. Create `term-<my-pid>/` atomically. Populate with:
   - Symlinks for `.credentials.json`, `.csq-account`, `.claude.json` → `../config-<N>/<same>` (the `.credentials.json` symlink resolves through to the identity-keyed canonical).
   - Materialize `settings.json` by deep-merging `~/.claude/settings.json` (user global) with the account overlay.
   - Symlinks for all shared items via `isolate_config_dir`.
   - Write `.live-pid` containing the csq CLI PID (which becomes the claude PID on exec).
3. Set `CLAUDE_CONFIG_DIR=<absolute path to term-<my-pid>>` in the child env.
4. Strip sensitive env vars (`ANTHROPIC_*`, etc.).
5. `exec claude` (Unix) or `spawn claude` + wait (Windows).
6. On any exec failure, csq removes `term-<my-pid>` before exiting.

### 2.3.3 Account switch: `csq swap M`

1. Resolve `CLAUDE_CONFIG_DIR` from env; verify it's a `term-<pid>` dir under the csq base. If not (legacy `config-N` launch, unset env, or non-csq-managed dir), refuse with an error that explains the cause. **Never rewrite a `config-<N>` dir on swap.**
2. Validate account M exists at `config-<M>/`. Refuse if not.
3. Validate M's credentials are not in `LOGIN-NEEDED` state. Refuse if so (with suggestion to run `csq login M`).
4. For each of `.credentials.json`, `.csq-account`, `.claude.json`:
   - Construct the target `../config-<M>/<same-filename>`.
   - `std::os::unix::fs::symlink(target, tmp_path)` to create a new symlink at a temp path inside the handle dir.
   - `std::fs::rename(tmp_path, final_path)` to atomically replace the existing symlink.
5. Re-materialize `settings.json` by deep-merging `~/.claude/settings.json` (user global) with the new account's slot overlay and writing the result to `term-<pid>/settings.json`.
   - **Overlay source priority:** `materialize_handle_settings` MUST consult the UUID-keyed path FIRST and fall back to the legacy path only when the UUID source is absent:
     1. `identities/<UUID>/settings.json` — preferred when `profiles.json::by_slot["M"]` resolves to a UUID AND the file exists. Written by `finalize_login` (pair-write), `mint_for_login` (idempotent seed), and daemon Pass 0 catch-up.
     2. `config-<M>/settings.json` — legacy fallback used when no UUID mapping exists (pure-legacy installs that have not yet reached daemon Pass 0) OR when the UUID file is absent on disk (cold-start race window before Pass 0 completes).
   - Every login path that writes `config-<N>/settings.json` ALSO writes `identities/<UUID>/settings.json` with identical bytes via `credentials::save_uuid_settings` (the settings write chokepoint; parity with `save_uuid_credentials` and `save_codex_canonical_for_uuid`).
6. Notify daemon to invalidate caches.
7. Print confirmation: `"Swapped to account M — token valid Xm"`.

**Swap is advisory only.** The CC process in the same terminal picks up the change on its next API call via spec 01 section 1.4. No inter-process signal is needed or possible. Swap latency from the user's perspective is "next API call," which is typically the user's next keystroke plus CC's normal startup.

**Settings write chokepoint:** `credentials::save_uuid_settings(base, uuid, &bytes)` in `csq-core/src/credentials/file.rs` is the canonical settings writer for the UUID-keyed path. Closure-injected via `save_uuid_settings_inner<W, S, R>` for partial-failure-cleanup testing (write_fn, secure_fn, replace_fn injectable). The legacy alias `write_uuid_settings` is preserved for daemon Pass 0 callsites.

### 2.3.4 Terminal exit: `csq exit` or `claude` process termination

Two paths:

**Path A (user runs `csq exit` or csq-run wrapper catches the exit):**

- csq removes `term-<its-pid>/` directory.
- Returns cleanly.

**Path B (claude process dies without csq involvement — kill, crash, etc.):**

- Handle dir remains on disk.
- Daemon sweep (see section 2.5) detects it on its next tick and removes it.

## 2.4 What `csq swap` MUST refuse

- Target account does not exist (`config-<M>` missing): error `account M not provisioned — run csq login M`.
- Target account in LOGIN-NEEDED state: error `account M needs re-login — run csq login M`.
- Current `CLAUDE_CONFIG_DIR` is not a `term-<pid>` dir (legacy launch, env unset, non-csq dir): error `csq swap is only available inside a csq-managed terminal — relaunch with csq run N`.
- Current `CLAUDE_CONFIG_DIR` points into a `config-<N>` dir (legacy mode): error `this terminal was launched in legacy per-account mode; swap would affect all terminals on config-<N>. Relaunch with csq run N to use per-terminal swap.` (See section 2.6 for the migration story.)
- `.live-pid` in the handle dir does not match the current process's parent PID (suggests inheriting a handle dir from a dead parent): error `stale handle dir detected, current PID does not match owner — re-run csq run`.

## 2.5 Handle dir sweep

The daemon periodically (every N seconds, configurable; default 30) scans `accounts/term-*/` and, for each:

1. Read `.live-pid`.
2. If the PID does not exist (Unix: `kill(pid, 0)` returns ESRCH; Windows: `OpenProcess` returns null), remove the handle dir.
3. Log the sweep outcome at DEBUG level.

This sweep handles the case where `claude` crashed or was killed without csq cleaning up. It MUST be idempotent (safe to run concurrently with `csq run` creating new handle dirs). It MUST NOT remove a handle dir whose PID is alive under any circumstance, even if the symlinks are stale or broken — a live process owns its dir.

## 2.6 Legacy mode retirement (final state)

The legacy `CLAUDE_CONFIG_DIR=config-<N>` swap mode is **fully retired**. The pre-handle-dir behavior — `csq swap` rewriting `config-N/.credentials.json` in place to forcibly move every terminal bound to that config dir — no longer exists in any code path.

### Final-state contract

- **No legacy launches.** `csq run` always creates `term-<pid>` handle dirs. There is no code path that produces a terminal whose `CLAUDE_CONFIG_DIR` points at a `config-<N>` dir.
- **Legacy swap refusal is the only path.** `csq swap M` invoked with `CLAUDE_CONFIG_DIR` pointing at a `config-<N>` dir (a terminal launched by a pre-handle-dir csq binary that the user has not yet relaunched) refuses with: `this terminal was launched in legacy per-account mode; swap would affect all terminals on config-<N>. Relaunch with csq run M to use per-terminal swap.` The refusal threads the user-typed target slot `M` into the suggested `csq run` command so the hint is copy-pasteable. This refusal is wired in `csq/src/cli/commands/swap.rs::detect_source_handle`.
- **No `rotation::swap_to` writer.** The `csq-core/src/rotation/swap.rs` module is **deleted**. The pre-retirement fallback that wrote credentials into `config-N/.credentials.json` during a legacy-mode swap is gone — there is no code site that can resurface it.
- **`config-<N>` dirs are read-only for csq-swap.** The only writers of `config-<N>/.credentials.json` in the final state are CC itself (subprocess) and the user (manual edits). The daemon refresher writes `identities/<UUID>/credentials.json` (the Anthropic write chokepoint); csq swap repoints handle-dir symlinks; broker fanout / pullsync / sibling-recovery / `copy_credentials_for_session` were all retired. See spec INV-01.

### What pre-handle-dir users see

Users whose terminals predate the handle-dir model keep working — CC continues to read `config-<N>/.credentials.json` directly because their `CLAUDE_CONFIG_DIR` env var points there. Any `csq swap` invocation inside such a terminal returns the refusal message above; the only forward path is to exit that terminal and relaunch with `csq run N`.

### Existing `term-*` dirs on upgrade

Any `term-*` dirs found on upgrade are handled by the daemon sweep as orphans (see § 2.5).

### Desktop dashboard swap

There is none. Swap is a per-terminal action — it repoints one `term-<pid>` handle dir — and the desktop has no handle on a terminal, so a dashboard or tray click cannot name an unambiguous swap target. The desktop swap affordance was removed entirely (the `swap_account` / `swap_session` Tauri commands and the tray `acct:<id>` click arm) because an affordance whose only possible outcome was a `DESKTOP_SWAP_UNAVAILABLE` refusal read as a bug. Desktop account cards, session rows, and tray account rows are status and management surfaces (rename, renumber, remove, re-auth, change model); the only swap entry point is `csq swap N` inside the terminal that should switch.

## 2.7 Handle-dir-native auto-rotator

### What the rotator does

1. Loads `rotation.json` on each tick (live reload; changes take effect within one tick interval).
2. If `enabled: false`, returns immediately.
3. Walks `accounts/term-*/` handle dirs (NOT `config-*/` dirs).
4. For each `term-<pid>/`:
   - Reads `.csq-account` via the handle dir's symlink. The symlink resolves through `term-<pid>/.csq-account → config-<current>/.csq-account`, returning the current account number.
   - Checks per-handle-dir cooldown (keyed on the `term-<pid>/` path, not the account number). One cooldown per terminal, independent across sessions.
   - Loads quota for the current account. If `five_hour_pct >= threshold_percent`, looks for a lower-usage target account.
   - Calls `handle_dir::repoint_handle_dir(base_dir, claude_home, &handle_dir, target)`. This atomically repoints the handle dir's symlinks (`.credentials.json`, `.csq-account`, `.claude.json`, `.quota-cursor`) to point at `config-<target>/` and re-materializes `settings.json`.
5. Logs rotated/skipped counts.

### Invariant preservation

- **INV-01 preserved**: `config-<N>/.credentials.json` is NEVER written by the rotator. The rotator only rewrites symlinks inside `term-<pid>/`. The permanent account credentials stay exactly where they are.
- **INV-04**: Repoint is atomic via rename-over (new symlink at a `.swap-tmp` path, then `std::fs::rename` over the existing symlink). CC sees either the pre-swap or post-swap file; never a half-written state.

### Cooldown semantics

The cooldown map is keyed on the `term-<pid>/` handle dir path. Two terminals bound to the same account each have their own independent cooldown entry. This allows them to rotate at different times and diverge to different accounts after cooldown expiry.

### Surface filter

`same_surface_as_active(_: AccountNum) -> bool` gates candidate selection in `find_target`, ensuring the rotator only rotates a terminal among accounts of the same provider surface (per spec 07's surface model).

### claude_home requirement

`repoint_handle_dir` calls `materialize_handle_settings(handle_dir, claude_home, new_config)` to deep-merge `~/.claude/settings.json` (user global) with `config-<target>/settings.json` (slot overlay). If `claude_home` is unresolvable (missing `$HOME` in a sandboxed environment), `spawn` logs a single WARN at startup and every `tick` call returns immediately (no-op). Fail-safe is "don't rotate" rather than "rotate with an empty settings base that would overwrite user customization".

## 2.8 Cross-references and retractions

The slot/account distinction is IRRELEVANT for the swap path. Handle dirs carry the `.csq-account` marker (via symlink) which is always correct because the symlink points to the real canonical marker. Slot number confusion cannot arise when there are no slots — only permanent account dirs and ephemeral handle dirs.

Subscription contamination cannot arise on swap: csq swap no longer writes credentials at all, so it cannot contaminate. Fanout no longer exists as a separate concern — writing the identity file once IS the fanout, because all handle dirs see it through symlinks.

There is no stale-session-detection mechanism. CC re-stats `.credentials.json` before every API call (spec 01 section 1.4), so a swap is in-flight by design — there is no `needs_restart` field, no grace period, and no restart badge.

Auto-rotation is per-terminal: each terminal may end up on a different account. This is a first-class feature of the handle-dir model, not a limitation.

## 2.9 What this spec does NOT cover

- The CLI surface of `csq swap` and `csq run` (flags, exit codes, output format). See spec 03.
- Daemon internals (refresh cadence, lock file management, subsystem lifecycle). See spec 04.
- Third-party providers (Z.AI, MiniMax) — they have their own per-slot `settings.json` files outside the OAuth flow. See spec 05.
- Per-surface on-disk layouts for providers that run a non-Claude-Code native CLI (Codex via `CODEX_HOME`, Gemini via `GEMINI_CLI_HOME`). See spec 07. Per-surface persistence carve-outs from INV-02 live there as INV-P04 and do not alter the base invariant for the `Surface::ClaudeCode` case.
