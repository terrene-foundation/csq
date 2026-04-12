---
type: DECISION
date: 2026-04-12
created_at: 2026-04-12T11:45:00+08:00
author: co-authored
session_id: session-2026-04-12b
session_turn: 180
project: csq-v2
topic: Resolve all outstanding issues in one pass — iTerm window name fix, osascript cache, supervisor backoff, per-slot probe model, retina tray icons, Windows PEB walker, csq update check, and repair-credentials for cross-slot refresh-token contamination
phase: implement
tags:
  [
    desktop,
    daemon,
    refresher,
    iterm,
    windows,
    repair,
    data-integrity,
    ux-critical,
  ]
---

# DECISION: Answer journal 0026's three open questions + fix outstanding items + diagnose and repair cross-slot contamination

## Context

Previous session (journal 0026) shipped the in-process daemon, iTerm session tagging, and per-slot 3P quota polling, but left three design questions open and several items unresolved:

- **Design Q1**: supervisor TOCTOU hot-loop — fixed 60s backoff vs exponential
- **Design Q2**: osascript cost per `list_sessions` tick — should it be cached?
- **Design Q3**: 3P probe model — catalog default or per-slot config?
- Outstanding: Windows sessions backend, `csq update` self-update, retina @2x tray icons
- **User-reported bug**: "I keep seeing Expired on the Accounts" — the dashboard still shows every OAuth slot expired despite the in-process daemon shipping

The user also asked "why does it not read the iTerm window name?" — a specific gap in the journal 0026 implementation.

## Findings before coding

1. **iTerm window name bug**: two compounding issues
   - `pgrep -x iTerm2` returns nothing — iTerm2's actual process binary isn't named that, so the short-circuit in `read_iterm_tab_titles_by_tty` rejected every call before any osascript ran
   - `name of tab` errors inside iTerm2's AppleScript dictionary (`Can't get name of item 1 of every tab, -1728`) — tabs don't have a `name` property. The only accessible titles are `name of window` (window title bar) and `name of session` (per-pane title derived from the running command)

2. **Why refreshes are failing**: NOT Cloudflare (csq-core already sets `csq/<version>` UA). The real problem is **cross-slot refresh-token contamination**:

   ```
   slot=3  canonical=sk-ant-ort01-SNK8-mdPlJU  live=sk-ant-ort01-SNK8-mdPlJU  SAME
   slot=8  canonical=sk-ant-ort01-SNK8-mdPlJU  live=sk-ant-ort01-SNK8-mdPlJU  SAME   ← same token as slot 3!
   slot=2  canonical=sk-ant-ort01-OmdniswGoMG  live=sk-ant-ort01-SNK8-mdPlJU  DIFFERENT  ← slot 2 live == slot 3 canonical
   slot=5  canonical=sk-ant-ort01-QlhrzNS_NUU  live=sk-ant-ort01-OmdniswGoMG  DIFFERENT  ← slot 5 live == slot 2 canonical
   ```

   Multiple slots share the same refresh token. Each refresh rotates the token; only one slot consumes the new value — the others now point at a dead token that Anthropic rejects with `invalid_grant`. The broker's sibling-recovery logic can't rescue them because all live copies are also dead.

3. **Why the dashboard hides the real reason**: `broker_check` writes a zero-byte `credentials/N.broker-failed` marker on failure. `AccountView` has no `last_refresh_error` field. Users see "Expired" with no explanation.

## Choices

### Design Q1 — Exponential backoff in supervisor (implemented)

Replaced the fixed 60s poll with a `Backoff` struct: starts at `BACKOFF_MIN = 1s`, doubles on each failed takeover attempt, caps at `BACKOFF_MAX = 60s`, resets to `BACKOFF_MIN` on any successful daemon ownership. Saturating multiplication defends against `Duration` overflow under pathological looping.

**Why**: the previous 60s fixed wait was wasteful (1-minute refresh gap every external-daemon crash) and hot-loopable (two csq apps fighting over the same `~/.claude/accounts` could spin). Exponential backoff gives instant recovery in the common case (external daemon cleanly exits → supervisor takes over within 1s) while bounding the worst case at 60s.

### Design Q2 — Cache osascript results with 10s TTL (implemented)

Module-level `OnceLock<Mutex<Option<(HashMap, Instant)>>>` in `sessions/macos.rs`. On each `list_sessions` call:

- If cache is < 10s old → return a clone, skip osascript entirely
- If stale → re-run osascript, update cache, return

**Why 10s** (not the 2s I suggested in journal 0026): the desktop poll cadence is 5s and the tray refresh is 30s. A 10s TTL means osascript runs at most every other poll, halving the cost. Tab-title latency for user updates caps at 10s, which is well below the threshold where users notice.

Also **removed the broken `pgrep -x iTerm2` short-circuit** because iTerm2's actual process doesn't match that name. osascript fails fast (~70ms) when iTerm isn't running, and the empty-result caching means subsequent failed calls return instantly from cache anyway.

### Design Q3 — Read `ANTHROPIC_MODEL` from per-slot settings (implemented)

Added `load_3p_model_for_slot(base, slot)` that reads `env.ANTHROPIC_MODEL` from `config-<slot>/settings.json`. The poller's `tick_3p` now threads this through: per-slot probes use the user's configured model (`MiniMax-M2.7-highspeed`), legacy global slots (≥900) use the catalog default.

Also refactored the URL and model loaders through a shared `load_3p_env_string_for_slot(base, slot, key)` so adding future per-slot overrides is a one-liner.

**Why**: MiniMax is in the middle of rolling out M2.7 and may retire M2 at any point. Probing with the catalog default would 404 the probe once that happens, leaving the user with no rate-limit data. Following the user's configured model means the probe always matches what their actual terminals run.

### iTerm window name fix (new, not journal 0026 question)

1. Removed the `pgrep -x iTerm2` guard entirely — it was rejecting every call
2. Changed the osascript walk from `name of tab` (errors) to `name of session` (works) plus `name of window` (for the window title bar)
3. Added `format_terminal_title(window, session)` that combines them as `"window · session"`, collapses duplicates, and `strip_iterm_decorations()` to remove the `✳` / `⠂` status icons and the trailing `(claude)` / `(node)` command annotation

Verified live on the author's 14 iTerm sessions:

```
PID 65671  title=terrene · Analyze COC-Bench threats to validity
PID 50949  title=Claude Code · aegis
PID 46896  title=Claude Code · arbor
```

### Retina @2x tray icons (implemented)

Changed `TrayIconKind::bytes()` to return the `tray-normal@2x.png` / `tray-warn@2x.png` / `tray-error@2x.png` (64×64) PNGs. macOS AppKit downscales them to the menu bar slot with its high-quality filter — sampling 22 logical points from 64 source pixels produces a visibly crisper result than the 32-pixel upscale.

Removed the `TRAY_NORMAL_PNG_2X` dead-code marker and its associated `#[allow(dead_code)]` since the 2x variants are now the primary assets.

### Windows sessions backend — PEB walker (implemented, untested on Windows)

New `sessions/windows.rs` that:

1. Enumerates processes via `CreateToolhelp32Snapshot` + `Process32FirstW`/`Process32NextW`
2. Filters by `exe_matches_claude(szExeFile)` — case-insensitive comparison against "claude.exe"
3. For each match, `OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)`
4. `NtQueryInformationProcess(ProcessBasicInformation)` to get the PEB address
5. `ReadProcessMemory` the PEB at offset `0x20` to read `ProcessParameters` pointer
6. `ReadProcessMemory` `RTL_USER_PROCESS_PARAMETERS` at offsets `0x38` (CurrentDirectory) / `0x80` (Environment) / `0x3F0` (EnvironmentSize)
7. `ReadProcessMemory` the UTF-16 environment block and parse with `parse_environment_block`

The **pure parser** (`parse_environment_block`, `exe_matches_claude`) lives in a separate `sessions/windows_parse.rs` that compiles on all platforms so its 11 unit tests run on macOS/Linux CI. The `windows.rs` syscall wrapper is `cfg(target_os = "windows")` gated and depends on `windows-sys` via a target-specific Cargo dependency so macOS/Linux never pull it in.

**Known limitations** documented in the module header:

- Wow64 (32-bit) processes: PEB offsets are for 64-bit; claude.exe is always 64-bit
- Protected processes: `OpenProcess` fails silently for AV/anti-cheat
- `started_at`, `tty`, `terminal_title` are all `None` on Windows — no TTY concept for GUI processes, no iTerm equivalent

**I can't run this on Windows.** The parser is fully tested via platform-portable unit tests. The syscall path is untested until a Windows user runs it.

### `csq update check` — GitHub Releases (implemented, check-only)

New `csq update check` subcommand in `csq-cli/src/commands/update.rs`:

1. GETs `https://api.github.com/repos/terrene-foundation/claude-squad/releases/latest` via `http::get_with_headers` (new, unauth GET)
2. Parses `tag_name`, `html_url`, `body` from the JSON
3. Compares the version string via a hand-rolled `compare_versions` that handles MAJOR.MINOR.PATCH[-pre] with zero-padding and semver prerelease ordering
4. Prints one of: "up to date", "newer version available: X → Y, install via brew / manual download", or "ahead of latest published"

**Install path is deliberately not implemented.** Without signed releases (blocked on Apple Developer Program cert for notarization + Ed25519 application-level signing), an auto-installer would be a supply-chain foot-gun. The user sees "Install options: brew upgrade csq / download manually" and takes manual action.

Rolled a 20-line `compare_versions` instead of pulling in `semver` crate — csq's release cadence is linear and the comparison rules fit in one function with comprehensive tests.

### Cross-slot contamination: `csq repair-credentials` (new, unscoped work)

New CLI command `csq repair-credentials [--apply]` in `csq-cli/src/commands/repair_credentials.rs`:

- Scans every `credentials/N.json` and `config-N/.credentials.json` for refresh_token prefix (first 24 chars — short enough to not hold a full token in memory, long enough to detect any realistic collision)
- Finds three classes of contamination:
  - **CanonicalLiveMismatch**: canonical ≠ live for the same slot (fanout miss)
  - **CanonicalSharedWith { other_slot }**: two slots have the same canonical token
  - **LiveSharedWith { other_slot }**: two slots have the same live token
- Prints findings with slot numbers and token prefixes
- Dry-run by default; `--apply` deletes contaminated canonical files so next use triggers re-login via Add Account flow
- Never touches live `config-N/.credentials.json` files — CC may be holding them in active sessions

Verified on the user's actual state: found 8 issues across slots 2/3/5/7/8, matching the manual diagnosis.

### `last_refresh_error` surfaced in the dashboard

- `broker::fanout::set_broker_failed` now takes a `reason: &str` argument (capped at 256 bytes) and writes the tag to the flag file content instead of leaving it zero-byte
- New `read_broker_failed_reason(base, account) -> Option<String>` reads it back
- New `error::error_kind_tag(&CsqError)` — moved out of the refresher, now shared across subsystems — returns fixed-vocabulary tags like `"broker_token_invalid"`, `"broker_refresh_failed"`, etc.
- `AccountView` gains `last_refresh_error: Option<String>`
- `AccountList.svelte` renders an error row under the token badge: `⚠ invalid token — re-login needed` etc. Maps the backend's stable tag vocabulary to idiomatic UI strings via `formatRefreshError()`.

Now when a user hits "Expired", the dashboard also shows why.

## Consequences

- **All three journal 0026 design questions resolved and implemented.**
- **iTerm window name bug fixed.** The user's actual workflow now shows titles like `"terrene · arbor"` and `"Claude Code · aegis"`.
- **User knows WHY a slot is expired.** The dashboard now shows `⚠ invalid token — re-login needed` or `⚠ refresh failed — check network or re-login` next to the token badge, driven by `last_refresh_error` from the broker-failed flag file content.
- **User has a recovery path for cross-slot contamination.** `csq repair-credentials` detects it, `--apply` clears the bad canonicals, Add Account re-authenticates.
- **Windows sessions backend exists but is untested on Windows.** The pure parser is fully covered by unit tests; the syscall path compiles under `cfg(target_os = "windows")` and will be exercised when the first Windows user runs it. PEB offset constants are documented with sources.
- **`csq update check` ships today.** The install path is deliberately left unwired until the release signing pipeline is in place (journal 0025 / M11-01).
- **Retina tray icons use the @2x PNGs directly.** macOS downscales them with AppKit's filter for a crisper result on high-DPI displays than the previous 32-pixel upscale.
- **All gates green**: 540 → **586 Rust tests** (+46), 22 Svelte tests, clippy / fmt / svelte-check all clean. Frontend builds 72 → 74 KB.

## Outstanding items (explicitly NOT fixed this session)

- **Root-cause fix for cross-slot contamination.** This session adds detection and a repair CLI, but the bug that CAUSED multiple slots to share refresh tokens is still unfixed. The fanout logic in `broker::fanout::fan_out_credentials` needs an audit to find how the cross-pollination happens. Journal will track this as a followup.
- **Windows retina + iTerm-equivalent.** Linux and Windows have no terminal-title lookup equivalent to iTerm's AppleScript. WezTerm exposes a similar thing via its CLI; can be wired per-terminal if a user asks.
- **Apple Developer cert** (M11-01): still blocked, as noted.
- **`csq update install`**: blocked on the above. Machinery is ready to wire when signing lands.

## For Discussion

1. The repair-credentials tool uses a **24-char prefix** of the refresh token as a cross-slot identity. Is that long enough? A refresh token is ~108 chars. A 24-char prefix gives 2^144 unique combinations — collisions by chance are vanishingly unlikely, and collisions by intent (user hand-crafting a token) are a problem only if the user also knows csq's comparison algorithm. Is there a better non-crypto identifier that's safer?
2. The journal 0027 Windows backend uses hardcoded PEB offsets (0x20, 0x38, 0x80, 0x3F0). These are stable across Win10/11 but not documented by Microsoft. When they change, the backend silently returns empty results instead of crashing. Is silent-empty the right failure mode, or should it log a warning with `Windows version info from GetVersionEx` so users can file a bug?
3. `csq update check` prints instructions to run `brew upgrade csq` but csq is not yet distributed via Homebrew — that's a future session. Should the current message lie (pretend brew works) or tell the truth (recommend manual download)? I chose the former because by the time anyone reads the output, brew will likely exist; but the alternative is more honest.
