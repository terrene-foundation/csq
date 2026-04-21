# csq v2.0.0 Stable — Release Gate Checklist

**Source brief:** `workspaces/csq-v2/briefs/03-v2-stable-readiness.md`
**Decision journal:** `workspaces/csq-v2/journal/0062-DECISION-v2-stable-definition-and-gate-checklist.md`
**Current state:** v2.0.0-alpha.21 tagged; workspace `Cargo.toml` still reads `2.0.0-alpha.21`; `tauri.conf.json` reads `2.0.0-alpha.21`.
**Mode:** Autonomous execution. Effort framed in sessions, not human-days.

A release captain reading this document must be able to execute every gate mechanically — no judgment calls, no interpretation. Each gate has a command and a pass criterion. If a gate lacks one, it's a bug in the checklist, not an acceptable vagueness.

---

## 1. Definition of Stable

csq v2.0.0 is "stable" when ALL of the following are simultaneously true. Every item is verifiable by a script, a command, or a documented manual procedure with a specific output.

| #   | Property                                                                                                         | Verifiable how                                                                                                                                                                                                                     |
| --- | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------- |
| D1  | Workspace version reads `2.0.0` (no pre-release suffix) in `Cargo.toml`, `tauri.conf.json`, and `csq --version`. | `grep -E '^version\s*=\s*"2.0.0"' Cargo.toml`; `grep '"version": "2.0.0"' csq-desktop/src-tauri/tauri.conf.json`; `csq --version` prints `csq 2.0.0`.                                                                              |
| D2  | All workspace tests pass on all three platforms.                                                                 | `cargo test --workspace` green on macOS-arm64, Linux-x86_64, Windows-x86_64 in CI.                                                                                                                                                 |
| D3  | Zero clippy warnings, zero fmt drift.                                                                            | `cargo clippy --workspace --all-targets -- -D warnings` exits 0; `cargo fmt --all -- --check` exits 0.                                                                                                                             |
| D4  | Svelte tests and type-check green.                                                                               | `npx vitest run` in `csq-desktop` exits 0; `npx svelte-check` exits 0.                                                                                                                                                             |
| D5  | Release workflow green on a `v2.0.0` tag push.                                                                   | GitHub Actions `Release` run for `v2.0.0` shows all jobs green; assets uploaded.                                                                                                                                                   |
| D6  | Golden-path install-to-swap works on a fresh-profile macOS Sonoma or Sequoia machine.                            | Smoke test procedure (§3, Journey 1) completes end-to-end; quota visible after login, account swaps, daemon restarts cleanly.                                                                                                      |
| D7  | No open red-team findings above LOW severity.                                                                    | `grep -rE 'severity:\s\*(CRITICAL                                                                                                                                                                                                  | HIGH | MEDIUM)' workspaces/csq-v2/journal/_RISK_.md` returns only entries marked "resolved" or "retracted". |
| D8  | Specs match code for all INV-01…INV-07 invariants.                                                               | `workspaces/csq-v2/journal/` shows no DISCOVERY or RISK entries from the last 30 days that contradict specs without a corresponding spec update commit. Spec 05 §5.3 and §5.4 (MiniMax GroupId / Z.AI) are no longer marked stale. |
| D9  | Documented limitations are honest — users read the release notes and meet the documented behavior.               | Release notes §"Known limitations" contains verbatim text from this checklist's §4 (Out-of-Scope); each limitation has a linked GitHub issue or spec reference.                                                                    |
| D10 | Auto-update from alpha.21 → 2.0.0 shows the upgrade banner.                                                      | Install alpha.21, bump the local `version.rs` to a test pre-release, run `csq update check` against `latest.json` → banner text appears. (Install step of updater is NOT required to succeed end-to-end — see §4.)                 |
| D11 | Every `#[tauri::command]` returns `Result<_, String>` or `Result<_, TypedError>`; no command panics into IPC.    | Grep audit: no `.unwrap()` or `.expect()` in `csq-desktop/src-tauri/src/commands/`. CI step verifies.                                                                                                                              |
| D12 | Credential writes preserve `subscription_type` and `rate_limit_tier` everywhere they occur.                      | All call sites of atomic credential write are covered by unit tests that assert field preservation. `grep -rn 'atomic_replace' csq-core/src/credentials/ csq-core/src/daemon/` against the fixture test.                           |

---

## 2. Release Gate Checklist

Every gate MUST be green before cutting `v2.0.0`. Gates are grouped; within a group they are independent and can be verified in parallel.

### Group A — Code health (automated)

| Gate | Verifies                                                | Command                                                                                                                          | Owner | Pass criterion                                                      |
| ---- | ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ----- | ------------------------------------------------------------------- |
| A1   | Workspace version bumped to `2.0.0`                     | `cargo pkgid -p csq-core csq-cli csq-desktop \| awk -F'#' '{print $2}'`                                                          | agent | Every line prints `2.0.0` (no suffix).                              |
| A2   | `cargo test --workspace` green on macOS, Linux, Windows | CI `.github/workflows/test.yml` matrix job                                                                                       | CI    | All three `Rust tests (os)` jobs green on the stable-branch commit. |
| A3   | Clippy denied warnings                                  | `cargo clippy --workspace --all-targets -- -D warnings`                                                                          | CI    | Exit code 0; no warnings in log.                                    |
| A4   | Rustfmt clean                                           | `cargo fmt --all -- --check`                                                                                                     | CI    | Exit code 0.                                                        |
| A5   | Svelte vitest green                                     | `cd csq-desktop && npx vitest run`                                                                                               | CI    | Exit code 0; no failed tests.                                       |
| A6   | Svelte type-check green                                 | `cd csq-desktop && npx svelte-check --fail-on-warnings`                                                                          | CI    | Exit code 0.                                                        |
| A7   | No stub markers in production code                      | `grep -REn 'TODO\|FIXME\|XXX\|STUB\|unimplemented!\|todo!\(' csq-core/src csq-cli/src csq-desktop/src csq-desktop/src-tauri/src` | agent | Zero matches outside `#[cfg(test)]` blocks and doc comments.        |
| A8   | No panic paths in Tauri command handlers                | `grep -REn '\.unwrap\(\)\|\.expect\(' csq-desktop/src-tauri/src/commands/`                                                       | agent | Zero matches (or only inside `#[cfg(test)]`).                       |
| A9   | `.env` / `credentials/` are gitignored                  | `grep -E '^\.env$\|^credentials/\|^config-\*' .gitignore`                                                                        | agent | All three patterns present.                                         |

### Group B — Release signing and updater (automated + external dep)

| Gate | Verifies                                                                                                            | Command                                                                                                                                     | Owner             | Pass criterion                                                                                                                                              |
| ---- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B1   | Foundation Ed25519 release key is configured                                                                        | `gh secret list -R terrene-foundation/csq \| grep RELEASE_SIGNING_KEY`                                                                      | release captain   | Secret exists. If absent, release is BLOCKED — see §4 limitation L2.                                                                                        |
| B2   | Tauri updater signing key configured                                                                                | `gh secret list -R terrene-foundation/csq \| grep TAURI_SIGNING_PRIVATE_KEY`                                                                | release captain   | Both `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` present.                                                                          |
| B3   | `RELEASE_PUBLIC_KEY_BYTES` in `csq-core/src/update/verify.rs` matches the production key, not the placeholder seed. | Inspect `verify.rs:~60` — the constant must be loaded from the Foundation's generated key pair, not the documented deterministic test seed. | security-reviewer | Source comment does not say "placeholder test keypair". If it still says placeholder, `csq update install` is KNOWN-BROKEN; release notes must say so (L2). |
| B4   | Updater manifest reachable                                                                                          | `curl -fsSL https://github.com/terrene-foundation/csq/releases/download/updater-manifest/latest.json \| jq .version`                        | agent             | Returns `"2.0.0"` after the release workflow completes.                                                                                                     |
| B5   | macOS DMG opens on a fresh profile.                                                                                 | Manual smoke on a Sequoia/Sonoma machine: download DMG → right-click Open → drag to Applications → launch.                                  | release captain   | App launches. If Gatekeeper blocks with "damaged", re-signing step in `release.yml:167-215` is regressed — investigate.                                     |
| B6   | Linux AppImage launches on fresh Ubuntu 22.04 profile                                                               | Manual: `chmod +x csq-desktop-linux.AppImage && ./csq-desktop-linux.AppImage`                                                               | release captain   | Desktop window appears; no missing lib errors.                                                                                                              |
| B7   | Windows installer runs on fresh Win 11 profile                                                                      | Manual: double-click `csq-desktop-windows-setup.exe`, complete install.                                                                     | release captain   | Installer completes; app launches from Start menu. Defender SmartScreen warning is expected — documented in L3.                                             |

### Group C — Golden-path smoke (manual, per platform)

Each journey in §3 is its own gate — run all 5 on macOS. Run Journey 1 on Linux and Windows.

| Gate | Verifies                                 | Procedure    | Owner           | Pass criterion                                                                |
| ---- | ---------------------------------------- | ------------ | --------------- | ----------------------------------------------------------------------------- |
| C1   | J1 (First install) on macOS              | §3 Journey 1 | release captain | Every step matches expected output.                                           |
| C2   | J2 (Second account) on macOS             | §3 Journey 2 | release captain | Same.                                                                         |
| C3   | J3 (Swap in a running terminal) on macOS | §3 Journey 3 | release captain | Same.                                                                         |
| C4   | J4 (Quota refresh + tray) on macOS       | §3 Journey 4 | release captain | Same.                                                                         |
| C5   | J5 (Upgrade from alpha.21) on macOS      | §3 Journey 5 | release captain | Same.                                                                         |
| C6   | J1 on Linux (Ubuntu 22.04 fresh VM)      | §3 Journey 1 | release captain | Same.                                                                         |
| C7   | J1 on Windows 11 (fresh VM)              | §3 Journey 1 | release captain | Same. Named-pipe IPC confirmed functional OR regressed — document either way. |

### Group D — Documentation and governance

| Gate | Verifies                                                                                 | Command                                                                                 | Owner                    | Pass criterion                                                                                                                |
| ---- | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| D1-1 | Release notes draft exists at `docs/releases/v2.0.0.md`                                  | `ls docs/releases/v2.0.0.md`                                                            | agent                    | File exists; contains §"Known limitations" with verbatim text from §4 of this document.                                       |
| D1-2 | Specs §5.3 (MiniMax GroupId) and §5.4 (Z.AI) no longer stale                             | `grep -E 'STALE\|TODO\|OUTDATED' specs/05-quota-polling-contracts.md`                   | spec-author              | Zero matches in those sections.                                                                                               |
| D1-3 | All open red-team journal entries have a `status: resolved` line or a retraction journal | `grep -L 'status:\s*resolved\|status:\s*retracted' workspaces/csq-v2/journal/*RISK*.md` | security-reviewer        | All files with RISK in the name have one of the two markers (or have been superseded by a DECISION entry that resolved them). |
| D1-4 | `CHANGELOG.md` contains a v2.0.0 section listing user-visible changes since alpha.0      | `grep -n '## \[2\.0\.0\]' CHANGELOG.md`                                                 | agent                    | Section exists.                                                                                                               |
| D1-5 | README install instructions point at the v2.0.0 release, not alpha.                      | `grep -E 'v2\.0\.0-(alpha\|beta\|rc)' README.md`                                        | agent                    | Zero matches; README says `v2.0.0` in install URLs.                                                                           |
| D1-6 | License and authorship correct                                                           | `head -5 LICENSE; grep -E 'Terrene Foundation' README.md`                               | gold-standards-validator | Apache 2.0 + Terrene Foundation. No "Copyright Kailash" or other non-Foundation attribution.                                  |

### Group E — Security review (automated + agent)

| Gate | Verifies                                                             | Command                                                                                | Owner             | Pass criterion                                                                                                                  |
| ---- | -------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| E1   | No secrets in git history                                            | `gitleaks detect --no-banner` or equivalent                                            | security-reviewer | Exit 0 on the stable-branch commit.                                                                                             |
| E2   | `error::redact_tokens` covers every OAuth error format site          | `grep -REn '\{e\}\|\{body\}' csq-core/src/credentials/ csq-core/src/daemon/`           | security-reviewer | Every match is either inside `redact_tokens(...)` or inside `#[cfg(test)]`.                                                     |
| E3   | Daemon Unix socket has `0o600` and peer-credential check             | Inspect `csq-core/src/daemon/server.rs` — umask + chmod + SO_PEERCRED/LOCAL_PEERCRED   | security-reviewer | All three mechanisms present. Journal 0006 invariants hold.                                                                     |
| E4   | Daemon OAuth callback route is TCP; all token routes are Unix-socket | Inspect `csq-core/src/daemon/server.rs` route registration vs. TCP listener            | security-reviewer | TCP listener serves only `/oauth/callback`; every other credential-handling route is socket-only. Journal 0011 invariants hold. |
| E5   | Subscription-metadata preservation guard in daemon refresher         | Inspect `csq-core/src/daemon/refresher.rs` for the "preserve subscription_type" branch | security-reviewer | Branch present; unit test asserts preservation. Journal 0029 invariants hold.                                                   |

---

## 3. User Journeys That Must Work on Day 1

Each journey is the exact path a v2.0.0 user is likely to take. If any of these is broken on stable, we ship broken and lose trust.

### Journey 1 — First install and first account

**User goal:** I downloaded csq; I want to run `claude` under my Anthropic account.

**Steps (user-level):**

1. Download `csq-desktop-macos.dmg` from GitHub Releases.
2. Open DMG, drag app to Applications. (Right-click → Open on first launch — documented.)
3. App opens; menubar/tray icon appears.
4. Click "Add Account" in the app.
5. Browser opens Anthropic OAuth, user authorizes.
6. App shows account 1 with quota percentage populated within ~30s.
7. Open a terminal, run `csq run 1` (or `csq 1`), claude starts, works normally.

**Success criterion:** User sees quota > 0% in the app within 30s of OAuth completion; `claude` launches and responds to a test prompt under account 1.

**Failure mode if we ship broken:** User sees quota "—" forever (daemon poll broken), or `claude` launches without credentials (handle-dir materialization broken), or statusline is blank (journal 0059 regression). Any of these means "csq doesn't work out of the box."

**Existing test coverage:** Partial. Daemon usage poller + handle-dir creation have Rust unit tests. OAuth flow has integration test. No end-to-end fresh-profile smoke is in CI today — this is the gap filled by gate C1.

---

### Journey 2 — Adding a second account

**User goal:** I hit my quota; I want to register a second account and swap to it.

**Steps:**

1. In-app, click "Add Account" again.
2. OAuth flow for account 2.
3. Quota for both accounts displays.
4. `csq run 2` in a new terminal launches claude under account 2.

**Success criterion:** Both accounts show independent quotas; `csq status` lists both; no credential cross-contamination (account 1's refresh token still works after account 2 is added).

**Failure mode if broken:** Account 2's login corrupts account 1's credentials (historical bug, journal 0029). Or account 2 inherits account 1's `subscription_type = None` and silently downgrades the model tier (journal 0029 guard).

**Existing test coverage:** Green. Unit tests cover the preservation guard; journal 0029 documented the fix. But fresh-profile smoke against a real OAuth flow is manual.

---

### Journey 3 — Swap account in a running terminal

**User goal:** I'm in a `claude` session, quota is getting low, I want to swap to another account without restarting.

**Steps:**

1. In a running `claude` terminal (launched via `csq run 1`), user opens a second terminal.
2. In the second terminal: `csq swap 2`.
3. User returns to the first terminal and sends a new prompt to claude.
4. Claude's next API call uses account 2's credentials. No restart, no re-auth.

**Success criterion:** The next claude response in terminal 1 does not show a "LOGIN-NEEDED" or rate-limit error; quota for account 2 ticks up.

**Failure mode if broken:** `csq swap` fails with "locked", or claude continues on account 1 (mtime re-stat regression), or the swap corrupts the handle-dir symlinks. All three historically surfaced — handle-dir model (spec 02) was the structural fix.

**Existing test coverage:** Green at the invariant level (INV-04 atomic symlink repoint). Live integration test with a running `claude` is manual.

---

### Journey 4 — Quota stays fresh and tray reflects it

**User goal:** I leave csq running overnight; when I come back, quotas reflect reality and nothing hangs.

**Steps:**

1. Launch desktop app; leave it running 12+ hours.
2. Return: tray tooltip shows current quota; dashboard shows current quota.
3. No daemon crash; no "last updated X hours ago" stale badge.

**Success criterion:** Daemon uptime > 12h; quota poll last-success timestamp < 10 minutes old; no errors in `~/.claude/accounts/daemon.log` above WARN.

**Failure mode if broken:** Daemon dies silently (supervisor regression) or polling backoff gets stuck (journal 0014 backoff regression). User opens app, sees stale data, doesn't know whether to trust it.

**Existing test coverage:** Partial. Poll cadence + backoff have unit tests. Supervisor restart logic has integration test. Overnight-stability is not tested in CI — this is a manual smoke.

---

### Journey 5 — Upgrade from alpha.21 to 2.0.0

**User goal:** I have alpha.21; I click "Update" in the app or run `csq update install`.

**Steps:**

1. alpha.21 installed; user sees update banner in-app (recurring check per alpha.21).
2. User clicks update. OR runs `csq update install` from CLI.
3. Binary is replaced atomically; app relaunches on 2.0.0.

**Success criterion:** Post-upgrade, `csq --version` prints `2.0.0`; all existing accounts still work (credentials preserved); statusline still renders (journal 0059-0060 migration kicks in on first `csq install`).

**Failure mode if broken:** Upgrade fails signature verification (L2 blocker — placeholder Ed25519 key). Or upgrade succeeds but per-slot statusline drift blanks the statusline (journal 0059). Or credentials are rewritten without `subscription_type` (journal 0029 regression).

**Existing test coverage:** Green for alpha.21's recurring check (landed this session). Per-slot statusline migration has unit tests (install.rs tests). Full upgrader-install path is blocked by L2 until Foundation signs the release key.

---

## 4. Out-of-Scope Limitations

These are explicit non-claims for v2.0.0. Each has release-notes text and the manual path that DOES work.

### L1 — Apple notarization not present

**What doesn't work:** Double-clicking the DMG on macOS Sonoma+ triggers Gatekeeper "developer cannot be verified."

**Release-notes text (verbatim):**

> csq 2.0.0 is ad-hoc signed on macOS. On first launch, right-click the app and choose "Open" (then confirm) to bypass the "unidentified developer" warning. Subsequent launches require no bypass. Apple Developer ID signing and notarization are pending provision of the Foundation's developer certificate.

**Workaround that works:** Right-click → Open is tested by gate B5. CLI-only users (`curl | sh`) are unaffected.

### L2 — `csq update install` one-click upgrade has limited manual validation

**Status (updated 2026-04-22 per commit `499d131`):** The Foundation's Ed25519 release-signing key was provisioned in `3af4f3e` and is compiled into `csq-core/src/update/verify.rs` as `RELEASE_PUBLIC_KEY_BYTES` in non-test builds. `SHA256SUMS` + `.sig` artifacts are published on every release; the signing pipeline is live. Cryptographic verification is NOT the gap. The remaining unknown is whether the in-app update flow (download → verify → apply) survives a real cross-version upgrade (e.g. alpha.21 → 2.0.0) on a fresh profile. Journal 0065 B1 records the key-provisioning confirmation.

**What isn't yet validated:** end-to-end `csq update install` against a real cross-version release on a fresh install. The first cross-version validation opportunity is the 2.0.0 → 2.0.1 cycle.

**Release-notes text (verbatim, matches `docs/releases/v2.0.0.md` post-499d131):**

> In csq 2.0.0, the in-app "Update" button and `csq update check` CLI detect new releases and prompt you. The Foundation's Ed25519 release-signing key is provisioned and `SHA256SUMS` / `.sig` assets are published with every release, so in-app install should succeed end-to-end. However, `csq update install` has not been exercised against a real cross-version release (alpha.N → 2.0.0) on a fresh install. If the in-app installer reports a verification or write failure, fall back to downloading the new DMG / AppImage / MSI from GitHub Releases and reinstalling manually — credentials and config persist across reinstalls. File any failure under the `updater` label with the command output and platform.

**Workaround that works:** Download the new installer from `https://github.com/terrene-foundation/csq/releases` and reinstall. Credentials and config persist across reinstalls — nothing is lost.

### L3 — Windows SmartScreen warning on first install

**What doesn't work:** The Windows NSIS installer is not EV-code-signed, so SmartScreen shows "Windows protected your PC."

**Release-notes text (verbatim):**

> The Windows installer is not yet EV-code-signed. On first run, Windows SmartScreen will display a warning — click "More info" → "Run anyway" to proceed. EV code signing is pending provision of the Foundation's Windows signing certificate.

**Workaround that works:** "More info → Run anyway" completes the install. Once installed, the app is trusted by Windows for future launches.

### L4 — Windows end-to-end NOT smoke-tested on every release

**What doesn't work:** Named-pipe IPC and installer paths are implemented (not missing, as the brief suggested), with Rust tests covering the pipe server. But csq does not have a fresh-profile Windows 11 smoke test in CI; the Windows matrix confirms "tests pass and artifacts build," not "app works end-to-end after install."

**Release-notes text (verbatim):**

> csq 2.0.0 ships with Windows support that has been code-tested (Rust unit + integration tests green on the Windows CI matrix) but has had limited manual validation on fresh Windows 11 profiles. File issues with the "windows" label if you hit anything — the named-pipe daemon IPC, installer, and CLI paths are in production-use on Linux and macOS and should carry over; where they don't, the Windows matrix bug takes priority over the Linux/macOS parity bug.

**Workaround that works:** Gate C7 runs Journey 1 on a Windows VM before cutting the release. Any hit there becomes a blocker.

### L5 — System tray on Linux requires AppIndicator

**What doesn't work:** On GNOME Wayland without the AppIndicator extension installed, the csq tray icon may not appear.

**Release-notes text (verbatim):**

> On Linux, the tray icon relies on the AppIndicator protocol. On GNOME Wayland, install the "AppIndicator and KStatusNotifierItem Support" extension if the tray icon does not appear. KDE Plasma, Cinnamon, and X11 desktops work without additional setup.

**Workaround:** `csq status` and `csq statusline` in the terminal continue to work; the dashboard window is always available via `csq daemon` + direct URL.

---

## 5. Category and Positioning Sanity Check

**Category:** "Claude Code account juggling."

Today a Claude Code power user running multiple Anthropic accounts has three options:

1. **Manual `mv ~/.claude/settings.json`** — rename config files by hand; lose session state; constant re-auth.
2. **In-house bash scripts** — what csq v1.x itself evolved from; brittle, platform-specific, no quota view, no token refresh.
3. **csq** — single binary, tray UI, central refresh, in-flight swap, quota polling.

**Minimum bar a Claude Code power user expects from a 2.0 STABLE tool:**

| Expectation                                                         | csq 2.0.0                                                | bash-script / manual                               |
| ------------------------------------------------------------------- | -------------------------------------------------------- | -------------------------------------------------- |
| One install step, no Python/Node runtime needed                     | Yes (single Rust binary + DMG)                           | No (bash + `jq` + sometimes `security` quirks)     |
| Doesn't burn refresh tokens                                         | Yes (broker lock, journal 0029)                          | No (every parallel session races on refresh)       |
| Quota visible before I hit the wall                                 | Yes (Anthropic `/api/oauth/usage`)                       | No (requires clicking into claude.ai)              |
| Swap account without restart                                        | Yes (handle-dir model, INV-04)                           | No (terminal restart)                              |
| Preserve `subscription_type` so Max users don't fall back to Sonnet | Yes (guard, journal 0029)                                | No (silent downgrade on most hand-rolled rotators) |
| Auto-update (detection)                                             | Yes (recurring check, alpha.21+)                         | No                                                 |
| Auto-update (install)                                               | Not in 2.0.0 — L2 blocker; manual download works         | No                                                 |
| Signed on macOS so Gatekeeper doesn't block                         | Ad-hoc only, right-click-Open documented                 | No                                                 |
| Works on Linux + Windows                                            | Yes on Linux (tested) + Windows (code-tested, L4 caveat) | Bash-only, no Windows                              |
| Tray icon + dashboard                                               | Yes                                                      | No                                                 |

**What a Claude Code user would NOT forgive in a 2.0 stable:**

- Quota field that shows stale or wrong values (violates the one thing csq claims to do).
- A swap that burns the refresh token and forces re-login on any account (historic bug mode).
- An install flow where the DMG shows "damaged" with no bypass (fixed by ad-hoc re-sign step in release.yml).
- A blank statusline after upgrading (journal 0059 fixed in alpha.22).

**What they WOULD forgive in 2.0 stable, if documented:**

- No one-click auto-update yet (L2).
- Gatekeeper right-click-Open on first run (L1).
- Windows SmartScreen warning (L3).

The positioning holds: csq beats every other option on the power-user checklist so long as the five "would-not-forgive" items are green, and the three documented limitations land in the release notes verbatim.

---

## 6. Gap List

### 6a — Known-open items that should NOT block v2.0.0

| Brief item                                                                           | Reason to defer                                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| "R6 — factor `set_slot_model_write` + `write_slot_model` into one `csq-core` helper" | Internal refactor. Zero user-visible behavior change. Red-team finding was "code duplication," not "bug." Ship v2.0.0 and clean up in 2.0.1.                                                                                                                                                               |
| "R11 — throttle `ollama-pull-progress` emit rate"                                    | Real bug, but user-visible symptom is "laggy progress bar during `ollama pull`." Pull is a pre-session configuration operation; it is not on the credential-handling hot path. Ship v2.0.0 with the current emit rate; follow up in 2.0.1. If user feedback surfaces UI freezes, promote to patch release. |
| Handle-dir settings re-materialization on `csq run` (journal 0059 second half)       | The `csq install` migration (journal 0060, alpha.22) clears the known in-the-wild drift. Structural fix (symlink handle-dir to per-slot) requires a spec change. Defer — no known live symptom after the migration runs once.                                                                              |

### 6b — Known-open items that MUST ship in v2.0.0

| Item                                                                      | Why it blocks                                                                                                                                                                                                                               |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Spec 05 §5.3 (MiniMax GroupId) and §5.4 (Z.AI) refresh                    | Specs are the source of truth (rule `specs-authority.md`). Shipping stable with specs marked "stale" violates that rule and leaves new contributors reading fiction. Low-effort: update the sections using journal 0032 as the data source. |
| Version bump 2.0.0-alpha.21 → 2.0.0 in `Cargo.toml` and `tauri.conf.json` | Mechanical, but A1 fails until done.                                                                                                                                                                                                        |
| Release notes `docs/releases/v2.0.0.md` with verbatim §4 limitation text  | D1-1 fails without this.                                                                                                                                                                                                                    |
| CHANGELOG entry for v2.0.0                                                | D1-4 fails without this.                                                                                                                                                                                                                    |
| README install instructions updated to `v2.0.0`                           | D1-5 fails without this.                                                                                                                                                                                                                    |

### 6c — Items MISSING from the brief that should ship before v2.0.0

| Gap                                                                                      | Why it matters                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Fresh-profile smoke test procedure documented.**                                       | Brief asserts "D6 — smoke test passes" but does not specify how. Journeys §3 above fill this; they need to be added to `docs/smoke-test.md` so any release captain (not just the authoring agent) can run them.                                                                                                                                                                                                                            |
| **CHANGELOG.md file doesn't exist at repo root** (check with `ls CHANGELOG.md`).         | Without a changelog, GitHub Releases pull from the tag annotation only, and users upgrading from alpha.N can't see "what changed since alpha.17" in one place.                                                                                                                                                                                                                                                                             |
| **`docs/releases/v2.0.0.md`** as the release-notes source.                               | Release notes are written once and reused (Markdown render in GitHub Releases UI + embedded in in-app update banner). Without a versioned file, text drifts between the in-app update banner and the GitHub release.                                                                                                                                                                                                                       |
| **Decision on claiming "stable" for Windows or shipping Windows as "preview."**          | L4 caveat is honest but ambiguous. Two valid paths: (a) ship Windows as a first-class platform with the L4 caveat and commit to patch releases on any Windows issue, or (b) label Windows "preview" in the release notes and drop the Windows smoke gate (C7). I recommend (a): the Windows code is as complete as macOS/Linux, and "preview" on a major release telegraphs less confidence than the code warrants. But a human must pick. |
| **"subscription_type preservation" unit test coverage for every credential-write path.** | Rule `account-terminal-separation.md` §4 enumerates the call sites. Gate E5 inspects the daemon refresher. Spot-check: are `csq login`, the `tray_refresh` path, and the repair-credentials path all covered? If not, add tests before v2.0.0.                                                                                                                                                                                             |

---

## 7. Verification Runbook (one-shot)

For the release captain cutting v2.0.0, run these in order:

```bash
# 1. Branch and bump versions
git checkout -b release/v2.0.0
sed -i '' 's/2.0.0-alpha.21/2.0.0/g' Cargo.toml csq-desktop/src-tauri/tauri.conf.json

# 2. Run Group A gates locally
cargo test --workspace                                   # A2 local
cargo clippy --workspace --all-targets -- -D warnings    # A3
cargo fmt --all -- --check                               # A4
cd csq-desktop && npx vitest run && npx svelte-check     # A5, A6

# 3. Write release notes + changelog
# Copy §4 verbatim into docs/releases/v2.0.0.md
# Add v2.0.0 section to CHANGELOG.md listing changes since alpha.0

# 4. Refresh stale specs
# Update specs/05-quota-polling-contracts.md §5.3 and §5.4 from journal 0032

# 5. Commit, push, open PR, merge (admin bypass if owner)
git commit -am "release: v2.0.0"
git push -u origin release/v2.0.0
gh pr create --title "release: v2.0.0" --body-file docs/releases/v2.0.0.md
gh pr merge --admin --merge --delete-branch

# 6. Tag and push
git tag v2.0.0
git push origin v2.0.0

# 7. Wait for Release workflow. Verify B4.
sleep 600
curl -fsSL https://github.com/terrene-foundation/csq/releases/download/updater-manifest/latest.json | jq .version

# 8. Run Group C gates on macOS, Linux, Windows VMs (manual, §3)

# 9. If any gate fails, do NOT delete the tag — cut v2.0.1 with the fix.
#    Tag deletion after release is a supply-chain smell; forward-fix instead.
```

If any gate fails, the release is not stable. Pick v2.0.1 as the forward-fix target; do not unship v2.0.0.
