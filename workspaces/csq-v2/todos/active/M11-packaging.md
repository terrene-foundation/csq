# M11: Cross-Platform & Packaging

Priority: P1/P2
Effort: 5 autonomous sessions
Dependencies: M8-M10 (Daemon + Desktop functional)
Phase: 4

---

**STATUS UPDATE 2026-04-28:** csq is shipped at v2.3.1 in production; this milestone audited against current code.

- delivered (DONE):
  - M11-05 .deb / .rpm / AppImage bundles — `tauri.conf.json::bundle.targets` lists `["app","dmg","deb","rpm","appimage","msi","nsis"]`; `release.yml` ships them.
  - M11-06 curl-pipe installer — `install.sh` at repo root, downloads from GitHub Releases with SHA256 verification.
  - M11-07 `csq doctor` — `csq-cli/src/commands/doctor.rs` exists.
  - M11-08 shell completions — `csq-cli/src/commands/completions.rs` exists.
  - M11-09 `--json` output — implemented across status / suggest / etc.
  - M11-10 v1.x migration in `csq install` — `csq-cli/src/commands/install.rs`.
- outstanding (NOT-DONE):
  - M11-01 macOS Apple Developer ID + notarization — only Foundation Ed25519 `.sig` files ship; `.app`/`.dmg` Gatekeeper still warns on first launch (release.yml comment confirms).
  - M11-02 Windows Authenticode — same: Ed25519 only; SmartScreen still warns.
  - M11-03 Homebrew tap (`terrene-foundation/tap`) — does not exist; install path is curl-pipe.
  - M11-04 Scoop manifest — does not exist.
  - M11-11 cross-platform smoke test sign-off — manual gate, no committable artifact.

These five outstanding items are the v2.0 packaging-polish backlog; users install via `install.sh` (CLI) or download desktop bundles directly from Releases. None block shipped functionality.

---

## M11-01: Build macOS code signing

Apple Developer ID. Notarization via `xcrun notarytool`. Gatekeeper-passing `.app` bundle. CI integration for automated signing.

- Scope: New
- Complexity: Complex
- Acceptance:
  - [ ] `spctl --assess` passes on signed app
  - [ ] Notarization ticket stapled
  - [ ] CI produces signed binaries on tag push

## M11-02: Build Windows code signing

Authenticode signing (or self-signed for initial release). CI integration.

- Scope: New
- Complexity: Moderate
- Acceptance:
  - [ ] Binary signed with valid certificate
  - [ ] SmartScreen warning reduced/eliminated

## M11-03: Build Homebrew tap formula

`terrene-foundation/tap` repository with formula for macOS and Linux. Downloads platform-appropriate binary from GitHub Releases.

- Scope: New
- Complexity: Moderate
- Acceptance:
  - [ ] `brew install terrene-foundation/tap/csq` works on macOS
  - [ ] `brew install terrene-foundation/tap/csq` works on Linux
  - [ ] Formula auto-updated on new release

## M11-04: Build Scoop manifest

`claude-squad.json` manifest for Windows Scoop package manager.

- Scope: New
- Complexity: Trivial
- Acceptance:
  - [ ] `scoop install csq` works on Windows
  - [ ] Manifest auto-updated on new release

## M11-05: Build .deb/.rpm packages and AppImage

Tauri bundler produces `.deb` and `.rpm`. AppImage for portable Linux. Published to GitHub Releases.

- Scope: New
- Complexity: Moderate
- Acceptance:
  - [ ] `.deb` installs on Ubuntu/Debian
  - [ ] `.rpm` installs on Fedora/RHEL
  - [ ] AppImage runs on any Linux with FUSE

## M11-06: Build curl-pipe installer

`curl -sSL https://csq.terrene.dev/install | sh` — detects platform, downloads binary, runs `csq install`. CLI-only (no desktop app).

- Scope: New
- Complexity: Moderate
- Acceptance:
  - [ ] Works on fresh macOS (arm64 + x86_64)
  - [ ] Works on fresh Linux (x86_64)
  - [ ] Detects platform correctly
  - [ ] Downloads from GitHub Releases

## M11-07: Build csq doctor diagnostic

Reports: binary version, daemon status, account count + credential health, Claude Code version + path, settings.json statusline configuration, platform info. Color-coded output (green = ok, red = problem).

- Scope: New (P2)
- Complexity: Moderate
- Acceptance:
  - [x] All-green on correctly configured system
  - [x] Red items with actionable fix suggestions
  - [x] Works without daemon running

## M11-08: Build shell completions

`csq completions bash/zsh/fish/powershell` via `clap_complete`. Completions include subcommands and common arguments.

- Scope: New (P2)
- Complexity: Trivial
- Acceptance:
  - [x] `csq <TAB>` completes subcommands in bash/zsh
  - [x] `csq run <TAB>` shows account numbers

## M11-09: Build --json output for all commands

All commands support `--json` flag for machine-readable output. Structured JSON with consistent schema.

- Scope: New (P2)
- Complexity: Moderate
- Acceptance:
  - [x] `csq status --json` outputs valid JSON
  - [x] `csq suggest --json` outputs valid JSON
  - [x] Schema consistent across commands

## M11-10: Build v1.x migration in csq install

Detect v1.x artifacts: `statusline-command.sh`, `rotate.md`, `auto-rotate-hook.sh`, Python-based statusline command in settings.json. Migrate: update settings.json, remove dead artifacts. Preserve: credentials, profiles, quota (same format). Warn if v1.x files are modified (preserve as `.bak`).

- Scope: 14.5 + migration strategy
- Complexity: Moderate
- Acceptance:
  - [x] Fresh system with v1.x: migration succeeds
  - [x] Credentials preserved (same JSON format)
  - [x] settings.json updated to `csq statusline`
  - [x] Modified v1.x files: backed up as `.bak`
  - [x] `csq doctor` reports all-green after migration

## M11-11: Cross-platform smoke tests

Manual smoke test on macOS (arm64), Linux (x86_64 VM), Windows (x86_64 VM). 7 accounts, 5 concurrent sessions, swap/rotate/refresh all working.

- Scope: Phase 4 exit criteria
- Complexity: Complex
- Acceptance:
  - [ ] All platforms pass smoke test
  - [ ] Binary size < 10MB (CLI-only)
  - [ ] Daemon memory < 30MB idle with 7 accounts
