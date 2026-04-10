# M11: Cross-Platform & Packaging

Priority: P1/P2
Effort: 5 autonomous sessions
Dependencies: M8-M10 (Daemon + Desktop functional)
Phase: 4

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
  - [ ] All-green on correctly configured system
  - [ ] Red items with actionable fix suggestions
  - [ ] Works without daemon running

## M11-08: Build shell completions

`csq completions bash/zsh/fish/powershell` via `clap_complete`. Completions include subcommands and common arguments.

- Scope: New (P2)
- Complexity: Trivial
- Acceptance:
  - [ ] `csq <TAB>` completes subcommands in bash/zsh
  - [ ] `csq run <TAB>` shows account numbers

## M11-09: Build --json output for all commands

All commands support `--json` flag for machine-readable output. Structured JSON with consistent schema.

- Scope: New (P2)
- Complexity: Moderate
- Acceptance:
  - [ ] `csq status --json` outputs valid JSON
  - [ ] `csq suggest --json` outputs valid JSON
  - [ ] Schema consistent across commands

## M11-10: Build v1.x migration in csq install

Detect v1.x artifacts: `statusline-command.sh`, `rotate.md`, `auto-rotate-hook.sh`, Python-based statusline command in settings.json. Migrate: update settings.json, remove dead artifacts. Preserve: credentials, profiles, quota (same format). Warn if v1.x files are modified (preserve as `.bak`).

- Scope: 14.5 + migration strategy
- Complexity: Moderate
- Acceptance:
  - [ ] Fresh system with v1.x: migration succeeds
  - [ ] Credentials preserved (same JSON format)
  - [ ] settings.json updated to `csq statusline`
  - [ ] Modified v1.x files: backed up as `.bak`
  - [ ] `csq doctor` reports all-green after migration

## M11-11: Cross-platform smoke tests

Manual smoke test on macOS (arm64), Linux (x86_64 VM), Windows (x86_64 VM). 7 accounts, 5 concurrent sessions, swap/rotate/refresh all working.

- Scope: Phase 4 exit criteria
- Complexity: Complex
- Acceptance:
  - [ ] All platforms pass smoke test
  - [ ] Binary size < 10MB (CLI-only)
  - [ ] Daemon memory < 30MB idle with 7 accounts
