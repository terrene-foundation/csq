---
type: DECISION
date: 2026-04-14
created_at: 2026-04-14T14:20:00+08:00
author: co-authored
session_id: 2026-04-14-alpha-14-ci-rescue
project: csq-v2
topic: alpha.14 candidate scope — five feature/fix PRs targeting the CLI-only re-auth gap, update visibility in the desktop app, doctor false negatives, and spec parity; release deferred pending user sign-off
phase: implement
tags: [alpha-14, release, daemon, desktop, doctor, update, spec]
---

# 0051 — DECISION — alpha.14 candidate scope + why each PR shipped

## Released

**Not yet.** Five PRs landed on main and are alpha.14-ready. The user asked to hold the release tag, so the scope is frozen as PRs #108–#112 plus the two CI-rescue PRs #113–#114. Cutting the tag is a one-step follow-up whenever the user signs off.

## What shipped (on main, not tagged)

### PR #108 — docs(spec-02): settings.json is materialized, not a symlink

Seven call sites in `specs/02-csq-handle-dir-model.md` still described `settings.json` as an account-bound symlink in the `term-<pid>` handle dir. Alpha.9 (PR #102) moved it to a materialized deep-merge of `~/.claude/settings.json` + `config-<N>/settings.json` via `handle_dir::materialize_handle_settings`. The spec just hadn't been updated. PR #108 corrects sections 2.1, 2.3.2, 2.3.3, and INV-02, and also bundles the missing alpha.13 journal 0048.

### PR #109 — fix(doctor): socket-based daemon check, relaxed statusline, broker_failed surface

Three latent false-negatives in `csq doctor`:

1. **Daemon check** used `daemon::status_of(pid_path)` which only looked at the PID file. If the process was alive but the socket was unreachable or `/api/health` was timing out, doctor reported "daemon running" — a lie. Switched to `daemon::detect::detect_daemon`, which does the 4-step protocol (PID file → alive → socket connect → `GET /api/health`).

2. **Statusline check** required the literal substring `"csq"` in `statusLine.command`. Any wrapper script that called csq via an alias or a full path failed this check. Relaxed to "any non-empty command" — the presence of the setting is the signal.

3. **broker_failed surface** was missing entirely. When the daemon's broker fan-out fails for a slot (invalid_grant, network, rate_limit) it writes `credentials/N.broker-failed` with a reason tag, but doctor didn't scan for them. Users had no way to see "slot 3 is LOGIN-NEEDED" short of running `csq login 3` and hitting the error. Doctor now reads via `broker::fanout::{is_broker_failed, read_broker_failed_reason}` and prints each stuck slot with a `csq login N` hint.

22 new tests.

### PR #110 — feat(daemon): --background flag and platform service install

Closes the CLI-only re-auth gap. Previously `csq daemon start` blocked the foreground, so a CLI-only user had to dedicate a terminal — most didn't, no daemon ran, tokens expired, the ~8h re-auth cycle we saw on the user's other machine kicked in.

- `csq daemon start -d` / `--background`: re-execs the binary with stdin/stdout/stderr to `/dev/null` and a detached process group, prints the PID, returns.
- `csq daemon install`: writes a `~/Library/LaunchAgents/foundation.terrene.csq.plist` (macOS) or `~/.config/systemd/user/csq.service` (Linux) and runs `launchctl load` / `systemctl --user enable --now`. Windows prints a "use `csq daemon start` directly" message; service integration tracked as M8-6.
- `csq daemon uninstall`: reverses install.

**Fork() intentionally avoided** — tokio + `fork()` in Rust is UB because the runtime has per-process internal state that fork duplicates in a broken way. Re-exec is the only safe pattern.

### PR #111 — feat(desktop): update-available banner with background GitHub check

Desktop app now shows a banner when a newer csq release is published. Wraps the existing `csq_core::update::*` module (alpha.12) in three new Tauri commands: `check_for_update`, `get_update_status`, `open_release_page`. A background thread in `setup()` fires 10s after launch, emits `update-available` event, caches the result on `AppState`.

Frontend component `UpdateBanner.svelte` mounts above the tabs in `App.svelte`, listens for the event, and opens the GitHub release page on click. Dismissal is session-scoped so the notice reappears next launch until the user upgrades.

**`tauri-plugin-updater` was rejected** because it polls `/releases/latest`, which excludes prerelease tags. csq ships prerelease-tagged binaries (`v2.0.0-alpha.*`), so the plugin would never see any updates. Custom IPC commands reuse the `per_page=30` + client-side semver sort from alpha.12.

**In-app install is intentionally absent.** The Foundation's Ed25519 signing key is still a placeholder (`is_placeholder_key()` check in `update::verify`). The banner links out to the GitHub release page for manual install until the production key is provisioned.

### PR #112 — chore: housekeeping

Journals 0041, 0043, the fix-dmg.sh script, `UpdateBanner.test.ts` (6 vitest cases), and a `.gitignore` entry for `.claude/scheduled_tasks.lock`. Nothing load-bearing; just catching up four pieces of work that accumulated between alpha.6 and alpha.13 and never found a commit.

## Why not tag alpha.14 this session

User asked to defer the release and "complete the rest we can do" first. The CI rescue (PRs #113 + #114) was not originally scope, but blocked any trustworthy release — you can't confidently tag when every recent main CI run has been red. With main now sustainably green for the first time since the rename (journal 0049), alpha.14 can be tagged at any time.

## Outstanding for alpha.14 → alpha.15

Deferred items still on the backlog:

- **Foundation Ed25519 signing key** — blocks `csq update install` from actually installing. External dependency.
- **Desktop bundle signing in release.yml** — CLI binaries get `.sig` files in releases; DMG/MSI/DEB/RPM don't. `SHA256SUMS` is also CLI-only.
- **Windows daemon service integration** (M8-6) — currently a "use `csq daemon start` directly" message.
- **Svelte unit tests for `AccountList`/`SessionList`/etc.** — only `UsageBar`, `TokenBadge`, `toast`, and (new) `UpdateBanner` have tests.
- **Spec 05 updates** for Z.AI + MiniMax — journal 0032 flagged 5.3 / 5.4 as stale.

## How to tag alpha.14 when ready

```bash
git checkout main && git pull
# Bump workspace version
sed -i '' 's/2.0.0-alpha.13/2.0.0-alpha.14/' Cargo.toml
# Commit + push version bump (release.yml triggers on tag push)
git commit -am "chore(release): bump to v2.0.0-alpha.14"
git push
git tag v2.0.0-alpha.14
git push --tags
# Release workflow builds + publishes the 16 assets
```

The user's `~/.local/bin/csq` is already alpha.13 (manually rebuilt this session to unblock the alpha.10 swap-staleness bug). Alpha.14 will need a fresh `cargo build --release -p csq-cli && cp target/release/csq ~/.local/bin/csq` until `csq update install` works.
