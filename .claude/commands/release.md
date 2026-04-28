---
name: release
description: "Cut a csq release: bump workspace version, validate, tag, push. CI builds + publishes the GitHub release."
---

Cut a csq release. The artifact build + publish is automated by `.github/workflows/release.yml` on tag push — this command verifies the workspace is releasable, bumps the version, tags, and pushes.

| Command          | Action                                                                              |
| ---------------- | ----------------------------------------------------------------------------------- |
| `/release`       | Interactive: detect version, recommend bump, confirm, run the full flow             |
| `/release patch` | Bump patch (e.g. 2.3.1 → 2.3.2)                                                     |
| `/release minor` | Bump minor (e.g. 2.3.1 → 2.4.0)                                                     |
| `/release major` | Bump major (e.g. 2.3.1 → 3.0.0)                                                     |
| `/release alpha` | Bump to next alpha pre-release (e.g. 2.3.1 → 2.4.0-alpha.1, or alpha.N → alpha.N+1) |
| `/release check` | Dry-run: read current version, run validate gate, do NOT tag                        |

## Pre-release gate (mandatory)

Before bumping, run the full `/validate` gate. The release workflow has no gating step of its own — once the tag pushes, CI builds and publishes immediately. A failing test on `main` becomes a failing release if skipped. Pre-existing failures are fixed in this session per `rules/zero-tolerance.md` Rule 1.

## Workflow

### Step 1: Detect current version

```bash
grep '^version' Cargo.toml | head -1
```

The workspace `[workspace.package].version` is the source of truth — `csq-core`, `csq-cli`, and `csq-desktop/src-tauri` all inherit via `version.workspace = true`. `csq-desktop/src-tauri/tauri.conf.json` carries an independent `version` field that MUST match the workspace version. Out-of-sync versions produce desktop apps that report the wrong version.

### Step 2: Recommend the bump

Per `rules/communication.md`: present current version, recommend a bump, and summarize changes since the previous tag using `git log v<previous-tag>..HEAD --oneline`. Pick per semver:

- **patch** — bug fixes only, no user-visible behavior changes
- **minor** — new features, backwards compatible
- **major** — breaking changes (CLI flag removed, on-disk layout incompatible, IPC schema changed)
- **alpha** — pre-release for in-progress major work; CI marks the GitHub release as `prerelease: true`

Confirm the bump with the user before proceeding (structural gate per `rules/autonomous-execution.md`).

### Step 3: Validate

Run the full `/validate` gate (fmt check, clippy `-D warnings`, cargo check, cargo test, svelte-check, vitest). Halt on first failure.

### Step 4: Bump and verify

Update both files in lockstep, then refresh the lockfile:

```bash
NEW_VERSION="2.4.0"  # example
# Edit Cargo.toml [workspace.package] version
# Edit csq-desktop/src-tauri/tauri.conf.json "version"
cargo update --workspace
```

Verify both files report `NEW_VERSION`:

```bash
grep '^version' Cargo.toml | head -1
python3 -c "import json; print(json.load(open('csq-desktop/src-tauri/tauri.conf.json'))['version'])"
```

If they diverge, fix and re-verify. Both MUST match before tagging.

### Step 5: Branch, commit, PR, merge

```bash
git checkout -b chore/release-v$NEW_VERSION
git add Cargo.toml Cargo.lock csq-desktop/src-tauri/tauri.conf.json
git commit -m "chore(release): bump version to v$NEW_VERSION"
git push -u origin chore/release-v$NEW_VERSION
gh pr create --title "chore(release): v$NEW_VERSION" --body "..."
gh pr merge <PR_NUMBER> --admin --merge --delete-branch
```

PR body lists changes since previous tag and confirms the test gate ran. Owner admin-bypass per `rules/branch-protection.md`. Per the user's standing feedback "Always merge PRs", merge immediately after CI is green.

### Step 6: Tag main and push (CI takes over)

```bash
git checkout main && git pull
git tag -a v$NEW_VERSION -m "Release v$NEW_VERSION"
git push origin v$NEW_VERSION
```

The push triggers `.github/workflows/release.yml`:

1. Builds CLI binaries for linux-x86_64, macos-aarch64, macos-x86_64, windows-x86_64.
2. Builds desktop bundles via Tauri for linux/macos/windows. The macOS step ad-hoc re-signs the `.app` and rebuilds the DMG to fix Tauri's incoherent signature (per the user's `discovery_tauri_dmg_signing_gap` memory).
3. Generates `SHA256SUMS`, signs CLI binaries with the Foundation Ed25519 key, generates `latest.json` for `tauri-plugin-updater`.
4. Publishes a GitHub Release with all assets (prerelease flag set automatically for `-alpha`/`-beta`/`-rc` tags).
5. Upserts the rolling `updater-manifest` release that hosts `latest.json` at a stable URL.

### Step 7: Verify the release

After CI completes (~15-25 min):

```bash
gh release view v$NEW_VERSION --repo terrene-foundation/csq
gh release view updater-manifest --repo terrene-foundation/csq
```

Expected assets:

- `csq-linux-x86_64`, `csq-macos-aarch64`, `csq-macos-x86_64`, `csq-windows-x86_64.exe` (each + `.sig`, entry in `SHA256SUMS`)
- `csq-desktop-linux.deb`, `.rpm`, `.AppImage` (each + `.sig`)
- `csq-desktop-macos.dmg`, `.app.tar.gz` (+ `.app.tar.gz.sig` for updater)
- `csq-desktop-windows.msi`, `-setup.exe` (+ `-setup.exe.sig` for updater)
- `latest.json` on the `updater-manifest` release

If any asset is missing, do NOT publish a fresh tag — re-run the failing CI job in the existing workflow.

## What this command does NOT do

- Does NOT publish to PyPI / crates.io / npm. csq is distributed via GitHub Releases only.
- Does NOT manage the Foundation Ed25519 key. That key is provisioned in CI as `RELEASE_SIGNING_KEY`; per `rules/security.md` it never appears in any local file.
- Does NOT push to any update server other than GitHub Releases. `tauri-plugin-updater` polls GitHub directly.

## Agent Teams

- **git-release-specialist** — runs version bump, branch, PR workflow, tag push.
- **security-reviewer** — MANDATORY before tagging when the release touches OAuth, keychain, IPC, or any credential path.
- **gold-standards-validator** — Foundation naming + license accuracy (Apache 2.0, Foundation-owned) in CHANGELOG.md and release notes.
- **testing-specialist** — confirm Tier 2 coverage for any new feature shipping in this release.

## Cross-References

- `.github/workflows/release.yml` — the actual build + publish pipeline
- `csq-desktop/src-tauri/tauri.conf.json` — the second version location that MUST match
- `rules/branch-protection.md`, `rules/git.md`, `rules/zero-tolerance.md`
