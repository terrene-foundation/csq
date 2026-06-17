# 14 — Release Artifact Contract

Spec version: 1.0.1

This spec is the authoritative reference for what csq's release pipeline produces, where it puts artifacts, and what guarantees clients (`tauri-plugin-updater`, Homebrew tap, `csq update install`) can rely on. The operational steps live in `docs/release-signing.md`; this spec captures the invariants those steps preserve.

## Scope

Governs:

- The set of platform/arch combinations csq publishes per release.
- The `latest.json` manifest schema served at `https://github.com/terrene-foundation/csq/releases/download/updater-manifest/latest.json`.
- The signing-flow split (stable vs prerelease).
- Cross-platform artifact naming, signature shape, and minisign-verification chain.

Does NOT govern:

- The Tauri plugin's client-side update logic (`csq/src/desktop/` consumer; updater client in `csq/src/desktop/mod.rs`).
- The Homebrew tap formula generator (CLI-only; the tap-bump step in `release.yml`).
- Per-binary code-signing identities (those are in `docs/release-signing.md`).

## Signing keys

csq desktop release artifacts are signed with a Terrene Foundation Ed25519 (minisign) key whose **public half is baked into every shipped client** (`csq-core/src/update/verify.rs::RELEASE_PUBLIC_KEY_BYTES`, and the desktop minisign pubkey embedded in `tauri.conf.json`). A client only accepts an update whose signature verifies against that baked-in public key. macOS bundles additionally carry a Developer ID signature + notarization so Gatekeeper accepts them without a quarantine prompt. The private signing material never appears in source.

## INV-01 — Published platforms per stable release

A stable release tag (matching `^v[0-9]+\.[0-9]+\.[0-9]+$`, no prerelease suffix) MUST publish updater-eligible artifacts for the following platform/arch keys:

| Platform key     | Artifact                              | Signing identity                   |
| ---------------- | ------------------------------------- | ---------------------------------- |
| `darwin-aarch64` | `csq-desktop-macos.app.tar.gz`        | Foundation Developer ID + minisign |
| `darwin-x86_64`  | `csq-desktop-macos.app.tar.gz` (same) | Foundation Developer ID + minisign |
| `linux-x86_64`   | `csq-desktop-linux.AppImage`          | minisign only                      |
| `windows-x86_64` | `csq-desktop-windows-setup.exe`       | minisign only                      |

**Universal-binary invariant**: `darwin-aarch64` and `darwin-x86_64` MUST point at the SAME `.app.tar.gz` file and MUST carry the SAME minisign signature. The macOS bundle is built with `cargo tauri build --target universal-apple-darwin`; the resulting `.app` carries a fat Mach-O with both `x86_64` and `arm64` slices. ONE signed + notarized artifact serves both arches.

**Why universal, not per-arch:**

- Gatekeeper enforces "same Team ID across updates". Per-arch artifacts would diverge under ad-hoc-codesign (prerelease) vs Developer-ID (stable), leading to silent auto-update failures across the boundary.
- One signing pass vs two; one notarization vs two. Linear maintainer cost reduction.
- No GitHub-hosted Intel (`macos-13`) runner needed; that runner image is on a deprecation timeline.

## INV-02 — `latest.json` manifest schema

The manifest published at `updater-manifest/latest.json` MUST conform to:

```json
{
  "version": "<X.Y.Z>",
  "notes": "<human-readable string>",
  "pub_date": "<ISO-8601 UTC timestamp>",
  "platforms": {
    "<platform-key>": {
      "signature": "<verbatim minisign .sig file contents>",
      "url": "<absolute https URL to the artifact>"
    }
  }
}
```

- `version` MUST equal the released tag minus the `v` prefix.
- Each `platforms.<key>.signature` MUST be the **verbatim contents** of the corresponding `.sig` file (no re-encoding, no transformation). `latest.json` generation reads `.sig` files from disk, NOT from shell env vars (defense against multi-line serialization drift).
- Each `platforms.<key>.url` MUST point at an asset attached to the release tag.
- For the two darwin keys: `platforms.darwin-aarch64.url == platforms.darwin-x86_64.url` AND `platforms.darwin-aarch64.signature == platforms.darwin-x86_64.signature` (universal-binary invariant from INV-01).

## INV-03 — Fail-closed on stable, fail-open on prerelease

The `latest.json` generator (`release.yml`'s "Generate latest.json" step) MUST fail-closed on stable tags when any expected platform key is missing. Missing keys = aborted publish.

On prerelease tags (`-alpha`, `-beta`, `-rc`), the generator MAY emit a partial `platforms` map. The rolling `updater-manifest` release is NOT updated on prereleases (see INV-04), so a partial prerelease manifest never reaches the stable user base.

**Rationale**: a silently-incomplete stable manifest leaves a class of users (the missing-platform users) on the manual-download path with no banner. Detection latency = "I haven't seen an update banner in weeks, is something wrong?" Fail-closed converts the failure mode from silent-incomplete to loud-aborted-publish.

## INV-04 — Rolling-manifest stability boundary

The rolling `updater-manifest` GitHub release (which tauri-plugin-updater polls) MUST only be upserted on stable tags. Prereleases do NOT advance the rolling manifest.

**Rationale:**

- Stable installs use Foundation Developer-ID signing; prereleases use CI ad-hoc-codesign.
- Gatekeeper's "same Team ID across updates" rule REJECTS an auto-update from a Developer-ID v(N) to an ad-hoc v(N+1) — every stable installation would brick.
- Prerelease testers install the versioned prerelease asset directly; they do not consume the rolling manifest.

## INV-05 — Maintainer-uploaded vs CI-built macOS split

On stable tags, the CI desktop matrix SKIPS the macOS cell. Three macOS artifacts are pre-uploaded to the draft release per `docs/release-signing.md` § Step 8:

- `csq-desktop-macos.dmg` (Developer-ID-signed + notarized + stapled)
- `csq-desktop-macos.app.tar.gz` (the universal `.app` wrapped for tauri-plugin-updater)
- `csq-desktop-macos.app.tar.gz.sig` (minisign signature from the Foundation key)

On prerelease tags, the CI desktop matrix RUNS the macOS cell and produces ad-hoc-codesigned artifacts.

The publish job has a fail-closed "Validate maintainer macOS artifacts" gate that REJECTS the publish on stable if any of the three required files are missing from the draft release.

**Why a manual macOS step:** Developer-ID signing + notarization require Apple credentials and a notarization round-trip that the hosted CI matrix is not provisioned for. The macOS artifacts are therefore signed, notarized, and uploaded out-of-band, then validated by the publish job's gate before they can reach users.

## INV-06 — Structural backstops on the uploaded `.app.tar.gz`

Because the uploaded macOS tarball is the load-bearing path for stable releases AND is operator-typed (i.e., subject to defects in the runbook execution), the publish job applies structural backstops before trusting it:

1. **AppleDouble guard** — rejects `._*` companion entries (defends against an omitted `COPYFILE_DISABLE=1` on the `tar` invocation).
2. **Path-traversal guard** — rejects tarballs with absolute paths or `..` entries; extracts into `mktemp -d` not workflow CWD; uses `--no-same-owner --no-same-permissions`.
3. **Version-coherence guard** — asserts `Info.plist` `CFBundleShortVersionString` equals the tag version (defends against a stale bundle reaching CI).
4. **Universal-binary guard** — parses the main Mach-O's fat header (Python on the Ubuntu runner; no `lipo` available), accepts both `0xCAFEBABE` and `0xCAFEBABF` magic; bounds `nfat ≤ 16`; rejects if the `x86_64` OR `arm64` slice is missing.
5. **Sig-encoding guard** — `.sig` base64-decodes EXACTLY once to a `untrusted comment:` minisign header; rejects a double-base64'd `.sig`.

## Implementation references

- **CI workflow**: `.github/workflows/release.yml`
  - Desktop matrix, universal-binary build (`--target universal-apple-darwin`), build-side `lipo` gate (macOS runner), maintainer-validation step (publish-side, Ubuntu runner), and `latest.json` generator.
- **Runbook**: `docs/release-signing.md`

## When to break INV-02 (and what to coordinate)

If a future cycle decides to ship per-arch macOS artifacts (e.g., Tauri's universal-binary support degrades, an Apple Silicon-only feature requires per-arch builds, or notarization rules diverge for fat Mach-O), INV-02 changes. The touch-points that MUST be updated atomically in the same PR (else `release.yml` and `docs/release-signing.md` diverge from this spec and one or both starts emitting misleading errors):

1. **`release.yml` "Generate latest.json" step `sigs` dict**: `darwin-aarch64` and `darwin-x86_64` would point at different files + different sig vars.
2. **`docs/release-signing.md` macOS-validation block**: the URL-equality + signature-equality assertions become incorrect; remove or invert per the new contract.
3. **`release.yml` "Validate maintainer macOS artifacts" step**: the required-files list would need to include both `darwin-aarch64` and `darwin-x86_64` artifacts.
4. **`release.yml` "Prune maintainer-uploaded macOS files"**: the `rm -f` list would need to include both arch variants.
5. **This spec's INV-01 and INV-02**: revise both to describe the new per-arch contract; bump the revision in §Revision history.

A change that touches only some of these surfaces is structurally broken — readers see one source-of-truth assert and another contradict.

## Revision history

- **1.0.0**: initial. Captures the universal-binary invariant.
- **1.0.1**: "Does NOT govern" boundary clause corrected — the Tauri updater consumer lives at `csq/src/desktop/` (updater client in `csq/src/desktop/mod.rs`); the previously-cited `csq/src-tauri/` does not exist in the single-binary layout.
