# 14 — Release Artifact Contract

Spec version: 1.1.2

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
- Each signature MUST bind the advertised `version` in its minisign trusted comment as a tab-separated `version:<X>` field. `plugins.updater.requireSignedVersion = true` makes the desktop client reject missing or mismatched signed versions. The producer is the lockfile-pinned `tauri signer sign --app-version` command on final updater artifacts. CI uses `tauri build --no-sign` for packaging; that build does not create the version-bound signature. The `scripts/verify/latest-json-signed-version.sh` gate rejects an unbound manifest before publication.

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

The key-free hosted `signer-producer` job has a fail-closed "Validate maintainer macOS artifacts (stable tags only)" gate that rejects stable publication if any of the three required files or either artifact-bound `.edition` claim is missing from the draft release.

**Why a manual macOS step:** Developer-ID signing + notarization require Apple credentials and a notarization round-trip that the hosted CI matrix is not provisioned for. The macOS artifacts are therefore signed, notarized, and uploaded out-of-band, then validated by `signer-producer` before isolated signing and publication.

## INV-06 — Structural backstops on the uploaded `.app.tar.gz`

Because the uploaded macOS tarball is the load-bearing path for stable releases AND is operator-typed (i.e., subject to defects in the runbook execution), the key-free hosted `signer-producer` job applies structural backstops before trusting it:

1. **AppleDouble guard** — rejects `._*` companion entries (defends against an omitted `COPYFILE_DISABLE=1` on the `tar` invocation).
2. **Path-traversal guard** — rejects tarballs with absolute paths or `..` entries; extracts into `mktemp -d` not workflow CWD; uses `--no-same-owner --no-same-permissions`.
3. **Version-coherence guard** — asserts `Info.plist` `CFBundleShortVersionString` equals the tag version (defends against a stale bundle reaching CI).
4. **Universal-binary guard** — parses the main Mach-O's fat header (Python on the GitHub-hosted Ubuntu `signer-producer` runner; no `lipo` available), accepts both `0xCAFEBABE` and `0xCAFEBABF` magic; bounds `nfat ≤ 16`; rejects if the `x86_64` OR `arm64` slice is missing.
5. **Sig-encoding guard** — `.sig` base64-decodes EXACTLY once to a `untrusted comment:` minisign header; rejects a double-base64'd `.sig`.

## INV-09 — Build, signing, and publication isolation

Before preparing release inputs, `signer-producer` independently re-measures the proposed community SHA using GitHub's live `compare/<SHA>...main` API and accepts only `identical` or `ahead`. It checks out that immutable SHA and requires both the workspace Cargo version and Tauri version to equal the release tag without its leading `v`. API errors, an unaccepted comparison status, or a version mismatch stop preparation.

The "Stage exact release assets and recompute their checksums" step accepts exactly four CLI binaries (`csq-linux-x86_64`, `csq-macos-aarch64`, `csq-macos-x86_64`, `csq-windows-x86_64.exe`) and seven desktop bundles (`csq-desktop-linux.AppImage`, `.deb`, `.rpm`; `csq-desktop-windows.msi`, `csq-desktop-windows-setup.exe`; `csq-desktop-macos.dmg`, `csq-desktop-macos.app.tar.gz`), plus an artifact-bound `.edition` claim for each desktop bundle and, on stable tags, the maintainer tarball's `.sig`. It rejects missing required inputs, unexpected names, duplicate basenames and symlinks. Corresponding `.sha256` sidecars may arrive in staging but are not trusted or copied into the prepared set. `SHA256SUMS` is recomputed from the actual bytes of all eleven allowlisted binaries and bundles, excluding edition claims and signatures.

`signer-producer` runs on a fresh GitHub-hosted Ubuntu runner without publisher-signing keys. It downloads matrix outputs, validates stable maintainer macOS inputs and edition claims, runs the license-refusal gate, builds the Foundation `sign-release` helper, and prepares assets and standalone Tauri signer tools. It exports artifact IDs and ZIP SHA-256 digests plus the helper SHA-256 through job outputs.

`sign-updater` and `sign-foundation` run separately on fresh GitHub-hosted Ubuntu runners in the `release-signing` environment. They check out the trusted workflow revision for verification code and lock metadata; they do not install packages, compile code, or run community build scripts. Before a signing step receives its key, `scripts/ci/release-artifact-guard.py` binds each downloaded artifact to its expected artifact ID, workflow run ID, workflow head SHA, and ZIP SHA-256, safely extracts it, and checks its file manifest. The helper must match the producer's separate SHA-256 output. The updater signer additionally compares the installed Tauri wrapper and native Linux CLI package inventory and bytes against the exact npm registry tarballs authenticated by the trusted lockfile's SHA-512 integrity values. Keys enter only the signing step's environment. The two jobs upload detached signatures; the separate `release` job verifies the prepared assets and signature transfers, generates and checks `latest.json`, and publishes without publisher-signing keys.

The updater signer uses the official Node.js 24.22.1 Linux x64 runtime archive, authenticated against its fixed SHA-256 pin before extraction. It verifies the extracted runtime executable and exact reported version before exposing the updater key, then invokes that runtime directly for signing. Neither a moving runtime version nor an unverified image-default executable satisfies this boundary.

SBOM generation runs in a separate fresh GitHub-hosted Ubuntu job with `contents: read` and no signing or publication secrets. It depends on `signer-producer` and checks out that producer's vetted community SHA; Cargo and SBOM tool installation and generation run there. The publisher downloads the SBOM through its artifact ID and ZIP digest, verifies the transfer, and attaches the resulting file with `gh release upload`. The `release` job performs no Cargo invocation or tool installation.

Linux desktop bundling uses the five tools pinned in `scripts/ci/tauri-linux-tools.json`, prepared by `scripts/ci/preseed-tauri-linux-tools.py` in a fresh job-owned cache. The helper validates download and installed SHA-256 values, file inventory and modes, and exports `XDG_CACHE_HOME`. The build MUST pass its generated `CSQ_TAURI_LINUX_TOOLS_CONFIG` through `--config`, forcing `bundle.useLocalToolsDir=false` so Tauri selects that cache. The post-bundle `--verify-only` step rechecks the cache and selector environment.

## Implementation references

- **CI workflow**: `.github/workflows/release.yml`
  - `build-desktop`: universal build, macOS `lipo` check, explicit ad-hoc seal/repack, and pinned Linux tools.
  - `signer-producer`: key-free hosted maintainer validation, helper compilation, and verified asset/tool preparation.
  - `sign-updater` / `sign-foundation`: isolated detached-signature production.
  - Separate SBOM job: read-only, secret-free generation from the producer-vetted community SHA.
  - `release`: verified asset/signature/SBOM transfer assembly, `latest.json` generation and signed-version gate, publication and SBOM attachment without Cargo or tool installation.
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

- **1.1.2** (2026-10-23): recorded independent community-SHA/version remeasurement, exact asset staging and byte-derived checksums, the verified pinned updater runtime, and separate secret-free SBOM production and verified publication transfer.

- **1.1.1** (2026-10-23): corrected job ownership and hosted runner descriptions; documented signing isolation, artifact and signer-byte verification, pinned Linux bundler tools, and separate publication. The prior signed-version producer update remains revision 1.1.0.

- **1.1.0** (2026-10-23): recorded the signed-version requirement and the separate `tauri signer sign --app-version` producer after key-free packaging.

- **1.0.0**: initial. Captures the universal-binary invariant.
- **1.0.1**: "Does NOT govern" boundary clause corrected — the Tauri updater consumer lives at `csq/src/desktop/` (updater client in `csq/src/desktop/mod.rs`); the previously-cited `csq/src-tauri/` does not exist in the single-binary layout.
