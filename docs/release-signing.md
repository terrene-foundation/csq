# macOS Release Signing Runbook

Operational reference for signing + notarizing csq macOS releases with the Foundation's Apple Developer ID.

Until this runbook is executed end-to-end and validated, releases continue to ship via the legacy ad-hoc-codesign block in `.github/workflows/release.yml`. Once cert + credentials are in hand and a clean notarized DMG has been produced locally, follow up with the release.yml integration PR.

## Context

- **Bundle id**: `foundation.terrene.claude-squad` (csq/tauri.conf.json:5 — do not change; auto-updater trust chain is keyed to it)
- **Publisher**: Terrene Foundation
- **Product name on disk**: `Code Squad Q.app`
- **Targets**: `.app` + `.dmg` (universal — both arm64 and x86_64 artifacts; see `.github/workflows/release.yml`)
- **What replaces what**: this signing flow REPLACES the ad-hoc `codesign --force --deep --sign -` + `hdiutil create` block at `.github/workflows/release.yml:210-254`. The ad-hoc block stays in the workflow as a fallback for non-tagged dev builds.

## Apple Portal Steps (one-time, ~30 min)

### 1. Create the Developer ID Application certificate

1. Sign in at <https://developer.apple.com/account>.
2. Navigate: **Certificates, Identifiers & Profiles** → **Certificates** → **+** (top right).
3. Select **Developer ID Application** (under "Software"). NOT "Developer ID Installer" — that's for PKG installers; csq ships DMG.
4. Generate a CSR locally first:
   - Open **Keychain Access** → menu **Keychain Access** → **Certificate Assistant** → **Request a Certificate From a Certificate Authority…**
   - Email: the Foundation's developer-program email
   - Common name: `Terrene Foundation`
   - Select **Saved to disk** + **Let me specify key pair information**
   - Click Continue → key size **2048**, algorithm **RSA**
   - Save the `.certSigningRequest` file
5. Upload the CSR in the Apple portal → click Continue → download the generated `.cer` file.
6. Double-click the `.cer` to install into Keychain (it joins the private key created during step 4).
7. Verify in Keychain Access: search for "Developer ID Application: Terrene Foundation" — should show a private key (disclosure triangle expands to reveal it).

### 2. Capture the identity string

Open Terminal and run:

```bash
security find-identity -p codesigning -v
```

Output should include a line like:

```
1) 0123456789ABCDEF0123456789ABCDEF01234567 "Developer ID Application: Terrene Foundation (TEAMIDXXXX)"
```

Record both the SHA-1 hash (`0123...`) and the human-readable string. The release pipeline will reference the human-readable string in the `--sign` argument.

The 10-char string in parentheses (`TEAMIDXXXX`) is the Foundation's **Team ID** — needed for notarization (next step).

### 3. Create an app-specific password for notarization

Apple's `notarytool` accepts either an App Store Connect API key OR an Apple ID + app-specific password. The app-specific password path is simpler for a single-maintainer setup; the API key path is preferred if multiple people will eventually run the notary step.

For app-specific password (recommended first step):

1. Sign in at <https://account.apple.com> with the Foundation's Apple ID.
2. **Sign-In and Security** → **App-Specific Passwords** → **+**.
3. Label: `csq-notarize-2026-05` (date-stamped so future rotations are obvious).
4. Copy the generated password (`abcd-efgh-ijkl-mnop` shape). **Save it immediately — Apple does not show it again.**
5. Store in macOS Keychain via:

```bash
xcrun notarytool store-credentials csq-notary \
  --apple-id 'YOUR_FOUNDATION_APPLE_ID@example.com' \
  --team-id 'TEAMIDXXXX' \
  --password 'abcd-efgh-ijkl-mnop'
```

After this, the credential profile is named `csq-notary` in Keychain; later commands reference it via `--keychain-profile csq-notary` without needing the password again.

## Local Signing + Notarization (per-release, ~15 min)

This is the maintainer-box flow that runs BEFORE pushing the release tag, so the GH Actions workflow uploads already-signed artifacts.

> **Self-test discipline (read once).** Every step §1–§8 below ends with a
> `set -e`-guarded assertion block — paste it verbatim after the step's
> commands; it `exit 1`s and aborts the flow the moment the step's output
> diverges from the expected invariant. §7a (AppleDouble guard) and §7b
> (pubkey parity check) are the original templates; §1–§7c/§8/§8a were
> retrofitted with the same pattern after three runbook-vs-tool drift
> defects (`-k`/`--private-key-path` j0052, `base64 <`/`cat` j0053,
> `--no-bundle=false`/bare j0054) each surfaced only at execution, never
> at static review. The assertions are the structural defense: a reviewed
> prose step whose correctness depends on a pinned third-party tool's
> argument grammar (or on local state like build freshness) is invisible
> to review and visible only to an inline check. Do NOT skip an assertion
> "because the step looked fine" — that is the exact failure class these
> guards exist to catch. (an internal journal entry)

### 1. Build the unsigned bundle

```bash
cd ~/repos/csq
BUILD_START=$(date +%s)              # freshness anchor — asserted below
cd csq && npm install && cd -    # if not already installed

# Ensure both rustup targets are present for the universal build.
# Silent-fallback risk: if x86_64-apple-darwin is not installed, Tauri
# may produce an arm64-only bundle under the "universal" path name —
# the lipo -info gate at the end of §1 catches that.
rustup target add aarch64-apple-darwin x86_64-apple-darwin

cd csq && npx tauri build --target universal-apple-darwin     # universal = fat Mach-O (arm64 + x86_64)
cd -
```

> **Do NOT pass `--no-bundle=false`.** This `@tauri-apps/cli` version
> treats `--no-bundle` as a boolean flag and hard-errors on `=false`
> (`unexpected value 'false' for '--no-bundle'`), producing no bundle.
> Plain `npx tauri build --target universal-apple-darwin` bundles;
> `--no-bundle` would _disable_ it.
> (Runbook-vs-tool drift, same class as the §7b/§9 defects; surfaced
> during the v2.8.0 cut. See an internal journal entry)

> **Why `--target universal-apple-darwin`?** The bundled `.app` carries
> a fat Mach-O with both arm64 and x86_64 slices, so ONE signed +
> notarized artifact serves both Intel and Apple Silicon Mac users
> through tauri-plugin-updater. Both `darwin-aarch64` and
> `darwin-x86_64` keys in `latest.json` point at the same file. This
> closes the Intel auto-update gap without introducing a second
> signing pass or a separate `macos-13` runner. See workspace
> `an internal workspace/an internal journal entry`.

This produces:

- `target/universal-apple-darwin/release/bundle/macos/Code Squad Q.app`
- `target/universal-apple-darwin/release/bundle/dmg/Code Squad Q_<version>_universal.dmg`

Universal-binary builds output under `target/universal-apple-darwin/`,
NOT `target/release/` — the rest of the runbook uses
`$APP_BUNDLE`/`$DMG_PATH` variables that point into this path.

**MANDATORY regression gate — bundle freshness + version coherence.**
This defends the j0054 defect: the `--no-bundle=false` hard-error left a
**stale pre-2.8.0 `.app`** in place and the cut nearly signed it. A stale
bundle has two tells — (a) its mtime predates this build, and (b) its
`Info.plist` `CFBundleShortVersionString` disagrees with `Cargo.toml`.
This block asserts both. It is the ONLY defect of the three that had no
guard before an internal journal entry

```bash
set -e
APP_BUNDLE="target/universal-apple-darwin/release/bundle/macos/Code Squad Q.app"
INFO_PLIST="$APP_BUNDLE/Contents/Info.plist"

# (a) the bundle exists at all (a silent no-op build leaves no fresh one)
if [ ! -d "$APP_BUNDLE" ] || [ ! -f "$INFO_PLIST" ]; then
  echo "::error::No $APP_BUNDLE — the build produced no bundle. If you"
  echo "::error::passed --no-bundle=false, that hard-errors and bundles"
  echo "::error::NOTHING (an internal journal entry). Re-run plain \`npx tauri build"
  echo "::error::--target universal-apple-darwin\`."
  exit 1
fi

# (b) freshness: the .app must have been written by THIS build, not a
#     leftover from a prior run that a no-op build failed to replace.
APP_MTIME=$(stat -f %m "$APP_BUNDLE")
if [ "$APP_MTIME" -lt "$BUILD_START" ]; then
  echo "::error::$APP_BUNDLE mtime ($APP_MTIME) predates this build"
  echo "::error::(BUILD_START=$BUILD_START). The build did not rebuild the"
  echo "::error::bundle — it is STALE. Signing it would ship old bytes"
  echo "::error::under a new version tag (an internal journal entry). Investigate the"
  echo "::error::build output before proceeding."
  exit 1
fi

# (c) version coherence: Info.plist version == Cargo.toml version.
CARGO_VERSION=$(grep '^version' Cargo.toml | head -1 | awk -F'"' '{print $2}')
PLIST_VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$INFO_PLIST")
if [ "$PLIST_VERSION" != "$CARGO_VERSION" ]; then
  echo "::error::Version incoherence: $APP_BUNDLE Info.plist says"
  echo "::error::'$PLIST_VERSION' but Cargo.toml says '$CARGO_VERSION'."
  echo "::error::This is the stale-bundle signature (an internal journal entry):"
  echo "::error::a leftover .app from an older version survived the build."
  echo "::error::DO NOT sign. Clean target/universal-apple-darwin/release/bundle/"
  echo "::error::and rebuild."
  exit 1
fi

# (d) universal-binary slices present. If --target universal-apple-darwin
#     silently fell back to host-arch-only output (rustup target not
#     installed, or Tauri CLI quirk), Intel Mac users would receive an
#     arm64-only .app and see "Bad CPU type in executable" on launch.
#     Catch it before notarization wastes the keychain/network round-trip.
MAIN_BINARY=$(find "$APP_BUNDLE/Contents/MacOS" -maxdepth 1 -type f | head -1)
LIPO_OUT=$(lipo -info "$MAIN_BINARY")
echo "$LIPO_OUT"
if ! echo "$LIPO_OUT" | grep -q 'x86_64' || ! echo "$LIPO_OUT" | grep -q 'arm64'; then
  echo "::error::$MAIN_BINARY is NOT a universal fat Mach-O — missing"
  echo "::error::x86_64 or arm64 slice. Intel Mac users would see"
  echo "::error::'Bad CPU type in executable' on launch."
  echo "::error::Check rustup target add aarch64-apple-darwin x86_64-apple-darwin"
  echo "::error::then re-run \`npx tauri build --target universal-apple-darwin\`."
  exit 1
fi
echo "Bundle freshness + version coherence + universal slices OK: v$PLIST_VERSION, fresh."
```

### 2. Sign the `.app`

```bash
APP_BUNDLE="target/universal-apple-darwin/release/bundle/macos/Code Squad Q.app"

# ── Standalone CLI helper for the shim refresh (an internal ticket) ──────────────
#
# The desktop app refreshes `~/.local/bin/csq` on launch by copying a binary
# from its own bundle (`csq_core::cli_deps::cli_shim`). It MUST NOT copy the
# bundle's MAIN executable (`Contents/MacOS/csq`): that binary's signature is
# bundle-bound (Info.plist + sealed resources), so it is INVALID at a
# standalone path → hardened-runtime Gatekeeper SIGKILLs every CLI call
# (exit 137). Instead the shim copies `Contents/Helpers/csq-cli`, a byte copy
# of the same binary signed as a STANDALONE Mach-O (no bundle binding) — valid
# at any path. `resolve_shim_source` looks for exactly this path.
#
# Create it BEFORE the `--deep` sign below so (a) `--deep` signs it as a
# nested standalone Mach-O (Info.plist=not bound) and (b) it is captured in the
# bundle's sealed-resources envelope. Adding it AFTER the sign would invalidate
# the .app seal and fail notarization.
MAIN_BINARY=$(find "$APP_BUNDLE/Contents/MacOS" -maxdepth 1 -type f | head -1)
mkdir -p "$APP_BUNDLE/Contents/Helpers"
cp "$MAIN_BINARY" "$APP_BUNDLE/Contents/Helpers/csq-cli"

codesign --force \
  --deep \
  --options runtime \
  --timestamp \
  --sign "Developer ID Application: Terrene Foundation (TEAMIDXXXX)" \
  "$APP_BUNDLE"

codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"

# Confirm the helper is a STANDALONE-valid signature (Info.plist=not bound) —
# the property that keeps it valid once copied to ~/.local/bin/csq. If this
# shows "Info.plist=bound" or fails, the shim copy will SIGKILL (an internal ticket).
codesign --display --verbose=4 "$APP_BUNDLE/Contents/Helpers/csq-cli" 2>&1 \
  | grep -E 'Info.plist|Sealed Resources' || true
codesign --verify --strict --verbose=2 "$APP_BUNDLE/Contents/Helpers/csq-cli"
```

Key flags:

- `--options runtime` enables the hardened runtime (REQUIRED for notarization).
- `--timestamp` requests Apple's timestamp server (REQUIRED for notarization).
- `--deep` propagates the signature into every nested bundle and Mach-O.

The verify step MUST report `satisfies its Designated Requirement` with no `not signed` or `resource not signed` errors. Any error here is a blocker for notarization.

**MANDATORY regression gate — signature satisfies the Designated
Requirement.** `codesign --verify` exits non-zero on a hard failure, but
the runbook is pasted step-by-step (not under a global `set -e`), so an
unguarded failure scrolls past. This block fails closed.

```bash
set -e
if ! codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE" 2>&1 \
     | tee /tmp/csq-codesign-verify.txt | grep -q 'satisfies its Designated Requirement'; then
  echo "::error::codesign --verify did not confirm the Designated"
  echo "::error::Requirement for $APP_BUNDLE. Notarization WILL reject."
  echo "::error::Output:"; sed 's/^/::error::  /' /tmp/csq-codesign-verify.txt
  exit 1
fi
if grep -qE 'not signed|resource not signed|invalid' /tmp/csq-codesign-verify.txt; then
  echo "::error::codesign --verify reported an unsigned/invalid nested"
  echo "::error::component. --deep should have covered it. Inspect:"
  sed 's/^/::error::  /' /tmp/csq-codesign-verify.txt
  exit 1
fi
echo "codesign verify OK: .app satisfies its Designated Requirement."
```

### 3. Rebuild the DMG around the signed `.app`

The DMG produced in step 1 contains the unsigned app. Rebuild it so the DMG carries the now-signed bundle.

**Naming note (universal-binary cut):** Tauri's bundler names the macOS
DMG with the `_universal` suffix when building with
`--target universal-apple-darwin`. The historical `_aarch64`/`_arm64`
ambiguity (an internal journal entry) is moot under the universal flow but the
glob below remains permissive so a stale single-arch DMG from a prior
build cannot survive next to the rebuilt universal one.

```bash
VERSION=$(grep '^version' Cargo.toml | head -1 | awk -F'"' '{print $2}')
DMG_DIR="target/universal-apple-darwin/release/bundle/dmg"
DMG_PATH="$DMG_DIR/Code Squad Q_${VERSION}_universal.dmg"  # what hdiutil writes
TMP_DMG_DIR=$(mktemp -d)
cp -R "$APP_BUNDLE" "$TMP_DMG_DIR/"
ln -s /Applications "$TMP_DMG_DIR/Applications"
rm -f "$DMG_DIR/Code Squad Q_${VERSION}_"*.dmg   # any arch suffix
hdiutil create \
  -volname "Code Squad Q" \
  -srcfolder "$TMP_DMG_DIR" \
  -ov \
  -format UDZO \
  "$DMG_PATH"
```

**MANDATORY regression gate — exactly one fresh DMG at the expected
path.** Assert the glob now resolves to exactly one file, it is
`$DMG_PATH`, and it post-dates the signed `.app` (so it wraps the
SIGNED bundle, not a leftover unsigned one from §1).

```bash
set -e
shopt -s nullglob
DMGS=( "$DMG_DIR/Code Squad Q_${VERSION}_"*.dmg )
shopt -u nullglob
if [ "${#DMGS[@]}" -ne 1 ]; then
  echo "::error::Expected exactly 1 DMG for v$VERSION, found ${#DMGS[@]}:"
  printf '::error::  %s\n' "${DMGS[@]}"
  echo "::error::A stale DMG survived the rm -f glob (an internal journal entry)."
  echo "::error::Delete all but the just-built one and re-verify."
  exit 1
fi
if [ "${DMGS[0]}" != "$DMG_PATH" ]; then
  echo "::error::DMG path mismatch: built '${DMGS[0]}' but \$DMG_PATH is"
  echo "::error::'$DMG_PATH'. Expected _universal suffix from"
  echo "::error::--target universal-apple-darwin (an internal journal entry of"
  echo "::error::an internal workspace workspace)."
  exit 1
fi
if [ "$(stat -f %m "$DMG_PATH")" -lt "$(stat -f %m "$APP_BUNDLE")" ]; then
  echo "::error::$DMG_PATH is OLDER than the signed .app — it wraps a"
  echo "::error::stale/unsigned bundle. Rebuild the DMG (this step)."
  exit 1
fi
echo "DMG gate OK: one fresh DMG at $DMG_PATH wrapping the signed .app."
```

### 4. Sign the DMG itself

```bash
codesign --force \
  --sign "Developer ID Application: Terrene Foundation (TEAMIDXXXX)" \
  --timestamp \
  "$DMG_PATH"

codesign --verify --verbose=2 "$DMG_PATH"
```

The DMG signature wraps the already-signed `.app` — two layers of trust.

**MANDATORY regression gate — DMG signature valid.**

```bash
set -e
if ! codesign --verify --verbose=2 "$DMG_PATH" 2>&1 \
     | tee /tmp/csq-dmg-verify.txt | grep -q 'valid on disk'; then
  echo "::error::codesign --verify did not confirm $DMG_PATH valid."
  echo "::error::Notarization submit will fail. Output:"
  sed 's/^/::error::  /' /tmp/csq-dmg-verify.txt
  exit 1
fi
echo "DMG signature gate OK: $DMG_PATH valid on disk + satisfies DR."
```

### 5. Submit to Apple's notary service

```bash
xcrun notarytool submit "$DMG_PATH" \
  --keychain-profile csq-notary \
  --wait | tee /tmp/csq-notary-submit.txt
```

`--wait` blocks until notarization completes (typically 2–15 min; first submission of the session may take longer if Apple's notary backend hasn't seen recent traffic from your Team ID). Output ends with `status: Accepted` on success. On `status: Invalid`, fetch the log:

```bash
xcrun notarytool log <submission-id> --keychain-profile csq-notary
```

Common failure modes:

- Missing `--options runtime` on the `.app` signature → re-do step 2.
- Missing `--timestamp` on either signature → re-do steps 2 or 4.
- Embedded binary (in `Contents/MacOS/` or `Contents/Frameworks/`) is unsigned or signed without hardened runtime → `--deep` should have caught this; check `codesign -dvvv` on the failing path.

**MANDATORY regression gate — notarization Accepted.** Some `notarytool`
versions exit 0 even on `status: Invalid`; assert the captured output
explicitly so a rejected submission cannot scroll past into stapling.

```bash
set -e
if ! grep -q 'status: Accepted' /tmp/csq-notary-submit.txt; then
  echo "::error::notarytool did NOT report 'status: Accepted'. Do not"
  echo "::error::staple a non-notarized DMG. Captured submit output:"
  sed 's/^/::error::  /' /tmp/csq-notary-submit.txt
  echo "::error::Fetch the log: xcrun notarytool log <id> --keychain-profile csq-notary"
  exit 1
fi
echo "Notarization gate OK: status: Accepted."
```

**Keychain-lock troubleshooting (gap from v2.7.8 cut, an internal journal entry):** if `notarytool submit` or `notarytool history` reports

```
Error: No Keychain password item found for profile: csq-notary
```

for a credential that worked earlier in the session, the **keychain is locked**, not wiped. `notarytool`'s read paths interpret a locked keychain as "item not found"; only `store-credentials` reports the honest `keychainLocked` error. Fix:

```bash
security unlock-keychain ~/Library/Keychains/login.keychain-db
```

(prompts for macOS login password; holds for the rest of the shell session). Retry the failing command — no re-store needed.

Note: `security show-keychain-info ... no-timeout` reports the auto-lock POLICY, not the CURRENT lock state. The keychain can be locked after screen-lock, sleep, or explicit lock despite the `no-timeout` line.

**`security` CLI cannot confirm the profile's absence (gap from v2.9.0 cut, an internal journal entry).** Modern `notarytool store-credentials` writes to the macOS **data-protection keychain**, which the legacy `security` CLI does NOT enumerate. `security find-generic-password`, `security dump-keychain | grep notary`, and any nonexistent-service probe will ALL report "not found" whether the profile exists or not — they are structurally blind, not evidence. Do NOT conclude "the credential is genuinely gone" from a `security` probe and do NOT recommend re-running `store-credentials` on that basis. The ONLY authoritative existence check is `xcrun notarytool history --keychain-profile csq-notary` ITSELF, run AFTER `security unlock-keychain`. If you must confirm lock state before the user is available: `security find-generic-password -l <a-real-genp-label> -w ~/Library/Keychains/login.keychain-db` — it blocks on a `SecurityAgent` GUI prompt iff the keychain is locked. During the v2.9.0 cut every `security` probe showed "absent" while the profile was intact (proven the instant `unlock` + `notarytool history` ran — full submission history, last entry the v2.8.0 cut).

### 6. Staple the notary ticket

Staple BOTH the DMG and the standalone `.app`. The DMG staple covers the first-install download; the `.app` staple is required for the auto-updater path (§7a re-tars the standalone `.app` — if it has no staple, Gatekeeper falls back to online lookup on first launch after update, breaking offline users and adding launch latency).

```bash
xcrun stapler staple "$DMG_PATH"
xcrun stapler validate "$DMG_PATH"

xcrun stapler staple "$APP_BUNDLE"
xcrun stapler validate "$APP_BUNDLE"
```

**MANDATORY regression gate — BOTH artifacts stapled.** This is the
an internal journal entry defect (prior runbook stapled only the DMG, leaving the
standalone `.app` unstapled — the auto-updater path §7a then shipped an
unstapled `.app`). Assert `stapler validate` succeeds for BOTH.

```bash
set -e
for artifact in "$DMG_PATH" "$APP_BUNDLE"; do
  if ! xcrun stapler validate "$artifact" 2>&1 \
       | tee /tmp/csq-stapler.txt | grep -q 'The validate action worked'; then
    echo "::error::stapler validate FAILED for: $artifact"
    echo "::error::An unstapled artifact forces Gatekeeper online on first"
    echo "::error::launch (breaks offline/air-gapped users; an internal journal entry)."
    echo "::error::Re-run notarize (§5) then staple (§6). Output:"
    sed 's/^/::error::  /' /tmp/csq-stapler.txt
    exit 1
  fi
done
echo "Staple gate OK: BOTH the DMG and the standalone .app are stapled."
```

Stapling embeds Apple's "notarized" receipt INTO the artifact, so Gatekeeper accepts it offline. Without stapling, Gatekeeper has to phone home on first launch — slower and breaks for users on air-gapped or restricted networks.

(Gap from v2.7.8 cut, an internal journal entry: prior runbook stapled only the DMG, leaving the standalone `.app` unstaple-validated.)

### 7. Smoke-test

```bash
set -e
# spctl prints the assessment to stderr; capture both streams.
spctl --assess --type install --verbose "$DMG_PATH" 2>&1 \
  | tee /tmp/csq-spctl-dmg.txt
if ! grep -q 'source=Notarized Developer ID' /tmp/csq-spctl-dmg.txt; then
  echo "::error::DMG spctl assessment is NOT 'Notarized Developer ID'."
  echo "::error::'source=Developer ID' (no 'Notarized') = stapler step"
  echo "::error::failed; re-do §6. Captured:"
  sed 's/^/::error::  /' /tmp/csq-spctl-dmg.txt
  exit 1
fi

# Mount + check the .app inside the DMG.
hdiutil attach "$DMG_PATH"
spctl --assess --type execute --verbose "/Volumes/Code Squad Q/Code Squad Q.app" 2>&1 \
  | tee /tmp/csq-spctl-app.txt
hdiutil detach "/Volumes/Code Squad Q"
if ! grep -q 'source=Notarized Developer ID' /tmp/csq-spctl-app.txt; then
  echo "::error::.app inside the DMG is NOT 'Notarized Developer ID'."
  echo "::error::Captured:"
  sed 's/^/::error::  /' /tmp/csq-spctl-app.txt
  exit 1
fi
echo "Smoke gate OK: DMG + embedded .app both Notarized Developer ID."
```

Both checks MUST report `source=Notarized Developer ID`. `source=Developer ID` (without "Notarized") means the cert is valid but the stapler step failed — re-do step 6.

### 7a. Produce the auto-updater bundle from the signed `.app`

The Tauri auto-updater plugin reads `csq-desktop-macos.app.tar.gz` from the release and atomically replaces the installed copy on disk. Gatekeeper enforces a "same Team ID across updates" rule: once a user installs the Developer-ID-signed DMG, every subsequent auto-update MUST carry the same Developer ID signature, or the update fails to launch. The tarball MUST therefore wrap the SIGNED + NOTARIZED + STAPLED `.app` — not the unsigned bundle Tauri produces by default.

```bash
APP_TARBALL="csq-desktop-macos.app.tar.gz"

# Tar from inside the bundle directory so the archive's top-level entry is
# "Code Squad Q.app/" (matches what tauri-plugin-updater expects).
#
# COPYFILE_DISABLE=1 is MANDATORY. After step 6 staples the notary ticket,
# the .app carries Apple extended attributes (com.apple.provenance, the
# stapled receipt, quarantine). macOS BSD `tar` serializes xattrs as
# `._<name>` AppleDouble companion entries unless COPYFILE_DISABLE is set.
# The Tauri updater unpacks with the Rust `tar` crate, which chokes on the
# top-level `._Code Squad Q.app` entry with:
#   failed to unpack `._Code Squad Q.app` into <tmpdir>
# breaking auto-update for every macOS user. (Root cause: v2.7.8 cut;
# an internal journal entry)
( cd "$(dirname "$APP_BUNDLE")" && COPYFILE_DISABLE=1 tar czf "$OLDPWD/$APP_TARBALL" "$(basename "$APP_BUNDLE")" )

# Verify the archive layout AND that NO AppleDouble entries leaked in.
tar tzf "$APP_TARBALL" | head -3
# Expected:
#   Code Squad Q.app/
#   Code Squad Q.app/Contents/
#   Code Squad Q.app/Contents/_CodeSignature/

# MANDATORY regression gate — AppleDouble guard. Counts `._*` basename
# entries anywhere in the archive. MUST be 0. A non-zero count means
# COPYFILE_DISABLE was not honored (e.g. tar aliased to gtar with a
# different env contract) — DO NOT upload; the updater will fail.
adouble_count=$(tar tzf "$APP_TARBALL" | grep -c '/\._\|^\._' || true)
if [ "$adouble_count" -ne 0 ]; then
  echo "::error::$adouble_count AppleDouble (._*) entries in $APP_TARBALL — updater WILL fail. Re-tar with COPYFILE_DISABLE=1."
  tar tzf "$APP_TARBALL" | grep '/\._\|^\._' | head -5
  exit 1
fi
echo "AppleDouble guard: 0 ._* entries — tarball is updater-safe."
```

### 7b. Minisign the auto-updater bundle

The auto-updater verifies the tarball's minisign signature against the Foundation Ed25519 public key baked into the app (key ID `F1C2F7FD79F952DD`, base64-encoded at `csq/tauri.conf.json:plugins.updater.pubkey`). The signing key lives in the `TAURI_SIGNING_PRIVATE_KEY` GH Actions secret used by CI; the maintainer's local copy is at **`~/.tauri/csq-updater.key`** (Tauri's default `signer generate` path; the 1Password vault `csq-tauri-signing-key` mentioned in earlier runbook drafts is an aspirational backup, not the primary store). Empty passphrase.

**Parity check before signing** (catches a key-drift between local and GH Actions secret — runs in <1 second):

The maintainer-box `~/.tauri/csq-updater.key.pub` is stored base64-encoded (Tauri `signer generate` default), NOT raw minisign text. The prior raw-text `diff` here ALWAYS false-positived "PUBKEY DRIFT" on the real box (verified 2026-05-17 during the v2.7.8 retro-fix; an internal journal entry). This normalizes BOTH sides (base64-or-raw) to the minisign key-body line, then compares.

```bash
python3 - <<'PY'
import base64, json, pathlib, sys

def norm(s: str) -> str:
    s = s.strip()
    if not s.startswith("untrusted comment:"):   # base64-wrapped → decode once
        s = base64.b64decode(s).decode().strip()
    body = [l for l in s.splitlines() if not l.startswith("untrusted comment:")]
    return body[0].strip() if body else ""

baked = norm(base64.b64decode(
    json.load(open("csq/tauri.conf.json"))["plugins"]["updater"]["pubkey"]).decode())
local = norm(pathlib.Path.home().joinpath(".tauri/csq-updater.key.pub").read_text())
print("PUBKEY PARITY OK" if baked and baked == local else "PUBKEY DRIFT — DO NOT SIGN")
sys.exit(0 if baked and baked == local else 1)
PY
```

If `PUBKEY DRIFT` appears, **STOP** — signing with a key whose public component doesn't match the baked pubkey breaks auto-updater verification for every existing v2.7.x user (silent failure: app rejects the update with no user-visible error).

```bash
# Sign the tarball. Use env var (TAURI_SIGNING_PRIVATE_KEY_PASSWORD) rather
# than the --password CLI flag: the flag puts the password in `ps` output
# where any same-UID process can see it during the brief signing window.
cd csq && env TAURI_SIGNING_PRIVATE_KEY_PASSWORD="" \
  npx @tauri-apps/cli signer sign \
    --private-key-path ~/.tauri/csq-updater.key \
    "$OLDPWD/$APP_TARBALL"
cd -

# Result: $APP_TARBALL.sig is created alongside the tarball.
ls -la "$APP_TARBALL" "$APP_TARBALL.sig"
```

(Gap from v2.7.8 cut, an internal journal entry: prior runbook directed the maintainer to load the key from a 1Password vault that did not exist; key was on disk all along at the Tauri default path.)

### 7c. Rename for upload

CI uses platform-stable filenames (`csq-desktop-<platform>.<ext>`); the maintainer artifacts MUST match.

**MANDATORY regression gate — `.sig` decodes ONCE to a minisign header.**
This single gate defends TWO drift defects at once:

- **j0052 signer-flag** (`signer sign -k` vs `--private-key-path`): if §7b
  ran with the wrong flag, no `.sig` is produced — this block fails on the
  missing/empty file before anything is uploaded.
- **j0053 double-base64**: the v2.7.8 retro-fix script `base64`'d an
  already-encoded `.sig`, so the field decoded to _another base64 blob_
  instead of a minisign file, and Tauri's updater aborted with "Invalid
  encoding in minisign data". A correct `.sig` base64-decodes EXACTLY ONCE
  to text beginning `untrusted comment:`. Decoding twice (or zero times)
  is the bug signature.

This is the local mirror of `release.yml`'s `read_sig()` invariant (it
`cat`s the `.sig` verbatim — never re-encodes it). §8a re-checks the same
property against the _published_ `latest.json` end-to-end.

```bash
set -e
SIG="$APP_TARBALL.sig"
if [ ! -s "$SIG" ]; then
  echo "::error::$SIG missing or empty. §7b signing did not produce a"
  echo "::error::signature — check the signer flag was --private-key-path"
  echo "::error::(NOT -k) and TAURI_SIGNING_PRIVATE_KEY_PASSWORD was set."
  echo "::error::(j0052 signer-flag drift defect.)"
  exit 1
fi
# Decode the .sig body ONCE. A correct Tauri/minisign .sig decodes to a
# file whose first line is the minisign 'untrusted comment:' header.
decoded_head=$(base64 -d < "$SIG" 2>/dev/null | head -c 18 || true)
if [ "$decoded_head" != "untrusted comment:" ]; then
  echo "::error::$SIG does NOT base64-decode once to a minisign header."
  echo "::error::Got first 18 bytes: '$decoded_head' (expected"
  echo "::error::'untrusted comment:'). If this looks like more base64,"
  echo "::error::the .sig was double-encoded — this is the EXACT j0053"
  echo "::error::defect that broke the macOS updater. Do NOT upload."
  echo "::error::latest.json embeds .sig VERBATIM (release.yml read_sig"
  echo "::error::= cat); never base64 it again."
  exit 1
fi
echo "Sig-encoding gate OK: $SIG decodes once to a minisign header."
```

```bash
# DMG: rename to the CI-stable name
mv "$DMG_PATH" "csq-desktop-macos.dmg"

# Tarball + sig already named correctly (csq-desktop-macos.app.tar.gz + .sig)

# Compute SHA256 sidecars for the release SHA256SUMS file
shasum -a 256 csq-desktop-macos.dmg          | awk '{print $1}' > csq-desktop-macos.dmg.sha256
shasum -a 256 csq-desktop-macos.app.tar.gz   | awk '{print $1}' > csq-desktop-macos.app.tar.gz.sha256
```

**MANDATORY regression gate — all three upload artifacts exist post-rename.**

```bash
set -e
for f in csq-desktop-macos.dmg csq-desktop-macos.app.tar.gz csq-desktop-macos.app.tar.gz.sig; do
  [ -s "$f" ] || { echo "::error::missing/empty upload artifact: $f"; exit 1; }
done
echo "Rename gate OK: 3 upload artifacts present (.dmg, .app.tar.gz, .sig)."
```

Final set of maintainer-produced files for upload:

- `csq-desktop-macos.dmg`
- `csq-desktop-macos.app.tar.gz`
- `csq-desktop-macos.app.tar.gz.sig`

(The `.sha256` sidecars are read by the publish job, not uploaded as separate assets — they roll up into the combined `SHA256SUMS` file.)

### 8. Upload to GitHub release (stable tag flow)

For STABLE tags (`vX.Y.Z`, no suffix), the workflow skips the macOS branch of the `build-desktop` matrix entirely. The maintainer's three artifacts MUST be on the release BEFORE the workflow's publish job runs — the publish job validates their presence and fails closed if missing.

```bash
# 1. Capture the EXACT commit SHA you're cutting from. `--target main`
#    would create a tag-ref pointing at "wherever main is when gh runs";
#    if main advances between draft-create and tag-push, the draft
#    release and the pushed tag diverge to different commits. Pinning
#    via SHA eliminates that race.
VERSION="2.7.8"
TAG="v${VERSION}"
git fetch origin main
SHA=$(git rev-parse origin/main)
echo "Cutting $TAG at $SHA"

# 2. Create the draft release pinned to that SHA.
gh release create "$TAG" \
  --draft \
  --title "v${VERSION}" \
  --notes-file "docs/releases/v${VERSION}.md" \
  --target "$SHA"

# 3. Upload the three macOS artifacts.
gh release upload "$TAG" \
  csq-desktop-macos.dmg \
  csq-desktop-macos.app.tar.gz \
  csq-desktop-macos.app.tar.gz.sig

# 3a. MANDATORY regression gate — the upload landed BEFORE the tag push.
#     The tag push (step 4) triggers the workflow; if the upload silently
#     failed (network, auth, rate-limit) the workflow's "Validate
#     maintainer macOS artifacts" step fails the whole release. Catch it
#     here while recovery is still a re-upload, not a re-cut.
set -e
gh release view "$TAG" --repo terrene-foundation/csq \
  --json assets --jq '.assets[].name' > /tmp/csq-rel-assets.txt
for f in csq-desktop-macos.dmg csq-desktop-macos.app.tar.gz csq-desktop-macos.app.tar.gz.sig; do
  grep -qxF "$f" /tmp/csq-rel-assets.txt || {
    echo "::error::$f did NOT land on draft $TAG. Re-run step 3 before"
    echo "::error::pushing the tag — the workflow fails closed if it is"
    echo "::error::missing at publish time. Draft assets seen:"
    sed 's/^/::error::  /' /tmp/csq-rel-assets.txt
    exit 1
  }
done
echo "Upload gate OK: 3 maintainer artifacts on draft $TAG; safe to tag."

# 4. Push the tag at the SAME SHA — this triggers the Release workflow.
git tag "$TAG" "$SHA"
git push origin "$TAG"

# 5. Monitor: the workflow's "Validate maintainer macOS artifacts" step
#    confirms the three files are present and fails the release otherwise.
gh run watch --repo terrene-foundation/csq

# 6. After the workflow completes, the release is ALREADY un-drafted by
#    softprops/action-gh-release@v2 (the action's default is draft=false
#    and the workflow doesn't override it — see release.yml:731-735).
#    This explicit un-draft is a no-op against the current workflow but
#    is kept here as a fail-safe in case the workflow's softprops input
#    is changed to `draft: true` in the future.
gh release edit "$TAG" --draft=false 2>/dev/null || true
```

(Gap from v2.7.8 cut, an internal journal entry: prior runbook treated step 6 as load-bearing for the §8a verification gate. In practice softprops auto-un-drafts, so §8a checks run post-publish. Recovery if §8a finds an issue: hotfix re-release at the next patch version. The workflow's pre-publish "Validate maintainer macOS artifacts" gate is the only check that fails closed and prevents publish.)

For PRERELEASE tags (`vX.Y.Z-rc.N`, `-alpha.N`, `-beta.N`), the workflow continues to use the ad-hoc-codesign fallback at `.github/workflows/release.yml` and produces the macOS artifacts itself. The maintainer does not need to sign RCs.

### 8a. Verification gate (executable — run before trusting the cut)

The old version of this section was a manual `- [ ]` checklist. Journal
0053 proved that a tired operator "verifying" a string match can
re-derive the _expected_ value with the same broken transform and pass a
checkbox tautologically (0052's `base64(.sig)`-self-compare masked the
double-encode bug). The fix per an internal journal entry: this is now a single
`set -e`-guarded block whose centerpiece is a real `minisign -V` of the
**published** `latest.json` signature against the **published** tarball
using the **baked** pubkey — a check that _cannot_ pass on a mis-encoded
field, because cryptographic verification of `base64(base64(sig))` fails
by construction.

Run this AFTER `gh run watch` reports the Release workflow succeeded.

```bash
set -euo pipefail

# minisign is the definitive check (j0053). It is mandatory, not optional.
command -v minisign >/dev/null || {
  echo "::error::minisign not installed — the definitive §8a check cannot"
  echo "::error::run. brew install minisign, then re-run this gate."
  exit 1
}

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

# 1. Presence: all maintainer + workflow-produced assets on the tag.
gh release view "$TAG" --repo terrene-foundation/csq \
  --json assets --jq '.assets[].name' | sort > "$WORK/tag-assets.txt"
for f in csq-desktop-macos.dmg csq-desktop-macos.app.tar.gz \
         csq-desktop-macos.app.tar.gz.sig \
         csq-desktop-linux.AppImage csq-desktop-linux.AppImage.sig \
         csq-desktop-windows-setup.exe csq-desktop-windows-setup.exe.sig \
         SHA256SUMS SHA256SUMS.sig latest.json; do
  grep -qxF "$f" "$WORK/tag-assets.txt" || {
    echo "::error::$TAG is missing asset: $f"; exit 1; }
done
echo "  ✓ all 10 expected assets present on $TAG"

# 2. The auto-updater pointer (the `updater-manifest` release) is the
#    field that broke in j0053 — verify THAT one, not just the per-tag.
gh release download updater-manifest --repo terrene-foundation/csq \
  --pattern latest.json --dir "$WORK" --clobber
gh release download "$TAG" --repo terrene-foundation/csq \
  --pattern csq-desktop-macos.app.tar.gz \
  --pattern csq-desktop-macos.app.tar.gz.sig \
  --dir "$WORK" --clobber

# 3. Verbatim + decode-once + minisign -V, all in one python block so the
#    "expected" value is never re-derived with the transform under test.
python3 - "$WORK" "$VERSION" <<'PY'
import base64, json, pathlib, subprocess, sys, tempfile

work = pathlib.Path(sys.argv[1]); version = sys.argv[2]
manifest = json.loads((work / "latest.json").read_text())

if manifest.get("version") != version:
    sys.exit(f"::error::latest.json version={manifest.get('version')!r} "
             f"!= cut version {version!r} — stale/wrong manifest "
             f"(the j0054 version-incoherence defect, end-to-end).")

# darwin-aarch64 + darwin-x86_64 are BOTH expected and BOTH must point at
# the same universal `.app.tar.gz` + same signature (Option A — one fat
# Mach-O serves both arches). Verify each key independently; an asymmetric
# manifest (one key present, the other missing or pointing elsewhere) is
# the failure mode this loop catches. See workspace
# `an internal workspace/an internal journal entry` (security-reviewer F9,
# requirements-analyst F10).
platforms = manifest.get("platforms", {})
for required_key in ("darwin-aarch64", "darwin-x86_64"):
    if required_key not in platforms:
        sys.exit(f"::error::latest.json missing required platform key "
                 f"{required_key!r}. Under Option A both darwin keys "
                 f"MUST be present and point at the same universal "
                 f"`.app.tar.gz`. Stable releases fail-closed when any "
                 f"expected platform is missing (release.yml "
                 f"'Generate latest.json' step).")
darwin_aarch64 = platforms["darwin-aarch64"]
darwin_x86_64  = platforms["darwin-x86_64"]
# Spec 14 INV-02 (universal-binary). Revisit BOTH assertions below
# if INV-02 changes (e.g., switching to per-arch artifacts in a
# future cycle). The spec's "When to break INV-02" section lists
# every touch-point that must change atomically.
if darwin_aarch64["url"] != darwin_x86_64["url"]:
    sys.exit("::error::darwin-aarch64.url != darwin-x86_64.url — under "
             "Option A (universal binary) both keys MUST point at the "
             "same csq-desktop-macos.app.tar.gz. Asymmetric manifest "
             "would break either Intel or Apple Silicon auto-update.")
if darwin_aarch64["signature"] != darwin_x86_64["signature"]:
    sys.exit("::error::darwin-aarch64.signature != darwin-x86_64.signature "
             "— under Option A the same .sig serves both keys.")

field = darwin_aarch64["signature"]
sig_file = (work / "csq-desktop-macos.app.tar.gz.sig")
sig_verbatim = sig_file.read_text()

# (a) VERBATIM: the field must equal `cat .sig` exactly — this is the
#     release.yml read_sig() invariant (it cat's, never re-encodes).
if field != sig_verbatim:
    sys.exit("::error::latest.json darwin-aarch64.signature != .sig "
             "VERBATIM. release.yml read_sig() embeds it with `cat`; any "
             "difference means a re-encode crept in (j0053). Field len="
             f"{len(field)} .sig len={len(sig_verbatim)}.")

# (b) DECODE-ONCE: the field base64-decodes EXACTLY once to a minisign
#     file. Decoding to more base64 is the j0053 double-encode signature.
try:
    decoded = base64.b64decode(field, validate=True)
except Exception as e:
    sys.exit(f"::error::signature field is not valid base64: {e}")
if not decoded.startswith(b"untrusted comment:"):
    sys.exit("::error::field decodes ONCE to something that is NOT a "
             f"minisign file (starts {decoded[:18]!r}). If it looks like "
             "more base64, this is the EXACT j0053 double-encode that "
             "broke the macOS updater. DO NOT trust this cut.")

# (c) DEFINITIVE: minisign -V of the decoded sig against the published
#     tarball, using the baked pubkey. Cannot pass on a mis-encoded field.
pub_b64 = json.loads(
    pathlib.Path("csq/tauri.conf.json").read_text()
)["plugins"]["updater"]["pubkey"]
pub_text = base64.b64decode(pub_b64).decode()           # minisign .pub file
sig_path = work / "decoded.minisig"; sig_path.write_bytes(decoded)
pub_path = work / "baked.pub";       pub_path.write_text(pub_text)
tarball  = work / "csq-desktop-macos.app.tar.gz"

r = subprocess.run(
    ["minisign", "-V", "-p", str(pub_path), "-m", str(tarball),
     "-x", str(sig_path)],
    capture_output=True, text=True)
if r.returncode != 0 or "verified" not in (r.stdout + r.stderr).lower():
    sys.exit("::error::minisign -V FAILED — the published manifest "
             "signature does NOT verify against the published tarball "
             f"with the baked pubkey. THIS IS THE j0053 CLASS.\n"
             f"::error::  stdout: {r.stdout.strip()}\n"
             f"::error::  stderr: {r.stderr.strip()}")

print("  ✓ verbatim == read_sig(); decodes once to minisign header;")
print(f"  ✓ minisign -V: {(r.stdout + r.stderr).strip()}")
print("§8a GATE PASSED — manifest signature is cryptographically valid.")
PY

# 4. Download the DMG and re-run the §7 smoke against the PUBLISHED bytes.
gh release download "$TAG" --repo terrene-foundation/csq \
  --pattern csq-desktop-macos.dmg --dir "$WORK" --clobber
spctl --assess --type install --verbose "$WORK/csq-desktop-macos.dmg" 2>&1 \
  | tee "$WORK/spctl.txt"
grep -q 'source=Notarized Developer ID' "$WORK/spctl.txt" || {
  echo "::error::published DMG is NOT Notarized Developer ID"; exit 1; }
echo "§8a COMPLETE — published artifacts verified end-to-end."
```

Any `::error::` above: do NOT trust the cut. The recovery is a hotfix
re-release at the next patch version (the release is already published by
the time §8a runs — see the §8 gap note). Diagnose against the specific
failing assertion; each maps to a named journal defect.

### 8b. Known limitation — ad-hoc-signed prereleases cannot auto-update to Developer-ID-signed stables

Gatekeeper enforces a "same Team ID across updates" rule
(`docs/release-signing.md` §7's Designated-Requirement chain). The
implication: anyone who installs a **prerelease** desktop build
(`-alpha`/`-beta`/`-rc` — these use the CI ad-hoc-codesign path with NO
Team ID) cannot auto-update to a **stable** desktop build (maintainer
Developer-ID-signed, real Team ID). The auto-update applies the new
bundle to disk but Gatekeeper refuses to launch it; the user sees a
"developer cannot be verified" prompt with no working bypass.

**This is not new to Intel.** Apple Silicon users on prereleases hit the
same wall when crossing to a stable cut. It is named here because the
Intel desktop launch makes the crossover more visible (every Intel
desktop installation today is from a prerelease — there has never been a
stable Intel desktop until the universal-binary cut).

**Recovery for affected users:** one-time manual reinstall of the stable
DMG from the GitHub release page. The next auto-update from stable v(N)
to stable v(N+1) works normally (same signing identity).

**Affected population estimate:** any user who installed a prerelease
csq-desktop bundle. CLI users are unaffected — the CLI does not invoke
`tauri-plugin-updater`.

**Release-notes guidance:** when promoting the first Intel-aware stable
release, the notes SHOULD include a sentence such as:

> Intel Mac users installing csq desktop for the first time, and any
> user previously running a prerelease build, should download the
> stable DMG from the release page once. Subsequent updates apply
> automatically.

See workspace `an internal workspace/an internal journal entry` (security-reviewer F8)
for the structural framing.

### 9. WINDOW-CLOSE gate — release N+1 precondition (RN1-E)

This gate is **NOT run on every release cut**. It is the structural
precondition for shipping the irreversible RN1-F (M4-13) deletion of
`ProfilesFile::accounts`. Run this immediately before deciding whether
the cut about to be tagged is allowed to include the RN1-F deletion.
If the gate prints `OPEN`, the release MUST cut without RN1-F and the
deletion waits for the next cycle.

The gate is `WINDOW-CLOSE = P1 ∧ P2 ∧ P3` (spec:
`internal-design-docs`):

- **P1 — local quiescence:** `csq doctor --json` emits zero
  `legacy_compat_state` entries of the three in-scope kinds
  (`v1_accounts_field_still_present`, `legacy_canonical_credentials_file_still_written`,
  `legacy_canonical_codex_credentials_file_still_written`).
  `decimal_marker_content_present` is **explicitly excluded** — it
  retires in a different, later shard and gating M4-13 on it would
  couple release N+1 to unrelated future work.
- **P2 — soak floor:** ≥ N consecutive stable-release cycles since the
  release-N anchor tag. **N = 2** (owner-overridable to 1 via
  `WINDOW_CLOSE_N=1`; an internal journal entry owner-approved default). Stable tag
  = `vX.Y.Z` (no pre-release suffix). v2.7.7 and v2.7.8 are treated as
  one release-N band; the anchor is v2.7.8 so v2.8.0 counts as the
  first elapsed cycle.
- **P3 — label-relocation soaked:** RN1-D5b's one-shot sentinel
  (`<accounts-base>/label-channel-migrated`, written by
  `csq_core::accounts::profiles::label_relocation_sentinel_path`,
  consumed abstractly here) exists AND its mtime is older than the
  **most-recent already-published stable tag's date** — proves the
  relocation ran in a release cycle **before** the current cut, i.e.
  has soaked across ≥ 1 full cycle on this host. (Comparing against
  the release-N anchor tag instead is structurally unsatisfiable:
  RN1-D5b's relocation code shipped post-anchor in v2.8.0 — an internal ticket —
  so the sentinel's mtime is ≥ anchor by construction on every host
  that ever ran the migration. The intent is "soaked across ≥ 1 cycle";
  the most-recent stable tag is the closest predecessor that proves
  it.)

Output is one line, exit-coded:

- `WINDOW-CLOSE: closed (P1 ✓ ... | P2 ✓ ... | P3 ✓ ...)` on exit 0
- `WINDOW-CLOSE: OPEN — <which predicate failed and why>` on non-zero
  exit (each predicate has its own exit code so the runbook reader can
  branch mechanically)

```bash
#!/usr/bin/env bash
# WINDOW-CLOSE gate — RN1-E (release N+1 / M4-13 precondition).
# Spec: internal-design-docs
# Owner-approved default N=2 (an internal journal entry); override with WINDOW_CLOSE_N=1.
set -euo pipefail

command -v jq >/dev/null 2>&1 || { echo "WINDOW-CLOSE: OPEN — jq missing (install jq to evaluate P1)"; exit 8; }

N="${WINDOW_CLOSE_N:-2}"
# v2.7.7/v2.7.8 are the release-N band (OQ-C §2); v2.7.8 is the anchor
# so v2.8.0 onward counts as elapsed stable cycles.
RELEASE_N_TAG="${WINDOW_CLOSE_RELEASE_N_TAG:-v2.7.8}"
BASE_DIR="${WINDOW_CLOSE_BASE_DIR:-${HOME}/.claude/accounts}"
# Sentinel path is the live value of
# csq_core::accounts::profiles::label_relocation_sentinel_path(base) —
# see csq-core/src/accounts/profiles.rs (post-RN1-D-merge HEAD).
# If that helper's path moves, update the literal below.
SENTINEL="$BASE_DIR/label-channel-migrated"

# P1 — local quiescence: zero in-scope legacy_compat_state bridges.
P1_KINDS='v1_accounts_field_still_present legacy_canonical_credentials_file_still_written legacy_canonical_codex_credentials_file_still_written'
if ! P1_REPORT="$(csq doctor --json 2>/dev/null)"; then
  echo "WINDOW-CLOSE: OPEN — P1: csq doctor --json failed (binary missing or daemon error)"
  exit 1
fi
P1_BRIDGES="$(printf '%s' "$P1_REPORT" | jq --arg kinds "$P1_KINDS" '
  [ (.legacy_compat_state // [])[]
    | select(.kind as $k | ($kinds | split(" ") | index($k))) ]
  | length
')"
if [ "$P1_BRIDGES" -ne 0 ]; then
  echo "WINDOW-CLOSE: OPEN — P1: $P1_BRIDGES in-scope legacy_compat_state bridge(s) remain (kinds: $P1_KINDS)"
  exit 2
fi

# P2 — soak floor: ≥ N stable-tag cycles since the release-N anchor.
ANCHOR_LINE="$(git for-each-ref --format='%(refname:short) %(creatordate:unix)' "refs/tags/$RELEASE_N_TAG" 2>/dev/null || true)"
if [ -z "$ANCHOR_LINE" ]; then
  echo "WINDOW-CLOSE: OPEN — P2: anchor tag $RELEASE_N_TAG not found in this checkout"
  exit 3
fi
ANCHOR_DATE="$(printf '%s' "$ANCHOR_LINE" | awk '{print $2}')"
P2_COUNT="$(git for-each-ref --sort=creatordate \
  --format='%(refname:short) %(creatordate:unix)' refs/tags \
  | awk -v anchor="$ANCHOR_DATE" '
      $1 ~ /^v[0-9]+\.[0-9]+\.[0-9]+$/ && $2+0 > anchor+0 { n++ }
      END { print n+0 }
    ')"
if [ "$P2_COUNT" -lt "$N" ]; then
  echo "WINDOW-CLOSE: OPEN — P2: only $P2_COUNT stable cycle(s) since $RELEASE_N_TAG (need $N)"
  exit 4
fi

# P3 — label-relocation soaked: sentinel exists AND mtime predates the
# most-recent already-published stable tag's date. (Comparing against
# the release-N anchor would be structurally unsatisfiable: RN1-D5b's
# relocation code shipped post-anchor in v2.8.0 / an internal ticket, so the
# sentinel's mtime is ≥ anchor by construction on every host that ever
# ran the migration. The intent is "soaked across ≥ 1 cycle"; the most-
# recent stable tag is the closest predecessor that proves it.)
if [ ! -f "$SENTINEL" ]; then
  echo "WINDOW-CLOSE: OPEN — P3: label-relocation sentinel absent at $SENTINEL"
  exit 5
fi
if   stat -f %m "$SENTINEL" >/dev/null 2>&1; then SENTINEL_MTIME="$(stat -f %m "$SENTINEL")"   # BSD/macOS
elif stat -c %Y "$SENTINEL" >/dev/null 2>&1; then SENTINEL_MTIME="$(stat -c %Y "$SENTINEL")"   # GNU/Linux
else echo "WINDOW-CLOSE: OPEN — P3: cannot stat sentinel mtime"; exit 6; fi
MOST_RECENT_STABLE_LINE="$(git for-each-ref --sort=-creatordate \
  --format='%(refname:short) %(creatordate:unix)' refs/tags \
  | awk '$1 ~ /^v[0-9]+\.[0-9]+\.[0-9]+$/ { print; exit }')"
if [ -z "$MOST_RECENT_STABLE_LINE" ]; then
  echo "WINDOW-CLOSE: OPEN — P3: no stable tag found in this checkout to compare sentinel mtime against"
  exit 9
fi
MOST_RECENT_STABLE_TAG="$(printf '%s' "$MOST_RECENT_STABLE_LINE" | awk '{print $1}')"
MOST_RECENT_STABLE_DATE="$(printf '%s' "$MOST_RECENT_STABLE_LINE" | awk '{print $2}')"
if [ "$SENTINEL_MTIME" -ge "$MOST_RECENT_STABLE_DATE" ]; then
  echo "WINDOW-CLOSE: OPEN — P3: sentinel mtime $SENTINEL_MTIME not older than $MOST_RECENT_STABLE_TAG ($MOST_RECENT_STABLE_DATE) — not soaked across the most-recent stable cycle"
  exit 7
fi

echo "WINDOW-CLOSE: closed (P1 ✓ 0 in-scope bridges | P2 ✓ $P2_COUNT stable cycles since $RELEASE_N_TAG | P3 ✓ sentinel older than $MOST_RECENT_STABLE_TAG)"
exit 0
```

**Why this is a runbook step and NOT a CI gate.** P1 surveys the
operator's host, not the user population. P2 reads the git tag ledger,
which is reproducible in CI but pointless without the human gate. P3
reads `~/.claude/accounts/`, which CI cannot observe meaningfully. The
gate is owner-authoritative; CI is an advisor at best (and currently
not wired — see "Optional CI echo" below for the trade-off).

**P1 local-vs-population caveat.** P1 proves the maintainer host has
no in-scope bridges. P2 is the structural compensation: ≥ N stable
release cycles between release N and the cut means real users have had
≥ N opportunities to upgrade and let the daemon clear the bridges via
the M4-12/M4-13 silent-removal paths. A pathological never-runs-the-daemon
install is invisible to P1; the M4-12/M4-13 idempotent self-heal paths
in `csq_core::daemon::startup_reconciler` cover that residual the same
way they cover the journal-0041 case — the gate inherits that coverage,
not better.

**Verdict authority over the irreversible deletion.** `OPEN` MUST defer
the M4-13 deletion to the next cycle. `closed` is the only verdict that
authorizes the irreversible cut. The cost asymmetry (over-wait one
extra release cycle vs ship an unrecoverable deletion against
unmigrated user state) is why N defaults to 2 and the owner override
to 1 is explicit rather than implicit.

**Tag-convention assumptions.** P2 and P3 both read the git tag ledger
via `git for-each-ref ... refs/tags`, filtering stable tags with the
regex `^v[0-9]+\.[0-9]+\.[0-9]+$`. Two conventions are structurally
assumed:

- **Annotated tags.** `creatordate:unix` returns the _tagger date_ for
  annotated tags (`git tag -a vX.Y.Z`) and falls through to the _committer
  date_ for lightweight tags (`git tag vX.Y.Z`). csq's release flow
  creates annotated tags (release.yml + manual cuts both pass `-a`). A
  hotfix cut via lightweight tag would silently shift the comparison
  axis to commit date — usually hours to days off the intended tag
  date. Re-tagging (delete + recreate) shifts `creatordate` to the
  recreate time, which is the desired behaviour for soak analysis (the
  re-tag IS the new release-date of record).
- **Tag prefix `vX.Y.Z`.** The regex anchors on `^v` and rejects any
  prefix drift (`epoch:vX.Y.Z`, `csq-vX.Y.Z`, etc.). If a future
  convention change ever ships, this §9 script must be updated in the
  same change-set — failing to do so causes the gate to silently anchor
  against the prior epoch's tags or, if no tag matches, exit 9 with
  `no stable tag found in this checkout`.

**Optional CI echo.** A non-blocking advisory echo in
`.github/workflows/release.yml` was considered and deferred: the
workflow runs in an ephemeral runner with no `csq` binary on PATH and
no `~/.claude/accounts/` content, so P1 and P3 cannot meaningfully
fire from CI. Wiring a partial echo (P2 only) would surface 1/3 of the
gate's signal with two-thirds of the visual weight, mis-cuing the
release operator. The runbook step IS the authoritative gate; CI echo
is rejected as a category error, not deferred work.

## Cert Rotation

Developer ID Application certs are valid for **5 years** from issue date. Record the expiry in a calendar reminder; re-issue 60 days before expiry to avoid release downtime. The renewal flow is identical to step 1 above — generate a fresh CSR (re-use the existing private key is acceptable but a new key per renewal is hygienic).

App-specific passwords have no formal expiry but should be rotated annually. Generate a new one, store under a new keychain-profile name (`csq-notary-2027`), then revoke the old one in <https://account.apple.com>.

## Future Work (CI-Integrated Signing)

Moving signing into GitHub Actions requires amending the `.claude/rules/ci-real-oauth-prohibition.md` Rule 1 allowlist table. As of 2026-06-10 (an internal journal entry) the table already covers the release-signing secrets that shipped in `release.yml` (`RELEASE_SIGNING_KEY`, `TAURI_SIGNING_PRIVATE_KEY`/`_PASSWORD`) plus `FOUNDATION_PAT` and the oauth-replay token — so the general publisher-signing carve-out exists. The Apple-notarization secret set below is NOT yet allowlisted. Adding it requires a Rule 1 table amendment (admin merge + per-secret justification) and an extension of Rule 1's audit-grep allowlist. The T23 self-test is not the surface to update: it only checks the bench workflow's own file, and its carrier is parked pending `csq-bench` runner provisioning (spec 10 §10.1.5).

Secrets to add (when the amendment lands):

- `APPLE_CERTIFICATE_P12_BASE64` — base64-encoded export of the Developer ID cert + private key from Keychain
- `APPLE_CERTIFICATE_PASSWORD` — password protecting the .p12 export
- `APPLE_ID` — Foundation's Apple ID email
- `APPLE_TEAM_ID` — the 10-char team identifier
- `APPLE_APP_SPECIFIC_PASSWORD` — the notary credential

The workflow imports the cert into a temporary keychain on the runner, signs/notarizes/staples, then exports the signed artifact. Keychain is deleted on workflow exit. Self-hosted macOS runner is preferred (per `.claude/rules/bench-stub-binary-policy.md` Rule 5 — same measurement-substrate logic applies to signing reliability).

That amendment + workflow change is a separate session; this runbook is the bridge until it lands.

## Cross-References

- `.github/workflows/release.yml:210-254` — current ad-hoc-codesign block (LEGACY for tagged releases once Developer ID signing is the default; remains as fallback for dev builds)
- `discovery_tauri_dmg_signing_gap.md` (auto-memory) — describes the ad-hoc workaround this runbook supersedes
- `.claude/rules/ci-real-oauth-prohibition.md` Rule 1 — blocks CI-integrated signing today; amendment required for the Future Work path
- `csq/tauri.conf.json:5` — bundle id `foundation.terrene.claude-squad` (DO NOT change)
- Apple docs: <https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution>
