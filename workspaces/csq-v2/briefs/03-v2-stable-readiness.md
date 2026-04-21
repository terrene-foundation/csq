# csq v2.0.0-stable — Release Readiness Brief

**Initiative:** Bring csq from v2.0.0-alpha.21 to v2.0.0 stable.
**Mode:** Autonomous execution — no human-team constraints on effort estimates.
**Created:** 2026-04-21
**Session:** alpha.22 fixes + stable readiness pass

## Context (what's already done)

csq is at v2.0.0-alpha.21 (tag pushed 2026-04-20, release workflow green, updater-manifest pointing at alpha.21). The "Full Rust Rewrite" vision from `01-vision.md` is structurally complete: single binary, Tauri desktop app, Svelte frontend, central token refresher, in-process daemon supervisor, OAuth flow, 3P providers (MiniMax, Z.AI, Ollama), handle-dir model, quota polling. 607+ Rust tests, zero clippy warnings, zero fmt drift at last check.

This session has shipped 4 PRs fixing: square app icon (was 4× upscale from 256px raster), Ollama HTTP API switch + `find_ollama_bin` helper, `csq install` per-slot statusline migration (journal 0059), plus TF square-icon SVG assets in the website repo.

## What "stable" means for csq

Candidate definition — scrutinise in analysis:

1. **No user-blocking bugs on the golden path.** Install → login → run → swap → quota visible → auto-refresh works, on a fresh-install machine AND on an alpha.x upgrader.
2. **No credential-drift risk.** Daemon refreshers, swap, login, and OAuth flows have no known contamination paths. Every write path preserves `subscription_type` (journal precedent).
3. **Auto-update actually delivers updates.** The alpha.20 → alpha.21 transition was hit by a single-shot check-on-launch; that's fixed in alpha.21 forward. Stable must not regress.
4. **Gatekeeper story is honest.** If the DMG is unsigned, the install README says so and the `right-click → Open` path is tested. If signed, the notarization ticket is stapled. No silent "locked by Gatekeeper" surprise.
5. **The desktop app smoke-tests on a fresh macOS (and ideally Linux, Windows) profile.** Not just "tests pass in CI."
6. **All open red-team findings above LOW are resolved or explicitly mitigated.** No residual-risk deferrals.
7. **Journal + specs reflect current truth.** No stale rules, no "spec 05 stale on Z.AI" markers left from earlier sessions.

## Known open items (carry-over from earlier sessions)

1. `csq-cli/src/commands/run.rs` — re-materialize `term-<pid>/settings.json` on launch so stale merges from a prior install can't survive a global upgrade (journal 0059 second half; first half shipped as PR #145).
2. Red-team R6 — factor `set_slot_model_write` (desktop) + `write_slot_model` (CLI) into one `csq-core` helper with shared atomic-write semantics.
3. Red-team R11 — throttle `ollama-pull-progress` emit rate (currently one Tauri event per CR/LF flush; fast pulls can saturate IPC).
4. Spec 05 (3P quota polling) — stale on Z.AI (§5.4) and MiniMax GroupId (§5.3) per journal 0032.

## Newly discovered during this session

5. **ChangeModelModal first-open bug.** The modal's `$effect` has a guard `modalState.kind !== 'loading'` that skips the load on the FIRST `isOpen=false → true` edge because the initial state is `'loading'`. User never sees installed models on the first open attempt. Svelte tests mount with `isOpen=true` so the bug is not reproduced in unit tests. Severity: P1 — core feature of the Ollama slot flow is broken. Fix landed via `ollama list via HTTP API` PR does NOT address this; the Tauri command is never being invoked.

## Known limitations (acceptable or needing explicit call-out)

- `csq update install` hard-fails on placeholder Ed25519 minisign key — **Foundation signing key blocker**. Acceptable if documented; we do NOT ship stable claiming auto-update works when it doesn't.
- Apple Developer cert absent — DMG is unsigned; Gatekeeper blocks double-click launch on Sonoma+. First-run UX needs a documented `right-click → Open` path or xattr-strip hint.
- Windows named-pipe IPC (M8-03) is not implemented; daemon IPC is Unix-socket-only. Windows experience is degraded vs macOS/Linux. If we ship Windows builds, this needs either implementation or an explicit "Windows stable pending" note.

## Objectives of this analysis

- Enumerate every remaining blocker and rank by severity.
- Produce a single, prioritized release checklist.
- Validate the "stable" definition above survives red-team scrutiny (what does it miss?).
- Decide: ship v2.0.0 after the blocker list clears, or cut another alpha / beta first.

## Non-goals

- Not a feature-add cycle. Anything beyond the known-open list needs a strong argument.
- Not rewriting specs from scratch — only refreshing stale sections (spec 05 §5.3/§5.4).
- Not adding Windows pipe IPC in this cycle if it's not a v2.0 commitment — document instead.

## Success criteria

v2.0.0 stable can be cut when:

1. Every P0/P1 item on the prioritized list is fixed and verified (not journaled as accepted).
2. `cargo test --workspace`, clippy, fmt, `npm run test`, `svelte-check` all green on the stable branch.
3. A clean-install smoke test passes on a fresh macOS profile: install DMG → login → run → swap → kill daemon → relaunch → credentials still valid → quota still visible.
4. Known limitations (signing key, Windows pipe) are explicitly documented in the release notes — no silent gaps.
