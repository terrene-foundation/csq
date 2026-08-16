# Changelog

All notable changes to csq are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); version numbering follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

---

## [2.13.1] — 2026-05-27

Patch release making `csq doctor` honest on healthy, fully-migrated hosts. Two diagnostics false-positived: `decimal_marker` flagged 3P API-key slots (which carry decimal ids by design) and modern OAuth slots whose marker never got rewritten; the legacy-terminal count flagged idle-but-migrated accounts on hosts that rotate between accounts. Both now consult the canonical identity-store membership predicate, so `csq doctor` reports a clean bill on a migrated host.

### Fixed

- **`csq doctor` `decimal_marker` + legacy-terminal detectors are now identity-store-aware.** `detect_decimal_marker` counted every `config-N/.csq-account` holding a decimal slot-id as a "legacy compat bridge pending migration" — including 3P API-key slots (`by_slot_identity = apikey:*`) that carry decimal ids by design, and modern OAuth slots whose marker simply never got rewritten by login/swap. The `legacy_count` terminal heuristic counted every `config-N` with credentials not bound to a live handle dir as a "legacy terminal" — flagging idle-but-migrated accounts. Both detectors now skip slots that are recovery-backed via the new canonical `profiles::is_slot_recovery_backed` predicate (`by_slot` ∪ `by_slot_identity` ∪ regular-file `credentials/gemini-<N>.json` marker), so they fire only for genuine pre-identity-store ("pure-legacy") footprints. Trade-off: the legacy-terminal count no longer detects a direct CC session run against a migrated `config-N` (unobservable without per-process env inspection); the constant idle-account false-positive outweighed the rare missed case. (an internal ticket, closes an internal ticket)

### Internal

- **New `profiles::is_slot_recovery_backed(base, pf, n)` canonical predicate.** Extracted from the three-way recovery-backed test that was inlined in `audit_coexistence`, so all three consumers (the `audit_coexistence` orphan check, doctor `decimal_marker`, doctor `legacy_count`) share ONE keep-set and cannot drift apart (per `reconciler-cleanup-parity.md` Rule 4). 6 new regression tests (helper contract incl. symlink-rejection + the two detector paths across `by_slot` / `by_slot_identity` / gemini-marker / genuine-orphan). (an internal ticket)

---

## [2.13.0] — 2026-05-26

**A++ CLOSEOUT** plus two desktop-prefs robustness shards. The headline is the M4-13 deletion of the v1 `profiles.json::accounts` field (deprecated v2.10.0 / M4-9, soaked 6 minor versions v2.6 → v2.12; an internal ticket closed). The soak gate is satisfied: the RN1-D R3 reconciler pass (`prune_redundant_accounts_entries`, shipped v2.12.0) drained all recoverable populated `accounts` maps from every upgraded host on daemon start, so the `detect_v1_accounts_field` (`accounts.len() > 0`) WINDOW-CLOSE predicate cannot fire on any v2.12.0+ host. The field is gone from the production struct; pre-M4-13 on-disk files load cleanly via the `#[serde(flatten)]` backward-compat hatch. Bundled in the same cut: a corrupt-`desktop-prefs.json` disclosure banner and the typed `PrefsLock` / `mutate_prefs` refactor.

### Added

- **Corrupt desktop-prefs disclosure banner.** When `desktop-prefs.json` is corrupt, truncated, or hand-edited to an invalid shape and csq resets preferences to defaults, the desktop app now shows a dismissible banner informing the user and prompting them to re-apply settings like "Launch to tray" or "Hide Dock icon". Dismissal is persisted via `localStorage` and resets when a new corruption event occurs. (an internal ticket)

### Removed

- **`profiles.json::accounts` field deleted from `ProfilesFile`.** The `pub accounts: HashMap<String, AccountProfile>` struct field and the `pub struct AccountProfile` type are removed from production code. Pre-M4-13 on-disk files containing `accounts: {...}` are absorbed into `ProfilesFile::extra` via `#[serde(flatten)]`; the data is still accessible to reconciler passes through `legacy_accounts_email_map`. The `AccountProfile` struct and test helpers (`set_profile`, `accounts_for_test`) are retained under `#[cfg(any(test, feature = "test-utils"))]` for test fixtures that need to stage pre-M4-13 on-disk shapes. (an internal ticket M4-13)

### Changed

- **`get_email()` resolution order simplified.** The former step (2) — `accounts[N].email` legacy compat — is removed. The method now resolves: (1) `by_slot_label[N]`, (2) `by_slot_identity[N]`, (3) `by_slot[N] → UUID → by_email`. Every slot that had an `accounts[N]` entry recoverable via another channel has had it pruned by the RN1-D R3 pass; genuinely unrecoverable entries were already holding the WINDOW-CLOSE gate open (correct behavior — they needed re-login). (an internal ticket M4-13)

### Internal

- **New public API `legacy_accounts_email_map(pf: &ProfilesFile) -> HashMap<String, String>`.** Reads `extra["accounts"]` for any reconciler pass that needs to inspect legacy data still present in the flatten hatch. Made `pub` (not `pub(crate)`) to allow `doctor.rs` in the `csq` crate to call it. (an internal ticket M4-13)
- **4 production callsites migrated.** `identity_mint.rs`, `doctor.rs`, and the `prune_redundant_accounts_entries` internal reader all updated to use `legacy_accounts_email_map`. Test-only callsites across 9 files updated to use `set_profile` / `accounts_for_test`. (an internal ticket M4-13)
- **2 new regression tests** for the backward-compat hatch: `profiles_load_tolerates_v1_accounts_field_via_flatten` and `profiles_round_trip_preserves_v1_accounts_via_extra`. Both cover the `#[serde(flatten)]` absorption path that prevents data loss on load of a pre-M4-13 profiles file. (an internal ticket M4-13)
- **Spec 02 rev 1.19.0.** INV-07 retitled to record A++ completion and an internal ticket closure. M4-13 deletion record added. `get_email()` priority table updated. Per `rules/specs-authority.md` MUST Rule 4.
- **CLOSEOUT journal** `internal-design-docs` documents the full A++ roadmap (23 milestones across 10 sessions), the M4-13 implementation record, and the reconciler-cleanup-parity Rule 6 consumer-detection audit. an internal ticket is declared CLOSED.
- **Typed `PrefsLock` newtype + `mutate_prefs` helper for `desktop-prefs.json`.** Replaces the manually acquired `Arc<Mutex<()>>` pattern in `AppState.desktop_prefs_lock` with a `PrefsLock` newtype whose `mutate_prefs` helper enforces lock acquisition in the type system. `load_desktop_prefs` / `save_desktop_prefs` visibility tightened to `pub(in crate::desktop)` so the only write path crossing the module boundary is `mutate_prefs`. The two production mutation callsites (`apply_and_persist_dock_hidden` + `apply_and_persist_dashboard_at_launch`) are refactored to use the helper; `apply_and_persist_dock_hidden_locked` removed. Five new tests cover persistence, pre-mutation state observation, concurrent serialization (`Barrier`-coordinated), save-failure propagation, and mutex poison recovery. (an internal ticket)

---

## [2.12.0] — 2026-05-26

Minor release closing a launch-blocker on post-A++ Codex slots, eliminating a class of false `csq doctor` `INCONSISTENT` verdicts, and shipping a settings-popover refactor of the desktop dashboard header that decouples `Hide Dock icon` from the new `Open dashboard at launch` preference — two semantically distinct behaviors conflated in the v2.11.0 dock-hide feature. Auto-update propagates everything; on first launch a one-time `desktop-prefs.json` migration preserves the observed pre-refactor behavior for users who had set `Hide Dock icon` on.

### Fixed

- **Identity-store-aware codex-only slot detection.** Four desktop / daemon / CLI surfaces detected "codex-only slots" solely by the legacy `credentials/codex-<N>.json` mirror file. v2.11.0's legacy-mirror cleanup retired that mirror on upgrade — which left any post-A++ Codex slot (identity recorded as `identities/<UUID>/identity.json` provider=codex + `credentials-codex.json`) misclassified as a broken Anthropic account. Symptoms: spurious `"phase4_gate should have caught this"` WARN every 5-min poll; `csq doctor` reported `Identity store: ⚠ INCONSISTENT: MissingCredentialsAtUuidPath(<UUID>)` (and the sibling `MissingSettingsAtUuidPath`); the desktop dashboard rendered the slot dimmed (opacity 0.5) with `discover_anthropic`'s Anthropic-first dedup suppressing the healthy Codex entry; the slot's token badge showed "No token". New `csq_core::accounts::identity_store::is_codex_only_slot` is the canonical predicate (codex-bound via `identity.json` provider OR `credentials-codex.json` OR legacy marker; AND not anthropic-bound); all four surfaces (`discover_anthropic`, `audit_coexistence` MissingCredentials + MissingSettings, desktop `get_accounts` token-badge) route through it. The desktop badge derives Codex token status from the JWT `exp` claim via `http::codex::jwt_exp_secs`. (an internal ticket)
- **`csq run` launch-blocker for post-A++ Codex slots.** Direct sibling of an internal ticket: `csq run <N>` for a post-A++ Codex slot hard-failed with `Error: failed to load canonical credentials for account <N> / credential file not found: identities/<UUID>/credentials.json`. The `surface_cli_for_slot` dispatch helper keyed on the retired legacy mirror only and routed the slot to the Anthropic launch path. v2.12.0 adds the identity-keyed branch mirroring the UUID-first resolution already in `verify_codex_canonical_is_regular_file`. (an internal ticket)
- **Gemini token badge no longer shows "No token".** Same bug class as the codex desktop badge, one surface over: Gemini slots fell through to the Anthropic else-branch of the badge builder, which loads `credentials.json` at the slot's UUID — a file Gemini never writes. v2.12.0 adds a Gemini-specific branch treating the badge like a third-party slot (binary `healthy` if `has_credentials`, `missing` otherwise, no countdown) — Gemini auth modes (API key / Service Account / OAuth) don't map to a single JWT exp. (an internal ticket)
- **Desktop renumber picker offers slots beyond 1-9.** The dashboard's slot-renumber dropdown was hardcoded to offer free slots in `1..=9`. Users running slots 10+ saw `No free slots in 1-9. Use CLI csq move <N> for higher.` and had no GUI path to renumber into a higher slot. v2.12.0 scales the upper bound to `max(9, highest_occupied + 1)` — gaps and the next slot above the working set are now pickable from the dropdown. Arbitrary far jumps still go through `csq move N M`. (an internal ticket)

### Added

- **Settings popover + decoupled `Hide Dock icon` from window visibility.** The v2.11.0 dock-icon-hide feature applied the macOS Accessory activation policy AND hid the main window at launch — two behaviors implemented as a single toggle. Users who enabled "Hide Dock icon" found that the dashboard window also stopped appearing on every relaunch. v2.12.0 separates these into two preferences:
  - **`Hide Dock icon`** — controls only the NSApp activation policy (Accessory ↔ Regular).
  - **`Open dashboard at launch`** _(new, default on)_ — controls whether the main window auto-shows at startup. When off, csq launches into the menu bar / tray only; click the tray icon to reveal the dashboard.

  One-time `desktop-prefs.json` migration on first v2.12.0 launch: hosts that had `Hide Dock icon` on are migrated to `open_dashboard_at_launch: false` to preserve the pre-refactor behavior; hosts that had `Hide Dock icon` off get `open_dashboard_at_launch: true`. (an internal ticket)

### Internal

- **`is_codex_only_slot` canonical predicate.** Single source of truth for codex-only classification at `csq_core::accounts::identity_store::is_codex_only_slot`. Adopted across 4 surfaces (`discover_anthropic`, `audit_coexistence` MissingCredentials + MissingSettings, desktop `get_accounts` token-badge). `rules/account-terminal-separation.md` MUST NOT Rule 4 extended to document the legacy-marker-only predicate as a same-bug-class regression vector — any future surface needing codex-only classification MUST call `is_codex_only_slot`, not re-derive from the marker.
- **RN1-D R3 `prune_redundant_accounts_entries` always-on prune.** Daemon startup reconciler pass drains every recoverable `accounts[N]` entry whose data is reproducible from `by_slot ∪ by_email ∪ by_slot_identity ∪ by_slot_label`. Load-bearing for v2.13.0's M4-13 `accounts` field deletion: the WINDOW-CLOSE P1 predicate cannot fire on any v2.12.0+ host.
- **macOS auto-updater trust chain unchanged** — Developer ID signed + notarized + stapled; minisign pubkey `F1C2F7FD79F952DD` (since v2.7.0).

---

## [2.11.0] — 2026-05-25

Minor release shipping the paired-cleanup half of the M4-12 retirement contract, the orphan-identity directory garbage collector + logout source-fix, the macOS dock-icon-hide UX option, and the codified `reconciler-cleanup-parity` rule that captures the 3-occurrence pattern. The first stable cut that activates the in-bundle daemon GC end-to-end — auto-update propagates the new daemon code to every csq user, clearing accumulated `csq doctor` `INCONSISTENT` warnings and the two M4-12-retiring `legacy_compat_state` bridges on the next desktop-app launch.

### Fixed

- **Orphan identity directories now garbage-collected on every daemon start.** Logout/renumber previously removed canonical credentials + `config-N/` + the three profile-map entries but never the `identities/<UUID>/` directory. The new `prune_orphan_identities` reconciler pass (`csq-core/src/accounts/orphan_identity_gc.rs`) deletes UUID dirs unreferenced by `by_slot ∪ by_email`, with three whole-pass fail-closed guards and a live-handle-dir scan covering both ClaudeCode `.credentials.json` and Codex `auth.json` symlinks. Resolves `csq doctor`'s `INCONSISTENT: OrphanIdentity(...)` warning and stops dead credential dirs accumulating. (an internal ticket)
- **Legacy `credentials/<N>.json` and `credentials/codex-<N>.json` mirrors pruned after the M4-12 writer retirement.** The new `prune_legacy_credential_mirrors` reconciler pass (`csq-core/src/accounts/legacy_mirror_cleanup.rs`) deletes pre-M4-12 Anthropic and Codex mirror files whose identity-keyed successor exists and parses; KEEPs otherwise with a 4-variant `KeptReason` taxonomy. Closes two of the three `legacy_compat_state` bridges and the WINDOW-CLOSE P1 predicate for them. (an internal ticket)
- **Logout source-fix prevents new orphans.** `logout_account` now removes the `identities/<UUID>/` directory when it drops the last reference to a UUID; shared-UUID siblings are preserved via the `by_slot ∪ by_email` re-check. Ordering invariant extends the M9 SAFETY-ORDERING comment: profile-map removal is durably saved BEFORE the directory delete, so a crash leaves an unreferenced (collectable) orphan, never a `by_slot` row pointing at a deleted dir. (an internal ticket)

### Added

- **macOS dock-icon-hide preference (Accessory policy).** New desktop option to hide the Code Squad Q dock icon and run as a menu-bar-only utility. Toggle persists in app preferences; takes effect on next launch. (an internal ticket)

### Internal

- **New rule `.claude/rules/reconciler-cleanup-parity.md`** capturing the 3-occurrence pattern (RN1-D R3 `prune_redundant_accounts_entries` + RN1-C R2 `prune_legacy_credential_mirrors` + orphan-GC `prune_orphan_identities`). Five MUST clauses: writer/lifecycle retirement ships its paired cleanup in the same shard; deletion passes run after every reader; live-namespace passes hold the lock across snapshot+enumeration+deletion; scanners enumerate the producer's real on-disk names; predicates fail closed (KEEP on any doubt). Path-scoped to reconciler/accounts/credentials/identity-mint/session. `claude-code-architect` APPROVE per `cc-artifacts.md` Rule 8. (an internal ticket)
- **Removed dead `sweep_orphan_identities`** (function + call site). The sentinel-gated, warn-only sweep was superseded by the GC pass; its R2-LOW-1 empty-maps guard is ported. (an internal ticket)
- **Spec 02 rev 1.17.0 → 1.18.0** adds `INV-ORPHAN-IDENTITY-GC` and a deviation log entry for the live-namespace lock posture (the load-bearing divergence from the RN1-C R2 sibling — this pass deletes in the live-mint namespace, so it must hold the profiles lock across the deletion to serialize against concurrent `csq login`).
- **4-lens `/analyze` + 3-round `/redteam` convergence.** R1 surfaced a CRITICAL credential-deletion bug (the live-handle scan was blind to live Codex sessions because Codex handle dirs symlink `auth.json`, not the guessed `.credentials-codex.json`) — fixed in-session and regression-pinned. R2 (security-reviewer) + R3 (deep-analyst) both CLEAN ≥ MED. All findings resolved in-session per `zero-tolerance.md` Rule 5.
- **23 net new tests** (16 GC unit incl. real-`mint_for_codex_login` FM1-CRITICAL coverage + the `auth.json` regression test; 5 logout source-fix; 2 reconciler-wiring/doctor-consistency integration). Workspace 3178 passed / 0 failed.

---

## [2.10.1] — 2026-05-23

Patch release closing the per-identity probe correctness work begun in v2.10.0 and shipping the 2026-05-21/22 codex-side correctness wave — wrong-variant binding classification, codex-only-slot UUID minting at login, the `token_invalidated` actionable hint, broker-sentinel clear-on-login parity, and an operator-surface path-redaction sweep. The single most-visible behavioural change: `csq probe N --provider codex` now reads the slot's own identity-store credentials instead of the user-global codex-cli state, so multi-codex-slot installs get honest per-slot answers.

### Fixed

- **`csq probe --provider codex` reads per-identity credentials.** Before this release, the codex probe loaded `~/.codex/auth.json` regardless of which slot was being probed — a leftover of the pre-A++ user-global model that survived the per-identity refactor at an internal ticket. Multi-codex-slot installs were structurally incapable of per-slot diagnosis. The dispatcher now resolves the slot to its UUID via `resolve_slot_to_uuid` and reads `identities/<UUID>/credentials-codex.json` (post-A++ path), falling back to `credentials/codex-<N>.json` only when the `by_slot` mapping is empty (pre-A++ installs). Spec 11 §11.2 updated to document the per-identity prerequisite. Closes `rules/account-terminal-separation.md` MUST NOT Rule 4 ("Diagnostic Surfaces Read From The Same Credential Channel As Daemon Production Paths") — adopted across `csq doctor` and `csq status` in the same cycle. (an internal ticket, closes an internal ticket)
- **`codex-wrong-variant-binding` classification + `csq doctor` surfacing.** Closes the v2.10.0 an internal ticket follow-up. A codex-prefixed credential file whose payload parses as Anthropic shape (the `cf.codex().is_none()` arm at `discover_codex`) was previously `continue`d silently; now classified as `Skipped` with `cell="codex-wrong-variant-binding"` and exit 64, and `csq doctor` surfaces such slots in its report. Spec 11 → rev 1.0.4. (an internal ticket, closes an internal ticket)
- **`SkipReason::NoCredentials` path leak fixed across the probe module + `$HOME` redaction across CLI operator surfaces.** Closes the v2.10.0 an internal ticket follow-up. The `NoCredentials` diagnostic previously interpolated the absolute identity-store path; now uses path-free fixed-vocabulary. Companion sweep redacts `$HOME` prefixes from operator-facing path output across the CLI surface. (an internal ticket, closes an internal ticket)
- **Codex-only slot UUID minting at `csq login` + Phase-4 gate codex-only-aware.** `csq login N --provider codex` on a codex-only slot now mints a UUID at login time; the daemon's Phase-4 gate Check 3 no longer false-fails on slots that legitimately have no Anthropic credentials (codex-only slots by design). Resolves the regression where the v2.10.0 install of the daemon refused to start against a codex-only-slot host state. (an internal ticket)
- **`code: "token_invalidated"` from ChatGPT now surfaces actionable "Run `csq login`" instead of the generic "Check status and retry."** Typed enum + broker mapping + probe hint, three-layer fix per the codified pattern. (an internal ticket)
- **Stale `broker_failed` sentinel cleared on `csq login` + on `BrokerResult::Valid` (Anthropic + Codex, early-return + post-lock-re-read).** Resolves false-positive `LOGIN-NEEDED (codex_refresh_reused)` lingering for hours after a successful re-login — `csq doctor` now reflects current broker state, not a stale snapshot. (an internal ticket)

### Internal

- **Fixture-fidelity testing pattern codified.** The an internal ticket investigation surfaced a generalisable principle: a unit test for a diagnostic surface MUST stage fixture credentials at every path the surface might read, not just the path the test author had in mind. Promoted to a project-wide testing rule and added to the `testing-specialist` agent's pre-flight checklist. (an internal ticket)
- **`daemon/mod.rs` subsystem map refresh.** The top-of-file comment carried v2.7-era "M8 scope" planning narrative (foreground-only, no IPC server yet) — long since superseded by the shipped daemon. Rewritten as a current-state subsystem map (server, refresher, usage_poller, auto_rotate, startup_reconciler, identity_mint, etc.). No runtime change. (an internal ticket)
- **Two rules codified in the same cycle.** `.claude/rules/sentinel-clearing-parity.md` captures the an internal ticket 4-call-site sentinel-clear pattern; `.claude/rules/account-terminal-separation.md` MUST NOT Rule 4 extended to all diagnostic surfaces. (an internal ticket)
- **Spec 11 → rev 1.0.5** (cumulative: rev 1.0.4 from an internal ticket wrong-variant + rev 1.0.5 from an internal ticket per-identity prerequisite). `SCHEMA_VERSION` unchanged at `"1.0.0"`.
- **macOS auto-updater trust chain unchanged** — Developer ID signed + notarized + stapled; minisign pubkey `F1C2F7FD79F952DD` (since v2.7.0).

---

## [2.10.0] — 2026-05-20

Minor release making `csq probe` trustworthy on corrupt-but-bound slots. Before this release, a slot whose per-surface binding file existed but failed to parse fell into one of two silent failure modes the operator could not see from the probe report: corrupt Gemini binding (reported `cell="unknown"` with misleading `NoCredentials`, or dropped entirely) and corrupt Codex credential (strictly worse — routed to `codex_oauth::probe` which reads the SHARED `~/.codex/auth.json`, emitting a green Cell 03 record for the WRONG account's quota). Both classes now classify explicitly as `Skipped` with `cell="{gemini,codex}-corrupt-binding"` and exit 64, carrying path-free fixed-vocabulary diagnostics with operator remediation hints.

### Fixed

- **`gemini-corrupt-binding` classification.** A new `cell="gemini-corrupt-binding"` `Skipped` outcome fires when a Gemini binding marker exists but `read_binding` returns `Err` (corrupt JSON, IO error, or schema newer than this binary). `csq probe --all` now includes the slot via a direct `is_gemini_corrupt_bound` scan that complements `discover_gemini`'s strict-parse drop. Also closed a latent C2 hint-path leak (`ambiguous_binding` previously interpolated the absolute identities-store path into `observed_shape` — now path-free fixed-vocabulary). (an internal ticket, closes an internal ticket)
- **`codex-corrupt-binding` classification + dispatcher Step 3.5 short-circuit.** The Codex analogue. A new `cell="codex-corrupt-binding"` `Skipped` outcome fires when `credentials/codex-<N>.json` is present but `credentials::file::load` fails. The dispatcher's new Step 3.5 short-circuits before the Anthropic-cred-None → `codex_slot_present && discovery_codex_match → codex_oauth::probe` fall-through, closing the silent mis-attribution path. (an internal ticket, closes an internal ticket)
- **Host-isolation Gemini gate fix.** Spec-08 MED-03: `csq doctor`'s host-iso Gemini gate keyed off a dead path, silently suppressing the gate. Fixed at root; the doctor's host-iso check now fires for canonical Gemini slots without providers-path artifacts. (an internal ticket)

### Changed

- **C2 ambiguous-binding now presence-presence across surfaces.** The C2 guard at `probe_slot` Step 2 was extended from `is_gemini_bound_slot(base, slot) && anthropic_present` to `(is_gemini_bound_slot(base, slot) || is_codex_bound_slot(base, slot)) && anthropic_present`. A slot with valid Codex credentials AND valid Anthropic identity-store credentials — previously a silent green Codex probe — now FAILs `ambiguous-binding` (exit 1). Operators with such side-by-side configurations must `csq logout <N>` and re-bind to a single surface. Documented in spec 11 §11.2 rev 1.0.3.
- **`csq probe --all --json` new `cell` values and exit code 64 contract.** Scripts parsing the JSON output must accept `gemini-corrupt-binding` and `codex-corrupt-binding` as new `cell` strings; their `failed_assertion` is prefixed `prerequisite:` and exits 64 (misconfiguration). Treat exit 64 as "prerequisite missing — operator action required."

### Internal

- **`SkipReason::CorruptBinding` promoted to struct variant `{ surface: Surface, kind: &'static str }`** — single path-free audit surface for both Gemini and Codex.
- **`CredentialError::error_kind_tag(&self) -> &'static str`** — five fixed-vocabulary path-free tags (`credentials_not_found`, `credentials_malformed`, `credentials_io`, `credentials_invalid_account`, `credentials_none`). Adopted at four `discovery.rs` `warn!` sites that previously interpolated `error = %e` (echoes absolute path via `Display`). In-scope sweep fixed three sibling sites alongside the originating `discover_codex` site (per zero-tolerance discipline).
- **`is_codex_bound_slot` lifted from `setkey.rs` into `csq-core/src/providers/codex/provisioning.rs`** alongside new sibling `is_codex_corrupt_bound`. Single source of truth, no re-export drift, matches the Gemini analogue.
- **Spec 11 advanced rev 1.0.1 → 1.0.3.** Rev 1.0.2 (an internal ticket Gemini convergence) + rev 1.0.3 (an internal ticket Codex + C2 presence-presence extension). `SCHEMA_VERSION` unchanged at `"1.0.0"` — new cell names + `SkipReason` shape are data within the existing JSON shape.
- **Release-cmd macOS signing-gap fix.** Resolved a stable-tag path gap in `csq release` that intermittently produced an unsigned `.app` under specific keychain states. (an internal ticket)
- **macOS auto-updater trust chain unchanged** — Developer ID signed + notarized + stapled; minisign pubkey `F1C2F7FD79F952DD` (since v2.7.0).

---

## [2.9.0] — 2026-05-19

Minor release making non-OAuth slots durable. Before this release, slots authenticated by a third-party API key (MiniMax, DeepSeek, Ollama, Z.AI), by Codex, or by Gemini had no reliable record of _which identity owns the slot_ independent of the volatile `accounts` bookkeeping — symptom: `csq doctor` false-flagging healthy 3P/Codex/Gemini slots as "orphans," and slot identity at risk of being lost when stale `accounts` entries were pruned. Plus `csq doctor` is now trustworthy on a healthy host — reports every consistency issue at once instead of stopping at the first, and a stale check that produced phantom warnings is retired at root. Upgrading from v2.8.0 (or any v2.7.x/v2.8.x) is in-place — the reconciler auto-backfills `by_slot_identity` for existing non-OAuth slots on first daemon start; no manual migration.

### Fixed

- **`csq doctor` reports every consistency issue at once.** `audit_coexistence` now returns a list of every consistency issue (`--json` schema bumped v7 → v8: `identity_store.consistency` is an array; empty = consistent). Previously surfaced one issue per run, so fixing the first revealed the next only on re-run. (an internal ticket)
- **Retired stale `MirrorDriftAtSlot` check.** The M3-7 credential mirror is inert in the current architecture; the check against it produced false "inconsistent" warnings on healthy hosts. Removed at root. (an internal ticket)
- **Account/slot identity hardening — RN1-C / RN1-D.** Legacy numeric canonical writer + numeric reader fallback retired (RN1-C); `get_email` / reconciler paths fail closed instead of silently falling back. Identity label channel + rename migration; login captures a pre-existing rename label (RN1-D R2); accounts-prune closes the WINDOW-CLOSE gate gap (RN1-D R3, arm-3 mirrors `get_email` step 3). `update_email` serialized under `ProfilesFileLock` (RN1-A) — removes a profiles.json write race. `csq doctor` surfaces Pass-0 `oauth_email_unresolved` skips and unrecoverable post-relocation rename labels. (an internal ticket–an internal ticket)

### Added

- **`by_slot_identity` recovery channel for non-OAuth slots.** A new `by_slot_identity` map in `profiles.json` records the durable identity of every non-OAuth slot. 3P API-key + Codex slots (an internal ticket) ship the channel and its daemon backfill/reconciler wiring; Gemini (an internal ticket) is the 3rd and final non-OAuth surface to write it; the accounts-less 3P backfill arm (an internal ticket) reclaims slots whose only record is a 3P API key on disk (no `accounts` entry) via a disk-walk arm the prior predicate left orphaned. Live reader chain consults the channel (spec 02 §INV-07). Net effect: `csq doctor` no longer false-flags non-OAuth slots, and the planned retirement of the legacy terminal-side `accounts` field will not orphan these slots. Existing non-OAuth slots are auto-backfilled on first daemon start after upgrade; no manual migration. (an internal ticket)

### Changed

- **`csq doctor --json` schema bumped v7 → v8.** `identity_store.consistency` is now an array (empty = consistent) rather than a single field. Scripts parsing the old single-issue shape should read the array.

### Internal

- **M4-12 numeric-writer retirement (an internal ticket).** Retired the legacy numeric canonical writer alongside the RN1-C reader-fallback removal — load-bearing prerequisite for the v2.11.0 paired-cleanup half (`prune_legacy_credential_mirrors`).
- **RN1-F (terminal `accounts`-field deletion) advances one soak cycle** — soak-gated by design (WINDOW-CLOSE N=2). The `by_slot_identity` channel shipped here is its prerequisite; RN1-F itself lands a later cycle.
- Changelog backfill v2.7.6→v2.8.0; workspace closeouts for the by_slot_identity and an internal workspace efforts; the WINDOW-CLOSE release-N+1 runbook gate; two repo-wide `/sweep` audits.
- **macOS auto-updater trust chain unchanged** — Developer ID signed + notarized + stapled; minisign pubkey `F1C2F7FD79F952DD` (since v2.7.0).

---

## [2.8.0] — 2026-05-16

Minor release closing the v2.7.8 retro-fix arc and shipping `.coc/`-gated capability auto-engage. First stable cut that exercises the maintainer-signed-macOS pipeline introduced in v2.7.8 end-to-end; three updater-pipeline defects surfaced by the v2.7.8 retro-fix execution are resolved at the source so subsequent cuts no longer need post-hoc patching. Closing an internal journal entry, tag `60d29d1`.

### Fixed

- **macOS updater tar AppleDouble corruption resolved.** The updater bundle's tar archive shipped with `._*` AppleDouble metadata files on macOS hosts using HFS+/APFS extended attributes, which Tauri's updater rejected when unpacking. `COPYFILE_DISABLE=1` is now exported during the tar step and a CI gate fails the workflow if any `._*` entry slips into the artifact. Closes the v2.7.8 retro-fix root cause. (an internal ticket)
- **Updater darwin signature double-base64 encoding fixed.** The release script base64-encoded the already-base64 detached signature before injecting it into `latest.json`, producing a doubly-encoded string that Tauri's verifier rejected as a malformed signature. The script now passes the raw base64 through unchanged. (an internal ticket)
- **Release runbook §1 build command fixed.** `--no-bundle=false` was an invalid Tauri CLI flag; the runbook's build step now uses the correct invocation. (an internal ticket)
- **Statusline env tests acquire the workspace-wide `test_env` mutex.** Concurrent statusline tests under nextest mutated `CLAUDE_CONFIG_DIR` without serialization, producing flaky failures. Aligning with `testing.md` Rule 6 (workspace env tests must hold the shared mutex) restores determinism. (an internal ticket)

### Added

- **Capability layer `.coc/`-gated auto-engage default (M7).** When a project root contains a `.coc/` directory, csq enables the capability layer by default — no opt-in flag needed. Projects without `.coc/` keep the prior off-by-default behavior. (an internal ticket)

### Changed

- **Updater manifest upsert gated to stable tags only.** Prerelease tags (`-rc.N`, `-alpha.N`) no longer mutate the public `latest.json`; only stable `vX.Y.Z` cuts publish a new updater manifest. Prevents prereleases from being offered to stable-channel users. (an internal ticket)

### Internal

- v2.7.8 retro-fix one-shot script (`docs/release/`) and `0048-DISCOVERY-macos-updater-appledouble-unpack-failure-root-cause.md` + `0052-…retrofix-executed.md` journals captured the diagnostic chain that informed the v2.8.0 source-level fixes. The stopgap script is removed at v2.8.0 cut now that an internal ticket/an internal ticket/an internal ticket close the defects at source. (an internal ticket)

---

## [2.7.8] — 2026-05-16

First maintainer-signed stable macOS bundle. Introduces Developer ID signing and notarization end-to-end in `release.yml` and ships a healed-Codex-identity 0o400 permission flip to bring Codex identity files to INV-P08 parity with ClaudeCode. Closing journals 0043 + 0045, tag `8e14a45`.

### Fixed

- **Healed Codex identity files now 0o400 (read-only by owner), matching INV-P08.** The Phase-4 self-heal path (an internal ticket) materialized Codex `identities/<UUID>/credentials.json` at the umask default (0o600), one notch wider than ClaudeCode's 0o400. The flip brings Codex into spec 02 §INV-P08 parity so both surfaces share the same on-disk permission contract. (an internal ticket)

### Added

- **Maintainer-signed macOS release bundles via Developer ID + notarization.** `release.yml` gains a stable-tag-only job that imports the maintainer's Developer ID certificate from the runner keychain, signs both the `.app` and the updater `.tar.gz`, submits to Apple notarization, and staples the ticket. The DMG and updater artifacts attached to the GitHub release are first-class signed-and-notarized bundles — Gatekeeper accepts them without right-click-Open ceremony. (an internal ticket)
- **macOS Developer ID signing + notarization runbook.** New `docs/release-signing.md` documents the 1Password-managed signing identity, notarytool credential profile, end-to-end signing sequence, and recovery steps for common failures (keychain locked, certificate expired, notarization rejection). (an internal ticket)
- **Top-level `phase-4-incomplete` alarm in `csq doctor`; doctor `schema_version` bumped to 5.** Surfaces partial-migration state at the top of the doctor output instead of buried inside per-slot rows, so users on a partial v2.7.3→v2.7.7 upgrade see the alarm immediately. (an internal ticket)
- **`csq doctor --repair-identities` + Phase-4 gate self-heal from legacy credentials.** When `phase4_gate_check` detects an unseeded `identities/<UUID>/credentials.json` with the legacy `credentials/<N>.json` still on disk, the daemon now self-heals by materializing the identity-keyed file from the legacy source. `csq doctor --repair-identities` exposes the same self-heal on demand for users skipping daemon startup. Closes the v2.7.3→v2.7.7 upgrade-skip class surfaced by an internal journal entry (an internal ticket)

### Internal

- Journals 0039 + 0040 captured the v2.7.7 Codex-fix and Phase-4-upgrade-skip discoveries that drove the v2.7.8 self-heal + repair design.

---

## [2.7.7] — 2026-05-15

**Phase-4 release N for an internal ticket** — completes the slot-to-identity decoupling rollout: profiles.json's v1 `accounts` field is emptied on every write, the `.csq-account` marker writers flip from decimal to UUID, the rotation legacy fallback is retired, and `csq doctor` gains a `legacy_compat_state` field with `schema_version: 4` so partial-migration state is observable. Closing an internal journal entry, tag `e98a7f0`. The v2.7.3→v2.7.7 upgrade-skip class surfaced after release (an internal journal entry) is healed in v2.7.8.

### Fixed

- **Codex `~/.codex/config.toml` user-global merged into slot config.toml at spawn.** The global config provided settings (sandbox, approval CLI flags) that the slot config did not inherit, causing spawned codex sessions to ignore the user's globally-set preferences. The spawn-time merge restores the expected precedence chain (slot overrides global). (an internal ticket)
- **Audit `LayerOutcome` + spawn result plumbed into `AuditRecord` (PR-CA10c).** Closes an internal ticket — capability-layer audit records now carry the layer outcome and the spawn result, so post-session audits can reconstruct what the layer did and how the spawn resolved. (an internal ticket)
- **`svelte-check` resolveSub narrowing + `npm run check` added to CI gate.** Closes an internal ticket — type-narrowing fix in a Svelte component plus the missing CI step that would have caught it. (an internal ticket)
- **Audit Windows `end_ts` + `rule_ids` semantics (R1 redteam HIGH+MED fixes).** (an internal ticket)
- **`h3_cap` test flake root-caused via structural invariant assertion.** Replaces the timing-sensitive margin bump with a structural assertion that proves the cap was enforced regardless of scheduler jitter. (an internal ticket)

### Added

- **`csq doctor --repair-identities` precursor: schema v4 + `legacy_compat_state` field (M4-11).** Adds the structured observability surface for partial-migration state that the v2.7.8 self-heal (an internal ticket) consumes. (an internal ticket)
- **`csq doctor` full coexistence consistency checks + `schema_version: 4` (M2-6).** Reports identity-vs-legacy disagreements per slot so downstream tooling can act on them.

### Changed

- **profiles.json `accounts` field empty-write across all production paths (M4-9).** The v1 `accounts` field is preserved on read (round-trip via `#[serde(flatten)] extra`) but every writer emits `accounts: {}` — the identity-keyed `by_slot`/`by_email`/`identities/<UUID>/` store is the canonical truth. Sets up the field's terminal deletion in a future release. (an internal ticket)
- **`.csq-account` marker writers flipped from decimal to UUID (M4-7).** Marker files now carry the identity UUID, not the decimal slot id. (an internal ticket)
- **Rotation legacy fallback retired (M4-8).** `rotation::swap.rs` no longer falls back to decimal-keyed credential paths; UUID-keyed identity paths are the only resolution. (an internal ticket)
- **Daemon readers flipped to identity-keyed credentials across 5+3 sites (M4-4).** Refresher, usage poller, and IPC handlers all read from `identities/<UUID>/credentials.json`; the legacy `credentials/<N>.json` path is read-only-on-self-heal. (an internal ticket)
- **Phase-4 gate strengthened with `SettingsUnseeded` + `CodexCredentialsUnseeded` variants (M4-5).** The gate fails closed when either is detected, preventing silent partial-migration runs. (an internal ticket)
- **Codex UUID-keyed credentials write (M4-1).** Codex credentials now write to `identities/<UUID>/credentials.json` alongside ClaudeCode. (an internal ticket)
- **settings.json UUID-keyed materialize (M4-2).** Per-slot settings.json materializes from the identity store, not the decimal slot. (an internal ticket)

### Internal

- M4-3 retired the `accounts::identity` module after callers migrated to the chokepoint helpers. (an internal ticket)
- M4-6 renamed the `broker` module to `refresh` to match its actual responsibility. (an internal ticket)
- M4-10 consolidated the Phase-4-release-N shipped surface into specs (final rewrite). (an internal ticket)

---

## [2.7.6] — 2026-05-12

Patch release on v2.7.5. Ships an internal ticket Phase 2 — the AddAccountModal in the desktop UI now shells out to `claude auth login` via the `start_claude_login_subprocess` Tauri command introduced in v2.7.4, matching the CLI's an internal ticket default. Brings the desktop flow into parity with the CLI on the "delegate to the reference client" pattern. Closing reference an internal journal entry, tag `cac9e56`.

### Changed

- **AddAccountModal (desktop) shells out via `start_claude_login_subprocess` (an internal ticket Phase 2).** The modal previously orchestrated an in-process parallel-race OAuth flow that bound a local loopback listener; that flow surfaced the same Anthropic-retired-loopback failure mode the CLI hit in v2.7.3. Phase 2 wires the modal to the v2.7.4 Tauri subprocess command, letting Claude Code handle the redirect end-to-end the same way the CLI now does. Phase 3 (race orchestrator + loopback infrastructure removal) tracks on an internal ticket. (an internal ticket)

---

## [2.7.5] — 2026-05-12

Patch release on v2.7.4. Two follow-up fixes surfaced by real-world testing on a headless Linux server (the host over Tailscale):

### Fixed

- **Gemini Code Assist OAuth now completes on headless Linux via SSH tunnel.** The previous behavior aborted the entire login when `open_browser` couldn't reach a GUI (`headless: no DISPLAY/WAYLAND_DISPLAY available`), even though the loopback listener was still bound and ready. The flow now treats the headless-browser-open as non-fatal: it emits explicit SSH port-forwarding instructions naming the exact loopback port csq bound (`ssh -L <port>:localhost:<port> <user@host>`), prints the auth URL for the user to open on a GUI machine, and keeps the listener alive. Once the user authorizes in their GUI browser, Google's redirect to `http://127.0.0.1:<port>/callback` traverses the SSH tunnel back to the headless host's listener and the flow completes normally.
- **`csq login N` (claude provider) now locates `claude` via `find_claude_binary` instead of bare `Command::new("claude")`.** v2.7.4 introduced the shell-out default but the spawn relied on `$PATH` alone, which fails on minimal non-interactive shells (SSH without an interactive login, GUI Tauri spawn, cron jobs) where `~/.local/bin` is not in PATH even though Claude Code is installed there. The Phase 1 Tauri subprocess command (an internal ticket) already followed this pattern; this fix brings the CLI in line.

---

## [2.7.4] — 2026-05-12

Patch release on v2.7.3. Three fixes that together restore `csq login` to a working state on headless Linux servers AND make the default flow work on every platform without requiring `--legacy-shell`. Closes an internal ticket.

### Fixed

- **`csq login N` (claude provider) now shells out to `claude auth login` by default.** The previous default — an in-process parallel-race flow that bound an IPv4 loopback listener (`http://127.0.0.1:<port>/callback`) — surfaced a "redirect URI fail" page in the browser because Anthropic retired loopback redirects for the Claude Code client_id. CC itself uses IPv6 `[::1]:<random>` + a hosted-page JS bridge, and per the "delegate to reference client" rule the right fix is to shell out rather than re-implement that surface. `--legacy-shell` is now a no-op alias kept so existing scripts keep parsing. (an internal ticket)
- **Headless Linux CLI login now works without browser noise.** `open_in_browser` pre-detects no-`$DISPLAY` / no-`$WAYLAND_DISPLAY` and returns Err before spawning `xdg-open`, so the existing manual-URL fallback fires cleanly instead of letting Chromium crash and pollute stderr with `ozone_platform_x11` errors. Same fix in the duplicate `csq-core/src/providers/gemini/oauth_flow.rs::open_browser` helper. Additionally, the codex `"Press Enter when 'Device code authorization' is enabled"` gate now detects stdin-EOF (no TTY) and fails fast with a clear "this terminal has no TTY — reconnect with `ssh -t`" message instead of silently skipping the gate. (an internal ticket)
- **Windows Rust test suite restored.** `cli_deps::install_path::tests::find_in_path_finds_binary_in_first_path_entry` now uses `std::env::consts::EXE_SUFFIX` and `std::env::join_paths` for platform-correct PATH composition; the `make_stub_npm_dir` integration-test helper is `#[cfg(unix)]`-gated to close the test-binary compile gap. The `windows-latest` Rust CI job is meaningful again after silently passing despite real failures since v2.7.0+. (an internal ticket)

### Added

- **`start_claude_login_subprocess` Tauri command (Phase 1 of an internal ticket).** New desktop command that shells out to `claude auth login` and lets CC handle the redirect end-to-end — same approach the CLI took in an internal ticket. Lives alongside the existing race-flow commands; Phase 2 (frontend modal rewire) and Phase 3 (race orchestrator + loopback infrastructure removal) are tracked on an internal ticket as separate workspaces.

### Internal

- `handle_race` and `run_race_with_browser` in the CLI marked `#[allow(dead_code)]` pending full removal in a follow-up; helper unit tests still pin `print_paste_prompt`, `stdin_paste_resolver`, and `race_or_cancel`.
- `xdg-open`'s child stdio is redirected to `/dev/null` on Linux to suppress browser-process noise even when `$DISPLAY` is set but the GUI session is degraded.

---

## [2.7.3] — 2026-05-11

Patch release on v2.7.2. Closes the v2.7.0 user-visible gap where codex slot quota was polled correctly by the daemon but the desktop UI displayed zero/blank 5h/7d numbers. Closes an internal ticket.

### Fixed

- **Codex 5h / 7d utilization windows now reach the desktop UI.** The `get_accounts` IPC gate at `csq/src/desktop/commands/mod.rs` used to filter quota fields on `AccountSource::Anthropic`, leaving codex slots with `five_hour_pct: 0.0` / `seven_day_pct: 0.0` in the payload — codex users saw blank usage bars despite the daemon writing correct numbers to `~/.claude/accounts/quota.json`. The gate now matches on the quota record's `surface` field against the account's surface, so codex slots surface codex quota, anthropic slots surface claude-code quota, and the an internal journal entry H2 leakage defense (slot-rebound-across-surfaces must not show prior occupant's numbers) is preserved AND strengthened — it's now structural surface-match rather than a source-based heuristic. (an internal ticket)

### Internal

- 3 new regression tests pin the contract: codex-slot-surfaces-codex-quota; anthropic-slot-still-surfaces-claude-code-quota; rebound-slot-does-not-leak-prior-surface-quota.
- No AccountView wire-shape change — the typed-quota refactor the issue suggested is deferred. Surface-match is a one-line behavior change with smaller blast radius and was sufficient to satisfy every acceptance criterion.

---

## [2.7.2] — 2026-05-11

Patch release on v2.7.1. Fixes the desktop bundle's `Info.plist` version string, which had drifted from the workspace `Cargo.toml` since v2.6.3. v2.7.0 + v2.7.1 desktop bundles' About dialog reported "2.6.3" despite the compiled code being correct; v2.7.2 is the first bundle since v2.6.3 with a correctly-stamped Info.plist. CLI binaries (compiled from `Cargo.toml`) were unaffected. Closes an internal ticket.

### Fixed

- **`csq/tauri.conf.json::version` re-pegged to the workspace version (`2.7.2`).** Previously hardcoded `2.6.3` since the v2.6.3 release — every v2.6.x → v2.7.x desktop bundle since then shipped with a stale Info.plist. The .app's compiled Rust code was always correct (built from `Cargo.toml`); only the bundle metadata was stale. (an internal ticket)

### Added

- **CI gate: `version-lockstep`.** New workflow (`.github/workflows/version-lockstep.yml`) fires on every PR that touches `Cargo.toml` or `csq/tauri.conf.json` and fails with `error_kind: version_drift` if the two versions do not match. `release.yml` gains a `version-check` job that `build-cli` and `build-desktop` depend on, so a release-tag push with mismatched versions (or a tag whose name does not match `Cargo.toml`) aborts before any matrix build. Inline self-test job exercises both pass and fail cases to keep the script honest (same shape as `roadmap-current.yml`). (an internal ticket)

---

## [2.7.1] — 2026-05-11

Patch release on v2.7.0. Refreshes the bundled codex model catalog to promote `gpt-5.5` to default (upstream made it the default between csq's 2026-05-07 refresh and v2.7.0 ship). Affects fresh-slot logins and the desktop UI dropdown only; users already on v2.7.0 with a working slot config.toml are unaffected (the file already says whatever the live-fetch path wrote).

### Changed

- **Codex default model bumped: `gpt-5.4` → `gpt-5.5`.** `csq-core::providers::catalog::CODEX::default_model` and `BUNDLED_MODELS[0]` now both point at `gpt-5.5`. The catalog and bundled list are the FALLBACK path (live fetch via `chatgpt.com/backend-api/codex/models` or `codex debug models` is the primary); v2.7.0's offline-first-login wrote `gpt-5.4` to a fresh codex slot's `config.toml`, which is wrong as of OpenAI's promotion of 5.5. v2.7.1 fixes the offline default. Users with an existing `config.toml` containing an explicit model (e.g. `gpt-5.5`, `gpt-5.4`) are unaffected. Desktop UI model picker now shows "GPT-5.5 (default)" pre-selected for fresh codex slots.

---

## [2.7.0] — 2026-05-11

### Added

- `csq cli install <name>` and `csq cli upgrade <name>` subcommands registered (stub today; full implementation lands in v2.7.0 final). Allowlist: `claude | codex | gemini`. Other inputs rejected at the clap layer before the handler is reached. (an internal ticket, M3 PR-MCD3)
- README "CLI dependency management" section documents doctor row meanings, pre-flight gates, `--ignore-cli-version`, minimum versions table, and `CSQ_CLI_DEPS_PROBE_DISABLE` escape hatch. (an internal ticket, M3 PR-MCD3)
- `csq doctor` reports presence + version + minimum + status for `claude`, `codex`, and `gemini` binaries, with row variants `✓ ok` / `⚠ outdated` / `✗ missing` / `⚠ wrong binary` / `⚠ probe timed out` / `⚠ probe disabled`. Surface rows are suppressed when no authenticated slots of that surface exist. (an internal ticket, AC 1; spec/13)
- `csq doctor --json` emits `"schema_version": 2` at the top level. v1 was unversioned (the absence of the field is the v1 signal). Per-surface keys (`claude_code`, `codex_cli`, `gemini_cli`) populated as objects when slots exist; OMITTED when not.
- `csq login N` and `csq run N` gain a pre-flight version gate spawn-adjacent to the existing CLI spawn. Outdated codex (<0.40.0) / gemini (<0.41.2) / claude (<2.0.0) bails with a structured remediation message naming `csq cli upgrade <name>` instead of the upstream's opaque clap error. (an internal ticket, AC 3)
- `csq login N --ignore-cli-version` and `csq run N --ignore-cli-version` flag — per-invocation override that downgrades the gate from BAIL to WARN for `Outdated` / `UnrecognizedVersion`. `Missing` and `WrongBinary` remain unconditional bails (no override). The flag is per-invocation only — no persistent state, no env var memory, no config file. WARN line is emitted on every honor.
- `csq cli install <name>` and `csq cli upgrade <name>` subcommands — installs or upgrades the named CLI via the user's existing package manager (npm / brew). Argv allowlist; range-pinned semver (`@>=<floor> <next-major>` not `@latest`); `[y/N]` consent gate; non-TTY refusal; EACCES non-escalation; chained Node-install when npm is missing. (an internal ticket, AC 2 + AC 4)
- `CSQ_CLI_DEPS_PROBE_DISABLE=1` env-var escape hatch — forces `cli_deps::probe()` to return `Ok(unparsed)` for all surfaces; disclosure WARN emitted at every gate site (login, run, doctor) so a hostile `.envrc` cannot silently disable gates.

### Changed

- `csq doctor`'s claude row gains a minimum-version comparison (was version-string-only). Behavior change: a claude binary below 2.0.0 surfaces as `⚠ outdated`.
- `csq doctor --json` claude_code key shape gains `min_version`, `status`, `manager` fields. Breaking-change for consumers that depended on EXACT field set; field-by-field consumers (most consumers) are unaffected. Migrate to `schema_version: 2`-aware code.

### Internal

**Note:** the bullets below describe the v2.7.0 endpoint shipping at M5, NOT what M0 stages. M0 ships only the spec + index row + this draft.

- M3 closeout: manpage scope retracted. csq does not currently ship a `man/csq.1` file or a `man/` directory. M3's scope item 3 ("Manpage updates") from the original M3 milestone file was based on an incorrect assumption. M9 A16 (Manpage CI lint) is struck — no manpage to lint. If a future cycle adds manpage support to csq, that is a separate workspace.

- New module `csq-core::cli_deps` (probe, install_path, minimum, version, sanitize, dispatch). 2s wall-clock probe budget; 8KB stdout cap; hand-rolled semver parser (no `semver` crate dep); single-canonicalize-per-probe; two-gate WrongBinary defense (prefix gate + install-path gate). [Lands at M1]
- New stub-binary harness at `coc-eval/bench/stubs/stub-cli` for integration tests across an internal workspace milestones. [Lands at M1]
- New spec: `specs/13-multi-cli-detection-contract.md`. [Landed at M0 — staged this draft alongside]
- R1 M1 redteam convergence (8 HIGH + 10 MEDIUM resolved, an internal ticket):
  - H-1: `WrongBinaryReason`-aware remediation text in `csq doctor` text path — per-reason messages for `prefix_mismatch`, `component_too_large`, `install_path_blocklisted`.
  - H-2: PATH-walk bounded at `MAX_PATH_ENTRIES=4096` / `MAX_PATH_ENTRY_BYTES=4096` in `find_in_path` to defend against adversarial PATH.
  - H-3: `child.wait()` called unconditionally after reader thread signals (kill is a no-op for already-exited processes; avoids potential block when cap exceeded before timeout fires).
  - H-4: `std::thread::spawn` JoinHandle stored and joined before `spawn_version_subprocess` returns — prevents FD leak across repeated probes.
  - M-2: `sanitize_for_display` applied to `hi.first_name` in `print_report` host-isolation warning.
  - M-3: `sanitize_for_display` applied to `daemon.version_drift`, `broker_failed[].reason`, `mixed_state_slots[].provider` in `print_report`.
  - F1: `child.stdout.take()` + explicit match replaces `.unwrap()` in `spawn_version_subprocess`.
  - F3 (semver leading-zero rejection): segments with leading zero and length > 1 (`01`, `002`) return `BadFormat`.
  - Spec §3 updated: `ProbeTimedOut.elapsed` renamed to `elapsed_ms: u64`. §5 Windows `Unknown` note added. §8 leading-zero rule added. §10 probe-disabled disclosure updated (structural field is the machine-readable signal; `eprintln!` is advisory supplement).
- Removed: nothing.

### Known limitations (v2.7.0)

- Windows `InstallManager` classification always returns `Unknown` — path-prefix patterns are macOS/Linux. Doctor still shows correct version/status. Manager-aware install dispatch falls back to the npm hint on Windows. This is in scope for a future Windows-first release.

### Per-PR bullets (M5 fills these in)

- PR #TBD (M0 — spec/13 + index)
- PR #TBD (M1 PR-MCD1 — `cli_deps` module)
- PR #TBD (M1 PR-MCD1.5 — wire to doctor)
- PR #TBD (M2 PR-MCD2 — login pre-flight)
- PR #TBD (M2 PR-MCD2.5 — run pre-flight + cache)
- PR #TBD (M3 — docs PR + subcommand stub)
- PR #TBD (M4 PR-MCD4 — install/upgrade)
- PR #TBD (M4 PR-MCD4.5 — multi-platform validation)
- PR #TBD (M5 PR-MCD5 — round-1 + round-2 redteam)
- PR #TBD (M5 PR-MCD6 — release cut)

### Migration notes

- Consumers of `csq doctor --json` that key-check by literal string MAY want to switch to `schema_version: 2`-aware code. The old `claude_code` key is preserved (additive).
- Users on outdated CLI installs will see the new gate fire on `csq login`/`csq run`. Either upgrade via `csq cli upgrade <name>` (recommended) or pass `--ignore-cli-version` to bypass.
- The minimum-version constants are deliberate code changes: codex 0.40.0 (`--device-auth` landing), gemini 0.41.2 (auth-subcommand removed), claude 2.0.0 (CC 2.x credential format). See `specs/13-multi-cli-detection-contract.md` §4.

### References

- Issue: https://github.com/terrene-foundation/csq/issues/362
- Spec: `specs/13-multi-cli-detection-contract.md`
- Workspace: `internal-design-docs` (analysis + plans + journals; closed at M5)

---

**End of draft.** This file is deleted in M5 PR-MCD6 after content is ported to `CHANGELOG.md`.

---

## [2.3.1] — 2026-04-26

Patch release on v2.3.0. Closes the desktop-side orphan-key risk that landed alongside the v2.3.0 Gemini surface, and rides one cosmetic csq-cli cleanup. No new features, no schema changes, no behavior change for users who never bind a Gemini account.

See `docs/releases/v2.3.1.md` for the full release notes.

### Fixed

- **D7 — desktop "remove Gemini account" deletes the OS keychain entry.** v2.3.0's CLI `csq logout N` cleared the vault; the desktop `remove_account` Tauri command did not, leaving the `gemini/<slot>` entry orphaned in the OS keychain after a desktop-driven removal. New `csq_core::providers::gemini::provisioning::delete_api_key_from_vault(base_dir, slot, vault)` reads the binding marker, calls `vault.delete` for `ApiKey` slots, and is a no-op for `VertexSa` slots or absent markers. `remove_account` calls it before touching the marker; `LogoutError::NotConfigured` is treated as success when the Gemini marker was removed (covers Gemini-only slots with no `config-N/`). Four new csq-core unit tests + two new csq-desktop integration tests pin the regression. Total: 1475 Rust tests (was 1469).
- **CI: `secret-in-memory` reachable in csq-desktop test builds.** `open_default_vault` gates the in-memory backend on `cfg!(any(test, feature = "secret-in-memory"))`, but `cfg!(test)` only fires when csq-core itself is being compiled with `--test`. csq-desktop's test build loads csq-core as a normal dep, so the gate was false on Linux + Windows runners (no OS keyring reachable) and the new D7 test fell through to `BackendUnavailable`. Fix: add `csq-core = { path = "...", features = ["secret-in-memory"] }` to csq-desktop's `[dev-dependencies]`. Cargo unifies features across `[dependencies]` and `[dev-dependencies]` of the same crate, so the in-memory backend is now reachable in `cargo test` builds and stays absent from `cargo build --release`.

### Changed

- **csq-cli — collapse Gemini orchestration to csq-core helpers.** `csq-cli/src/commands/setkey.rs::provision_api_key` now calls `csq_core::providers::gemini::provisioning::provision_api_key_via_vault` directly instead of re-implementing the vault-set + write-binding + rollback dance. `csq-cli/src/commands/models.rs::write_gemini_model_to_binding` now calls `set_model_name`. ~30 LOC of duplication collapsed; no behavior change. The `AIza` prefix guard, error mapping, and user-facing print output stay in csq-cli where they belong.

---

## [2.3.0] — 2026-04-26

Gemini as a first-class third surface alongside ClaudeCode and Codex: API-key provisioning (AI Studio paste or Vertex SA JSON path) under `platform::secret` encryption-at-rest, in-flight `csq swap` between Gemini slots, cross-surface swap with the existing v2.1.0 confirm + tombstone path, `csq run` that does not require a running daemon (a deliberate inversion of v2.1.0's INV-P02 for Codex), event-driven quota via a CLI-durable NDJSON event log, a 7-layer Terms-of-Service defense (EP1–EP7) pinned to gemini-cli 0.38.x, and a desktop UI mirroring the ClaudeCode and Codex flows. No schema migration; quota.json stays at v2.

See `docs/releases/v2.3.0.md` for the full release notes.

### Added

- `Surface::Gemini` variant + dispatch wiring across `discovery`, `auto_rotate`, `rotation::swap_to`, `daemon::refresher`, `usage_poller`. Surface dispatch architecture from v2.1.0 extends to a third variant.
- `csq_core::platform::secret` — encryption-at-rest primitive with five backends: `macos.rs` (Keychain via `security-framework`), `linux.rs` (Secret Service with AES-GCM file fallback), `windows.rs` (DPAPI + Credential Manager), `file.rs` (AES-GCM-only fallback for headless / CI / WSL-no-keyring environments), `in_memory.rs` (test-only). All five implement the same `SecretStore` trait; `audit.rs` carries the security-reviewer sign-off ledger.
- `csq_core::providers::gemini` — full Gemini surface module: `provisioning.rs` (vault wiring + model orchestration), `spawn.rs` (`spawn_gemini` with EP2/EP3 pre-spawn guards), `tos_guard.rs` (EP4 stderr sentinel pinned to gemini-cli 0.38.x), `tos.rs` (per-slot ToS marker mirror of `codex/tos.rs`), `capture.rs` (NDJSON emitter with `O_APPEND` + `fsync`), `event_id.rs` (envelope ID minting), `keyfile.rs` (canonical path for at-rest secret artifacts).
- `csq setkey gemini <slot> --from-stdin` — CLI provisioning. API key piped on stdin; never reaches argv; redacted by `error::redact_tokens` (now learns `AIza*` prefix).
- `csq run` — Gemini surface dispatch via `discovery::discover_all`. Does not require a running daemon for Gemini slots (ADR-G09, INV-P02 inverted).
- `csq swap` — cross-surface routing for Gemini slots; same-surface Gemini→Gemini repoints atomically; cross-surface follows v2.1.0 INV-P05 confirm + INV-P10 rename-source-to-tombstone + `exec`.
- `csq models switch` — Gemini dispatch via `discover_all`; static catalog with 4 entries (`gemini-2.5-pro`, `gemini-2.5-flash`, `gemini-2.0-flash-exp`, `gemini-1.5-pro`).
- `accounts/gemini-events-<N>.ndjson` — per-slot event log, 0o600, gitignored, drained by daemon. Spec 07 §7.2.3.1 freezes the event-delivery contract: 50 ms non-blocking connect ceiling, drop-on-unavailable semantics, NDJSON-as-durability-floor invariant.
- Daemon NDJSON consumer + live IPC route — drains every `gemini-events-<N>.ndjson` on startup and on each tick; advances `quota.json`; rotates corrupt logs to `gemini-events-<N>.corrupt.<unix_ms>` and starts fresh.
- Desktop UI (PR-G5): AddAccountModal Gemini tab with two sub-tabs (AI Studio key paste / Vertex SA JSON file picker), ToS disclosure modal, inline OAuth-residue warning panel; ChangeModelModal static Gemini list with preview-tier downgrade warning; AccountCard surface badge + downgrade chip + "quota: n/a" rendering.
- Six new Tauri commands: `is_gemini_tos_acknowledged`, `acknowledge_gemini_tos`, `gemini_probe_tos_residue`, `gemini_provision_api_key`, `gemini_provision_vertex_sa`, `gemini_switch_model`.

### Changed

- `error::redact_tokens` learns the `AIza*` prefix (Google API keys) alongside the existing `sk-ant-*` and long-hex coverage. Applied at every Gemini-adjacent error format site.
- `dialog:allow-open` permission grant added to `csq-desktop/src-tauri/capabilities/default.json` (narrow, replaces no `:default` 3P plugin grants — capability audit per `rules/tauri-commands.md`).

### Deferred

- **D7 — vault-delete-on-unbind from desktop** (an internal journal entry §FD #1, restated in 0013). CLI `csq logout` calls `vault.delete`; desktop "remove Gemini account" flow does not yet. Follow-up PR.
- **csq-cli orchestration cleanup** (an internal journal entry). `setkey.rs::handle_gemini` and `models.rs::write_gemini_model_to_binding` carry ~30 LOC of contained duplication that collapses to single-source via `csq-core` helpers.
- **`launch_gemini` / `exec_gemini` factoring** (an internal journal entry §D4). 2 callers today; threshold is 3. Re-evaluate at v2.4 if a third caller appears.

---

## [2.2.0] — 2026-04-25

Minor release on v2.1.1. Two backwards-compatible onboarding improvements reported against fresh WSL installs: `csq status` now shows every configured surface (was Anthropic-only), and `csq install` + `csq run` pre-emptively detect the two failure modes behind `SessionStart:startup hook error` / `node:internal/modules/cjs/loader:1143`.

See `docs/releases/v2.2.0.md` for the full release notes.

### Added

- `csq_core::platform::env_check` — hook-environment preflight module. `run_preflight(claude_home, cwd)` parses both global and project `settings.json` hook blocks, resolves every hook command's script path (with `$CLAUDE_PROJECT_DIR` / `~` expansion), verifies existence, and for `.js` scripts also resolves every `require("./relative")` target against node's standard extension set (`.js`, `.cjs`, `.mjs`, `.json`, `index.js`). Emits `EnvIssue::NodeMissingForHooks`, `::HookScriptMissing`, or `::HookRelativeRequireMissing` with full path context. `detect_linux_flavor()` classifies WSL / Debian / RedHat / Arch / Other from `/proc/version` + `/etc/os-release`; `node_install_hint()` returns the right package-manager one-liner per platform.
- `csq install` runs the preflight after settings patching. On Linux flavors where csq knows the install command, prompts `[y/N]` before running `sudo apt` / `dnf` / `pacman`. macOS / Windows / unknown flavors print the hint only.
- `csq run` runs the same preflight at the top of `handle()`, stderr-only and non-blocking — mid-session launches are never stranded.
- `AccountStatus` gains `source: AccountSource` and `surface: Surface` fields (both with `#[serde(default)]`) so third-party and Codex rows carry enough context for surface-aware rendering.
- README Troubleshooting entry for the `loader:1143` error string with per-platform fix commands.

### Changed

- `csq-core::quota::status::show_status` now calls `discovery::discover_all` instead of `discover_anthropic`. The daemon's `GET /api/accounts` (via `cached_discovery` in `daemon::server`) makes the same switch, so the daemon-delegated path and the direct path both enumerate every configured surface. Previously both were Anthropic-only.
- `AccountStatus::format_line` renders a surface tag after the label — `[codex]` for Codex OAuth rows, `[<provider>]` for third-party rows (e.g. `[minimax]`, `[zai]`, `[ollama]`), `[manual]` for manually configured rows. Anthropic OAuth rows render an empty tag so existing `csq status` output is byte-identical for Anthropic-only setups.
- `AccountStatus::format_line` skips the `5h:— / 7d:—` quota suffix for surfaces csq does not poll (third-party + manual) and renders `(api-key)` instead, so "no polling" is distinguishable from "no data yet".

---

## [2.1.1] — 2026-04-24

Patch release on v2.1.0 closing two on-disk-artifact migration gaps reported the day after the v2.1.0 cut. No new features, no schema changes, no behavior change for fresh installs.

See `docs/releases/v2.1.1.md` for the full release notes.

### Fixed

- **an internal ticket** — daemon-startup migration to strip legacy `apiKeyHelper` from 3P settings written by pre-alpha.8 csq. The field was the provider's `system_primer` string serialized into a key CC interprets as a shell command; affected slots emitted `apiKeyHelper failed: exited 127` plus an auth-conflict warning on every CC launch. The write paths were hardened in alpha.8 but on-disk artifacts on upgraded machines were never cleaned up. New `pass4` in the daemon's startup reconciler walks `<base_dir>/config-<N>/settings.json` and `<base_dir>/settings-*.json` and strips `apiKeyHelper` only when both `apiKeyHelper` AND `env.ANTHROPIC_AUTH_TOKEN` are present (the unambiguous legacy-bug signature; user-authored helper scripts alone are preserved). Atomic + 0o600 + idempotent + mtime-preserving on no-op.
- **an internal ticket** — `csq install` now walks per-terminal handle dirs at `~/.claude/accounts/term-*/settings.json` alongside the existing `config-<N>/settings.json` walk. Pre-install terminals carrying the stale `bash ~/.claude/accounts/statusline-quota.sh` wrapper no longer silently lose their statusline when `cleanup_v1_artifacts` renames the wrapper to `.bak`. Install summary line now reports both per-slot and per-handle migrations on separate lines.

### Changed

- `ReconcileSummary` gains two counter fields (`api_key_helper_files_seen`, `api_key_helper_files_migrated`) for telemetry / `csq doctor`.
- `csq install` extracts the per-file statusline-strip work into a shared `strip_legacy_statusline_from_file` helper used by both `migrate_per_slot_statuslines` and the new `migrate_handle_dir_statuslines`.

---

## [2.1.0] — 2026-04-23

Codex as a first-class second surface alongside ClaudeCode: device-auth login, central token refresh, live `wham/usage` polling, in-flight `csq swap` between Codex slots, cross-surface swap with confirm-prompt + clean handover, and a desktop UI with Terms-of-Service disclosure. Quota schema writer flips v1 → v2; v2.0.1 dual-read keeps downgrade compatible.

See `docs/releases/v2.1.0.md` for the full release notes including the surface dispatch architecture, two redteam convergence rounds, the M10 same-surface Codex repoint decision, the M-CDX-1 ordering invariant, the Windows caveat carry-over, and migration & compatibility notes.

### Added

- Codex surface across `discovery`, `auto_rotate`, `rotation::swap_to`, `daemon::refresher`, and `usage_poller`. `Surface::ClaudeCode` and `Surface::Codex` enums replace the prior implicit Anthropic-only assumption.
- `csq login N --provider codex` CLI flow + desktop AddAccountModal Codex panels (codex-tos, codex-keychain-prompt, codex-running, codex-picker in ChangeModelModal). Five new Tauri commands: `start_codex_login`, `complete_codex_login`, `list_codex_models`, `acknowledge_codex_tos`, `set_codex_slot_model`. Plus `cancel_codex_login` from the round-1 hardening.
- Daemon Codex refresher (`broker_codex_check` + `HttpPostFnCodex`), surface-dispatched `tick`, startup reconciler (INV-P08 mode flip + INV-P03 config.toml drift), Windows H2 gate (`require_daemon_healthy` cross-platform + named-pipe surface-dispatch integration test).
- `usage_poller/codex.rs` parses live `wham/usage` per an internal journal entry schema (5h primary + 7d secondary rate-limit windows; `used_percent` is 0–100). Circuit breaker 5-fail → 15min → 80min cap. Raw-body capture to `accounts/codex-wham-raw.json` (0600, redactor-first). STABLE per an internal journal entry capture.
- `quota.json` schema_version 2 writer (PR-C6). Nested `CounterState` / `RateLimitState` per spec 07 §7.4.1 + `extras: Option<serde_json::Value>` escape hatch. Idempotent v1 → v2 migration on first daemon tick.
- `csq swap` cross-surface dispatch (PR-C7). INV-P05 confirm prompt (`--yes` bypasses), INV-P10 rename-source-to-tombstone, then `exec` the target binary. Same-surface Codex routes to the new in-flight `repoint_handle_dir_codex` (M10).
- `csq models switch <slot> <model>` Codex dispatch — Codex slots route to a `TomlModelKey` writer that updates `config.toml`.
- New `csq-core/src/platform/test_env.rs` shared cross-module mutex for env-var-mutating tests.
- Surface badge in AccountList per slot.
- `repoint_handle_dir_codex` for in-flight same-surface Codex swap (M10 / an internal journal entry). codex-cli re-stats `auth.json` before each API call so the next request authenticates as the new slot; UNIX open-after-rename keeps in-flight session fds valid until close.
- `RouteKind` + `route()` pure dispatcher helper in `csq-cli/src/commands/swap.rs` with three-way matrix unit tests (L-CDX-3, an internal journal entry).

### Changed

- Auto-rotate is **ClaudeCode-only by design** in v2.1 (CRITICAL fix in an internal journal entry). `find_target` short-circuits when the current account's surface is not ClaudeCode; `repoint_handle_dir` adds a belt-and-suspenders refusal for Codex-shape handle dirs.
- IPC payload audit flipped from blacklist to per-struct **whitelist** via `assert_ipc_keys_whitelisted` helper (round 1).
- `app.emit` for `codex-device-code` narrowed to `app.emit_to("main", ...)` so the device code does not broadcast to every window.
- `csq swap` cross-surface path uses atomic `rename` to a `.sweep-tombstone-swap-<pid>-<nanos>` sibling instead of `remove_dir_all`, closing the Ctrl-C signal-window race and preserving open fds for the running surface process.
- `repoint_handle_dir_codex` `codex_links` slice rewrites credential (`auth.json`) BEFORE marker (`.csq-account`) so a mid-loop rename failure cannot leave the marker pointing at slot N+1 while the credential still resolves to slot N (M-CDX-1 / an internal journal entry).

### Fixed

- `is_device_code_shape` narrowed to exactly `XXXX-XXXX` (8 alphanumerics + mandatory middle dash); regression tests pin acceptance and rejection patterns.
- `acknowledgeCodexTos` recursion guard via `tosRetry` parameter — second `tos_required` returns a user-facing error instead of looping.
- `complete_codex_login` outer `.map_err` re-redacts via `redact_tokens` so the full anyhow chain is sanitized at the IPC boundary.
- Keychain purge errors wrapped in `redact_tokens` before formatting.
- Raw-auth-json wipe uses a fixed 64 KiB zero buffer + `O_WRONLY|O_TRUNC` + `sync_all`; retries `remove_file` after zero-write.
- `/api/invalidate-cache` HTTP POST wrapped in 500ms `recv_timeout` so a hung daemon cannot block the calling `spawn_blocking` thread indefinitely.
- `mpsc::channel(unbounded)` in the codex device-auth piped reader converted to `sync_channel(4)` with `try_send` so banner repetition cannot fill memory; forwarder drains all codes but only fires `on_code` for the first.
- `tos::is_acknowledged` distinguishes `NotFound` (silent) from other `io::Error` kinds (logged at WARN with named error_kind tags).
- `complete_login_scrubs_written_auth_json_when_canonical_save_fails` regression — extracted `scrub_and_remove_written` helper called from BOTH success cleanup AND `save_canonical_for` error branch.
- `set_codex_slot_model` consults `discover_all` and refuses non-Codex slots with a named error.
- Codex surface guard in `repoint_handle_dir_codex` requires BOTH `auth.json` AND `config.toml` AND each must be a symlink (L-CDX-1 / an internal journal entry).
- `csq swap` Codex→Codex no longer silently `exec`-replaces the running codex process (M10 / an internal journal entry). Prior behaviour dropped the user's conversation with no warning.

### Platform notes

- **Windows.** Codex on Windows is **not supported** in v2.1 — Codex slots require a running daemon (INV-P02), and the daemon supervisor still short-circuits per v2.0.1's PR-VP-C1a (the `windows-daemon` Cargo feature is default-off pending PR-VP-C1b). Same-surface Codex swap on Windows is also untested per L-CDX-2 (the `repoint_handle_dir_codex` regression tests are all `#[cfg(unix)]`, matching the existing ClaudeCode `repoint_handle_dir` path's status). Both repoint paths will be audited together when the Windows port workstream lands.
- **macOS / Linux.** Full Codex support; carries over the v2.0.1 macOS ad-hoc signature and Linux daemon socket layout.

### Deferred to v2.1.x or v2.2

- PR-VP-C1b — Windows daemon flag flip.
- L-CDX-2 — same-surface Codex swap on Windows behaviour audit (paired with the Windows port).
- `RepointStrategy` trait extraction — re-evaluate at N=3 surfaces.
- IPC whitelist proc-macro — re-evaluate if a second IPC slip materializes past the unit-test harness.

---

## [2.0.1] — 2026-04-22

Safety patch on v2.0.0. One CRITICAL credential-handling risk fixed (auto-rotation routing Anthropic OAuth tokens through 3P endpoints under a narrow but reachable mix of OAuth + 3P bindings on the same slot), four HIGH correctness bugs, nine MED/LOW hardening items. Adds READ tolerance for the v2 quota.json schema that v2.1 writes (dual-read; v2.0.1 continues to write v1).

See `docs/releases/v2.0.1.md` for the full red-team finding inventory (an internal journal entry), structural rotation fix (PR-A1 / an internal journal entry), credential-sync guards (PR-B7 / an internal journal entry), and quota schema shakedown (PR-C1.5 / VP-final).

## [2.0.0] — 2026-04-22

First stable release of the Rust rewrite. Retires the v1.x bash + Python stack.

See `docs/releases/v2.0.0.md` for the full release notes with install instructions, migration guide, and known limitations.

### Added

- Full Rust CLI: `csq run`, `csq swap`, `csq status`, `csq login`, `csq setkey`, `csq install`, `csq doctor`, `csq update check`, `csq statusline`, `csq models switch`.
- Tauri desktop app with Svelte 5 frontend — system tray, OAuth flow, quota dashboard, in-app update detection, Ollama model switcher.
- Handle-dir session model (spec 02) — each terminal has an ephemeral `term-<pid>/` with symlinks, enabling in-flight `csq swap` without terminal restart.
- Third-party provider support: MiniMax, Z.AI, Ollama. Per-slot bindings, per-provider quota polling.
- Central token refresher with per-account exponential backoff (10min × 2^n, cap 80min).
- Daemon IPC hardened with umask 0o077 + chmod 0o600 + peer-credential check (`SO_PEERCRED` / `LOCAL_PEERCRED`) + per-user socket directory.
- Recurring in-app update check with exponential-backoff retry and tray menu trigger.
- Paste-code OAuth flow (replaces the legacy loopback TCP listener).
- Square TF app-icon family (full 16→1024 `.icns`, no Retina pixelation).
- Subscription-metadata preservation guard across every credential write site (`rotation::swap_to`, `broker::fanout::fan_out_credentials`, `broker::sync::backsync`, `credentials::refresh::merge_refresh`).
- Token redaction (`error::redact_tokens`) at every OAuth body error-format surface.
- `csq install` migrates legacy per-slot `statusLine` (v1.x `statusline-quota.sh` references) to `csq statusline` on upgrade.
- `csq models switch` CLI for in-place 3P model retarget; `--pull-if-missing` auto-pulls Ollama models before binding.
- Ollama integration via HTTP API (`http://localhost:11434/api/tags`) + `find_ollama_bin()` resolver (searches `$OLLAMA_BIN`, `/usr/local/bin`, `/opt/homebrew/bin`, PATH).

### Fixed

- Auto-rotation no longer corrupts `config-N/.credentials.json` under the handle-dir model — refuses to run when any `term-*/` dir is present (an internal journal entry, P0-1).
- `download_and_apply` updater path guards against placeholder signing key at the core entry, not just the CLI wrapper (an internal journal entry H1).
- `broker::sync::backsync` preserves canonical's `subscription_type` when live carries `None` (an internal journal entry P1-1) — prevents silent Max→Sonnet downgrade after re-login.
- `bind_provider_to_slot` preserves user-edited `permissions`, `plugins`, `effortLevel`, and user-custom env keys when rebinding a 3P provider (an internal journal entry P1-2).
- `providers::settings::save_settings` propagates `secure_file` chmod errors — 3P API-token files can no longer silently publish at umask default.
- `ChangeModelModal` loads installed Ollama models on every open edge (an internal journal entry) — alpha.21 had a `$effect` guard that skipped the first open entirely.
- `cancel_login` IPC command uses fixed-vocabulary error tags (an internal journal entry M1) — future OAuthError widening cannot leak token material.
- Tauri capabilities narrowed to per-command allowlists (`opener:allow-open-url`, `autostart:allow-*`, `process:allow-restart/exit`) (an internal journal entry M2).
- Resurrection-log JSONL uses `serde_json::to_string` (an internal journal entry M3) — paths with backslash or control characters no longer corrupt the forensic trail.
- Desktop header shows the bundled `tauri.conf.json` version via `getVersion()` instead of a hardcoded literal (an internal journal entry P1-5).

### Platform notes

- Windows desktop supervisor short-circuits on `#[cfg(not(unix))]` — the non-unix `run_daemon` was a stub; the supervisor no longer fake-claims daemon ownership and no longer blocks token refresh expectations. Full Windows named-pipe daemon wiring ships in a post-2.0 release. See L4 in the release notes.

### Deferred to 2.0.1

- Handle-dir-native auto-rotator (structural fix to P0-1).
- Shared `csq-core` helper for `set_slot_model_write` / `write_slot_model` atomic write (red-team R6).
- Throttled `ollama-pull-progress` emit rate (red-team R11).
- Defense-in-depth canonicalization guard on all `base_dir: String` Tauri commands (security audit L7).
- Security audit M-level cleanups: L1 (make `OAuthError::Http.body` private), L2–L6 (log-line cleanups), L7 (base_dir canonicalization).

---

## [1.1.0] — 2026-04-10

Z.AI GLM-5.1 provider support + coding-orchestration benchmark harness. Last v1.x release before the Rust rewrite.

## [1.0.0] — 2026-04-09

Initial multi-provider session manager for Claude Code. Bash + Python implementation with rotation engine, token refresh daemon, quota statusline, and paste-code OAuth.

---

[2.0.0]: https://github.com/terrene-foundation/csq/releases/tag/v2.0.0
[1.1.0]: https://github.com/terrene-foundation/csq/releases/tag/v1.1.0
[1.0.0]: https://github.com/terrene-foundation/csq/releases/tag/v1.0.0
[2.0.1]: https://github.com/terrene-foundation/csq/releases/tag/v2.0.1
[2.1.0]: https://github.com/terrene-foundation/csq/releases/tag/v2.1.0
[2.1.1]: https://github.com/terrene-foundation/csq/releases/tag/v2.1.1
