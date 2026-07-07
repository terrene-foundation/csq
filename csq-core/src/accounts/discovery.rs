//! Account discovery — finds all configured accounts from multiple sources.
//!
//! Sources: Anthropic credentials, per-slot third-party bindings, global
//! third-party settings, manual accounts.

use super::identity_store;
use super::profiles;
use super::{AccountInfo, AccountSource, BillingMode};
use crate::credentials;
use crate::providers::catalog::Surface;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tracing::warn;

/// Reads `oauthAccount.emailAddress` from a credential JSON file on disk.
///
/// This is the trust anchor for `AccountInfo.oauth_email` in
/// `discover_anthropic` — the credential file is Anthropic's authenticated
/// record, independent of any csq-managed profile state.
///
/// Returns `None` if the file is missing, not valid JSON, or has no
/// non-empty `emailAddress` field. Callers should treat `None` as
/// "OAuth email unknown" and skip `by_email` writes for this slot.
fn read_oauth_email_from_cred_path(cred_path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(cred_path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    let email = json
        .get("oauthAccount")
        .and_then(|a| a.get("emailAddress"))
        .and_then(|v| v.as_str())?;
    if email.is_empty() {
        None
    } else {
        Some(email.to_string())
    }
}

/// Discovers all configured accounts from all sources, deduplicating by ID.
///
/// Sources checked in priority order:
/// 1. Anthropic OAuth (`credentials/N.json`)
/// 2. Per-slot third-party bindings (`config-N/settings.json` with a 3P
///    `ANTHROPIC_BASE_URL`) — these take numbered slots (9, 10, …)
///    alongside OAuth accounts so users see one unified list.
/// 3. Global third-party bindings (`settings-mm.json` / `settings-zai.json`
///    at the base dir level, synthetic slots 901/902) — suppressed if the
///    same provider is already bound to a numbered slot above.
/// 4. Manual accounts (`dashboard-accounts.json`)
///
/// First source wins on duplicate slot IDs.
pub fn discover_all(base_dir: &Path) -> Vec<AccountInfo> {
    let mut seen: HashMap<u16, ()> = HashMap::new();
    let mut accounts = Vec::new();

    // Priority 1: Anthropic OAuth accounts
    for info in discover_anthropic(base_dir) {
        if seen.insert(info.id, ()).is_none() {
            accounts.push(info);
        }
    }

    // Priority 1b (PR-C3a): Codex OAuth accounts. Slot numbers are
    // disjoint from Anthropic by filename prefix (`codex-<N>.json` vs
    // `<N>.json`), but the shared `AccountInfo.id` namespace still
    // deduplicates — first source wins. Landing Codex here (before 3P
    // per-slot) matches the OAuth-first priority established for
    // Anthropic.
    for info in discover_codex(base_dir) {
        if seen.insert(info.id, ()).is_none() {
            accounts.push(info);
        }
    }

    // Priority 1c (Round-7): Google Gemini bindings — Code Assist
    // OAuth, AI Studio API key, or Vertex SA. Stored as
    // `credentials/gemini-<N>.json`; the binding marker carries the
    // auth-mode tag.
    for info in discover_gemini(base_dir) {
        if seen.insert(info.id, ()).is_none() {
            accounts.push(info);
        }
    }

    // Priority 2: Per-slot third-party bindings. These occupy real
    // numbered slots (e.g. 9 = MiniMax, 10 = Z.AI) and should appear
    // in the dashboard alongside OAuth accounts 1-8.
    let mut per_slot_providers: HashSet<String> = HashSet::new();
    for info in discover_per_slot_third_party(base_dir) {
        if let AccountSource::ThirdParty { provider } = &info.source {
            per_slot_providers.insert(provider.clone());
        }
        if seen.insert(info.id, ()).is_none() {
            accounts.push(info);
        }
    }

    // Priority 3: Global third-party bindings at synthetic 9xx slots.
    // Suppress entries whose provider already appears as a per-slot
    // binding — otherwise the user sees both "9 MiniMax" and "902
    // MiniMax" for the same underlying setup.
    for info in discover_third_party(base_dir) {
        if let AccountSource::ThirdParty { provider } = &info.source {
            if per_slot_providers.contains(provider) {
                continue;
            }
        }
        if seen.insert(info.id, ()).is_none() {
            accounts.push(info);
        }
    }

    // Priority 4: Manual accounts
    for info in discover_manual(base_dir) {
        if seen.insert(info.id, ()).is_none() {
            accounts.push(info);
        }
    }

    accounts
}

/// Classifies an `ANTHROPIC_BASE_URL` into a known provider name.
///
/// Returns `None` for `api.anthropic.com` (native Anthropic is handled
/// via OAuth discovery, not 3P) and for any URL that doesn't match a
/// known host. Returns a display name like `"MiniMax"` / `"Z.AI"` /
/// `"DeepSeek"` / `"Ollama"` otherwise.
///
/// The match is host-substring-based so variant hostnames like
/// `api.minimax.io` (vs. the catalog default `api.minimax.chat`)
/// still classify correctly.
/// Maps a 3P provider's display name to its [`BillingMode`].
///
/// **Provisional Phase A dispatch — see an internal journal entry for the design
/// rework planned for Phase B'.** This dispatch is structurally
/// flawed: billing mode is a property of the user's PLAN with a
/// provider, not the provider itself. MiniMax, Z.AI, and DeepSeek all
/// ship BOTH subscription tiers AND pay-per-token modes; the API key
/// authenticates either. A static catalog-driven mapping cannot tell
/// them apart.
///
/// For now, the field is set on AccountInfo but no UI consumer
/// branches on it — the rendering reverted to the pre-Phase-B
/// 5h/7d-bars-for-everyone shape (commit reverting AccountList badge
/// changes 2026-05-06). The empirical mode (subscription vs
/// pay-per-token) will be discovered at poll time once Phase B' lands
/// the per-slot usage tracker.
///
/// Returns `Local` only for Ollama (genuinely no billing surface).
/// All other 3P providers default to `Subscription` so the existing
/// 5h/7d bar rendering doesn't regress for users on subscription
/// plans.
pub(crate) fn billing_mode_for_3p(provider_display_name: &str) -> BillingMode {
    match provider_display_name {
        "Ollama" => BillingMode::Local,
        _ => BillingMode::Subscription,
    }
}

pub(crate) fn provider_from_base_url(base_url: &str) -> Option<&'static str> {
    let lower = base_url.to_ascii_lowercase();
    // Native Anthropic is not a 3P account — skip it.
    if lower.contains("api.anthropic.com") {
        return None;
    }
    if lower.contains("minimax") {
        return Some("MiniMax");
    }
    if lower.contains("z.ai") {
        return Some("Z.AI");
    }
    if lower.contains("deepseek") {
        return Some("DeepSeek");
    }
    if lower.contains("localhost") || lower.contains("127.0.0.1") {
        return Some("Ollama");
    }
    None
}

/// Walks `base_dir/config-N/settings.json` files and emits one
/// `AccountInfo` per slot that has a 3P provider binding.
///
/// A "3P binding" means the slot's `settings.json` has
/// `env.ANTHROPIC_BASE_URL` pointing at a host other than
/// `api.anthropic.com`. The provider name is derived from the URL
/// via `provider_from_base_url`. `has_credentials` reflects whether
/// `env.ANTHROPIC_AUTH_TOKEN` is present (required for bearer-auth
/// providers).
///
/// Slot IDs are taken from the `config-<N>` dir name, 1..=999.
/// Symlinks are rejected to prevent traversal outside base_dir.
pub fn discover_per_slot_third_party(base_dir: &Path) -> Vec<AccountInfo> {
    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut accounts = Vec::new();
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        // Reject symlinks — a config-N symlinked outside base_dir
        // would let IPC-side account listing escape the boundary.
        if file_type.is_symlink() || !file_type.is_dir() {
            continue;
        }
        let name_os = entry.file_name();
        let Some(name) = name_os.to_str() else {
            continue;
        };
        let Some(num_str) = name.strip_prefix("config-") else {
            continue;
        };
        let id: u16 = match num_str.parse() {
            Ok(n) if (1..=999).contains(&n) => n,
            _ => continue,
        };

        let settings_path = entry.path().join("settings.json");
        let content = match std::fs::read_to_string(&settings_path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let json: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_e) => {
                // Fixed-vocabulary tag only — `settings.json` carries 3P
                // `ANTHROPIC_AUTH_TOKEN`s, and `serde_json::Error` Display
                // can echo a fragment of the document near the parse fault.
                // `security.md` MUST Rule 2 forbids `%e` of error bodies in
                // credential-adjacent modules. The slot id is the actionable
                // signal; the malformed file is at `config-<slot>/settings.json`.
                warn!(
                    error_kind = "settings_json_invalid",
                    slot = id,
                    "skipping per-slot settings.json with invalid JSON"
                );
                continue;
            }
        };

        // Extract env.ANTHROPIC_BASE_URL. `ANTHROPIC_BASE_URL` at the
        // top level is also accepted for forward-compat, but the
        // canonical location is under `env.`.
        let env = json.get("env");
        let base_url = env
            .and_then(|e| e.get("ANTHROPIC_BASE_URL"))
            .or_else(|| json.get("ANTHROPIC_BASE_URL"))
            .and_then(|v| v.as_str());
        let Some(base_url) = base_url else { continue };

        let Some(provider_name) = provider_from_base_url(base_url) else {
            continue;
        };

        let has_token = env
            .and_then(|e| e.get("ANTHROPIC_AUTH_TOKEN"))
            .or_else(|| json.get("ANTHROPIC_AUTH_TOKEN"))
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);

        // A user rename (`by_slot_label`) wins over the provider-name default,
        // matching the Anthropic `get_email` step-1 precedence. Only the
        // display `label` is affected — the canonical `provider` id below is
        // untouched (downstream dispatch keys on it).
        let label =
            profiles::slot_rename_label(base_dir, id).unwrap_or_else(|| provider_name.to_string());
        accounts.push(AccountInfo {
            id,
            label,
            oauth_email: None,
            source: AccountSource::ThirdParty {
                provider: provider_name.to_string(),
            },
            surface: Surface::ClaudeCode,
            method: "api_key".into(),
            has_credentials: has_token,
            billing_mode: billing_mode_for_3p(provider_name),
        });
    }

    // Deterministic ordering by slot id for dashboard stability.
    accounts.sort_by_key(|a| a.id);
    accounts
}

/// Discovers Anthropic OAuth accounts.
///
/// **Post-M4-4 (Phase 4 reader flip).** Single-pass walk routed by
/// `profiles.json::by_slot`:
///
/// - **Identity-keyed path (preferred).** For each `(slot_str, uuid)` entry
///   in `profiles.json::by_slot`, parse the slot, resolve `identities/<UUID>/credentials.json`
///   via [`identity_store::credentials_path_for`], and yield an `AccountInfo`.
///   The `phase3_gate_check` in `daemon::startup_reconciler` guarantees that
///   every UUID in `by_slot` has its identity credentials file seeded before
///   the daemon serves any request — so a missing identity credentials file
///   here is a hard error (logged, slot skipped), not a fallback trigger.
/// - **Pure-legacy fallback.** When `by_slot` is empty (no UUID mapping in
///   `profiles.json` — i.e. a csq install that has never run an A++-aware
///   daemon Pass 0), walk `credentials/N.json` ONCE and synthesize
///   `AccountInfo` per entry. No second-pass live-fallback against
///   `config-N/.credentials.json`: the pre-M4-4 Pass 2 closed the alpha.11
///   recovery seam, but the M3-7 `phase3_gate_check` (and M4-5
///   `phase4_gate_check`) now closes the same seam at the gate, refusing
///   daemon start when identity credentials are unseeded. Pass 2 is retired.
///
/// **Slot-id channel.** Slot id originates from `profiles.json::by_slot` keys
/// (UUID-keyed branch) or `credentials/N.json` filenames (pure-legacy
/// branch). Neither channel derives slot from terminal-scoped state — both
/// satisfy `account-terminal-separation.md` MUST Rule 1.
///
/// Cross-references with `profiles.json::accounts` for email labels.
pub fn discover_anthropic(base_dir: &Path) -> Vec<AccountInfo> {
    let profiles_path = profiles::profiles_path(base_dir);
    let profiles =
        profiles::load(&profiles_path).unwrap_or_else(|_| profiles::ProfilesFile::empty());

    let mut accounts = Vec::new();

    // UUID-keyed branch: walk `profiles.json::by_slot`. After the codex-only
    // skip below, every remaining UUID is an Anthropic-bound slot whose
    // credentials `phase4_gate_check` (M4-5) seeded before the daemon serves
    // any request — so an unreadable file at this point is a hard error worth
    // surfacing, not a fallback signal. (Codex-only slots are skipped first
    // because they legitimately have no Anthropic `credentials.json`.)
    if !profiles.by_slot.is_empty() {
        for (slot_str, uuid) in &profiles.by_slot {
            let id: u16 = match slot_str.parse() {
                Ok(n) if (1..=999).contains(&n) => n,
                _ => {
                    warn!(
                        slot_key = %slot_str,
                        "by_slot key is not a valid slot number, skipping"
                    );
                    continue;
                }
            };

            // Skip slots owned by a Gemini binding. Without this, the
            // Anthropic refresher would try to refresh a Gemini-owned
            // identity that has no Anthropic OAuth tokens. Origin:
            // redteam round 1 M3 (an internal journal entry) — pre-M4-4 the equivalent
            // skip lived in Pass 2; the structural concern is identical.
            let gemini_marker = base_dir
                .join("credentials")
                .join(format!("gemini-{id}.json"));
            if gemini_marker.exists() {
                continue;
            }

            // Skip codex-only slots (UUID minted for `csq login N --provider
            // codex` without any prior Anthropic OAuth). Such a slot is
            // structurally codex-bound — `identity.json` carries `"provider":
            // "codex"` and its credentials live at `credentials-codex.json` —
            // but has NO Anthropic credentials anywhere. Without this skip,
            // discover_anthropic would tag the slot as Anthropic-with-broken-
            // credentials and emit a spurious "phase4_gate should have caught
            // this" WARN. The detection is identity-store-aware (per
            // account-terminal-separation.md MUST Rule 4): the canonical
            // post-A++ signal is `identity.json` provider, with the legacy
            // `credentials/codex-<N>.json` marker as a pre-A++ fallback —
            // a post-A++ slot whose legacy mirror was retired (host slot 8)
            // has no marker but is still codex-only. The codex surface
            // enumerator (discover_codex) owns these slots.
            if identity_store::is_codex_only_slot(base_dir, id, *uuid) {
                continue;
            }

            let uuid_cred_path = identity_store::credentials_path_for(base_dir, *uuid);
            let has_credentials = match credentials::load(&uuid_cred_path) {
                Ok(_) => true,
                Err(e) => {
                    // Distinguish a genuine phase4-gate miss from a slot whose
                    // Anthropic credentials were INTENTIONALLY cleared (e.g.
                    // `csq repair --heal-contaminated`, which deletes the store
                    // AND the legacy `credentials/N.json`, leaving the slot
                    // cleanly awaiting re-login). phase4_gate Check 3 refuses
                    // start ONLY when the legacy ClaudeCode canonical is present;
                    // its ABSENCE means the gate CORRECTLY let the slot through,
                    // so the "gate should have caught this" WARN would
                    // misattribute a designed post-heal state to a gate bug.
                    let legacy_present = crate::types::AccountNum::try_from(id)
                        .map(|acct| {
                            crate::credentials::file::canonical_path_for(
                                base_dir,
                                acct,
                                Surface::ClaudeCode,
                            )
                            .exists()
                        })
                        .unwrap_or(false);
                    // Path-free fixed-vocabulary tag; never `error = %e`
                    // (CredentialError::Display echoes the absolute path
                    // and serde_json error fragments). security.md §2;
                    // mirror of the discover_codex fix at line 534.
                    if legacy_present {
                        warn!(
                            slot = id,
                            uuid_short = %uuid.to_canonical_string().chars().take(8).collect::<String>(),
                            path = %uuid_cred_path.display(),
                            error_kind = e.error_kind_tag(),
                            "by_slot identity credentials unreadable but legacy canonical \
                             present; phase4_gate should have caught this — daemon running \
                             in degraded mode for this slot"
                        );
                    } else {
                        // No legacy source → gate correctly passed; benign
                        // awaiting-login state (credentials cleared, e.g. by
                        // `csq repair --heal-contaminated`, or a fresh-mint race).
                        // The slot stays credential-less until `csq login`.
                        tracing::debug!(
                            slot = id,
                            uuid_short = %uuid.to_canonical_string().chars().take(8).collect::<String>(),
                            error_kind = e.error_kind_tag(),
                            "by_slot Anthropic credentials unreadable (no legacy canonical) — \
                             slot awaiting `csq login`"
                        );
                    }
                    false
                }
            };

            // RN1-D1 (Finding-3d, C2 fix): label = display email (may be
            // user-chosen rename); oauth_email = sourced directly from the
            // credential file's `oauthAccount.emailAddress` field — NOT from
            // `profiles.oauth_email_for_slot` (which reads `by_email` in a
            // circular way: if `by_email` is polluted, the "trusted" email
            // returned IS the polluted value, cementing the corruption on the
            // next Pass-0 re-ingest). The credential file is Anthropic's
            // authenticated record and is the correct trust anchor.
            // F-L-1 R1C defense-in-depth: route every label through
            // `sanitize_for_display` so by_slot_identity-derived labels
            // (Codex `account_id_hint`-shaped strings) cannot smuggle
            // control bytes into the renderer if a future provider hint
            // includes one. Belt-and-suspenders — the Svelte renderer is
            // a text-node consumer today, but the defense lives at the
            // label-mint site so any future renderer inherits it.
            let label = crate::quota::format::sanitize_for_display(
                profiles.get_email(id).unwrap_or("unknown"),
            )
            .into_owned();
            let oauth_email = read_oauth_email_from_cred_path(&uuid_cred_path);
            accounts.push(AccountInfo {
                id,
                label,
                oauth_email,
                source: AccountSource::Anthropic,
                surface: Surface::ClaudeCode,
                method: "oauth".into(),
                has_credentials,
                billing_mode: BillingMode::Subscription,
            });
        }
        accounts.sort_by_key(|a| a.id);
        return accounts;
    }

    // Pure-legacy fallback: no `by_slot` entries. Walk
    // `credentials/<N>.json` ONCE — no Pass 2 against
    // `config-N/.credentials.json`. The pre-M4-4 Pass 2 closed the
    // alpha.11 live-only-fallback seam; the M3-7/M4-5 gate now closes
    // it structurally at daemon start.
    let mut seen_ids: HashSet<u16> = HashSet::new();
    let creds_dir = base_dir.join("credentials");
    if let Ok(entries) = std::fs::read_dir(&creds_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            let stem = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s,
                None => continue,
            };

            let id: u16 = match stem.parse() {
                Ok(n) if n >= 1 => n,
                _ => continue,
            };

            let has_credentials = match credentials::load(&path) {
                Ok(_) => true,
                Err(e) => {
                    // Path-free fixed-vocabulary tag (security.md §2;
                    // mirror of discover_codex fix at line 534).
                    warn!(
                        path = %path.display(),
                        error_kind = e.error_kind_tag(),
                        "skipping invalid credential file"
                    );
                    false
                }
            };

            // Pure-legacy: no by_slot entry → read oauth_email from
            // config-N/.credentials.json (CC's auth-time output that contains
            // oauthAccount.emailAddress). If absent, fall back to
            // accounts[N].email (written by the pre-RN1-D3 login flow, which
            // stored the OAuth email there before any rename feature existed).
            // Only "unknown" (the get_email sentinel) should map to None.
            let config_creds = base_dir
                .join(format!("config-{id}"))
                .join(".credentials.json");
            let oauth_email = read_oauth_email_from_cred_path(&config_creds).or_else(|| {
                profiles
                    .get_email(id)
                    .filter(|e| !e.is_empty() && *e != "unknown")
                    .map(|s| s.to_string())
            });
            // F-L-1 R1C defense-in-depth: sanitize before display. See the
            // sibling assignment in the `by_slot`-populated branch above.
            let email = crate::quota::format::sanitize_for_display(
                profiles.get_email(id).unwrap_or("unknown"),
            )
            .into_owned();
            seen_ids.insert(id);
            accounts.push(AccountInfo {
                id,
                label: email,
                oauth_email,
                source: AccountSource::Anthropic,
                surface: Surface::ClaudeCode,
                method: "oauth".into(),
                has_credentials,
                billing_mode: BillingMode::Subscription,
            });
        }
    }

    accounts.sort_by_key(|a| a.id);
    accounts
}

/// Discovers Codex OAuth accounts.
///
/// Walks `{base_dir}/credentials/codex-<N>.json` (PR-C2a canonical
/// path for `Surface::Codex`) and yields one [`AccountInfo`] per
/// credentials file that parses as a valid Codex variant.
///
/// Files that parse as the Anthropic variant (i.e. a misplaced
/// `claudeAiOauth` shape at a `codex-N.json` path) are logged at WARN
/// and skipped — the filename encodes surface, and a shape mismatch
/// indicates operator error or a broken write path.
///
/// Unlike [`discover_anthropic`], there is no live-fallback pass from
/// `config-N/codex-auth.json` — Codex accounts are always provisioned
/// canonical-first by the daemon's OAuth flow (PR-C3b). A missing
/// canonical file indicates the slot was never logged in.
///
/// Label is currently the slot number (`"codex-<N>"`) because Codex
/// does not ship with a lightweight profile file (no `profiles.json`
/// equivalent for Codex). Email-style labels arrive in a future PR
/// once `id_token` claim decoding is wired in.
///
/// # Task 6: UUID-keyed slot discovery (post-M4-12 + root-cause fix)
///
/// After the root-cause fix, Codex-only slots (never touched by an
/// Anthropic `csq login`) have their credentials at
/// `identities/<UUID>/credentials-codex.json` with NO corresponding
/// `credentials/codex-<N>.json` (the numeric path is retired as a write
/// destination in M4-12). Discovery now performs TWO passes:
///
/// 1. Legacy scan: `credentials/codex-<N>.json` (existing behaviour).
/// 2. UUID scan: enumerate `profiles.json::by_slot` entries; for each slot
///    that has a UUID AND a `identities/<UUID>/credentials-codex.json`, add
///    the slot if it was not already added via the legacy scan. Duplicate-
///    free: a slot found in BOTH passes appears exactly once.
pub fn discover_codex(base_dir: &Path) -> Vec<AccountInfo> {
    // Collect slot ids found via the legacy scan so we can skip them in the
    // UUID scan (duplicate-free guarantee).
    let mut seen_slots: std::collections::HashSet<u16> = std::collections::HashSet::new();
    let mut accounts = Vec::new();

    // ── Pass 1: legacy numeric scan (credentials/codex-<N>.json) ────────────
    let creds_dir = base_dir.join("credentials");
    if let Ok(entries) = std::fs::read_dir(&creds_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            let stem = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s,
                None => continue,
            };
            // Only `codex-<N>.json` files — skip Anthropic `<N>.json` and
            // any unexpected filename shape.
            let Some(num_str) = stem.strip_prefix("codex-") else {
                continue;
            };
            let id: u16 = match num_str.parse() {
                Ok(n) if (1..=999).contains(&n) => n,
                _ => continue,
            };

            let has_credentials = match credentials::load(&path) {
                Ok(cf) => {
                    // Filename said Codex — payload must match. If it
                    // doesn't, skip with a fixed-vocabulary log tag so
                    // an operator can trace a broken write path without
                    // any risk of token leakage.
                    if cf.codex().is_none() {
                        warn!(
                            path = %path.display(),
                            error_kind = "codex_discovery_wrong_variant",
                            "skipping codex-<N>.json whose payload is not the Codex variant"
                        );
                        continue;
                    }
                    true
                }
                Err(e) => {
                    // Skip legacy entry if a UUID-keyed alternative exists — otherwise
                    // the legacy 'has_credentials=false' entry masks the working one
                    // (DA-H4: corrupt legacy blocks Pass 2 from discovering same slot).
                    let uuid_alternative_exists = profiles::resolve_slot_to_uuid(base_dir, id)
                        .map(|uuid| {
                            identity_store::credentials_codex_path_for(base_dir, uuid).exists()
                        })
                        .unwrap_or(false);

                    // Path-free fixed-vocabulary tag; never `error = %e` (CredentialError::Display
                    // echoes the absolute path AND for `Corrupt`, raw serde_json fragments).
                    // security.md §2; in-scope per zero-tolerance.md Rule 5; mirror of #514's
                    // ambiguous_binding leak fix. The path interpolation in `path = %path.display()`
                    // is intentional for the structured-log subscriber audit trail (path is a
                    // local OS path, not a token); the `error = %e` was the load-bearing leak.
                    warn!(
                        path = %path.display(),
                        error_kind = e.error_kind_tag(),
                        "skipping invalid codex credential file"
                    );

                    if uuid_alternative_exists {
                        // Pass 2 will pick this slot up via the UUID-keyed path.
                        continue;
                    }
                    false
                }
            };

            seen_slots.insert(id);
            // A user rename (`by_slot_label`) wins over the `codex-N` default,
            // matching the Pass-2 precedence below and the Anthropic `get_email`
            // step-1 precedence. `pf` is not yet loaded in Pass 1, so use the
            // base_dir accessor.
            let label =
                profiles::slot_rename_label(base_dir, id).unwrap_or_else(|| format!("codex-{id}"));
            accounts.push(AccountInfo {
                id,
                label,
                oauth_email: None,
                source: AccountSource::Codex,
                surface: Surface::Codex,
                method: "oauth".into(),
                has_credentials,
                // Codex via OAuth is a ChatGPT subscription per
                // CodexAuth::Chatgpt / ChatgptAuthTokens / AgentIdentity
                // (an internal journal entry §"Codex"). The API-key (`OPENAI_API_KEY`)
                // path lands under a different AccountSource — Phase A
                // does not unify those yet.
                billing_mode: BillingMode::Subscription,
            });
        }
    }

    // ── Pass 2: UUID-keyed scan (identities/<UUID>/credentials-codex.json) ───
    //
    // Root-cause fix: after `mint_for_codex_login`, Codex-only slots have
    // credentials only at the UUID-keyed path. Enumerate by_slot entries from
    // profiles.json and add any slot not already found in the legacy scan.
    let profiles_path = profiles::profiles_path(base_dir);
    let pf = match profiles::load(&profiles_path) {
        Ok(p) => p,
        Err(_) => {
            // profiles.json absent or unreadable — no UUID-keyed slots to discover.
            accounts.sort_by_key(|a| a.id);
            return accounts;
        }
    };

    for (slot_str, uuid) in &pf.by_slot {
        let id: u16 = match slot_str.parse::<u16>() {
            Ok(n) if (1..=999).contains(&n) => n,
            _ => continue,
        };
        // Already found via legacy scan — skip.
        if seen_slots.contains(&id) {
            continue;
        }

        let uuid_cred_path = identity_store::credentials_codex_path_for(base_dir, *uuid);
        if !uuid_cred_path.exists() {
            // No credentials-codex.json at this UUID path — not a provisioned
            // Codex slot (may be an Anthropic-only slot that shares the UUID).
            continue;
        }

        let has_credentials = match credentials::load(&uuid_cred_path) {
            Ok(cf) => {
                if cf.codex().is_none() {
                    warn!(
                        slot = id,
                        error_kind = "codex_discovery_uuid_wrong_variant",
                        "skipping UUID-keyed credentials-codex.json whose payload is not Codex variant"
                    );
                    continue;
                }
                true
            }
            Err(e) => {
                warn!(
                    slot = id,
                    error_kind = e.error_kind_tag(),
                    "skipping invalid UUID-keyed codex credential file"
                );
                false
            }
        };

        // Precedence (mirrors `get_email` step 1): a user rename in
        // `by_slot_label` wins over the identity-derived default. Without this,
        // renaming a Codex slot writes `by_slot_label[N]` but discovery keeps
        // showing the `by_slot_identity` label (the "rename doesn't save" bug).
        // Fallback: `by_slot_identity` filtered to "codex-" so a stale
        // Anthropic-surface label (e.g. "anthropic-12/email") from an earlier
        // login on the same slot does not bleed into Codex discovery (DA-M2),
        // then the `codex-N` default.
        let label = pf
            .by_slot_label
            .get(slot_str)
            .cloned()
            .or_else(|| {
                pf.by_slot_identity
                    .get(slot_str)
                    .filter(|s| s.starts_with("codex-"))
                    .cloned()
            })
            .unwrap_or_else(|| format!("codex-{id}"));

        accounts.push(AccountInfo {
            id,
            label,
            oauth_email: None,
            source: AccountSource::Codex,
            surface: Surface::Codex,
            method: "oauth".into(),
            has_credentials,
            billing_mode: BillingMode::Subscription,
        });
    }

    accounts.sort_by_key(|a| a.id);
    accounts
}

/// Discovers Google Gemini bindings from `credentials/gemini-<N>.json`.
/// Round-7 (this session) — Gemini provisioning has been writing these
/// bindings since an internal journal entry (Stage 2), but the discovery layer
/// didn't know about them, so Gemini-bound slots were invisible in the
/// unified slot list (`csq` listing, desktop dashboard).
///
/// `binding.auth.mode` selects the per-slot dispatch in `csq run`
/// (`api_key` / `vertex_sa` / `code_assist_oauth`). For listing
/// purposes we surface them all under `AccountSource::Gemini` with
/// a method tag so the UI can distinguish if it cares.
pub fn discover_gemini(base_dir: &Path) -> Vec<AccountInfo> {
    use crate::providers::gemini::provisioning::{read_binding, AuthMode};
    use crate::types::AccountNum;

    let creds_dir = base_dir.join("credentials");
    let entries = match std::fs::read_dir(&creds_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut accounts = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        // Reject symlinks at discovery boundary, matching the pattern
        // in `discover_per_slot_third_party` and `discover_anthropic`.
        // `read_binding` follows symlinks; the symmetry break was a
        // future-leak vector if discovery error formatting ever
        // surfaced the read body. Origin: redteam round 1 M1 (journal
        // 0058).
        if let Ok(file_type) = entry.file_type() {
            if file_type.is_symlink() {
                continue;
            }
        } else {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        let Some(num_str) = stem.strip_prefix("gemini-") else {
            continue;
        };
        let id: u16 = match num_str.parse() {
            Ok(n) if (1..=999).contains(&n) => n,
            _ => continue,
        };
        // Reject leading-zero filename forms (`gemini-013.json`) so
        // they don't collide with `gemini-13.json` at the same id.
        // Filesystem iteration order is undefined; without this
        // canonicalization, which file wins is implementation-defined.
        // Origin: redteam round 1 LOW.
        if num_str != id.to_string() {
            continue;
        }
        let slot = match AccountNum::try_from(id) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let binding = match read_binding(base_dir, slot) {
            Ok(b) => b,
            Err(e) => {
                // Branch on the error kind so a schema-version drift
                // from a newer csq release surfaces a distinct log tag
                // (operator-actionable) vs a benign IO race (concurrent
                // logout deleted the file between read_dir and
                // read_binding). Origin: redteam round 1 M2.
                // `error_kind` is the path-free tag (security.md §2);
                // `error = %e` removed — ProvisionError::Display carries
                // the absolute path and (for Malformed) serde_json
                // fragments. Mirror of the discover_codex fix at 534.
                warn!(
                    path = %path.display(),
                    error_kind = e.error_kind_tag(),
                    "skipping unreadable gemini binding"
                );
                continue;
            }
        };
        let method = match &binding.auth {
            AuthMode::ApiKey => "api_key",
            AuthMode::VertexSa { .. } => "vertex_sa",
            AuthMode::CodeAssistOAuth => "code_assist_oauth",
        };
        // A user rename (`by_slot_label`) wins over the `gemini-N` default,
        // matching the Anthropic `get_email` step-1 precedence.
        let label =
            profiles::slot_rename_label(base_dir, id).unwrap_or_else(|| format!("gemini-{id}"));
        accounts.push(AccountInfo {
            id,
            label,
            oauth_email: None,
            source: AccountSource::Gemini,
            surface: Surface::Gemini,
            method: method.into(),
            has_credentials: true,
            // Gemini billing depends on the auth mode + plan. Code
            // Assist OAuth is subscription-bounded; API key + Vertex
            // SA are pay-per-token. Default to Subscription for the
            // OAuth path, PayPerToken for the others. This matches
            // an internal journal entry's per-plan design.
            billing_mode: match &binding.auth {
                AuthMode::CodeAssistOAuth => BillingMode::Subscription,
                AuthMode::ApiKey | AuthMode::VertexSa { .. } => BillingMode::ApiKey,
            },
        });
    }
    accounts.sort_by_key(|a| a.id);
    accounts
}

/// Discovers third-party provider accounts from settings files.
/// Checks `settings-zai.json` and `settings-mm.json`.
pub fn discover_third_party(base_dir: &Path) -> Vec<AccountInfo> {
    let mut accounts = Vec::new();

    let providers = [
        ("settings-zai.json", "Z.AI", 901u16),
        ("settings-mm.json", "MiniMax", 902u16),
    ];

    for (file, provider, synthetic_id) in &providers {
        let path = base_dir.join(file);
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                // Check for ANTHROPIC_AUTH_TOKEN at the top level OR
                // inside the `env` subobject (which is where
                // ProviderSettings::get_api_key reads from).
                let has_top_level = json.get("ANTHROPIC_AUTH_TOKEN").is_some()
                    || json.get("ANTHROPIC_BASE_URL").is_some();
                let has_env_key = json
                    .get("env")
                    .and_then(|env| {
                        env.get("ANTHROPIC_AUTH_TOKEN")
                            .or_else(|| env.get("ANTHROPIC_BASE_URL"))
                    })
                    .is_some();
                if has_top_level || has_env_key {
                    accounts.push(AccountInfo {
                        id: *synthetic_id,
                        label: provider.to_string(),
                        oauth_email: None,
                        source: AccountSource::ThirdParty {
                            provider: provider.to_string(),
                        },
                        surface: Surface::ClaudeCode,
                        method: "api_key".into(),
                        has_credentials: true,
                        billing_mode: billing_mode_for_3p(provider),
                    });
                }
            }
        }
    }

    accounts
}

/// Discovers manually configured accounts from `dashboard-accounts.json`.
pub fn discover_manual(base_dir: &Path) -> Vec<AccountInfo> {
    let path = base_dir.join("dashboard-accounts.json");
    match std::fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str::<Vec<AccountInfo>>(&content).unwrap_or_default(),
        Err(_) => vec![],
    }
}

/// Saves a manual account to `dashboard-accounts.json`.
pub fn save_manual_account(
    base_dir: &Path,
    info: AccountInfo,
) -> Result<(), crate::error::ConfigError> {
    save_manual_account_inner(
        base_dir,
        info,
        |tmp, bytes| std::fs::write(tmp, bytes),
        crate::platform::fs::secure_file,
        crate::platform::fs::atomic_replace,
    )
}

/// Closure-injected core of [`save_manual_account`] so each §5a failure
/// branch (write / secure_file / atomic_replace) has a regression test
/// without chmod tricks (redteam-discipline Rule 5; mirrors
/// `desktop::preferences::save_desktop_prefs_inner`).
fn save_manual_account_inner<W, S, R, ES, ER>(
    base_dir: &Path,
    info: AccountInfo,
    write: W,
    secure: S,
    replace: R,
) -> Result<(), crate::error::ConfigError>
where
    W: FnOnce(&Path, &[u8]) -> std::io::Result<()>,
    S: FnOnce(&Path) -> Result<(), ES>,
    R: FnOnce(&Path, &Path) -> Result<(), ER>,
    ES: std::fmt::Display,
    ER: std::fmt::Display,
{
    let path = base_dir.join("dashboard-accounts.json");
    let mut accounts = discover_manual(base_dir);

    // Replace existing entry with same ID, or append
    if let Some(pos) = accounts.iter().position(|a| a.id == info.id) {
        accounts[pos] = info;
    } else {
        accounts.push(info);
    }

    let json = serde_json::to_string_pretty(&accounts).map_err(|e| {
        crate::error::ConfigError::InvalidJson {
            path: path.clone(),
            reason: format!("serialization: {e}"),
        }
    })?;

    let tmp = crate::platform::fs::unique_tmp_path(&path);
    // §5a cleanup: AccountInfo.label may carry email PII per accounts/mod.rs.
    // Partial-failure leaves PII-bearing tmp at umask 0o644.
    if let Err(e) = write(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(crate::error::ConfigError::InvalidJson {
            path: tmp,
            reason: format!("write: {e}"),
        });
    }

    // Fail closed: a secure_file failure would publish the PII-bearing tmp
    // at umask default. Remove the tmp and surface the error (mirrors the
    // fail-closed posture in `accounts::profiles::save`).
    if let Err(e) = secure(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(crate::error::ConfigError::InvalidJson {
            path: tmp,
            reason: format!("secure_file: {e}"),
        });
    }

    if let Err(e) = replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(crate::error::ConfigError::InvalidJson {
            path: path.clone(),
            reason: format!("atomic replace: {e}"),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{self, AnthropicCredentialFile, CredentialFile, OAuthPayload};
    use crate::types::{AccessToken, RefreshToken};
    use tempfile::TempDir;

    fn write_cred(dir: &Path, account: u16) {
        let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new(format!("at-{account}")),
                refresh_token: RefreshToken::new(format!("rt-{account}")),
                expires_at: 9999999999999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        });
        let path = dir.join("credentials").join(format!("{account}.json"));
        credentials::save(&path, &creds).unwrap();
    }

    #[test]
    fn discover_anthropic_finds_credential_files() {
        let dir = TempDir::new().unwrap();
        write_cred(dir.path(), 1);
        write_cred(dir.path(), 3);
        write_cred(dir.path(), 7);

        let accounts = discover_anthropic(dir.path());
        assert_eq!(accounts.len(), 3);
        assert_eq!(accounts[0].id, 1);
        assert_eq!(accounts[1].id, 3);
        assert_eq!(accounts[2].id, 7);
        assert!(accounts
            .iter()
            .all(|a| a.source == AccountSource::Anthropic));
    }

    #[test]
    fn discover_anthropic_with_profiles() {
        // M4-13: get_email no longer reads from extra["accounts"].
        // Use by_slot_label (the canonical post-M4-13 label channel) to set
        // the label that discover_anthropic should surface.
        let dir = TempDir::new().unwrap();
        write_cred(dir.path(), 1);

        let mut profiles = profiles::ProfilesFile::empty();
        profiles
            .by_slot_label
            .insert("1".into(), "user@test.com".into());
        profiles::save(&profiles::profiles_path(dir.path()), &profiles).unwrap();

        let accounts = discover_anthropic(dir.path());
        assert_eq!(accounts[0].label, "user@test.com");
    }

    #[test]
    fn discover_anthropic_missing_profile_shows_unknown() {
        let dir = TempDir::new().unwrap();
        write_cred(dir.path(), 1);

        let accounts = discover_anthropic(dir.path());
        assert_eq!(accounts[0].label, "unknown");
    }

    #[test]
    fn discover_anthropic_no_credentials_dir() {
        let dir = TempDir::new().unwrap();
        let accounts = discover_anthropic(dir.path());
        assert!(accounts.is_empty());
    }

    // ── M4-4 reader flip: identity-keyed read path tests ─────────────
    //
    // The pre-M4-4 Pass 2 (`config-N/.credentials.json` live fallback)
    // is retired in favor of the M3-7/M4-5 fail-closed gate
    // (`phase4_gate_check`). The four retired tests below were:
    //   - `discover_anthropic_finds_live_only_accounts`
    //   - `discover_anthropic_live_fallback_respects_marker_mismatch`
    //   - `discover_anthropic_live_fallback_excludes_third_party`
    //   - `discover_anthropic_canonical_wins_over_live_fallback`
    // Their structural concern (alpha.11 recovery seam) is now closed
    // by the gate refusing daemon start when identity credentials are
    // unseeded for any `by_slot` entry. The two replacement tests below
    // cover the two M4-4 branches: UUID-keyed (`by_slot` populated)
    // and pure-legacy (`by_slot` empty / no profiles.json).

    #[test]
    fn discover_anthropic_reads_via_profiles_by_slot_in_coexisting_layout() {
        // M4-4 AC: in a coexisting fixture (3 slots, 3 identities),
        // `discover_anthropic` reads through `profiles.json::by_slot`
        // and yields 3 `AccountInfo` with `has_credentials=true`
        // sourced from `identities/<UUID>/credentials.json` — not
        // from `credentials/<N>.json`.
        let fixture = crate::testing::identity_fixtures::coexisting_fixture(3);
        let base = fixture.path();

        // The coexisting_fixture writes only identity.json in the
        // identity dir, not credentials.json. M4-4 reads credentials
        // from `identities/<UUID>/credentials.json`, so seed it here
        // — and write garbage to `credentials/<N>.json` to prove that
        // the UUID-keyed branch is being read, not the legacy branch.
        for slot in 1..=3u16 {
            let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(slot);
            let uuid_path = crate::accounts::identity_store::credentials_path_for(base, uuid);
            let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
                claude_ai_oauth: OAuthPayload {
                    access_token: AccessToken::new(format!("at-uuid-{slot}")),
                    refresh_token: RefreshToken::new(format!("rt-uuid-{slot}")),
                    expires_at: 9999999999999,
                    scopes: vec![],
                    subscription_type: None,
                    rate_limit_tier: None,
                    extra: HashMap::new(),
                },
                extra: HashMap::new(),
            });
            credentials::save(&uuid_path, &creds).unwrap();

            // Garbage at legacy path proves UUID-keyed branch is read.
            let legacy_path = base.join("credentials").join(format!("{slot}.json"));
            std::fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
            std::fs::write(&legacy_path, "this is not valid JSON").unwrap();
        }

        let accounts = discover_anthropic(base);
        let ids: Vec<u16> = accounts.iter().map(|a| a.id).collect();
        assert_eq!(ids, vec![1, 2, 3], "must yield 3 slots from by_slot");
        assert!(
            accounts.iter().all(|a| a.has_credentials),
            "all 3 must have has_credentials=true sourced from identity-keyed path"
        );
        assert!(
            accounts
                .iter()
                .all(|a| a.source == AccountSource::Anthropic),
            "all 3 must be AccountSource::Anthropic"
        );
    }

    /// **2026-05-22 codex-only regression** — slot 12 in the user-reported
    /// session had a UUID minted by an internal ticket's codex-only mint path with
    /// legacy `credentials/codex-12.json` (codex binding signal) but NO
    /// legacy `credentials/12.json` (no Anthropic OAuth ever ran). The
    /// pre-fix `discover_anthropic` enumerated slot 12 via `by_slot`,
    /// tried to load the non-existent Anthropic identity credentials,
    /// and emitted a spurious "phase4_gate should have caught this" WARN
    /// before tagging the slot `has_credentials=false`. This test pins
    /// the fix: codex-only slots are skipped entirely (mirror of the
    /// gemini-skip pattern above) so the slot doesn't appear as a
    /// broken Anthropic account.
    #[test]
    fn discover_anthropic_skips_codex_only_slots() {
        use crate::accounts::identity_store::IdentityId;

        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("12".to_string(), uuid);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // Codex binding signal: legacy `credentials/codex-12.json` exists.
        // No Anthropic legacy `credentials/12.json` — this is what
        // distinguishes a codex-only slot from a dual-bound slot.
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(
            creds_dir.join("codex-12.json"),
            br#"{"tokens":{"access_token":"codex"}}"#,
        )
        .unwrap();

        let accounts = discover_anthropic(dir.path());
        assert!(
            accounts.iter().find(|a| a.id == 12).is_none(),
            "codex-only slot 12 MUST NOT appear in discover_anthropic output \
             (would surface as broken Anthropic account in `csq status`). Got: {:?}",
            accounts.iter().map(|a| a.id).collect::<Vec<_>>()
        );
    }

    /// **2026-05-25 post-A++ codex-only regression (host slot 8)** — a Codex
    /// slot minted post-A++ has its codex-ness recorded ONLY in the identity
    /// store (`identity.json` provider=codex + `credentials-codex.json`); its
    /// legacy `credentials/codex-<N>.json` mirror was retired by the
    /// legacy-mirror cleanup, so the pre-fix legacy-marker-only skip missed it.
    /// `discover_anthropic` then loaded the absent Anthropic `credentials.json`
    /// and fired "phase4_gate should have caught this" on every 5-min poll.
    /// This pins the identity-store-aware skip: no legacy marker, still skipped.
    #[test]
    fn discover_anthropic_skips_post_aplusplus_codex_slot_without_legacy_mirror() {
        use crate::accounts::identity_store::{
            credentials_codex_path_for, identity_path, IdentityId,
        };

        let dir = TempDir::new().unwrap();
        let uuid = IdentityId::new_v4();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("8".to_string(), uuid);
        let profiles_path = crate::accounts::profiles::profiles_path(dir.path());
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();

        // Identity store records codex; NO legacy credentials/codex-8.json.
        let id_dir = identity_path(dir.path(), uuid);
        std::fs::create_dir_all(&id_dir).unwrap();
        std::fs::write(
            id_dir.join("identity.json"),
            br#"{"email":"codex:abc","provider":"codex","created_at":"t","key_id":null}"#,
        )
        .unwrap();
        std::fs::write(credentials_codex_path_for(dir.path(), uuid), b"{}").unwrap();

        let accounts = discover_anthropic(dir.path());
        assert!(
            accounts.iter().find(|a| a.id == 8).is_none(),
            "post-A++ codex-only slot 8 (identity.json provider=codex, no legacy \
             mirror) MUST NOT appear in discover_anthropic output. Got: {:?}",
            accounts.iter().map(|a| a.id).collect::<Vec<_>>()
        );
    }

    /// Sibling of the codex-only-skip test: when a slot is dual-bound
    /// (legacy `credentials/codex-N.json` AND legacy `credentials/N.json`
    /// both exist), `discover_anthropic` MUST still enumerate the slot.
    /// The codex skip is for slots that are CODEX-ONLY, not for slots
    /// that happen to also have a codex binding.
    #[test]
    fn discover_anthropic_keeps_dual_bound_anthropic_plus_codex_slot() {
        let fixture = crate::testing::identity_fixtures::coexisting_fixture(1);
        let base = fixture.path();
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);

        // Anthropic identity credentials at identity-keyed path.
        let uuid_path = crate::accounts::identity_store::credentials_path_for(base, uuid);
        let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("at".to_string()),
                refresh_token: RefreshToken::new("rt".to_string()),
                expires_at: 9999999999999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        });
        credentials::save(&uuid_path, &creds).unwrap();

        // BOTH legacy bindings present: Anthropic + codex.
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("1.json"), b"{}").unwrap();
        std::fs::write(creds_dir.join("codex-1.json"), b"{}").unwrap();

        let accounts = discover_anthropic(base);
        assert!(
            accounts.iter().any(|a| a.id == 1),
            "dual-bound slot 1 MUST be enumerated by discover_anthropic (codex \
             skip targets codex-only, not codex-plus-anthropic). Got: {:?}",
            accounts.iter().map(|a| a.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn discover_anthropic_legacy_fallback_when_no_by_slot() {
        // M4-4 AC: in a pure-legacy fixture (3 slots, 0 identities),
        // `discover_anthropic` falls back to walking `credentials/<N>.json`
        // and yields 3 `AccountInfo` from the legacy path.
        let dir = TempDir::new().unwrap();
        // 3 legacy credential files, no profiles.json, no identities dir
        write_cred(dir.path(), 1);
        write_cred(dir.path(), 2);
        write_cred(dir.path(), 3);

        let accounts = discover_anthropic(dir.path());
        let ids: Vec<u16> = accounts.iter().map(|a| a.id).collect();
        assert_eq!(
            ids,
            vec![1, 2, 3],
            "pure-legacy fallback must yield 3 slots from credentials/<N>.json"
        );
        assert!(
            accounts.iter().all(|a| a.has_credentials),
            "all 3 must have has_credentials=true"
        );
        assert!(
            accounts
                .iter()
                .all(|a| a.source == AccountSource::Anthropic),
            "all 3 must be AccountSource::Anthropic"
        );
    }

    #[test]
    fn discover_anthropic_skips_invalid_json() {
        let dir = TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("1.json"), "not json").unwrap();

        let accounts = discover_anthropic(dir.path());
        assert_eq!(accounts.len(), 1);
        assert!(!accounts[0].has_credentials);
    }

    #[test]
    fn discover_third_party_zai() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("settings-zai.json"),
            r#"{"ANTHROPIC_AUTH_TOKEN": "key", "ANTHROPIC_BASE_URL": "https://api.zai.com"}"#,
        )
        .unwrap();

        let accounts = discover_third_party(dir.path());
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].label, "Z.AI");
        assert_eq!(
            accounts[0].source,
            AccountSource::ThirdParty {
                provider: "Z.AI".into()
            }
        );
    }

    #[test]
    fn discover_third_party_env_nested_key() {
        // Regression test: settings files with keys ONLY in the `env`
        // subobject (the canonical location per ProviderSettings)
        // must still be discovered.
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("settings-mm.json"),
            r#"{"env":{"ANTHROPIC_AUTH_TOKEN":"key","ANTHROPIC_BASE_URL":"https://api.mm.com"}}"#,
        )
        .unwrap();

        let accounts = discover_third_party(dir.path());
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].label, "MiniMax");
        assert_eq!(accounts[0].id, 902);
    }

    #[test]
    fn discover_third_party_no_settings() {
        let dir = TempDir::new().unwrap();
        let accounts = discover_third_party(dir.path());
        assert!(accounts.is_empty());
    }

    // ── rename precedence: by_slot_label wins across ALL providers ─────
    // Regression for the "rename doesn't save" bug: `rename_account` writes
    // `by_slot_label[N]`, which Anthropic honors via `get_email` step 1 but
    // Codex / Gemini / 3P discovery ignored (they read by_slot_identity /
    // hardcoded `gemini-N` / provider name). Empirically: a codex slot with
    // by_slot_label set kept showing its by_slot_identity label.

    #[test]
    fn discover_codex_legacy_rename_wins() {
        // Pass 1 (legacy credentials/codex-N.json): by_slot_label wins over
        // the `codex-N` default.
        let dir = TempDir::new().unwrap();
        write_codex_cred(dir.path(), 9);

        let mut profiles = profiles::ProfilesFile::empty();
        profiles
            .by_slot_label
            .insert("9".into(), "my-codex-rename".into());
        profiles::save(&profiles::profiles_path(dir.path()), &profiles).unwrap();

        let accounts = discover_codex(dir.path());
        let slot9 = accounts.iter().find(|a| a.id == 9).expect("slot 9 present");
        assert_eq!(slot9.label, "my-codex-rename");
    }

    #[test]
    fn discover_codex_uuid_keyed_rename_wins() {
        // Pass 2 (identities/<UUID>/credentials-codex.json — the production
        // path for post-A++ codex slots, e.g. the user's slot 9): a user
        // rename wins over both by_slot_identity and the `codex-N` default.
        use crate::accounts::identity_store::IdentityId;
        use std::str::FromStr;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = IdentityId::from_str("11111111-2222-3333-4444-555555555555").unwrap();
        let slot: u16 = 9;

        let mut pf = profiles::ProfilesFile::empty();
        pf.by_slot.insert(slot.to_string(), uuid);
        pf.by_slot_identity
            .insert(slot.to_string(), "codex-8/3bf322e8".into());
        pf.by_slot_label
            .insert(slot.to_string(), "my-codex-rename".into());
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();
        write_codex_cred_uuid(base, uuid); // no legacy codex-9.json → Pass 2

        let accounts = discover_codex(base);
        let slot9 = accounts.iter().find(|a| a.id == 9).expect("slot 9 present");
        assert_eq!(
            slot9.label, "my-codex-rename",
            "user rename (by_slot_label) must win over by_slot_identity in Pass 2"
        );
    }

    #[test]
    fn discover_codex_uuid_keyed_falls_back_to_by_slot_identity() {
        // Pass 2 without a rename → the existing by_slot_identity label wins
        // (regression guard: the fix must not break the fallback).
        use crate::accounts::identity_store::IdentityId;
        use std::str::FromStr;
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let uuid = IdentityId::from_str("11111111-2222-3333-4444-555555555555").unwrap();
        let slot: u16 = 9;

        let mut pf = profiles::ProfilesFile::empty();
        pf.by_slot.insert(slot.to_string(), uuid);
        pf.by_slot_identity
            .insert(slot.to_string(), "codex-8/3bf322e8".into());
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();
        write_codex_cred_uuid(base, uuid);

        let accounts = discover_codex(base);
        let slot9 = accounts.iter().find(|a| a.id == 9).expect("slot 9 present");
        assert_eq!(slot9.label, "codex-8/3bf322e8");
    }

    #[test]
    fn discover_per_slot_third_party_rename_wins() {
        let dir = TempDir::new().unwrap();
        write_slot_settings(dir.path(), 11, "https://api.deepseek.com/anthropic", "tok");

        let mut profiles = profiles::ProfilesFile::empty();
        profiles
            .by_slot_label
            .insert("11".into(), "my-deepseek".into());
        profiles::save(&profiles::profiles_path(dir.path()), &profiles).unwrap();

        let accounts = discover_per_slot_third_party(dir.path());
        let slot11 = accounts
            .iter()
            .find(|a| a.id == 11)
            .expect("slot 11 present");
        assert_eq!(
            slot11.label, "my-deepseek",
            "user rename must win over the 3P provider-name default"
        );
        // The canonical provider id is untouched — only the display label moved.
        assert!(matches!(
            &slot11.source,
            AccountSource::ThirdParty { provider } if provider == "DeepSeek"
        ));
    }

    #[test]
    fn discover_gemini_rename_wins() {
        use crate::providers::gemini::provisioning::{write_binding, AuthMode, GeminiBinding};
        let dir = TempDir::new().unwrap();
        // discover_gemini enumerates credentials/gemini-N.json stems, then
        // reads the binding — set up both.
        std::fs::create_dir_all(dir.path().join("credentials")).unwrap();
        std::fs::write(dir.path().join("credentials/gemini-6.json"), "{}").unwrap();
        write_binding(
            dir.path(),
            crate::types::AccountNum::try_from(6u16).unwrap(),
            &GeminiBinding::new(AuthMode::ApiKey, "gemini-2.5-flash"),
        )
        .unwrap();

        let mut profiles = profiles::ProfilesFile::empty();
        profiles
            .by_slot_label
            .insert("6".into(), "my-gemini".into());
        profiles::save(&profiles::profiles_path(dir.path()), &profiles).unwrap();

        let accounts = discover_gemini(dir.path());
        let slot6 = accounts.iter().find(|a| a.id == 6).expect("slot 6 present");
        assert_eq!(
            slot6.label, "my-gemini",
            "user rename must win over the gemini-N default"
        );
    }

    #[test]
    fn discover_manual_round_trip() {
        let dir = TempDir::new().unwrap();
        let info = AccountInfo {
            id: 100,
            label: "Manual Account".into(),
            oauth_email: None,
            source: AccountSource::Manual,
            surface: Surface::ClaudeCode,
            method: "api_key".into(),
            has_credentials: true,
            billing_mode: BillingMode::Subscription,
        };

        save_manual_account(dir.path(), info.clone()).unwrap();
        let accounts = discover_manual(dir.path());
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, 100);
        assert_eq!(accounts[0].label, "Manual Account");
    }

    #[test]
    fn discover_all_deduplicates() {
        let dir = TempDir::new().unwrap();
        write_cred(dir.path(), 1);

        // Also create a manual account with ID 1 — should be deduped
        let manual = AccountInfo {
            id: 1,
            label: "Manual Duplicate".into(),
            oauth_email: None,
            source: AccountSource::Manual,
            surface: Surface::ClaudeCode,
            method: "manual".into(),
            has_credentials: false,
            billing_mode: BillingMode::Subscription,
        };
        save_manual_account(dir.path(), manual).unwrap();

        let accounts = discover_all(dir.path());
        // Only 1 entry for ID 1 (Anthropic wins)
        let count_id_1 = accounts.iter().filter(|a| a.id == 1).count();
        assert_eq!(count_id_1, 1);
        assert_eq!(
            accounts.iter().find(|a| a.id == 1).unwrap().source,
            AccountSource::Anthropic
        );
    }

    #[test]
    fn discover_all_empty_sources() {
        let dir = TempDir::new().unwrap();
        let accounts = discover_all(dir.path());
        assert!(accounts.is_empty());
    }

    // ── provider_from_base_url ─────────────────────────────

    #[test]
    fn provider_from_url_detects_minimax_on_any_host() {
        assert_eq!(
            provider_from_base_url("https://api.minimax.chat/anthropic"),
            Some("MiniMax")
        );
        assert_eq!(
            provider_from_base_url("https://api.minimax.io/anthropic"),
            Some("MiniMax")
        );
    }

    #[test]
    fn provider_from_url_detects_zai() {
        assert_eq!(
            provider_from_base_url("https://api.z.ai/api/anthropic"),
            Some("Z.AI")
        );
    }

    #[test]
    fn provider_from_url_detects_deepseek() {
        assert_eq!(
            provider_from_base_url("https://api.deepseek.com/anthropic"),
            Some("DeepSeek")
        );
    }

    /// Provisional Phase A dispatch — see an internal journal entry Static
    /// dispatch can't distinguish per-plan modes; everything except
    /// genuinely-billing-less Ollama defaults to Subscription so
    /// existing 5h/7d bar rendering doesn't regress for users on
    /// subscription tiers.
    #[test]
    fn billing_mode_for_3p_classifies_correctly() {
        assert_eq!(billing_mode_for_3p("Ollama"), BillingMode::Local);
        assert_eq!(billing_mode_for_3p("MiniMax"), BillingMode::Subscription);
        assert_eq!(billing_mode_for_3p("Z.AI"), BillingMode::Subscription);
        assert_eq!(billing_mode_for_3p("DeepSeek"), BillingMode::Subscription);
        assert_eq!(
            billing_mode_for_3p("UnknownProvider"),
            BillingMode::Subscription
        );
    }

    #[test]
    fn provider_from_url_detects_ollama() {
        assert_eq!(
            provider_from_base_url("http://localhost:11434"),
            Some("Ollama")
        );
        assert_eq!(
            provider_from_base_url("http://127.0.0.1:11434"),
            Some("Ollama")
        );
    }

    #[test]
    fn provider_from_url_skips_native_anthropic() {
        // Native Anthropic is OAuth — not a 3P binding.
        assert_eq!(provider_from_base_url("https://api.anthropic.com"), None);
    }

    #[test]
    fn provider_from_url_unknown_host_returns_none() {
        assert_eq!(provider_from_base_url("https://example.com/api"), None);
    }

    // ── discover_per_slot_third_party ──────────────────────

    /// Writes a `{base}/config-N/settings.json` with the given base
    /// URL and auth token.
    fn write_slot_settings(base: &Path, slot: u16, base_url: &str, token: &str) {
        let dir = base.join(format!("config-{slot}"));
        std::fs::create_dir_all(&dir).unwrap();
        let json = format!(
            r#"{{"env":{{"ANTHROPIC_BASE_URL":"{base_url}","ANTHROPIC_AUTH_TOKEN":"{token}"}}}}"#
        );
        std::fs::write(dir.join("settings.json"), json).unwrap();
    }

    #[test]
    fn per_slot_discovers_minimax_and_zai_as_numbered_slots() {
        let dir = TempDir::new().unwrap();
        write_slot_settings(dir.path(), 9, "https://api.minimax.io/anthropic", "tok-mm");
        write_slot_settings(dir.path(), 10, "https://api.z.ai/api/anthropic", "tok-zai");

        let accounts = discover_per_slot_third_party(dir.path());
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].id, 9);
        assert_eq!(accounts[0].label, "MiniMax");
        assert!(accounts[0].has_credentials);
        assert_eq!(accounts[1].id, 10);
        assert_eq!(accounts[1].label, "Z.AI");
    }

    #[test]
    fn per_slot_ignores_slots_without_settings_json() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("config-5")).unwrap();
        let accounts = discover_per_slot_third_party(dir.path());
        assert!(accounts.is_empty());
    }

    #[test]
    fn per_slot_ignores_slots_bound_to_native_anthropic() {
        let dir = TempDir::new().unwrap();
        write_slot_settings(dir.path(), 3, "https://api.anthropic.com", "tok");
        let accounts = discover_per_slot_third_party(dir.path());
        assert!(
            accounts.is_empty(),
            "native Anthropic slot must not appear as a 3P account"
        );
    }

    #[test]
    fn per_slot_ignores_unknown_base_urls() {
        let dir = TempDir::new().unwrap();
        write_slot_settings(dir.path(), 7, "https://my.custom.proxy/anthropic", "tok");
        let accounts = discover_per_slot_third_party(dir.path());
        assert!(accounts.is_empty());
    }

    #[test]
    fn per_slot_marks_empty_token_as_missing_credentials() {
        let dir = TempDir::new().unwrap();
        write_slot_settings(dir.path(), 9, "https://api.minimax.io/anthropic", "");
        let accounts = discover_per_slot_third_party(dir.path());
        assert_eq!(accounts.len(), 1);
        assert!(!accounts[0].has_credentials);
    }

    #[test]
    fn per_slot_rejects_out_of_range_slot_numbers() {
        let dir = TempDir::new().unwrap();
        write_slot_settings(dir.path(), 0, "https://api.minimax.io/anthropic", "tok");
        // Manual dir creation for 1000 since write_slot_settings uses u16.
        std::fs::create_dir_all(dir.path().join("config-1000")).unwrap();
        std::fs::write(
            dir.path().join("config-1000").join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.z.ai/api/anthropic","ANTHROPIC_AUTH_TOKEN":"tok"}}"#,
        )
        .unwrap();

        let accounts = discover_per_slot_third_party(dir.path());
        assert!(
            accounts.is_empty(),
            "out-of-range slot numbers must be rejected"
        );
    }

    #[test]
    fn per_slot_rejects_non_config_dirs() {
        let dir = TempDir::new().unwrap();
        // `other-9/settings.json` with a valid 3P binding.
        let other = dir.path().join("other-9");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(
            other.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.minimax.io","ANTHROPIC_AUTH_TOKEN":"tok"}}"#,
        )
        .unwrap();
        let accounts = discover_per_slot_third_party(dir.path());
        assert!(accounts.is_empty());
    }

    #[test]
    fn per_slot_returns_deterministic_order() {
        let dir = TempDir::new().unwrap();
        // Insert in non-sorted order; expect ascending output.
        write_slot_settings(dir.path(), 10, "https://api.z.ai/api/anthropic", "tok");
        write_slot_settings(dir.path(), 9, "https://api.minimax.io/anthropic", "tok");

        let accounts = discover_per_slot_third_party(dir.path());
        assert_eq!(
            accounts.iter().map(|a| a.id).collect::<Vec<_>>(),
            vec![9, 10]
        );
    }

    // ── discover_all with per-slot 3P suppression ──────────

    #[test]
    fn discover_all_per_slot_3p_suppresses_global_duplicate() {
        // User has BOTH a per-slot binding (config-9 → MiniMax) AND
        // a legacy global settings-mm.json. The per-slot entry wins
        // and the global 902 is dropped so the dashboard shows one
        // MiniMax row, not two.
        let dir = TempDir::new().unwrap();
        write_slot_settings(dir.path(), 9, "https://api.minimax.io/anthropic", "tok");
        std::fs::write(
            dir.path().join("settings-mm.json"),
            r#"{"env":{"ANTHROPIC_AUTH_TOKEN":"legacy","ANTHROPIC_BASE_URL":"https://api.mm.com"}}"#,
        )
        .unwrap();

        let accounts = discover_all(dir.path());
        let minimax: Vec<_> = accounts
            .iter()
            .filter(|a| matches!(&a.source, AccountSource::ThirdParty { provider } if provider == "MiniMax"))
            .collect();
        assert_eq!(
            minimax.len(),
            1,
            "global 3P entry must be suppressed when per-slot binding exists"
        );
        assert_eq!(minimax[0].id, 9);
    }

    #[test]
    fn discover_all_global_3p_preserved_when_no_per_slot() {
        // Only the global settings-zai.json — no per-slot binding.
        // Should still emit the synthetic 901 entry for backward compat.
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("settings-zai.json"),
            r#"{"env":{"ANTHROPIC_AUTH_TOKEN":"tok","ANTHROPIC_BASE_URL":"https://api.z.ai"}}"#,
        )
        .unwrap();

        let accounts = discover_all(dir.path());
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, 901);
        assert_eq!(accounts[0].label, "Z.AI");
    }

    #[test]
    fn discover_all_mixed_oauth_and_per_slot_3p() {
        // Canonical happy path: OAuth slots 1-3, per-slot 3P slots 9-10.
        let dir = TempDir::new().unwrap();
        write_cred(dir.path(), 1);
        write_cred(dir.path(), 2);
        write_cred(dir.path(), 3);
        write_slot_settings(dir.path(), 9, "https://api.minimax.io/anthropic", "tok-mm");
        write_slot_settings(dir.path(), 10, "https://api.z.ai/api/anthropic", "tok-zai");

        let accounts = discover_all(dir.path());
        let ids: Vec<u16> = accounts.iter().map(|a| a.id).collect();
        assert_eq!(ids, vec![1, 2, 3, 9, 10]);
        let providers: Vec<_> = accounts
            .iter()
            .map(|a| match &a.source {
                AccountSource::Anthropic => "Anthropic",
                AccountSource::Codex => "Codex",
                AccountSource::Gemini => "Gemini",
                AccountSource::ThirdParty { provider } => provider.as_str(),
                AccountSource::Manual => "Manual",
            })
            .collect();
        assert_eq!(
            providers,
            vec!["Anthropic", "Anthropic", "Anthropic", "MiniMax", "Z.AI"]
        );
    }

    // ── discover_codex (PR-C3a) ────────────────────────────────────────

    fn write_codex_cred(dir: &Path, account: u16) {
        use crate::credentials::{CodexCredentialFile, CodexTokensFile};
        let creds = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some(format!("uuid-{account}")),
                access_token: format!("eyJaccess.codex-{account}.sig"),
                refresh_token: Some(format!("rt_codex_{account}")),
                id_token: Some(format!("eyJid.codex-{account}.sig")),
                extra: HashMap::new(),
            },
            last_refresh: Some("2026-04-22T00:00:00Z".into()),
            extra: HashMap::new(),
        });
        let path = dir
            .join("credentials")
            .join(format!("codex-{account}.json"));
        credentials::save(&path, &creds).unwrap();
    }

    #[test]
    fn discover_codex_finds_codex_prefixed_credential_files() {
        let dir = TempDir::new().unwrap();
        write_codex_cred(dir.path(), 1);
        write_codex_cred(dir.path(), 3);

        let accounts = discover_codex(dir.path());
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].id, 1);
        assert_eq!(accounts[0].source, AccountSource::Codex);
        assert_eq!(accounts[0].surface, Surface::Codex);
        assert_eq!(accounts[0].method, "oauth");
        assert!(accounts[0].has_credentials);
        assert_eq!(accounts[0].label, "codex-1");
        assert_eq!(accounts[1].id, 3);
    }

    #[test]
    fn discover_codex_ignores_anthropic_credential_files() {
        // An Anthropic-shaped file at `credentials/<N>.json` must not
        // be yielded by discover_codex — filename prefix is the gate.
        let dir = TempDir::new().unwrap();
        write_cred(dir.path(), 1);
        write_cred(dir.path(), 7);
        // And a Codex file to verify we still find it.
        write_codex_cred(dir.path(), 4);

        let accounts = discover_codex(dir.path());
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, 4);
    }

    #[test]
    fn discover_codex_skips_wrong_variant_payload() {
        // A `codex-<N>.json` file whose content is actually the
        // Anthropic shape must be skipped (logged at WARN) — not
        // silently treated as a valid Codex account.
        let dir = TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        // Write an Anthropic-shape JSON at a codex-prefixed path.
        std::fs::write(
            creds_dir.join("codex-5.json"),
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","refreshToken":"sk-ant-ort01-y","expiresAt":1000,"scopes":[]}}"#,
        )
        .unwrap();

        let accounts = discover_codex(dir.path());
        assert!(
            accounts.is_empty(),
            "codex-N.json with Anthropic payload must be skipped: {accounts:?}"
        );
    }

    #[test]
    fn discover_codex_skips_invalid_json() {
        let dir = TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("codex-1.json"), "not json").unwrap();

        let accounts = discover_codex(dir.path());
        assert_eq!(accounts.len(), 1);
        assert!(!accounts[0].has_credentials);
    }

    #[test]
    fn discover_codex_rejects_out_of_range_slot_numbers() {
        let dir = TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        // Write codex-0.json and codex-1000.json with valid payloads.
        use crate::credentials::{CodexCredentialFile, CodexTokensFile};
        let sample = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: None,
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: None,
                access_token: "t".into(),
                refresh_token: None,
                id_token: None,
                extra: HashMap::new(),
            },
            last_refresh: None,
            extra: HashMap::new(),
        });
        credentials::save(&creds_dir.join("codex-0.json"), &sample).unwrap();
        credentials::save(&creds_dir.join("codex-1000.json"), &sample).unwrap();

        let accounts = discover_codex(dir.path());
        assert!(
            accounts.is_empty(),
            "codex slot numbers outside 1..=999 must be rejected: {accounts:?}"
        );
    }

    #[test]
    fn discover_codex_empty_dir_returns_empty() {
        let dir = TempDir::new().unwrap();
        let accounts = discover_codex(dir.path());
        assert!(accounts.is_empty());
    }

    #[test]
    fn discover_all_includes_codex_accounts() {
        let dir = TempDir::new().unwrap();
        write_cred(dir.path(), 1);
        write_codex_cred(dir.path(), 2);

        let accounts = discover_all(dir.path());
        let ids: Vec<u16> = accounts.iter().map(|a| a.id).collect();
        assert_eq!(ids, vec![1, 2]);
        assert_eq!(accounts[0].source, AccountSource::Anthropic);
        assert_eq!(accounts[1].source, AccountSource::Codex);
    }

    #[test]
    fn discover_all_anthropic_wins_over_codex_on_same_slot() {
        // Unusual but possible: if `credentials/3.json` AND
        // `credentials/codex-3.json` both exist, Anthropic wins via
        // priority-1 discovery. The Codex entry for slot 3 is dropped.
        let dir = TempDir::new().unwrap();
        write_cred(dir.path(), 3);
        write_codex_cred(dir.path(), 3);

        let accounts = discover_all(dir.path());
        let slot_3: Vec<_> = accounts.iter().filter(|a| a.id == 3).collect();
        assert_eq!(slot_3.len(), 1);
        assert_eq!(slot_3[0].source, AccountSource::Anthropic);
    }

    // ── discover_codex: Task 6 — UUID-keyed slot discovery ─────────────

    /// Writes a valid Codex credential at the UUID-keyed identity path
    /// (`identities/<UUID>/credentials-codex.json`).
    fn write_codex_cred_uuid(dir: &Path, uuid: crate::accounts::identity_store::IdentityId) {
        use crate::credentials::{CodexCredentialFile, CodexTokensFile};
        let creds = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some("uuid-hint".to_string()),
                access_token: "eyJaccess.uuid.sig".into(),
                refresh_token: Some("rt_uuid".into()),
                id_token: Some("eyJid.uuid.sig".into()),
                extra: HashMap::new(),
            },
            last_refresh: Some("2026-05-22T00:00:00Z".into()),
            extra: HashMap::new(),
        });
        let path = identity_store::credentials_codex_path_for(dir, uuid);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        credentials::save(&path, &creds).unwrap();
    }

    #[test]
    fn discover_codex_uuid_keyed_slot_found_when_no_legacy_file() {
        // Root-cause fix regression: a Codex-only slot (provisioned
        // post-fix) has credentials ONLY at the UUID-keyed path
        // (`identities/<UUID>/credentials-codex.json`). Pass 1 produces
        // nothing; Pass 2 must yield the slot.
        use crate::accounts::identity_store::IdentityId;
        use std::str::FromStr;

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let uuid = IdentityId::from_str("11111111-2222-3333-4444-555555555555").unwrap();
        let slot: u16 = 12;

        // Seed profiles.json::by_slot[12] → uuid (what mint_for_codex_login writes)
        let mut pf = profiles::ProfilesFile::empty();
        pf.by_slot.insert(slot.to_string(), uuid);
        pf.by_email.insert(format!("codex:slot-{slot}"), uuid);
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();

        // Write UUID-keyed credentials-codex.json. No legacy codex-12.json.
        write_codex_cred_uuid(base, uuid);

        let accounts = discover_codex(base);
        assert_eq!(
            accounts.len(),
            1,
            "UUID-keyed slot must be found by Pass 2: {accounts:?}"
        );
        assert_eq!(accounts[0].id, slot);
        assert_eq!(accounts[0].source, AccountSource::Codex);
        assert!(
            accounts[0].has_credentials,
            "has_credentials must be true for valid UUID-keyed credential"
        );
    }

    #[test]
    fn discover_codex_uuid_keyed_not_duplicated_when_legacy_also_exists() {
        // If a slot has BOTH a legacy `credentials/codex-<N>.json` AND a
        // UUID-keyed path (upgraded slot), it must appear exactly once
        // (Pass 1 wins; Pass 2 skips via seen_slots).
        use crate::accounts::identity_store::IdentityId;
        use std::str::FromStr;

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let uuid = IdentityId::from_str("aaaabbbb-cccc-dddd-eeee-ffffffffffff").unwrap();
        let slot: u16 = 7;

        // profiles.json::by_slot[7] → uuid
        let mut pf = profiles::ProfilesFile::empty();
        pf.by_slot.insert(slot.to_string(), uuid);
        pf.by_email.insert(format!("codex:slot-{slot}"), uuid);
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();

        // Legacy file at credentials/codex-7.json.
        write_codex_cred(base, slot);
        // UUID-keyed file also present (post-migration state).
        write_codex_cred_uuid(base, uuid);

        let accounts = discover_codex(base);
        let slot_entries: Vec<_> = accounts.iter().filter(|a| a.id == slot).collect();
        assert_eq!(
            slot_entries.len(),
            1,
            "slot {slot} must appear exactly once even when both paths exist: {accounts:?}"
        );
    }

    #[test]
    fn discover_codex_uuid_keyed_slot_absent_when_no_credentials_file() {
        // by_slot has an entry but the UUID-keyed credentials-codex.json
        // is missing (Anthropic-only slot sharing the UUID). Pass 2 must
        // skip it — no AccountInfo emitted.
        use crate::accounts::identity_store::IdentityId;
        use std::str::FromStr;

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let uuid = IdentityId::from_str("00000000-0000-0000-0000-000000000001").unwrap();
        let mut pf = profiles::ProfilesFile::empty();
        pf.by_slot.insert("5".to_string(), uuid);
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();

        // No credentials-codex.json written — Anthropic-only slot.

        let accounts = discover_codex(base);
        assert!(
            accounts.is_empty(),
            "Anthropic-only UUID slot must not be emitted by discover_codex: {accounts:?}"
        );
    }

    /// §5a regression (security.md MUST Rule 5a, an internal journal entry B2,
    /// /redteam round 3 2026-05-09): when `save_manual_account` fails
    /// after the tmp file would have been created (parent dir read-only
    /// → write fails), no `.tmp.` file must remain on disk.
    ///
    /// AccountInfo.label may carry email PII; partial-failure must not
    /// leave PII-bearing tmp at umask 0o644.
    #[cfg(unix)]
    #[test]
    fn save_manual_account_partial_failure_cleans_tmp_file() {
        use crate::providers::catalog::Surface;

        // Arrange: write an initial dashboard-accounts.json so the
        // parent dir is known to exist with 0o700 when we start.
        let dir = TempDir::new().unwrap();
        let info = AccountInfo {
            id: 200,
            label: "b2-test@example.com".into(),
            oauth_email: None,
            source: AccountSource::Manual,
            surface: Surface::ClaudeCode,
            method: "api_key".into(),
            has_credentials: false,
            billing_mode: BillingMode::Subscription,
        };
        save_manual_account(dir.path(), info.clone()).unwrap();

        // Act + Assert: read-only parent → write fails → no tmp leak.
        crate::platform::fs::assert_no_tmp_leak_on_readonly_parent(dir.path(), || {
            save_manual_account(dir.path(), info)
        });
    }

    /// §5a regression (redteam 2026-06-11 R1): `secure_file` failure MUST
    /// fail closed — remove the PII-bearing tmp and propagate the error.
    /// The pre-fix code was `secure_file(&tmp).ok()` (fail-open): a chmod
    /// failure published `dashboard-accounts.json` content at umask 0o644.
    #[test]
    fn save_manual_account_secure_file_failure_cleans_tmp_and_errors() {
        use crate::providers::catalog::Surface;

        let dir = TempDir::new().unwrap();
        let info = AccountInfo {
            id: 201,
            label: "r1-secure-fail@example.com".into(),
            oauth_email: None,
            source: AccountSource::Manual,
            surface: Surface::ClaudeCode,
            method: "api_key".into(),
            has_credentials: false,
            billing_mode: BillingMode::Subscription,
        };

        let err = save_manual_account_inner(
            dir.path(),
            info,
            |tmp, bytes| std::fs::write(tmp, bytes),
            |_tmp| Err("injected chmod failure"),
            |_tmp, _path| -> Result<(), &str> {
                panic!("replace must not run after secure_file failure")
            },
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("secure_file"),
            "error must name the failing step: {err}"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "tmp leaked: {leftovers:?}");
        assert!(
            !dir.path().join("dashboard-accounts.json").exists(),
            "target must not be published on secure_file failure"
        );
    }

    /// §5a regression (redteam 2026-06-11 R1): `atomic_replace` failure
    /// removes the tmp before propagating (pins the pre-existing
    /// fail-closed branch via closure injection).
    #[test]
    fn save_manual_account_replace_failure_cleans_tmp_and_errors() {
        use crate::providers::catalog::Surface;

        let dir = TempDir::new().unwrap();
        let info = AccountInfo {
            id: 202,
            label: "r1-replace-fail@example.com".into(),
            oauth_email: None,
            source: AccountSource::Manual,
            surface: Surface::ClaudeCode,
            method: "api_key".into(),
            has_credentials: false,
            billing_mode: BillingMode::Subscription,
        };

        let err = save_manual_account_inner(
            dir.path(),
            info,
            |tmp, bytes| std::fs::write(tmp, bytes),
            |_tmp| -> Result<(), &str> { Ok(()) },
            |_tmp, _path| Err("injected rename failure"),
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("atomic replace"),
            "error must name the failing step: {err}"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "tmp leaked: {leftovers:?}");
    }

    /// DA-H4 regression: a corrupt legacy `credentials/codex-<N>.json`
    /// (e.g. zero-byte truncation from a crash mid-write) must NOT produce a
    /// `has_credentials=false` entry that masks the slot's valid UUID-keyed
    /// credentials in Pass 2. When a UUID-keyed alternative exists, Pass 1
    /// must skip the legacy entry entirely so Pass 2 picks it up.
    #[test]
    fn discover_codex_corrupt_legacy_does_not_mask_uuid_keyed_slot() {
        use crate::accounts::identity_store::IdentityId;
        use std::str::FromStr;

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        let uuid = IdentityId::from_str("deadbeef-0000-1111-2222-333333333333").unwrap();
        let slot: u16 = 12;

        // Seed profiles.json::by_slot[12] → uuid.
        let mut pf = profiles::ProfilesFile::empty();
        pf.by_slot.insert(slot.to_string(), uuid);
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();

        // Write a CORRUPT (zero-byte) legacy credential at credentials/codex-12.json.
        let creds_dir = base.join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        // Empty file → credentials::load will fail with a parse error (corrupt).
        std::fs::write(creds_dir.join("codex-12.json"), b"").unwrap();

        // Write a valid UUID-keyed credential at identities/<UUID>/credentials-codex.json.
        write_codex_cred_uuid(base, uuid);

        let accounts = discover_codex(base);

        // The corrupt legacy entry must be skipped; the UUID-keyed entry picked up by Pass 2.
        assert_eq!(
            accounts.len(),
            1,
            "slot 12 must appear exactly once (from Pass 2 UUID path): {accounts:?}"
        );
        assert_eq!(accounts[0].id, slot);
        assert!(
            accounts[0].has_credentials,
            "has_credentials must be true (UUID-keyed path is valid): {accounts:?}"
        );
        // Ensure Pass 1 did NOT emit a has_credentials=false entry for the same slot.
        assert!(
            !accounts.iter().any(|a| a.id == slot && !a.has_credentials),
            "corrupt legacy must not produce a has_credentials=false entry: {accounts:?}"
        );
    }
}
