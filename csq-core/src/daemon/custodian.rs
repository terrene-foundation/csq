//! Keychain custodian (Option A) — daemon-side per-account reconcile.
//!
//! Recent Claude Code reads OAuth credentials keychain-first and self-refreshes
//! each session's token; Anthropic rotates the refresh-token on every refresh,
//! invalidating the prior one. So when several CC sessions run on one account,
//! one session's self-refresh strands its siblings (and csq's store) on a
//! rotated-dead token. The custodian dissolves that refresh war: each tick it
//! HARVESTS the freshest token across the account's live handle-dir keychains,
//! VALIDATES it against Anthropic (the only authority on chain liveness), and
//! ADOPTS the freshest LIVE token into the canonical store — which the existing
//! post-tick keychain sweep then redistributes to every sibling session.
//!
//! ## Why validate-before-adopt (an internal journal entry/0004)
//!
//! The canonical store is account-GLOBAL: a wrong write 401s every session of the
//! account. A harvested token's `expiresAt` being in the future does NOT prove its
//! refresh-CHAIN is live — a rotated-dead token keeps a future `expiresAt` until its
//! own TTL lapses, yet Anthropic 401s it immediately (confirmed by live probe,
//! an internal journal entry). So `max(expiresAt)` alone can promote a dead token. The custodian
//! therefore validates each candidate (freshest-first) with a single server call
//! and adopts only a server-confirmed-LIVE token:
//!   - **200 → Live**  → adopt, done.
//!   - **401 → Dead**  → discard, try the next-freshest candidate.
//!   - **429/other → Unknown** → cannot confirm; adopt NOTHING this tick, retry next
//!     tick (a 429 is neither "dead" nor "live"; fail-closed avoids promoting an
//!     unconfirmed token AND avoids hammering the rate-limited endpoint).
//!
//! That single call is `/api/oauth/profile` (see `verify_token_owner`), NOT
//! `/api/oauth/usage`: a 200 from `/api/oauth/profile` proves BOTH liveness AND that
//! the token belongs to this account (its `account.email`), closing the
//! "liveness ≠ ownership" gap in Part 2 without a second round-trip.
//!
//! Slot-id channel (`account-terminal-separation.md` MUST Rule 1): `account` is
//! supplied by the daemon's per-account tick iteration (channel (a)), never derived
//! from terminal-scoped state.
//!
//! ## Why validate-OWNER-before-adopt — the wrong-account guard (Part 2)
//!
//! A harvested keychain token is ACCOUNT-ANONYMOUS: the opaque `sk-ant-oat01-`
//! access token + the `claudeAiOauth` payload carry no account identity, the
//! keychain item's account attribute is the constant system username, and
//! `/api/oauth/usage` confirms LIVENESS, not OWNERSHIP. So a live token belonging
//! to a DIFFERENT account (a dir whose keychain CC wrote a foreign token into via
//! in-session `/login`, or a keychain/binding mismatch) would pass the liveness
//! gate and corrupt the account-GLOBAL store (401s every session of the account).
//! Two gates enforce this, defence-in-depth:
//!   1. `candidate_account_matches` — a cheap PRE-filter on the bound account's
//!      `identity.json` email vs the candidate dir's `.claude.json`
//!      `oauthAccount.emailAddress` (captured under the swap lock as
//!      `HarvestCandidate.candidate_email`). Fail-closed on any absence/mismatch.
//!   2. `verify_token_owner` — the AUTHORITATIVE gate, immediately before the adopt
//!      write: `/api/oauth/profile` with the candidate TOKEN returns the account it
//!      actually belongs to. The `.claude.json` email is a handle-dir SELF-REPORT
//!      and can DISAGREE with the token's real owner (a scrambled keychain, or a
//!      swap/login race where the keychain token and `.claude.json` are momentarily
//!      out of sync). Gate 1 alone let a foreign live token whose dir happened to
//!      self-report the right email be adopted → the cross-slot credential scramble.
//!      Gate 2 verifies the token itself, fail-closed on any mismatch/absence/error.
//!
//! **Scope: this guard defends the store-INGEST boundary only.** The post-tick
//! keychain sweep that redistributes the canonical store token to sibling sessions
//! TRUSTS the store. That is sound only because every store writer is itself
//! same-account: this custodian (now guarded), the daemon refresher (refreshes the
//! account's own token), and `csq login`. The legacy `config-N`→store restore in
//! `finalize_login` was the last un-guarded ingest path (a stale-config-N
//! overwrite) — it never wrote a FOREIGN account's token, but it could REGRESS the
//! store to a stale/rotated-dead same-account token. It is now monotonic too:
//! `finalize_login` routes its config-N re-seed through
//! `save_canonical_for_if_fresher` (2026-06-24 fix), so it can only advance the
//! store, never regress it. Net: every store INGEST writer is now guarded against
//! its own threat — this custodian by an identity gate (its harvest source is
//! account-anonymous), and `finalize_login` by a freshness gate (its source is the
//! per-slot-path-keyed `config-N`, which cannot carry a FOREIGN account's token,
//! only a stale same-account one).

use crate::accounts::{identity_store, profiles};
use crate::credentials::{self, file, CredentialFile};
use crate::daemon::usage_poller::anthropic::{ANTHROPIC_BASE_URL, ANTHROPIC_BETA_HEADER};
use crate::daemon::usage_poller::HttpGetFn;
use crate::refresh::sentinel;
use crate::types::AccountNum;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Hard ceiling on a harvested raw keychain payload before we parse/adopt it
/// (security H2). A normal `claudeAiOauth` credential is a few hundred bytes;
/// anything past this is rejected without parsing.
const MAX_RAW_CANDIDATE_BYTES: usize = 64 * 1024;

/// Server verdict on whether a candidate token BELONGS to the bound account.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum OwnerVerdict {
    /// `/api/oauth/profile` returned 200 AND `account.email` equals the anchor
    /// (ASCII-case-insensitive, trimmed). The token is BOTH live and owned by the
    /// bound account — safe to adopt.
    Match,
    /// 200 but `account.email` != anchor — a FOREIGN token (live, but another
    /// account's). Decisive: never adopt it into this account's store.
    Mismatch,
    /// 401 — the token's refresh chain is revoked. Discard; try the next candidate.
    Dead,
    /// 429 — per-IP Cloudflare throttle; propagate to the tick's cross-account backoff.
    RateLimited,
    /// Transport / 5xx / parse / absent `account.email` / absent anchor — cannot
    /// confirm ownership. Fail-closed: adopt nothing.
    Unknown,
}

/// Confirm a candidate access token's ACTUAL account ownership via
/// `GET /api/oauth/profile`, comparing the server-returned `account.email`
/// against the bound account's `anchor_email` (its `identity.json` email).
///
/// This closes the "liveness ≠ ownership" gap that a usage-only liveness check
/// leaves open: `/api/oauth/usage` proves the token's refresh chain is alive, NOT
/// that the token belongs to `anchor_email`. A harvested keychain token is
/// account-anonymous in its bytes, and the handle dir's `.claude.json` email
/// (checked by [`candidate_account_matches`]) is the dir's SELF-REPORT — it can
/// disagree with the token's real owner when the keychain is scrambled or a
/// swap/login race left the token and `.claude.json` out of sync. Adopting on the
/// self-report alone corrupts the account-global store with a foreign token (the
/// cross-slot quota-scramble bug). `/api/oauth/profile` is the authoritative
/// owner signal (200 also proves liveness, so this SUPERSEDES the usage-based
/// liveness check on the adopt path — no extra round-trip).
///
/// NEVER logs the token or the returned email. Fail-closed: any `None` /
/// parse / transport error, or a missing anchor, → [`OwnerVerdict::Unknown`].
pub(crate) fn verify_token_owner(
    token: &str,
    anchor_email: Option<&str>,
    http_get: &HttpGetFn,
) -> OwnerVerdict {
    let anchor = match anchor_email.map(str::trim) {
        Some(a) if !a.is_empty() => a,
        // No anchor to compare against — cannot confirm ownership. Fail-closed.
        _ => return OwnerVerdict::Unknown,
    };
    let url = format!("{ANTHROPIC_BASE_URL}/api/oauth/profile");
    let headers = [("Anthropic-Beta", ANTHROPIC_BETA_HEADER)];
    let (status, body) = match http_get(&url, token, &headers) {
        Ok(v) => v,
        Err(_) => return OwnerVerdict::Unknown,
    };
    match status {
        200 => {}
        401 => return OwnerVerdict::Dead,
        429 => return OwnerVerdict::RateLimited,
        _ => return OwnerVerdict::Unknown,
    }
    let json: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(j) => j,
        Err(_) => return OwnerVerdict::Unknown,
    };
    let email = json
        .get("account")
        .and_then(|a| a.get("email"))
        .and_then(|e| e.as_str());
    match email.map(str::trim) {
        // 200 but empty/whitespace `account.email` (post-trim `""`), or no field at
        // all (`None`) — cannot confirm ownership (an unreadable owner is "cannot
        // confirm" = Unknown, NOT "confirmed foreign" = Mismatch). Fail-closed
        // either way; this keeps the telemetry honest.
        Some("") | None => OwnerVerdict::Unknown,
        Some(e) if e.eq_ignore_ascii_case(anchor) => OwnerVerdict::Match,
        Some(_) => OwnerVerdict::Mismatch,
    }
}

/// Ownership status of a slot's Anthropic STORE token, for the `csq doctor` /
/// `csq repair` contamination detector (an internal ticket follow-up).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SlotOwnership {
    /// The store token's `/api/oauth/profile` account matches the slot's
    /// `identity.json` anchor — healthy.
    Owned,
    /// The store token belongs to a DIFFERENT account than the slot's anchor —
    /// the cross-slot credential-scramble class. The store shows the right label
    /// but polls a foreign account's quota. Heal: `csq login <slot>`.
    Contaminated,
    /// Cannot confirm (no UUID mapping / no anchor / no store token / transport /
    /// parse / 401 / 429). Fail-closed: NEVER reported as contaminated on doubt.
    Unknown,
}

/// Resolve the Anthropic **store** credential path for `slot` — the single file
/// that [`check_slot_store_token_ownership`] reads and that
/// `csq repair --heal-contaminated` clears. UUID-keyed
/// (`identities/<UUID>/credentials.json`) when `by_slot` is populated, legacy
/// numeric (`credentials/N.json`) otherwise — mirroring [`reconcile_account`]'s
/// store-path resolution.
///
/// Exposed so the detector and the heal act on the SAME path (one keep-set across
/// consumers — `reconciler-cleanup-parity.md` Rule 4). Path resolution only;
/// performs no I/O and never touches another slot's identity dir.
pub fn slot_store_credential_path(base_dir: &Path, slot: AccountNum) -> PathBuf {
    match profiles::resolve_slot_to_uuid(base_dir, slot.get()) {
        Some(u) => identity_store::credentials_path_for(base_dir, u),
        None => file::canonical_path(base_dir, slot),
    }
}

/// Detect whether slot `slot`'s Anthropic **store** token actually belongs to the
/// account bound to that slot (its `identity.json` anchor email).
///
/// This is the diagnostic counterpart to the custodian's ingest gate
/// ([`verify_token_owner`]): the gate PREVENTS new cross-slot contamination
/// (an internal ticket), but a store already scrambled before that fix landed does not
/// self-heal — the store token keeps a `future`-enough expiry that the refresher
/// never replaces it, yet it polls a foreign account's quota. `csq doctor` had no
/// way to see this (it trusts the label); this surfaces it so an operator can
/// re-login the affected slot.
///
/// **Read-only.** Performs at most one `GET /api/oauth/profile` with the store
/// token and mutates nothing. `http_get` is injected so the detector is
/// unit-testable without the network. Resolves the store path + anchor exactly
/// as the custodian's [`reconcile_account`] does (UUID-keyed, legacy fallback).
///
/// NEVER logs the token or the returned email.
pub fn check_slot_store_token_ownership(
    base_dir: &Path,
    slot: AccountNum,
    http_get: &HttpGetFn,
) -> SlotOwnership {
    let uuid = profiles::resolve_slot_to_uuid(base_dir, slot.get());
    // Store path: UUID-keyed when by_slot is populated, legacy numeric fallback
    // otherwise. Resolved through the shared [`slot_store_credential_path`] so the
    // detector and the `csq repair --heal-contaminated` clearer act on the SAME
    // file (reconciler-cleanup-parity Rule 4 — one keep-set across consumers).
    let store_path = slot_store_credential_path(base_dir, slot);
    // Anchor comes from identity.json (keyed by UUID). A legacy slot without a
    // UUID has no anchor → `verify_token_owner` fail-closes to Unknown.
    let anchor = uuid.and_then(|u| identity_store::read_identity_email(base_dir, u));

    let store_cred = match file::load(&store_path) {
        Ok(c) => c,
        Err(_) => return SlotOwnership::Unknown,
    };
    let Some(anth) = store_cred.anthropic() else {
        return SlotOwnership::Unknown;
    };
    let token = anth.claude_ai_oauth.access_token.expose_secret();

    match verify_token_owner(token, anchor.as_deref(), http_get) {
        OwnerVerdict::Match => SlotOwnership::Owned,
        OwnerVerdict::Mismatch => SlotOwnership::Contaminated,
        // Dead (revoked) / RateLimited / Unknown (transport/parse/absent) all
        // mean "cannot confirm foreign ownership" → not a contamination alarm.
        OwnerVerdict::Dead | OwnerVerdict::RateLimited | OwnerVerdict::Unknown => {
            SlotOwnership::Unknown
        }
    }
}

/// Wrong-account adopt guard (fail-closed). Returns `true` ONLY when the bound
/// account's anchor email and the candidate session's CC-recorded email are BOTH
/// present and, after trimming, equal **ASCII-case-insensitively** (OAuth emails
/// are ASCII and case-insensitive; the anchor is already trim+lowercased at mint,
/// so trimming the candidate makes the comparison symmetric — redteam R1 LOW). Any
/// `None` or empty-after-trim on EITHER side (absent `.claude.json`, absent
/// `identity.json` email, unparseable UUID) → `false` → do NOT adopt.
///
/// This is the structural defense against adopting a live token that belongs to a
/// DIFFERENT account than the one being reconciled. A harvested keychain token is
/// account-anonymous — the opaque `sk-ant-oat01-` access token and the
/// `claudeAiOauth` payload carry no account identity, the keychain item's account
/// attribute is the constant system username, and `/api/oauth/usage` confirms
/// liveness, not ownership. So a positive same-account match on the only available
/// local identity signal (the candidate dir's `.claude.json` `oauthAccount` email
/// vs the bound `identity.json` email) is REQUIRED before any write to the
/// account-global store. Fail-closed: doubt → refuse → the refresh war persists
/// for this account this tick (non-catastrophic, self-heals next tick) rather than
/// corrupting the account-global store with a foreign token (catastrophic — 401s
/// every session of the account).
pub(crate) fn candidate_account_matches(
    anchor_email: Option<&str>,
    candidate_email: Option<&str>,
) -> bool {
    match (anchor_email, candidate_email) {
        (Some(a), Some(c)) => {
            let (a, c) = (a.trim(), c.trim());
            !a.is_empty() && !c.is_empty() && a.eq_ignore_ascii_case(c)
        }
        _ => false,
    }
}

/// Compute the fixed-vocabulary `reason` tag for an identity-unconfirmed candidate
/// rejection (the `warn!` telemetry field). Pure + unit-testable — the tracing
/// field is otherwise unobservable in tests (redteam R2 testing-specialist F1).
///
/// The `candidate_email == None` case is split into `candidate_email_drift` (a
/// PRESENT `.claude.json` the wrong-account gate can't read an email from — the
/// #833 format drift) vs `candidate_email_absent` (absent/empty file — benign
/// not-yet-populated), via [`crate::credentials::claude_json::classify_oauth_account`],
/// so the daemon log carries the same drift-vs-fresh signal as the `csq doctor`
/// custodian canary (redteam R1 F6 — cross-surface parity). Telemetry only: the
/// adopt decision stays fail-closed on `candidate_email == None` regardless of this
/// tag. `source_tag` is the `term-<pid>` handle-dir basename, so
/// `base_dir.join(source_tag)` is the handle dir the candidate came from.
fn identity_unconfirmed_reason(
    base_dir: &Path,
    source_tag: &str,
    anchor_email: Option<&str>,
    candidate_email: Option<&str>,
) -> &'static str {
    use crate::credentials::claude_json::{classify_oauth_account, OauthAccountState};
    match (anchor_email, candidate_email) {
        (None, _) => "anchor_email_absent",
        (_, None) => {
            let handle_dir = base_dir.join(source_tag);
            match classify_oauth_account(&handle_dir) {
                OauthAccountState::FieldMissing => "candidate_email_drift",
                _ => "candidate_email_absent",
            }
        }
        _ => "email_mismatch",
    }
}

/// Outcome of [`reconcile_account`] — telemetry/test surface, carries no secrets.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum ReconcileOutcome {
    /// Adopted a harvested live token into the store (it was strictly fresher).
    Adopted,
    /// The store already holds a token at-or-fresher than every candidate.
    StoreFreshest,
    /// No live handle-dir held a harvestable candidate for this account.
    NoCandidates,
    /// Candidates existed and beat the store, but none was usable: every one was
    /// rejected BEFORE validation (oversized / unparseable / non-Anthropic). Distinct
    /// from `AllDead` (which means candidates were validated and came back revoked).
    NoEligibleCandidate,
    /// Every candidate that reached validation came back Dead (all chains rotated away).
    AllDead,
    /// At least one candidate beat the store but its account could not be confirmed
    /// as the bound account. Covers BOTH gates: gate 1 — the session's CC-recorded
    /// `.claude.json` `oauthAccount.emailAddress` did not match the bound account's
    /// `identity.json` email (`error_kind = "custodian_identity_unconfirmed"`); and
    /// gate 2 — the harvested TOKEN's real owner (per `/api/oauth/profile`) was
    /// foreign (`error_kind = "custodian_owner_mismatch"`). Fail-closed: adopted
    /// NOTHING. Distinct from `AllDead` (chains revoked) and `NoEligibleCandidate`
    /// (pre-validation rejects). The two gates are distinguishable in the logs but
    /// map to the same outcome here.
    IdentityUnconfirmed,
    /// A validation call returned Unknown (transport/5xx) — retry next tick.
    SkippedUnknown,
    /// A validation call returned 429 — the endpoint is rate-limiting; the tick MUST
    /// back off (`rate_limited_this_tick`). Retry next tick.
    RateLimited,
    /// The store write was rejected/failed under the lock (logged, no overwrite).
    NotAdopted,
}

/// Reconcile one Anthropic account: harvest → validate (freshest-first) → adopt the
/// first server-confirmed-live token strictly fresher than the store.
///
/// `account_uuid` is the account's identity-store UUID (the harvest binding key).
/// Pure of terminal-derived slot ids — `account` comes from the tick iteration.
pub(crate) fn reconcile_account(
    base_dir: &Path,
    account: AccountNum,
    account_uuid: &str,
    http_get: &HttpGetFn,
) -> ReconcileOutcome {
    // Baseline: the store's current Anthropic token expiry (None = no/invalid store
    // token — then any live candidate is an improvement). Resolve the store path the
    // SAME way broker_check does: UUID-keyed when by_slot is populated, legacy numeric
    // fallback otherwise.
    let store_path = match profiles::resolve_slot_to_uuid(base_dir, account.get()) {
        Some(uuid) => identity_store::credentials_path_for(base_dir, uuid),
        None => file::canonical_path(base_dir, account),
    };
    let store_cred = file::load(&store_path).ok();
    let store_expiry = store_cred
        .as_ref()
        .and_then(|c| c.anthropic())
        .map(|a| a.claude_ai_oauth.expires_at);

    // Freshest-first candidates across the account's LIVE handle-dir keychains.
    let candidates = credentials::keychain::harvest_account_candidates(base_dir, account_uuid);
    if candidates.is_empty() {
        return ReconcileOutcome::NoCandidates;
    }

    // Wrong-account adopt anchor: the bound account's authenticated OAuth email
    // (identity.json, written at mint). A harvested keychain token is account-
    // anonymous, so the ONLY local signal of a candidate session's account is its
    // handle dir's `.claude.json` `oauthAccount.emailAddress` (what CC recorded).
    // The guard below adopts a candidate ONLY when that matches this anchor —
    // fail-closed on absent/mismatch (a CC in-session `/login` to another account
    // rewrites `.claude.json`; a stale/unknown dir cannot be confirmed). See
    // `candidate_account_matches`.
    let anchor_email = account_uuid
        .parse::<identity_store::IdentityId>()
        .ok()
        .and_then(|id| identity_store::read_identity_email(base_dir, id));

    reconcile_candidates(
        base_dir,
        account,
        anchor_email.as_deref(),
        &candidates,
        store_expiry,
        http_get,
    )
}

/// The post-harvest decision loop, factored out of [`reconcile_account`] so the
/// wrong-account guard + outcome wiring are unit-testable WITHOUT the macOS
/// keychain (harvest is macOS-only; this consumes the already-harvested
/// candidate list). Validates freshest-first and adopts the first
/// server-confirmed-live candidate that is strictly fresher than the store AND
/// passes the wrong-account guard.
///
/// Assumes a non-empty slice: the production caller [`reconcile_account`] returns
/// `NoCandidates` upstream when the harvest is empty, so an empty slice here maps
/// to `NoEligibleCandidate` by construction (redteam R2 NIT — contract note).
pub(crate) fn reconcile_candidates(
    base_dir: &Path,
    account: AccountNum,
    anchor_email: Option<&str>,
    candidates: &[credentials::keychain::HarvestCandidate],
    store_expiry: Option<u64>,
    http_get: &HttpGetFn,
) -> ReconcileOutcome {
    // Set only when a candidate actually REACHED validation and came back Dead —
    // distinguishes "all chains revoked" (AllDead) from "candidates all rejected
    // pre-validation" (NoEligibleCandidate). A candidate dropped for oversize / parse
    // / non-Anthropic never sets this.
    let mut validated_dead = false;
    // Set when a candidate beat the store but failed the wrong-account guard
    // (identity absent/mismatched) — surfaces the fail-closed wrong-account outcome.
    let mut identity_unconfirmed = false;
    for cand in candidates {
        // security H2: reject an oversized payload without parsing.
        if cand.raw_json.len() > MAX_RAW_CANDIDATE_BYTES {
            warn!(
                source_tag = %cand.source_tag,
                "custodian: candidate rejected (raw payload exceeds ceiling)"
            );
            continue;
        }

        // Candidates are sorted freshest-first: once one is not strictly fresher than
        // the store, none of the rest are either → the store is already freshest.
        if let Some(se) = store_expiry {
            if cand.expiry_ms <= se {
                return ReconcileOutcome::StoreFreshest;
            }
        }

        // Wrong-account guard (fail-closed) — BEFORE the network validation call
        // and the adopt write. `cand.candidate_email` was captured atomically with
        // the keychain bytes under the per-dir swap lock (no lock-free re-read —
        // redteam R1 MED). A foreign-account token (CC in-session `/login` to a
        // different account, or any keychain/binding mismatch) is account-anonymous
        // in its bytes but its dir's `.claude.json` names the wrong account →
        // rejected here, never adopted into the account-global store. A legitimately
        // bound dir whose `.claude.json` is absent / not-yet-CC-populated also fails
        // closed (refused this tick; self-heals once CC writes oauthAccount).
        let candidate_email = cand.candidate_email.as_deref();
        if !candidate_account_matches(anchor_email, candidate_email) {
            // Distinct reason tags so an operator can tell a benign not-yet-populated
            // dir (candidate_email_absent) or a missing anchor (anchor_email_absent —
            // mint crash window) from a real wrong-account rejection (email_mismatch)
            // — redteam R1 LOW.
            let reason = identity_unconfirmed_reason(
                base_dir,
                &cand.source_tag,
                anchor_email,
                candidate_email,
            );
            warn!(
                account = account.get(),
                source_tag = %cand.source_tag,
                error_kind = "custodian_identity_unconfirmed",
                reason,
                "custodian: candidate rejected — session account identity unconfirmed or mismatched"
            );
            identity_unconfirmed = true;
            continue;
        }

        // Parse (untagged → Anthropic variant for a claudeAiOauth payload). A
        // non-Anthropic or unparseable candidate is skipped (fail-closed), never
        // logged with its bytes.
        let parsed: CredentialFile = match serde_json::from_str(&cand.raw_json) {
            Ok(c) => c,
            Err(_) => {
                warn!(source_tag = %cand.source_tag, "custodian: candidate parse failed");
                continue;
            }
        };
        let anth = match parsed.anthropic() {
            Some(a) => a,
            None => continue, // not an Anthropic credential — skip
        };
        let token = anth.claude_ai_oauth.access_token.expose_secret();

        // A0 gate: only a token that is server-confirmed-live AND server-confirmed
        // to BELONG to this account may be adopted. `/api/oauth/profile` proves
        // BOTH (200 ⇒ live; `account.email` ⇒ owner), so it supersedes the
        // usage-based liveness check on the adopt path — the `.claude.json`
        // self-report (`candidate_account_matches`, above) is necessary but not
        // sufficient: a scrambled keychain / swap race can pair a foreign token
        // with the right `.claude.json` email. Verifying the TOKEN's real owner
        // here is the structural fix for the cross-slot credential scramble.
        match verify_token_owner(token, anchor_email, http_get) {
            OwnerVerdict::Match => {
                match adopt_candidate(base_dir, account, parsed, store_expiry) {
                    Ok(true) => {
                        info!(
                            account = account.get(),
                            source_tag = %cand.source_tag,
                            "custodian: adopted fresher live token into canonical store"
                        );
                        return ReconcileOutcome::Adopted;
                    }
                    // Guard rejected under the lock (a concurrent login/refresh won the
                    // race) — store already fresher; do not keep trying older candidates.
                    Ok(false) => return ReconcileOutcome::StoreFreshest,
                    Err(_) => {
                        warn!(
                            account = account.get(),
                            error_kind = "custodian_adopt_write_failed",
                            "custodian: adopt write failed (non-fatal)"
                        );
                        return ReconcileOutcome::NotAdopted;
                    }
                }
            }
            // Live but FOREIGN: the token's real owner (per /api/oauth/profile) is a
            // different account than the one being reconciled. NEVER adopt it — this
            // is the exact write that scrambled the store. Reject and keep trying the
            // next-freshest candidate (a correctly-owned one may still be present).
            OwnerVerdict::Mismatch => {
                warn!(
                    account = account.get(),
                    source_tag = %cand.source_tag,
                    error_kind = "custodian_owner_mismatch",
                    "custodian: candidate rejected — token owner != bound account (foreign token)"
                );
                identity_unconfirmed = true;
                continue;
            }
            // Rotated-dead chain: discard and fall back to the next-freshest candidate.
            OwnerVerdict::Dead => {
                validated_dead = true;
                continue;
            }
            // 429 — propagate to the tick's cross-account IP backoff; stop here.
            OwnerVerdict::RateLimited => return ReconcileOutcome::RateLimited,
            // Transport/5xx/parse/absent-email: cannot confirm ownership; adopt
            // nothing this tick.
            OwnerVerdict::Unknown => return ReconcileOutcome::SkippedUnknown,
        }
    }

    // Loop exhausted with no early return. Outcome precedence: IdentityUnconfirmed
    // is reported ahead of AllDead when both occurred this tick — an unconfirmed-
    // identity candidate is the more actionable operator signal (a possible
    // wrong-account / contaminated dir) than a dead sibling chain (redteam R1 NIT).
    // Both are non-adopting, so precedence is telemetry-only; it never changes the
    // adopt decision.
    if identity_unconfirmed {
        ReconcileOutcome::IdentityUnconfirmed
    } else if validated_dead {
        ReconcileOutcome::AllDead
    } else {
        ReconcileOutcome::NoEligibleCandidate
    }
}

/// Adopt a validated-live candidate into the canonical store. Returns `Ok(true)`
/// when the TOCTOU-guarded write happened, `Ok(false)` when the guard rejected it
/// (store already fresher under the lock). On a successful adopt, clears any stale
/// `broker_failed` sentinel (sentinel-clearing-parity: adopt is a new "account
/// healthy" success boundary — without this, `csq doctor` would keep reporting
/// LOGIN-NEEDED on a now-healthy account; the an internal ticket class).
///
/// **Subscription metadata (Rule 5)** is preserved by the write chokepoint itself:
/// `save_canonical_for_if_fresher` → `save_uuid_credentials` →
/// `preserve_subscription_metadata`, which reads the CURRENT on-disk credential
/// UNDER THE LOCK and backfills `subscription_type` / `rate_limit_tier` when the
/// incoming token omits them. That is strictly better than backfilling here from a
/// pre-lock in-memory snapshot, so no manual merge is done in the custodian.
fn adopt_candidate(
    base_dir: &Path,
    account: AccountNum,
    parsed: CredentialFile,
    store_expiry: Option<u64>,
) -> Result<bool, crate::error::CredentialError> {
    // TOCTOU-guarded write: re-reads the store expiry under the per-account mutex and
    // writes only if still strictly fresher than both the pre-lock baseline and the
    // current store. Re-serializes the canonical field set (never the raw bytes).
    let wrote =
        file::save_canonical_for_if_fresher(base_dir, account, &parsed, store_expiry.unwrap_or(0))?;
    if wrote {
        sentinel::clear_broker_failed(base_dir, account);
    }
    Ok(wrote)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn http_status(status: u16, body: impl Into<Vec<u8>>) -> HttpGetFn {
        let body: Vec<u8> = body.into();
        Arc::new(move |_url: &str, _tok: &str, _hdrs: &[(&str, &str)]| Ok((status, body.clone())))
    }

    /// Body shape returned by `/api/oauth/profile` for a given account email.
    fn profile_body(email: &str) -> Vec<u8> {
        format!(r#"{{"account":{{"uuid":"u","email":"{email}"}}}}"#).into_bytes()
    }

    #[test]
    fn owner_200_matching_email_is_match() {
        let g = http_status(200, profile_body("jack@researchroom.sg"));
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g),
            OwnerVerdict::Match
        );
    }

    #[test]
    fn owner_200_matching_email_is_case_insensitive_and_trimmed() {
        let g = http_status(200, profile_body("Jack@ResearchRoom.SG"));
        assert_eq!(
            verify_token_owner("tok", Some("  jack@researchroom.sg  "), &g),
            OwnerVerdict::Match
        );
    }

    #[test]
    fn owner_200_foreign_email_is_mismatch() {
        // The exact scramble: the live token belongs to integrum, but the account
        // being reconciled is researchroom. MUST reject.
        let g = http_status(200, profile_body("jack@integrum.global"));
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g),
            OwnerVerdict::Mismatch
        );
    }

    #[test]
    fn owner_401_is_dead() {
        let g = http_status(401, b"{}");
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g),
            OwnerVerdict::Dead
        );
    }

    #[test]
    fn owner_429_is_rate_limited() {
        let g = http_status(429, b"");
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g),
            OwnerVerdict::RateLimited
        );
    }

    #[test]
    fn owner_500_is_unknown() {
        let g = http_status(500, b"err");
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g),
            OwnerVerdict::Unknown
        );
    }

    #[test]
    fn owner_transport_error_is_unknown() {
        let g: HttpGetFn = Arc::new(|_u: &str, _t: &str, _h: &[(&str, &str)]| Err("boom".into()));
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g),
            OwnerVerdict::Unknown
        );
    }

    #[test]
    fn owner_absent_anchor_is_unknown_fail_closed() {
        // No anchor to compare against → cannot confirm ownership → fail-closed.
        let g = http_status(200, profile_body("jack@researchroom.sg"));
        assert_eq!(verify_token_owner("tok", None, &g), OwnerVerdict::Unknown);
        assert_eq!(
            verify_token_owner("tok", Some("   "), &g),
            OwnerVerdict::Unknown
        );
    }

    #[test]
    fn owner_200_missing_account_email_is_unknown_fail_closed() {
        let g = http_status(200, br#"{"account":{"uuid":"u"}}"#);
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g),
            OwnerVerdict::Unknown
        );
    }

    #[test]
    fn owner_200_empty_account_email_is_unknown_not_mismatch() {
        // An empty/whitespace `account.email` is "cannot confirm" (Unknown), NOT
        // "confirmed foreign" (Mismatch) — both fail-closed, but the classification
        // must stay honest (security review L1).
        let g = http_status(200, profile_body(""));
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g),
            OwnerVerdict::Unknown
        );
        let g_ws = http_status(200, profile_body("   "));
        assert_eq!(
            verify_token_owner("tok", Some("jack@researchroom.sg"), &g_ws),
            OwnerVerdict::Unknown
        );
    }

    // ── check_slot_store_token_ownership (doctor/repair detector) ─────────────

    /// Materialize slot `slot` → uuid with an `identity.json` anchor + an
    /// Anthropic store `credentials.json` carrying `token`.
    fn setup_slot_store(
        base: &Path,
        slot: u16,
        uuid: identity_store::IdentityId,
        anchor_email: &str,
        token: &str,
    ) {
        let mut pf = profiles::ProfilesFile::empty();
        pf.by_slot.insert(slot.to_string(), uuid);
        profiles::save(&profiles::profiles_path(base), &pf).unwrap();

        let cred_path = identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(cred_path.parent().unwrap()).unwrap();
        // identity.json (the anchor) lives beside credentials.json.
        std::fs::write(
            cred_path.parent().unwrap().join("identity.json"),
            format!(
                r#"{{"email":{},"provider":"anthropic","created_at":"t","key_id":null}}"#,
                serde_json::to_string(anchor_email).unwrap()
            ),
        )
        .unwrap();

        let cred = CredentialFile::Anthropic(crate::credentials::AnthropicCredentialFile {
            claude_ai_oauth: crate::credentials::OAuthPayload {
                access_token: crate::types::AccessToken::new(token.into()),
                refresh_token: crate::types::RefreshToken::new("sk-ant-ort01-x".into()),
                expires_at: 4_102_444_800_000,
                scopes: vec!["user:inference".into()],
                subscription_type: Some("max".into()),
                rate_limit_tier: None,
                extra: std::collections::HashMap::new(),
            },
            extra: std::collections::HashMap::new(),
        });
        file::save(&cred_path, &cred).unwrap();
    }

    #[test]
    fn slot_ownership_owned_when_store_token_matches_anchor() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = identity_store::IdentityId::new_v4();
        setup_slot_store(
            dir.path(),
            2,
            uuid,
            "jack@researchroom.sg",
            "sk-ant-oat01-store",
        );
        // /api/oauth/profile reports the SAME account as the anchor.
        let g = http_status(200, profile_body("jack@researchroom.sg"));
        assert_eq!(
            check_slot_store_token_ownership(dir.path(), AccountNum::try_from(2u16).unwrap(), &g),
            SlotOwnership::Owned
        );
    }

    #[test]
    fn slot_ownership_contaminated_when_store_token_is_foreign() {
        // The exact #955 scramble: slot 2 is bound to researchroom, but its STORE
        // token actually belongs to integrum → the detector MUST flag it.
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = identity_store::IdentityId::new_v4();
        setup_slot_store(
            dir.path(),
            2,
            uuid,
            "jack@researchroom.sg",
            "sk-ant-oat01-foreign",
        );
        let g = http_status(200, profile_body("jack@integrum.global"));
        assert_eq!(
            check_slot_store_token_ownership(dir.path(), AccountNum::try_from(2u16).unwrap(), &g),
            SlotOwnership::Contaminated
        );
    }

    #[test]
    fn slot_ownership_unknown_when_no_store_token() {
        // No profiles / no store cred → cannot confirm → Unknown (never a false
        // contamination alarm). The http_get must not even be consulted.
        let dir = tempfile::TempDir::new().unwrap();
        let g: HttpGetFn = Arc::new(|_u: &str, _t: &str, _h: &[(&str, &str)]| {
            panic!("http_get must not be called")
        });
        assert_eq!(
            check_slot_store_token_ownership(dir.path(), AccountNum::try_from(2u16).unwrap(), &g),
            SlotOwnership::Unknown
        );
    }

    #[test]
    fn slot_ownership_unknown_on_401_not_contaminated() {
        // A revoked store token (401) is "cannot confirm ownership", NOT foreign.
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = identity_store::IdentityId::new_v4();
        setup_slot_store(
            dir.path(),
            2,
            uuid,
            "jack@researchroom.sg",
            "sk-ant-oat01-dead",
        );
        let g = http_status(401, b"{}".to_vec());
        assert_eq!(
            check_slot_store_token_ownership(dir.path(), AccountNum::try_from(2u16).unwrap(), &g),
            SlotOwnership::Unknown
        );
    }

    // ── slot_store_credential_path (shared detector/heal path resolution) ─────

    #[test]
    fn store_path_is_uuid_keyed_when_slot_has_uuid_and_matches_detector_read() {
        // The heal MUST clear the SAME file the detector read. `setup_slot_store`
        // writes the store at the UUID-keyed path; `slot_store_credential_path`
        // must resolve to exactly that file (and it must exist).
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = identity_store::IdentityId::new_v4();
        setup_slot_store(
            dir.path(),
            2,
            uuid,
            "jack@researchroom.sg",
            "sk-ant-oat01-store",
        );
        let resolved = slot_store_credential_path(dir.path(), AccountNum::try_from(2u16).unwrap());
        assert_eq!(
            resolved,
            identity_store::credentials_path_for(dir.path(), uuid),
            "must resolve to the UUID-keyed store the detector reads"
        );
        assert!(
            resolved.exists(),
            "the resolved store file must be the real one"
        );
    }

    #[test]
    fn store_path_falls_back_to_legacy_when_no_uuid_mapping() {
        // A legacy slot with no `by_slot` UUID resolves to the numeric canonical
        // path (`credentials/N.json`) — the same fallback the detector uses.
        let dir = tempfile::TempDir::new().unwrap();
        let resolved = slot_store_credential_path(dir.path(), AccountNum::try_from(5u16).unwrap());
        assert_eq!(
            resolved,
            file::canonical_path(dir.path(), AccountNum::try_from(5u16).unwrap()),
            "no UUID → legacy numeric canonical path"
        );
    }

    // ── Wrong-account guard (candidate_account_matches) ───────────────────────

    #[test]
    fn account_matches_when_both_present_and_equal() {
        assert!(candidate_account_matches(
            Some("user@example.com"),
            Some("user@example.com")
        ));
    }

    #[test]
    fn account_matches_is_case_insensitive() {
        // OAuth emails are case-insensitive; CC and the mint may differ in case.
        assert!(candidate_account_matches(
            Some("User@Example.COM"),
            Some("user@example.com")
        ));
    }

    #[test]
    fn account_mismatch_rejected() {
        // The catastrophic case: a live token whose session is on a DIFFERENT
        // account than the one being reconciled. Fail-closed.
        assert!(!candidate_account_matches(
            Some("bound@example.com"),
            Some("foreign@example.com")
        ));
    }

    #[test]
    fn account_unconfirmed_when_anchor_absent() {
        // No identity.json email for the bound account → cannot confirm → refuse.
        assert!(!candidate_account_matches(None, Some("user@example.com")));
    }

    #[test]
    fn account_unconfirmed_when_candidate_absent() {
        // The candidate dir's .claude.json has no oauthAccount email → refuse.
        assert!(!candidate_account_matches(Some("user@example.com"), None));
    }

    #[test]
    fn account_unconfirmed_when_both_absent() {
        assert!(!candidate_account_matches(None, None));
    }

    #[test]
    fn account_unconfirmed_when_anchor_empty() {
        // Defensive: an empty anchor string must never match an empty candidate.
        assert!(!candidate_account_matches(Some(""), Some("")));
        assert!(!candidate_account_matches(
            Some(""),
            Some("user@example.com")
        ));
    }

    #[test]
    fn account_matches_trims_whitespace() {
        // Anchor is trim+lowercased at mint; candidate is CC-raw. Trimming both
        // makes the comparison symmetric so a stray space/newline does not
        // false-reject a legitimate same-account token (redteam R1 LOW).
        assert!(candidate_account_matches(
            Some("user@example.com"),
            Some("  user@example.com\n")
        ));
    }

    #[test]
    fn account_unconfirmed_when_candidate_empty_or_whitespace() {
        // Symmetric empty rejection (redteam R1 NIT): an empty/whitespace
        // candidate must never match, regardless of the anchor.
        assert!(!candidate_account_matches(
            Some("user@example.com"),
            Some("")
        ));
        assert!(!candidate_account_matches(
            Some("user@example.com"),
            Some("   ")
        ));
    }

    // ── reconcile_candidates wiring (the guard's integration path) ────────────
    //
    // These exercise the actual decision loop (anchor vs cand.candidate_email →
    // skip/adopt → outcome), not just the pure matcher — the gap redteam R1
    // flagged HIGH. harvest itself is macOS-only, so the loop was factored out to
    // consume an already-built candidate list and is testable on every platform.

    fn mk_candidate(
        email: Option<&str>,
        expiry_ms: u64,
    ) -> crate::credentials::keychain::HarvestCandidate {
        crate::credentials::keychain::HarvestCandidate {
            raw_json: r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-test","refreshToken":"sk-ant-ort01-test","expiresAt":4102444800000}}"#.to_string(),
            expiry_ms,
            source_tag: "term-1".to_string(),
            candidate_email: email.map(str::to_owned),
        }
    }

    /// An http_get that fails the test if validation is ever invoked — proves a
    /// guard-rejected candidate never reaches the network call (or the adopt write).
    fn never_called() -> HttpGetFn {
        Arc::new(|_u: &str, _t: &str, _h: &[(&str, &str)]| {
            panic!("validation MUST NOT run for a candidate rejected by the wrong-account guard")
        })
    }

    #[test]
    fn reconcile_candidates_rejects_mismatched_identity() {
        // The catastrophic case end-to-end: a live token whose dir names a
        // FOREIGN account is refused → IdentityUnconfirmed, store untouched,
        // validation never called.
        let dir = tempfile::TempDir::new().unwrap();
        let acct = AccountNum::try_from(2u16).unwrap();
        let cands = vec![mk_candidate(Some("foreign@example.com"), 4102444800000)];
        let out = reconcile_candidates(
            dir.path(),
            acct,
            Some("bound@example.com"),
            &cands,
            None,
            &never_called(),
        );
        assert_eq!(out, ReconcileOutcome::IdentityUnconfirmed);
    }

    #[test]
    fn reconcile_candidates_rejects_absent_candidate_email() {
        let dir = tempfile::TempDir::new().unwrap();
        let acct = AccountNum::try_from(2u16).unwrap();
        let cands = vec![mk_candidate(None, 4102444800000)];
        let out = reconcile_candidates(
            dir.path(),
            acct,
            Some("bound@example.com"),
            &cands,
            None,
            &never_called(),
        );
        assert_eq!(out, ReconcileOutcome::IdentityUnconfirmed);
    }

    #[test]
    fn reconcile_candidates_rejects_absent_anchor() {
        // Mint crash window: no identity.json email → cannot confirm → refuse.
        let dir = tempfile::TempDir::new().unwrap();
        let acct = AccountNum::try_from(2u16).unwrap();
        let cands = vec![mk_candidate(Some("bound@example.com"), 4102444800000)];
        let out = reconcile_candidates(dir.path(), acct, None, &cands, None, &never_called());
        assert_eq!(out, ReconcileOutcome::IdentityUnconfirmed);
    }

    #[test]
    fn reconcile_candidates_matched_candidate_reaches_validation() {
        // Positive wiring: a same-account candidate (case-insensitive) PASSES the
        // guard and reaches validation — proven by 401→Dead→AllDead (the network
        // call ran). The guard does not block legitimate same-account healing.
        let dir = tempfile::TempDir::new().unwrap();
        let acct = AccountNum::try_from(2u16).unwrap();
        let cands = vec![mk_candidate(Some("Bound@Example.com"), 4102444800000)];
        let dead = http_status(401, b"{}");
        let out = reconcile_candidates(
            dir.path(),
            acct,
            Some("bound@example.com"),
            &cands,
            None,
            &dead,
        );
        assert_eq!(out, ReconcileOutcome::AllDead);
    }

    #[test]
    fn reconcile_candidates_rejects_foreign_token_owner_past_gate1() {
        // Gate 2 end-to-end — THE cross-slot scramble case: the candidate's
        // `.claude.json` SELF-REPORTS the bound account (passes gate 1
        // `candidate_account_matches`), but the harvested TOKEN's real owner (per
        // `/api/oauth/profile`) is FOREIGN. verify_token_owner returns Mismatch →
        // the candidate is rejected, the store is NEVER written, outcome is
        // IdentityUnconfirmed. This is the exact write the old code performed and
        // this fix prevents.
        let dir = tempfile::TempDir::new().unwrap();
        let acct = AccountNum::try_from(2u16).unwrap();
        let cands = vec![mk_candidate(Some("bound@example.com"), 4102444800000)];
        // Passes gate 1 (self-report == anchor), but the profile endpoint reports the
        // token actually belongs to a DIFFERENT account.
        let foreign = http_status(200, profile_body("foreign@example.com"));
        let out = reconcile_candidates(
            dir.path(),
            acct,
            Some("bound@example.com"),
            &cands,
            None,
            &foreign,
        );
        assert_eq!(out, ReconcileOutcome::IdentityUnconfirmed);
    }

    #[test]
    fn reconcile_candidates_owner_mismatch_does_not_abort_scan() {
        // A foreign fresher token no longer aborts the scan: gate-2 Mismatch does
        // `continue`, so a later candidate is still evaluated. Proven by the call
        // COUNT reaching 2 (both candidates hit the network) — the outcome itself
        // stays IdentityUnconfirmed because that precedence outranks the 2nd
        // candidate's Dead verdict.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = tempfile::TempDir::new().unwrap();
        let acct = AccountNum::try_from(2u16).unwrap();
        let cands = vec![
            mk_candidate(Some("bound@example.com"), 4102444800001), // freshest, foreign token
            mk_candidate(Some("bound@example.com"), 4102444800000), // owned-report, 401 dead
        ];
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = Arc::clone(&calls);
        let g: HttpGetFn = Arc::new(move |_u: &str, _t: &str, _h: &[(&str, &str)]| {
            let n = calls_c.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                // gate-1 passes; gate-2 sees a FOREIGN owner → Mismatch → continue.
                Ok((
                    200,
                    br#"{"account":{"uuid":"u","email":"foreign@example.com"}}"#.to_vec(),
                ))
            } else {
                Ok((401, b"{}".to_vec())) // 2nd candidate → Dead
            }
        });
        let out = reconcile_candidates(
            dir.path(),
            acct,
            Some("bound@example.com"),
            &cands,
            None,
            &g,
        );
        // Both candidates reached verify_token_owner → the Mismatch did NOT short-circuit.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // identity_unconfirmed (gate-2 Mismatch) outranks the 2nd candidate's Dead.
        assert_eq!(out, ReconcileOutcome::IdentityUnconfirmed);
    }

    #[test]
    fn reconcile_candidates_store_fresher_returns_store_freshest() {
        // store_expiry strictly newer than the candidate → freshest-cutoff fires
        // BEFORE the guard/validation: no adopt, validation never called. Pins the
        // store_expiry forwarding + early-return ordering (redteam R2 NIT).
        let dir = tempfile::TempDir::new().unwrap();
        let acct = AccountNum::try_from(2u16).unwrap();
        let cands = vec![mk_candidate(Some("bound@example.com"), 1_000)];
        let out = reconcile_candidates(
            dir.path(),
            acct,
            Some("bound@example.com"),
            &cands,
            Some(2_000),
            &never_called(),
        );
        assert_eq!(out, ReconcileOutcome::StoreFreshest);
    }

    // ── identity_unconfirmed_reason (the daemon-log drift/fresh tag) ───────────
    // R2 testing-specialist F1: the candidate_email_drift branch was structurally
    // unreachable from any test. These exercise every reason arm directly.

    #[test]
    fn reason_anchor_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        assert_eq!(
            identity_unconfirmed_reason(dir.path(), "term-1", None, Some("c@x.com")),
            "anchor_email_absent"
        );
    }

    #[test]
    fn reason_email_mismatch() {
        let dir = tempfile::TempDir::new().unwrap();
        assert_eq!(
            identity_unconfirmed_reason(dir.path(), "term-1", Some("a@x.com"), Some("b@x.com")),
            "email_mismatch"
        );
    }

    #[test]
    fn reason_candidate_absent_is_fresh_not_drift() {
        // No term-1 dir → classify_oauth_account → NotYetPopulated → absent (fresh).
        let dir = tempfile::TempDir::new().unwrap();
        assert_eq!(
            identity_unconfirmed_reason(dir.path(), "term-1", Some("a@x.com"), None),
            "candidate_email_absent"
        );
    }

    #[test]
    fn reason_candidate_drift_when_populated_no_oauth_account() {
        // Populated .claude.json without oauthAccount → classify FieldMissing →
        // "candidate_email_drift" (the #833 degradation surfaced in the daemon log).
        let dir = tempfile::TempDir::new().unwrap();
        let handle = dir.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        std::fs::write(
            handle.join(".claude.json"),
            r#"{"numStartups":3,"userID":"x"}"#,
        )
        .unwrap();
        assert_eq!(
            identity_unconfirmed_reason(dir.path(), "term-1", Some("a@x.com"), None),
            "candidate_email_drift"
        );
    }
}
