---
type: DECISION
date: 2026-04-14
created_at: 2026-04-14T11:00:00+08:00
author: co-authored
session_id: 2026-04-14-alpha-11
session_turn: 30
project: csq-v2
topic: OAuth refresher silently skipped accounts whose canonical credentials/N.json was missing, causing 8h re-auth on machines with broken write paths; alpha.11 adds live-only fallback discovery, in-tick canonical resurrection, forensic breadcrumbs, and a csq doctor summary to identify root cause
phase: implement
tags:
  [
    alpha-11,
    handle-dir,
    auto-auth,
    oauth-refresher,
    resurrection,
    forensics,
    csq-doctor,
  ]
---

# 0046 — DECISION — alpha.11 live-only discovery and canonical resurrection

**Status**: Implemented (branch
`fix/alpha-11-discover-live-only-accounts`).
**Predecessors**: 0045 (alpha.10 swap rewrites `.claude.json`), 0044
(alpha.9 handle-dir settings materialization).

## Symptom

User reports on machines other than the developer machine: every ~8
hours `csq` displays the "re-auth" button for every OAuth slot and
statusline stops updating. Running `claude` directly works; the desktop
app says the daemon is running; quota polling runs correctly in the
background. Only the OAuth token refresh is broken.

The 8-hour boundary is the lifetime of a Claude OAuth access token.
When the daemon refresher fails to run against an account before
`expires_at`, the access token dies in place and CC demands re-auth.

## Root cause (hypothesis, not yet confirmed on affected machines)

`csq-core::daemon::refresher::tick` calls
`discovery::discover_anthropic(base_dir)` to enumerate Anthropic OAuth
slots. Until alpha.11, `discover_anthropic` walked **only**
`{base_dir}/credentials/*.json` (the "canonical" path) and yielded no
account that wasn't present there. If a slot had `config-N/.credentials.json`
but not `credentials/N.json` (the "live-only" state), the refresher
did not know the slot existed and silently skipped it every 5 minutes
until the token expired.

Separately, in the refresher tick itself, the expires_at load was
wrapped in `debug!` on failure:

```rust
let expires_at_ms = match credentials::load(&canonical) {
    Ok(c) => c.claude_ai_oauth.expires_at,
    Err(e) => {
        debug!(account = info.id, error = %e, "could not read canonical");
        continue;
    }
};
```

So even a same-tick canonical-missing state (discovery yields it, load
fails) produced a single debug-level log line and the tick moved on
with no user-visible signal and no forensic record.

How did the live-only state arise? The candidates are:

1. Old csq installs that wrote `config-N/.credentials.json` directly
   without the canonical mirror, and current csq never reconstituted.
2. A broken login / Add Account path on one specific machine's build
   chain.
3. User manually deleted `credentials/N.json` without knowing the
   daemon depends on it.
4. A swap / rotation path that promoted a sibling credential but
   failed to write canonical.

Alpha.11 ships the fix **preemptively** without confirming which of
those produced the orphan, because the affected machines are
currently broken and the fix is fully defensive. The forensic
breadcrumb system (below) lets the operator investigate after the
fact.

## Decision

Ship three changes together:

1. **Live-only discovery fallback** in `discover_anthropic`: a second
   pass that walks `config-*/.credentials.json` for slots the
   canonical pass didn't yield.
2. **In-tick canonical resurrection** in `refresher::tick`: when
   canonical is missing for a discovered account, copy the live file
   to canonical in the same tick so `broker_check` (which reads
   canonical) has something to work with.
3. **Forensic breadcrumbs + csq doctor summary**: every resurrection
   appends a JSONL record to `{base_dir}/.resurrection-log.jsonl`
   and `csq doctor` surfaces a warning showing the count, distinct
   accounts, last timestamp, and a sample of recent slots. The
   breadcrumb is what turns "the daemon silently fixes your broken
   install" into "the daemon fixes your broken install and tells
   you exactly which accounts had to be rescued so you can trace
   the bad write path".

### Why `csq doctor` (user feedback loop)

A pure auto-heal would erase the evidence the next session needs to
find the root cause. The forensic breadcrumb + doctor summary turns
the heal into a tripwire: every resurrection is recorded, durable
across daemon restarts, and visible at the top of the user's next
`csq doctor` run. Operators can `jq` the log directly for richer
analysis.

### What is NOT in alpha.11

- Identifying the bad write path itself. Alpha.11 is fix-and-detect.
  Fix-and-diagnose is a follow-up after real resurrection records
  come in from the affected machines.
- Removing the debug-level `could not read canonical` path. Replaced
  with a `warn!` after both resurrection attempts fail so the silent
  skip is gone in all paths.
- Making `csq doctor` actively check write paths (login, rotation)
  for correctness. That's a bigger audit.

## Implementation

### 1. `csq-core/src/accounts/discovery.rs::discover_anthropic`

Split into two sequential passes:

- **Pass 1 (canonical)**: existing behavior. Walks
  `{base_dir}/credentials/*.json` and yields accounts from them.
- **Pass 2 (live-only fallback)**: walks `{base_dir}/config-*/`
  entries. For each `config-<N>/` directory:
  1. Rejects symlinks (traversal safety — matches
     `discover_per_slot_third_party`).
  2. Parses `N` from the dir name and ensures `1..=999`.
  3. Skips if pass 1 already yielded this account.
  4. Skips 3P slots (has `settings.json` with
     `env.ANTHROPIC_BASE_URL`) — those have no refresh token and
     belong to the usage poller, not the OAuth refresher.
  5. Requires `config-<N>/.credentials.json` to exist and parse.
  6. Requires the `.csq-account` marker (if present) to match the
     dir name — a mismatch means the dir was renamed without the
     marker and attributing the creds to the dir-name ID would
     refresh the wrong profile.
  7. Logs at `warn!` with account ID and live path — "canonical is
     missing, refresher will resurrect next tick".
  8. Yields an `AccountInfo` with `has_credentials: true`.

### 2. `csq-core/src/daemon/refresher.rs::tick`

When `credentials::load(&canonical)` fails, try
`credentials::load(&live_path)` before giving up:

```rust
let expires_at_ms = match credentials::load(&canonical) {
    Ok(c) => c.claude_ai_oauth.expires_at,
    Err(canonical_err) => {
        let live = cred_file::live_path(base_dir, account);
        match credentials::load(&live) {
            Ok(c) => {
                // ... warn + cred_file::save(&canonical, &c) +
                //     append_resurrection_breadcrumb + fall through
                c.claude_ai_oauth.expires_at
            }
            Err(live_err) => {
                warn!(...);
                continue;
            }
        }
    }
};
```

Resurrection is in the **same tick** — not deferred — so the user
doesn't wait 5 minutes for the refresh to happen after the canonical
is rebuilt. `broker_check` runs against the freshly-resurrected
canonical and Anthropic gets one refresh call this tick.

Both fallbacks fail loudly at `warn!` level. The `debug!` silent-skip
is gone.

### 3. Forensic breadcrumbs — `.resurrection-log.jsonl`

`append_resurrection_breadcrumb` writes one JSONL record per event:

```json
{
  "timestamp_secs": 1776196240,
  "account": 3,
  "event": "canonical_resurrected",
  "live_mtime_secs": 1776196200,
  "live_path": "/Users/esperie/.claude/accounts/config-3/.credentials.json"
}
```

Rationale:

- **`timestamp_secs`** — when the resurrection happened. Essential
  for correlating with other logs / install events.
- **`account`** — which slot. Lets the operator narrow the
  investigation to specific login flows.
- **`live_mtime_secs`** — when the live file was last modified. An
  operator can correlate this with their shell history to identify
  the write that orphaned canonical ("I ran `csq login 3` at 10:17
  and the breadcrumb shows live_mtime_secs=10:17:03 — yes, login is
  the culprit").
- **`event`** — currently always `canonical_resurrected`, left
  extensible for other daemon self-heals in the future.
- **`live_path`** — full path for operator jq-ability. Escaped
  double quotes in case of paths with quotes (extremely unlikely on
  Unix, possible on Windows).

Best-effort write: swallowed errors. A missing breadcrumb must not
block the refresh.

0o600 via `secure_file` on the breadcrumb log — defense in depth;
the parent dir is already 0o700.

### 4. `csq doctor` summary

`csq-cli/src/commands/doctor.rs` gets a new `ResurrectionInfo`
section:

```
  Resurrections: ⚠ 3 canonical rebuilds across 2 account(s) — last at
  2026-04-14 03:10:40 UTC — investigate write path (recent: 3, 5, 3).
  Breadcrumbs: ~/.claude/accounts/.resurrection-log.jsonl
```

Only printed when `total > 0`. Zero-count suppresses the line — no
noise for healthy installs.

Date formatting is hand-rolled (Howard Hinnant's civil-from-days
algorithm) because adding `chrono` or `time` for a single print
statement is excess baggage.

## Tests

Nine new unit tests across three modules:

**`accounts::discovery::tests`** (4):

- `discover_anthropic_finds_live_only_accounts` — two live-only slots
  (3, 5) appear alongside a canonical slot (1).
- `discover_anthropic_live_fallback_respects_marker_mismatch` —
  corrupt `.csq-account` marker disqualifies the dir. Paranoid check
  against renamed dirs.
- `discover_anthropic_live_fallback_excludes_third_party` — 3P slot
  with `env.ANTHROPIC_BASE_URL` is not yielded.
- `discover_anthropic_canonical_wins_over_live_fallback` —
  duplicates don't appear; first-pass (canonical) wins.

**`daemon::refresher::tests`** (1):

- `tick_resurrects_canonical_from_live_and_refreshes` — live-only
  expired account, one tick, assertion: canonical file exists,
  refresh HTTP call happened, cache status recorded, breadcrumb
  appended with correct event tag.

**`commands::doctor::tests`** (4):

- `check_resurrections_absent_file_reports_zero` — missing
  breadcrumb file returns zero counts.
- `check_resurrections_counts_unique_accounts` — three records across
  two accounts, correct distinct count, correct most-recent timestamp,
  correct recent_accounts sample.
- `check_resurrections_ignores_malformed_lines` — non-JSON and empty
  lines are skipped, only valid records count.
- `format_utc_date_round_trips_known_timestamps` — asserts
  `1776132000` renders as `2026-04-14 02:00:00 UTC` and epoch renders
  as `1970-01-01 00:00:00 UTC`.

## Verification

- **713 tests passing** (704 alpha.10 baseline + 9 new)
- `cargo clippy --workspace --all-targets -- -D warnings`: clean
- `cargo fmt --all -- --check`: clean
- `cargo build --release -p csq-cli`: clean

## Consequences

### Fixed

- OAuth refresh works even when `credentials/N.json` is missing,
  provided `config-N/.credentials.json` is valid.
- The silent-skip path in the refresher tick is gone. Any credential
  load failure now produces a `warn!` log.
- Operators get a forensic trail: `csq doctor` + JSONL breadcrumbs.

### Deferred (requires affected-machine data)

- Identifying the specific write path(s) that orphaned canonicals.
  Current hypothesis: old csq versions that wrote only to live, or a
  broken login / rotation path. Alpha.11 detects and fixes; alpha.12
  or later can root-cause and prevent based on actual breadcrumb
  data.
- `csq doctor --json` output gains a `resurrections` key so
  dashboards / monitoring can alert on non-zero counts. Already
  present structurally via `ResurrectionInfo : Serialize`; no
  additional work needed.

### Potential downside

The resurrection path is intentionally permissive: any
`config-N/.credentials.json` that parses is promoted to canonical.
If an attacker could write `config-N/.credentials.json` with a
token they control, they could trick the refresher into refreshing
their token using the user's OAuth client. Mitigation: the
same-user threat model means an attacker with write access to
`~/.claude/accounts/config-N/` already has arbitrary read/write
on the user's credentials; live-fallback doesn't widen the attack
surface. Symlink rejection in the discovery pass prevents a poisoned
dir from pointing outside `base_dir`.

## For Discussion

1. The breadcrumb log is per-`base_dir` and append-only. It grows
   without bound if a write path continuously creates orphans. We
   don't rotate or truncate. What threshold should trigger a rotate
   or a "too many resurrections — something's wrong" escalation in
   `csq doctor` beyond the current "just show the count" warning?
   Counterfactual: if we had rotated after the first record, the
   alpha.11 user investigation would have lost the early evidence.

2. The fix promotes any parseable `config-N/.credentials.json` to
   canonical without verifying the token is actually valid against
   Anthropic first. If the live copy is stale (expired RT, revoked
   grant), resurrection saves a dead canonical and the next tick's
   refresh fails. Acceptable because the alternative (pre-flight
   verify) adds a round-trip to Anthropic per resurrection and the
   same-tick broker_check will classify the failure correctly. Is
   there a case where the pre-flight would have changed behavior
   that we missed?

3. The `event` field is hardcoded to `canonical_resurrected` — there
   is no `canonical_corrupted_but_live_also_unreadable` event even
   though that path exists (both load failures in the refresher).
   Should the breadcrumb schema cover the "everything failed" case
   so operators know the daemon gave up, or is a `warn!` log enough?
