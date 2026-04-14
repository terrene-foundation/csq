---
type: DISCOVERY
date: 2026-04-14
created_at: 2026-04-14T12:00:00+08:00
author: co-authored
session_id: 2026-04-14-alpha-12
session_turn: 15
project: csq-v2
topic: csq update install permanently reported "up to date" on alpha.9 because of three overlapping bugs — /releases/latest skipped prereleases, lexicographic prerelease compare ranked alpha.11 < alpha.9, and GitHub /releases list order was not reliably chronological; fixed in alpha.12 with client-side semver sort and per-segment prerelease compare
phase: implement
tags:
  [alpha-12, update-check, semver, github-api, version-compare, install-script]
---

# 0047 — DISCOVERY — alpha.12 update-check three bugs

**Status**: Fixed in v2.0.0-alpha.12 (branch
`fix/alpha-12-update-check-multi-release-sort`).
**Predecessor**: 0046 (alpha.11 live-only discovery + resurrection).

## Symptom

User ran `csq update install` on alpha.9 and got "up to date"
repeatedly, even though alpha.10, alpha.11, and the about-to-ship
alpha.12 all existed as pre-release tags on GitHub.
`install.sh` also returned alpha.9 as "latest" when invoked without
a pinned `CSQ_VERSION`.

## Three overlapping bugs

### Bug A — `/releases/latest` skips prereleases

`csq-core::update::github::check_latest_version` was hitting
`https://api.github.com/repos/terrene-foundation/csq/releases/latest`.

That endpoint has documented behavior: it returns the most recent
release where `prerelease == false` and `draft == false`. Since
csq is in `2.0.0-alpha.*` state, **every** v2 release is a
prerelease — so the endpoint falls back to `v1.1.0` (the Python-era
line).

Empirical verification:

```bash
$ curl -sSL https://api.github.com/repos/terrene-foundation/csq/releases/latest | jq .tag_name
"v1.1.0"
```

Combined with bug B below, this meant `csq update install`
compared `1.1.0` against `CURRENT_VERSION = 2.0.0-alpha.9`, saw
`1.1.0 < 2.0.0-alpha.9`, and returned `Ok(None) == up to date`.

### Bug B — lexicographic prerelease compare

`compare_versions` split the version on `-` and compared prerelease
suffixes with `String::cmp`:

```rust
match (a_pre, b_pre) {
    (Some(a), Some(b)) => a.cmp(&b),
    // ...
}
```

So `"alpha.11".cmp(&"alpha.9")` returned `Ordering::Less` because at
character index 6, `'1' < '9'` lexicographically. That made
`compare_versions("2.0.0-alpha.11", "2.0.0-alpha.9")` report that
alpha.11 is **smaller** than alpha.9, and `csq update` treat every
double-digit alpha as a downgrade even if the user got the right
tag from the API.

SemVer 2.0.0 section 11 is explicit about this:

> When comparing prerelease versions, identifiers consisting of only
> digits are compared numerically and identifiers with letters or
> hyphens are compared lexically in ASCII sort order.

The old code violated the "only digits are compared numerically"
part. SemVer also says numeric identifiers have LOWER precedence
than non-numeric ones (so `1.0.0-alpha.1 < 1.0.0-alpha.beta`), which
the old code also didn't handle.

Fix: split each prerelease by `.`, per segment try `parse::<u64>`,
then:

| a           | b           | ordering                         |
| ----------- | ----------- | -------------------------------- |
| numeric     | numeric     | numeric compare                  |
| numeric     | non-numeric | Less (numeric loses, per SemVer) |
| non-numeric | numeric     | Greater                          |
| non-numeric | non-numeric | ASCII string compare             |

After all shared segments compare equal, the prerelease with MORE
segments wins (`1.0.0-alpha < 1.0.0-alpha.1`).

### Bug C — GitHub `/releases` server order is not reliable

The "obvious" workaround to bug A is to hit `/releases?per_page=1`
and take the first entry. `install.sh` already did that. But
empirical check of the live csq API:

```
$ curl -sSL 'https://api.github.com/repos/terrene-foundation/csq/releases?per_page=5' \
    | jq '.[] | {tag: .tag_name, pre: .prerelease, created: .created_at, pub: .published_at}'

{"tag":"v2.0.0-alpha.9",  "created":"2026-04-14T01:11:59Z", "pub":"2026-04-14T01:23:41Z"}
{"tag":"v2.0.0-alpha.11", "created":"2026-04-14T02:52:19Z", "pub":"2026-04-14T03:02:16Z"}
{"tag":"v2.0.0-alpha.10", "created":"2026-04-14T02:38:38Z", "pub":"2026-04-14T02:50:15Z"}
{"tag":"v2.0.0-alpha.8",  "created":"2026-04-13T15:17:49Z", "pub":"2026-04-13T15:27:41Z"}
{"tag":"v2.0.0-alpha.7",  "created":"2026-04-13T10:09:33Z", "pub":"2026-04-13T10:20:10Z"}
```

Note the order: `alpha.9` comes first even though it has the oldest
`created_at` AND oldest `published_at` of the top three. The server
order is **not** sorted by either visible date field — most likely
it sorts by an internal `updated_at` that gets bumped when assets
are uploaded in a second pass after the release was originally
published.

Consequence: `install.sh`'s `resolve_tag` (which did
`curl .../releases?per_page=1 | grep tag_name | head -1`) returned
alpha.9 even after alpha.10 and alpha.11 were published. And the
fixed `csq update` would have hit the same problem if we'd only
changed the endpoint without also sorting client-side.

## Fix — alpha.12

### `csq-core/src/update/github.rs`

1. Swap `GITHUB_API_LATEST` (`/releases/latest`) for
   `GITHUB_API_RELEASES` (`/releases?per_page=30`).
2. Parse the response as `Vec<LatestRelease>`.
3. Filter out `draft == true` entries. Keep prereleases — csq opts
   in to them explicitly.
4. Client-side sort descending by `compare_versions`.
5. Take the first entry as "the latest".
6. Proceed with the existing asset-discovery / HTTPS-validation path.

`compare_versions` is rewritten per SemVer 2.0.0 section 11 with
numeric-aware per-segment compare. The prerelease handling now
lives in a separate `compare_prerelease` helper.

### `install.sh::resolve_tag`

Same strategy at the shell level: `curl /releases?per_page=30`,
extract all `tag_name` lines, filter to strict semver shapes, pipe
through `sort -Vr`, take the first. `sort -V` does proper version
sorting including prerelease suffixes; both GNU coreutils and macOS
Ventura+ ship it.

The `prerelease` flag lookup for the selected tag now uses an
`awk` match that locates the tag line and then the nearest
`"prerelease":` line after it. Best-effort; failure silently
suppresses the PRE-RELEASE warning rather than blocking the install.

## Verification

- **719 tests passing** (713 alpha.11 + 6 new)
  - Broken by the endpoint switch: `run_update_check_with_writes_cache_on_up_to_date`
    (mod.rs) was using a bare-object fake; updated to one-element
    array.
- 8 new tests in `update::github::tests`:
  - `compare_double_digit_alpha_numeric_order` — alpha.9/10/11/100
    compare correctly
  - `compare_prerelease_semver_spec_rules` — numeric vs non-numeric,
    short vs long prerelease
  - `check_latest_picks_highest_semver_from_unsorted_list` — server
    returns alpha.9 first, client picks alpha.11
  - `check_latest_ignores_v1_x_stable_when_current_is_alpha` —
    v1.1.0 doesn't float to the top when newer prereleases exist
  - `check_latest_skips_draft_releases` — draft entries excluded
  - `check_latest_returns_none_when_all_older` — every release older
    than current → Ok(None)
  - (Two more are updates to existing tests to use `wrap_in_array`.)
- Manual live-API verification of `install.sh`'s pipeline:
  ```
  $ curl .../releases?per_page=30 | grep tag_name | sed ... | sort -Vr | head -1
  v2.0.0-alpha.11
  ```
- `cargo clippy --workspace --all-targets -- -D warnings`: clean
- `cargo fmt --all -- --check`: clean

## Consequences

### Fixed

- `csq update install` now reliably finds the highest semver-sorted
  non-draft release regardless of server order.
- `install.sh` with no pin resolves the same.
- Double-digit alpha releases (alpha.10, alpha.11, alpha.12, …)
  compare correctly as higher-than-alpha.9.
- v1.1.0 can never again poison the update check just because it's
  the only non-prerelease in the catalog.

### New invariant

The source of "latest" truth is client-side semver sort of
`/releases?per_page=30`. The server's list order is explicitly
distrusted. If this assumption ever needs revisiting (e.g. csq ships
so many releases that 30 isn't enough), it becomes a pagination
problem — not a correctness one.

### What the alpha.9/10/11 users need to do

- alpha.9 binary: `csq update install` is permanently broken. The
  fix lives in alpha.12+, so the user must install alpha.12 via
  `install.sh` (with either the new install.sh or `CSQ_VERSION=v2.0.0-alpha.12`
  pinned) to escape the trap.
- alpha.10/11 binary: same. All pre-alpha.12 binaries have the bug.
- From alpha.12 onward, `csq update install` self-upgrades correctly.

### Ordering risk on release day

Because the server returns releases in an order that appears to be
`updated_at`-based, a release whose assets were re-uploaded recently
can "float" to the top even though a chronologically newer release
also exists. Client-side sort is immune to this. But consumers of
the GitHub API in other parts of the codebase (if any) should be
audited for the same assumption — grep for `releases/latest` and
`per_page=1`.

## For Discussion

1. The fix treats `/releases?per_page=30` as a complete list. 30 is
   comfortable now (csq has had 13 releases total) but becomes a
   pagination problem at ~30 releases. Is there a cleaner strategy
   than "bump per_page"? Options: (a) chase the `Link: rel=next`
   header until exhausted, (b) switch to a stable-order endpoint
   that accepts `sort=published_at` (GitHub doesn't currently
   expose one), (c) fetch `/releases/latest` for stable lineage +
   `/releases?per_page=10` for current alphas and merge.

2. The old code's lexicographic prerelease bug would have been
   caught by a property test on compare_versions that generated
   synthetic `alpha.N` pairs and asserted `N1 < N2 ⇒ alpha.N1 <
alpha.N2`. We have unit tests now. Counterfactual: if we'd had
   such a property test at PR #56 (when `csq update` shipped),
   would it have caught this bug before user impact, or would it
   have been written to only cover single-digit cases and miss the
   `alpha.11` boundary?

3. `install.sh` uses `sort -Vr` for version sort. `sort -V` on
   BSD `sort` (pre-macOS-Ventura) doesn't exist. We ship csq's
   install script with this dependency. What's the failure mode
   on a user with an outdated `sort`, and is there a pure-awk
   fallback worth writing?
