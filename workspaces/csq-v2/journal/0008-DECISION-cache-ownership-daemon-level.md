---
type: DECISION
date: 2026-04-10
created_at: 2026-04-10T23:15:00Z
author: agent
session_id: m8-http-api-routes
session_turn: 160
project: csq-v2
topic: TTL cache ownership lives at daemon-start level, not inside subsystems
phase: implement
tags: [m8, daemon, architecture, cache, refactoring]
---

# DECISION: Cache ownership lives at daemon-start level

## Context

M8.4's refresher created its own `Arc<TtlCache<u16, RefreshStatus>>`
inside `spawn_with_config` and returned it via `RefresherHandle.cache`.
This worked for the refresher in isolation, but when M8.5 needed HTTP
routes to READ from the same cache, two bad options surfaced:

1. Thread the cache Arc out through `RefresherHandle` and pass it to
   `server::serve()` after the refresher is spawned. This creates a
   startup ordering constraint (refresher must spawn before server)
   and two code paths that both "know" the cache layout.
2. Build a shared-state singleton. Invasive, unnecessary, and
   couples every subsystem to every other subsystem.

## Decision: own the cache at `handle_start`, pass Arc clones down

The daemon-start function (in `csq-cli/src/commands/daemon.rs`)
creates the cache once:

```rust
let refresh_cache: Arc<TtlCache<u16, RefreshStatus>> =
    Arc::new(TtlCache::with_default_age());
```

Then clones the Arc into both subsystems:

- `RouterState { cache: Arc::clone(&refresh_cache), base_dir }` → passed
  to `serve()`
- `spawn_refresher(base_dir, Arc::clone(&refresh_cache), http_post, shutdown)`

`refresher::spawn` and `spawn_with_config` signatures were updated to
take `cache: Arc<TtlCache<...>>` as an external parameter. All
refresher tests updated to construct their own cache externally.

## Why this pattern

1. **Cache outlives both subsystems naturally.** `handle_start`'s
   stack frame holds the Arc until after both join handles
   complete, so there's no lifetime concern.
2. **Subsystems are symmetric.** Neither the server nor the
   refresher is "the owner" — both are readers/writers of shared
   state. That shared state belongs in the function that owns the
   lifecycle, not in any one subsystem.
3. **Future subsystems slot in trivially.** M8.6's usage poller
   will create its own `Arc<TtlCache<u16, UsageStatus>>` at
   `handle_start` and hand clones to the poller task and a future
   `/api/usage` route. Same pattern, no refactor needed.
4. **Testable without a daemon.** Each subsystem takes the cache
   as a parameter, so unit tests can drive them with a
   purpose-built cache and assert state without spinning up the
   whole daemon.

## Architectural invariant going forward

**All shared daemon state lives at the `handle_start` scope, passed
to subsystems as `Arc` parameters.** Sub-systems must NOT own
shared state internally — if another subsystem needs to read it,
the owning subsystem is in the wrong place.

Concrete list of future state that will follow this pattern:

- M8.6: `Arc<TtlCache<u16, UsageStatus>>` (usage poller + HTTP routes)
- M8.6: `Arc<TtlCache<PathBuf, Vec<AccountInfo>>>` (short-TTL
  discovery cache addressing M8.5 MED #1)
- M8.7: `Arc<Mutex<OAuthStateStore>>` (PKCE state + `/api/login` +
  `/oauth/callback`)
- M8.8: `Arc<JoinSet<()>>` (per-connection shutdown tracking)

## For Discussion

1. Is there a scale at which this becomes unwieldy? A
   `handle_start` function with 8 `Arc` fields to track would be
   ugly. At what point do we collapse into a `DaemonState` struct
   and pass that around instead?
2. The refresher's `RefresherHandle.cache` field is now redundant
   with the Arc the caller already holds. Keep it for
   ergonomics (tests still use it) or remove?
3. This pattern relies on the daemon being single-threaded at
   startup — if `handle_start` ever became a concurrent
   initialization story (M8.6's poller starts its own tokio
   subruntime?), the ownership model gets muddier. Should we
   document explicitly that `handle_start` is the sole
   ownership boundary?
