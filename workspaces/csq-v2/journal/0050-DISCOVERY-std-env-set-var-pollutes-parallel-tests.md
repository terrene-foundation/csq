---
type: DISCOVERY
date: 2026-04-14
created_at: 2026-04-14T14:10:00+08:00
author: co-authored
session_id: 2026-04-14-alpha-14-ci-rescue
project: csq-v2
topic: `std::env::set_var` is process-global; per-test env overrides leak into concurrent tests' env reads and cause non-deterministic "passes-on-PR-fails-on-main" flakes. Discovered while fixing Windows + Linux pid_file_path tests in PR #113 → #114.
phase: validate
tags: [testing, env-vars, rust, pid-file, parallelism]
---

# 0050 — DISCOVERY — `std::env::set_var` pollutes parallel tests

## Context

Busting the CI cache (journal 0049, PR #113) unblocked the build and surfaced five latent test failures. Two of them were Windows-specific races on `daemon::detect::tests::detect_corrupt_pid_file_is_stale` and `detect_dead_pid_is_stale`, both of which call `pid_file_path(base_dir)`.

`pid_file_path` on Windows **ignores `base_dir`** and returns `%LOCALAPPDATA%\csq\csq-daemon.pid` — a process-global path. Two parallel tests writing different file contents race on the same path. The existing `detect_missing_pid_file_is_not_running` test tried to dodge this with:

```rust
#[cfg(target_os = "windows")]
unsafe { std::env::set_var("LOCALAPPDATA", dir.path()); }
```

I followed the same pattern for the two failing tests in PR #113 round one. PR CI went green (all six jobs). I merged.

**Post-merge main CI went red** with a different test failing: `detect_live_pid_but_missing_socket_is_stale` on Ubuntu, panicking with `expected Stale, got NotRunning`.

## Root cause

`std::env::set_var` mutates **process-global state**, not the caller's scope. That's why Rust 1.79+ marks it `unsafe`. When `detect_corrupt_pid_file_is_stale` set `XDG_RUNTIME_DIR` to its TempDir path, every other test in the same binary reading `XDG_RUNTIME_DIR` saw that path too — including tests that ran _after_ my test's TempDir had been dropped and the directory cleaned up.

The surviving failure mode on Ubuntu:

1. `detect_corrupt_pid_file_is_stale` runs, sets `XDG_RUNTIME_DIR = /tmp/A`, writes garbage to `/tmp/A/csq-daemon.pid`, asserts Stale, passes.
2. TempDir drops → `/tmp/A` is removed from disk. `XDG_RUNTIME_DIR` env still points at the now-nonexistent path.
3. `detect_live_pid_but_missing_socket_is_stale` runs, creates its own TempDir `/tmp/B`, calls `pid_file_path(/tmp/B)`. On Linux this returns `$XDG_RUNTIME_DIR/csq-daemon.pid` = `/tmp/A/csq-daemon.pid`. The directory no longer exists — write fails silently OR writes to a bogus location.
4. `detect_daemon(/tmp/B)` reads `pid_file_path` (same stale path) → file missing → `NotRunning`.
5. Test asserted `Stale`, got `NotRunning`, panic.

Whether the post-drop assertion fired depended on test execution order, which is non-deterministic under parallel execution. The PR run got lucky; the post-merge run didn't.

## Why the PR run was green but main was red

Rust's test runner orders tests alphabetically within a module and runs multiple modules' tests concurrently. Exact interleaving depends on thread scheduling, which differs between runs. On the PR branch CI run 24383270060, `detect_live_pid_but_missing_socket_is_stale` happened to run **before** my env-polluting tests. On the post-merge main CI run 24383429708, it ran **after**. Same code, same runner, different order.

This is the textbook "passes-on-PR-fails-on-main" pattern that makes env-based test overrides dangerous.

## Fix

PR #114 reduced the affected tests to `#[cfg(target_os = "macos")]`. On macOS, `pid_file_path` honors `base_dir` directly without any env-var indirection, so the TempDir isolation actually works. Losing Linux + Windows coverage for these two tests is a small cost — the corrupt / dead PID logic is platform-agnostic, only the path resolution is platform-specific, and path resolution has its own dedicated tests (`pid_file_path_includes_filename`, `macos_paths_under_base_dir`, `linux_prefers_xdg_runtime_dir`, etc.).

## Lessons

- **`std::env::set_var` is radioactive in tests.** If you find yourself reaching for it to mock a config path, stop and ask: can I pass the path as an argument instead? Can I gate the test to a platform where the function doesn't read env?
- **Env-override test patterns "work" until another test happens to read the same var.** The existing `detect_missing_pid_file_is_not_running` had been silently flaky for the same reason — it just hadn't surfaced because its assertion (`NotRunning`) tolerated both the intended and the polluted state.
- **"Passes on PR, fails on main" is almost always a test-ordering bug.** GitHub Actions runs PR CI on a separate workflow trigger from main CI; the two runs can execute tests in different orders due to thread scheduling.
- **Guard-struct env overrides (save/restore on Drop) are still unsafe under parallelism** — the window between `set_var` and `Drop` is long enough for another thread to read the polluted value. The only safe fix is to avoid the mutation.

## Safer patterns for future tests that need config paths

1. **Take the path as a function argument**, not an env var. Refactor production code if needed.
2. **Gate platform-specific env-reading tests to platforms where the env isn't used** (what #114 does).
3. **Use a static `Mutex`** to serialize ALL tests in the binary that touch the env var. Note: this requires every reader to also acquire the lock, which is easy to forget and hard to lint for.
4. **Use a crate like `temp-env`** that serializes env mutations via an internal mutex. Still not truly safe under parallelism because other tests without the crate's mutex can still race.
5. **`cargo test -- --test-threads=1`** disables parallelism entirely. Too blunt for a large suite.

## Artifacts

- PR #113 — initial fix + env-override pattern (the broken approach)
- PR #114 — `fix(detect): gate corrupt/dead-pid tests to macOS only`
- `csq-core/src/daemon/detect.rs` — the three tests that touched `pid_file_path` + env
- Run 24383429708 — post-merge main run that exposed the pollution
- Run 24384325249 — post-#114 main run, all 6 jobs green
