---
type: DISCOVERY
date: 2026-04-22
created_at: 2026-04-22T05:46:00Z
author: co-authored
session_id: 2026-04-22-codex-pr-c00
session_turn: 18
project: codex
topic: OPEN-C03 RESOLVED — std::fs::remove_dir_all on modern Rust does not follow symlinks; the Codex sessions/ symlink in handle-dir model is safe against the sweep
phase: analyze
tags: [codex, sweep, symlink-safety, OPEN-C03, pr-c00]
---

# Discovery — OPEN-C03: `remove_dir_all` symlink-safe on APFS in current Rust

## Context

`workspaces/codex/02-plans/01-implementation-plan.md` lists OPEN-C03 as a PR-gating precondition. The concern: the `Surface::Codex` handle-dir layout (spec 07 §7.2.3.1) includes `term-<pid>/sessions → config-<N>/codex-sessions/` as a symlink. When csq's `sweep_dead_handles` removes a dead handle dir via `std::fs::remove_dir_all(handle_dir)`, if the implementation follows the symlink, it would walk into `config-<N>/codex-sessions/` and delete the user's actual session rollouts — a destructive data-loss regression.

This is the same class as CVE-2022-21658 (Rust's pre-1.58 `remove_dir_all` TOCTOU race that allowed attackers to delete files outside the target directory). The fix in Rust 1.58 switched to file-descriptor-based operations that do not follow symlinks.

## Probe

Environment: macOS 25.3.0 (Darwin, APFS), Rust toolchain shipped with Xcode / Homebrew.

Minimal reproducer compiled and run as a standalone binary:

```rust
use std::fs;
use std::os::unix::fs::symlink;
fn main() {
    let tmp = std::env::temp_dir().join("csq-sweep-probe");
    let sensitive_dir = tmp.join("sensitive-sessions");
    fs::create_dir_all(&sensitive_dir).unwrap();
    let sentinel = sensitive_dir.join("sentinel.txt");
    fs::write(&sentinel, b"MUST_SURVIVE").unwrap();
    let handle_dir = tmp.join("term-pid");
    fs::create_dir_all(&handle_dir).unwrap();
    symlink(&sensitive_dir, handle_dir.join("sessions")).unwrap();
    println!("before: sentinel exists = {}", sentinel.exists());
    fs::remove_dir_all(&handle_dir).unwrap();
    println!("after:  sentinel exists = {}", sentinel.exists());
    println!("after:  handle_dir exists = {}", handle_dir.exists());
    println!("after:  sensitive_dir exists = {}", sensitive_dir.exists());
}
```

Output:

```
before: sentinel exists = true
after:  sentinel exists = true
after:  handle_dir exists = false
after:  sensitive_dir exists = true
```

Kernel: `Darwin Kernel Version 25.3.0: xnu-12377.91.3~2/RELEASE_ARM64_T6041 arm64`.

The sentinel inside `sensitive_dir` survived. `remove_dir_all(handle_dir)` removed only the symlink — not the target.

## Discovery

`std::fs::remove_dir_all` on macOS 25.x (APFS) with modern Rust does NOT follow symlinks. The symlink `handle_dir/sessions → sensitive_dir/` is unlinked (the link itself) without descending into the target directory. This matches the post-CVE-2022-21658 contract enforced since Rust 1.58.

csq-core already has regression tests for the equivalent case on the Claude Code image-cache symlink — `csq-core/src/session/handle_dir.rs` test `sweep_handles_image_cache_symlink` (line 2180) plants `term-<pid>/image-cache → /path/to/sensitive/dir` and asserts the sensitive dir survives the sweep. That test exercises the same property on the same codebase, reinforcing this finding.

## Why this matters

1. **Codex `sessions/` symlink is safe in the handle-dir model.** PR-C3 can link `term-<pid>/sessions → config-<N>/codex-sessions/` with the confidence that sweep removes the link, not the target.

2. **No need for an explicit `unlink` pass before `remove_dir_all` in PR-C3.** Earlier drafts of the plan considered manually unlinking every symlink before the directory removal to defend against historic Rust behavior; this is unnecessary on modern Rust.

3. **The existing image-cache regression test IS the regression test for Codex.** Adding a second near-identical test for `sessions/` symlink is low-value duplication. PR-C0's `tests/integration_codex_sweep.rs` should instead exercise a Codex-specific edge case: e.g. a broken symlink (target already deleted), a symlink-to-symlink chain, or a symlink pointing at a path outside the account tree.

4. **ext4 expectation (Linux): same behavior.** Rust's `remove_dir_all` is implemented identically across Unix filesystems at the `openat`/`unlinkat`/`AT_REMOVEDIR` level; APFS vs ext4 difference is below the abstraction boundary. Not empirically verified here but extremely low risk.

## Limits of this probe

- **Current Rust release.** If the Rust stdlib ever regressed `remove_dir_all` to follow symlinks, this finding would invert. MSRV regression tests guard against this — csq's existing symlink tests fail instantly on such a regression.
- **macOS / APFS only.** Linux ext4 behavior inferred from Rust's std implementation, not empirically confirmed. Windows has a different path (no symlinks by default; junction points are a separate concern for PR-C1b).
- **Did not test symlink-to-symlink.** If a user's `config-<N>/codex-sessions` is itself a symlink (unusual but possible on enterprise machines with NFS mounts), the two-hop behavior is untested.

## Decision impact

- **Spec 07 §7.7.3 status flip.** OPEN-C03 → RESOLVED POSITIVE with citation to this journal.
- **PR-C0's `tests/integration_codex_sweep.rs` scope refined.** Test the Codex-specific edge cases (broken symlink, symlink-to-symlink) rather than re-proving the already-tested "basic symlink survival" case.
- **Plan §PR-C3 unblocked.** Handle-dir layout per spec 07 §7.2.3.1 (Codex) is safe to implement.

## For Discussion

1. **Should PR-C0's integration test run on Linux CI (ext4) as well as macOS (APFS)?** GitHub Actions runs `ubuntu-latest` which is ext4 — adding an identical test in that job is nearly free and closes the empirical-gap on the "inferred" half of this finding.

2. **The existing image-cache test was written to defend against a specific attack scenario (malicious symlink pointing at user credentials). Does the Codex case have an analogous adversarial framing, or is the concern purely "accidental data loss"?** The framing affects what the integration test asserts — adversarial tests exercise worst-case paths; accidental-loss tests check the happy path more thoroughly.

3. **If Rust ever regressed `remove_dir_all` — say a future MSRV pins a pre-1.58 version due to a toolchain rollback — how quickly would csq's test suite catch it?** The existing image-cache test catches it on the first CI run after the rollback, but the rollback's window-of-exposure (from MSRV pin to next CI run) could still ship a broken release. Hypothesis: not worth a dedicated defense beyond the test.

## Cross-references

- `csq-core/src/session/handle_dir.rs` — existing sweep code + regression tests for image-cache symlink (lines 2180, 2216)
- CVE-2022-21658 — Rust `remove_dir_all` TOCTOU fixed in 1.58
- Spec 07 §7.2.3.1 (Codex handle-dir) + §7.7.3 (OPEN-C03 status flipped by PR-C00)
- PR-C0 (code) — `tests/integration_codex_sweep.rs` scope refined per this journal
- Kernel: `Darwin 25.3.0` (Jan 2026 release)
