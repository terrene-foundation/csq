# M1: Platform Abstraction Layer

Priority: P0 (Launch Blocker)
Effort: 2 autonomous sessions
Dependencies: M0 complete
Phase: 1, Stream A

---

## M1-01: Build platform detection module

Compile-time platform detection via `cfg(target_os)`. Constants: `IS_MACOS`, `IS_LINUX`, `IS_WINDOWS`. Platform-conditional module imports.

- Scope: 1.1-1.2
- Complexity: Trivial
- Acceptance:
  - [x] `Platform::current()` returns correct variant
  - [x] `cfg` gates compile on all targets

## M1-02: Build secure file permissions

`secure_file(path)` — sets `0o600` on Unix, no-op on Windows. Uses `std::fs::set_permissions`.

- Scope: 1.5
- Complexity: Trivial
- Acceptance:
  - [x] Unix: file mode is `0o600` after call
  - [x] Windows: no error, no-op

## M1-03: Build atomic file replace

`atomic_replace(tmp, target)` — `std::fs::rename` on Unix. On Windows: retry loop (5 attempts, 100ms delay) for file-in-use conflicts using `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`.

- Scope: 1.6
- Complexity: Moderate
- Acceptance:
  - [x] Concurrent writers (10 threads, 100 writes each): no corruption
  - [x] Windows: locked file retries succeed within 500ms

## M1-04: Build POSIX file locking

`lock_file(path)` — blocking via `flock(LOCK_EX)`. `try_lock_file(path)` — non-blocking via `flock(LOCK_EX | LOCK_NB)`, returns `None` if held. `unlock_file(fd)` — `flock(LOCK_UN)`.

- Scope: 1.7-1.8, 1.11
- Complexity: Moderate
- Acceptance:
  - [x] Two processes: one holds lock, other's try_lock returns None
  - [x] Lock released on drop (RAII guard)

## M1-05: Build Windows named mutex locking

`lock_file(name)` — `CreateMutexW` + `WaitForSingleObject(INFINITE)`. `try_lock_file(name)` — `WaitForSingleObject(0)`. Handle `WAIT_ABANDONED` as "acquired with warning" per GAP-8 resolution. RAII guard calls `ReleaseMutex` on drop.

- Scope: 1.9-1.10, 1.11, GAP-8
- Complexity: Complex
- Acceptance:
  - [ ] Mutex acquired, released on drop
  - [ ] WAIT_ABANDONED: acquired + warning logged
  - [ ] WAIT_TIMEOUT: returns None
  - [ ] Windows CI runner passes

## M1-06: Build POSIX process detection

`is_pid_alive(pid)` — `kill(pid, 0)`. `find_cc_pid()` — walk parent process tree via `/proc/{pid}/status` (Linux) or `sysctl` (macOS), up to 20 levels. `is_cc_command(cmd)` — pattern match on "claude" binary name.

- Scope: 1.12, 1.14, 1.16
- Complexity: Complex
- Acceptance:
  - [x] Own PID: alive. PID 99999999: dead
  - [x] Spawn mock process tree: correct CC PID found
  - [x] "node /usr/local/bin/claude" → true, "/bin/bash" → false

## M1-07: Build Windows process detection

`is_pid_alive(pid)` — `OpenProcess` + `GetExitCodeProcess`. `find_cc_pid()` — `CreateToolhelp32Snapshot`, build PID-to-parent map, walk parent chain.

- Scope: 1.13, 1.15, 1.17
- Complexity: Complex
- Acceptance:
  - [ ] Windows CI: own PID alive, dead PID returns false
  - [ ] Process tree walk finds correct parent

## M1-08: Integration tests for platform layer

Cross-platform integration tests: concurrent file locking, atomic writes under contention, process lifecycle (spawn, detect, kill, verify gone).

- Scope: Phase 1 test strategy
- Complexity: Moderate
- Acceptance:
  - [x] All platform tests pass on macOS, Linux, Windows CI
  - [x] > 90% line coverage on `platform/`
