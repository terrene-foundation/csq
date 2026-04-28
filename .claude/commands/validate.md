---
name: validate
description: "Pre-merge gate: cargo check + clippy + fmt + tests + svelte-check + vitest + stub scan. Halt on first failure."
---

Run the full pre-merge validation gate. Halts on first failure with the actual command output. No silent recovery — any failure is owned and fixed in this session per `rules/zero-tolerance.md` Rule 1.

| Command              | Action                                                                               |
| -------------------- | ------------------------------------------------------------------------------------ |
| `/validate`          | Full gate: format check + clippy + check + tests + svelte-check + vitest + stub scan |
| `/validate rust`     | Rust-only: fmt check + clippy + cargo check + cargo test                             |
| `/validate frontend` | Frontend-only: svelte-check + tsc + vitest                                           |
| `/validate stubs`    | Stub/TODO/FIXME scan only — surface anything `rules/no-stubs.md` blocks              |
| `/validate security` | Hand off to `security-reviewer` for credential, OAuth, IPC, atomic-write audit       |

## Default workflow (each step halts on failure)

### Step 1: Rust formatting

```bash
cargo fmt --all -- --check
```

Drift here means a contributor skipped `cargo fmt` before commit. Fix: run `cargo fmt --all` and commit the diff separately.

### Step 2: Rust clippy (deny warnings)

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Treats every clippy warning as an error. Per `rules/zero-tolerance.md` Rule 1, pre-existing warnings are fixed in this session, not deferred.

### Step 3: Rust type check

```bash
cargo check --workspace --all-targets
```

Catches type errors faster than `cargo test`. Useful when iterating.

### Step 4: Rust tests

```bash
cargo test --workspace --all-targets
```

Includes integration tests in `csq-core/tests/`. Live OAuth tests (`oauth_race_live.rs`) are `#[ignore]`d and not run here — see `/test live` for those.

### Step 5: Svelte + TypeScript check

```bash
cd csq-desktop && npm run check
```

Runs `svelte-check --tsconfig ./tsconfig.app.json && tsc -p tsconfig.node.json`. Type errors here are real bugs (Svelte 5's `$state` proxying surfaces type mismatches that runtime would only catch under specific reactive triggers).

### Step 6: Svelte vitest

```bash
cd csq-desktop && npx vitest run
```

Component tests under `csq-desktop/src/lib/__tests__/`.

### Step 7: Stub scan

```bash
grep -rEn 'TODO|FIXME|HACK|XXX|todo!\(\)|unimplemented!\(\)|panic!\("not yet' \
  --include='*.rs' --include='*.ts' --include='*.svelte' --include='*.js' \
  --exclude-dir=node_modules --exclude-dir=target \
  csq-core csq-cli csq-desktop/src csq-desktop/src-tauri/src 2>/dev/null
```

Any hit is BLOCKED by `rules/no-stubs.md` and `rules/zero-tolerance.md` Rule 2. The PostToolUse hook `validate-workflow.js` also blocks stubs at write time, but the gate scan catches anything that slipped past.

### Step 8: Capability narrowing audit (security-adjacent)

```bash
grep -Eh '"[a-z-]+:default"' csq-desktop/src-tauri/capabilities/*.json
```

Per `rules/tauri-commands.md` § "Permission Grant Shape — Narrow by default": every `<plugin>:default` grant MUST be either narrowed to specific sub-permissions or have an inline comment listing every sub-permission it loads. Each match here needs justification.

## Convergence

Validation passes when:

1. All steps exit 0.
2. Stub scan returns empty.
3. Capability scan returns empty OR every match has the required justification comment.

Any failure: diagnose root cause, fix in same session, re-run from Step 1. Per `rules/zero-tolerance.md`, "pre-existing failure" is not a deferral category.

## Agent Teams

- **rust-specialist** — clippy/check failures, ownership and lifetime issues.
- **svelte-specialist** — svelte-check failures, runes patterns, $effect cycles.
- **rust-desktop-specialist** — Tauri command type errors, IPC type mismatches.
- **build-fix** — linker errors, FFI mismatches (minimum-change fixes).
- **security-reviewer** — required for the `/validate security` subcommand and any OAuth/credential touch.
- **gold-standards-validator** — Foundation naming, license accuracy, terminology compliance.

## Cross-References

- `rules/zero-tolerance.md` — pre-existing failures are fixed in-session
- `rules/no-stubs.md` — blocked patterns enumerated
- `rules/tauri-commands.md` — capability narrowing rule
- `rules/git.md` — pre-commit checklist
- `/test` — runs the test surface alone (no clippy/fmt/check)
