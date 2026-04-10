---
type: DISCOVERY
date: 2026-04-10
created_at: 2026-04-10T17:00:00Z
author: agent
session_id: m87c-m86-c5-security-debt
session_turn: 45
project: csq-v2
topic: macOS `security add-generic-password -w -` does not read from stdin
phase: implement
tags: [security, macos, keychain, c2, credentials]
---

# DISCOVERY: macOS `security -w -` stores literal "-", does not read stdin

## Context

C2 from the PR #39 red team flagged that `security add-generic-password`
passes the hex-encoded credential payload via the `-w` command-line
argument, making it visible to any user via `ps aux` for the duration
of the `security` process (~100ms).

The session notes said: "Requires switching from `security` CLI
subprocess to `security-framework` crate."

During this session, I attempted the simpler fix first: use `-w -` as
the password argument, on the hypothesis that macOS `security` would
read from stdin (as many Unix tools do with the `-` convention).

## Finding

macOS `security add-generic-password -w -` does **not** read the
password from stdin. It literally stores the single-character string
`-` as the keychain password.

Verified empirically:

```bash
$ echo -n "test-value-via-stdin" | security add-generic-password -U -s "csq-c2-test" -a "test" -w -
$ security find-generic-password -s "csq-c2-test" -a "test" -w
-
```

The stored password is `-`, not `test-value-via-stdin`. The macOS
`security` CLI has no stdin-piping mode for password data.

## Implications

1. **C2 cannot be fixed without a dependency change.** The only
   approaches that eliminate argv exposure are:
   - **`security-framework` crate** (Rust bindings to the native
     Security.framework API). Calls `SecKeychainAddGenericPassword`
     directly — no subprocess, no `ps` exposure, no timeout
     polling. This is the right fix.
   - **`keyring` crate** (cross-platform, uses security-framework
     internally on macOS). Higher-level, also correct.
2. **The risk under the same-UID threat model is low.** Any
   process running as the same UID can already read
   `credentials/N.json` (0600 permissions). The `ps` vector only
   adds cross-UID exposure on shared systems with fast-user-
   switching, which is a narrow scenario for a developer tool.
3. **The hex encoding is defense-in-depth.** The `ps` output shows
   hex-encoded JSON, not raw credentials. An attacker needs to
   decode the hex AND parse the JSON to extract the token. This
   doesn't prevent extraction, but it does prevent casual
   shoulder-surfing of the `ps` output.

## Decision

C2 remains deferred. The fix is tracked but does not justify
blocking this session's other work. When `security-framework` is
added (likely alongside the keyring refactor for Linux/Windows
parity), the entire `run_security_command` subprocess approach
should be replaced with native API calls.

## For Discussion

1. **Evidence check** — the `security-framework` crate's
   `add_generic_password` function takes the password as a `&[u8]`
   parameter passed to `SecKeychainAddGenericPassword`. Does that
   API guarantee the bytes never appear in a system log or
   sysdiagnose bundle? The native API is better than argv, but
   "never visible anywhere" is a stronger claim.
2. **Counterfactual** — if macOS `security` HAD supported `-w -`
   (stdin piping), would that have been sufficient, or would we
   still want the native API for robustness (no subprocess
   timeout, no process spawn overhead, no PATH dependency)?
3. **Scope question** — adding `security-framework` as a
   dependency specifically for keychain writes changes the
   project's dependency surface. Is the cross-UID `ps` exposure
   narrow enough that the dependency cost outweighs the security
   gain, or is this a "fix it because it's the right thing"
   situation regardless of threat model probability?
