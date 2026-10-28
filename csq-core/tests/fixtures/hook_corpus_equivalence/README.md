# Hook comparison instrument

The default integration suite executes synthetic process controls to test the
instrument. These helpers are not product hooks, and their success does not
qualify the undelivered 344 corpus, native activation, effects or Gate execution.

Run a **trusted**, independently reviewed owner corpus explicitly:

```sh
CSQ_HOOK_EQUIVALENCE_CORPUS=/absolute/path/corpus.json \
CSQ_HOOK_EQUIVALENCE_SHA256=<independently supplied SHA256 of exact manifest bytes> \
trestle run -- cargo test -p csq-core --features test-utils \
  --test hook_corpus_equivalence -- --ignored \
  --exact supplied_corpus_matches_frozen_oracle --nocapture
```

The supplied path must be present in the selected trestle snapshot/runtime.
This runner executes owner-described programs; `env_clear`, temporary HOME,
cwd/config/base roots and process groups are isolation mechanics, not a security
sandbox. Do not supply untrusted executable content. POSIX supervision is the
supported on Linux and macOS. Required effect/platform profiles retain their case
denominator as unsupported, perform zero calls and cannot pass comparison.

Comparison-manifest version 1 is an instrument input, not the emitter's hook registry:

```json
{
  "format": 1,
  "release": "owner-release",
  "source_revision": "immutable owner source identity",
  "profile": "verdict_output_v1",
  "files": [{"path": "adapter.js", "sha256": "64 lowercase hex chars"}],
  "cases": [{
    "id": "owner-stable-case-id",
    "stdin": "exact payload bytes represented as a JSON string",
    "timeout_ms": 1000,
    "initial_files": {"seed.txt": "identical initial bytes"},
    "standalone": {
      "program": "/absolute/path/to/runtime",
      "program_sha256": "64 lowercase hex chars",
      "args": ["${CORPUS_ROOT}/adapter.js", "standalone", "${CASE_ROOT}"]
    },
    "dispatched": {
      "program": "/absolute/path/to/runtime",
      "program_sha256": "64 lowercase hex chars",
      "args": ["${CORPUS_ROOT}/adapter.js", "dispatched", "${CASE_ROOT}"]
    },
    "expected": {
      "exit_code": 0,
      "observation": {"decision": "deny", "context": [], "rewrite": null},
      "stderr": ""
    }
  }]
}
```

Each adapter must invoke its actual standalone/dispatcher entrypoint and emit
exactly one JSON observation (allow, deny, continue, advisory, refuse_handback or
incomplete), ordered context, optional rewrite, and expected stderr/exit status.
Adapter event projection and the oracle must be independently reviewed before
execution. Both arms matching each other while violating the oracle is a failure.
The runner does not discover completeness, dependency closure, event semantics
or effects. Owner-declared files are hashed and copied into a frozen snapshot;
`${CORPUS_ROOT}` names an independent arm copy of that snapshot, `${CASE_ROOT}`
the independent arm fixture. One arm's source/fixture changes cannot alter the other.
Only plain relative fixture paths are allowed. `PATH` is an empty directory;
owner commands must explicitly bind every runtime/helper they need. File copies
are data files; invoke scripts through the pinned interpreter rather than relying
on executable modes. Program hashing occurs before spawn, not fd-exec attestation.

Manifest is capped at 4 MiB; declared source closure at 64 MiB; stdin/stdout/stderr at 8192 bytes each; every case has
a 1–5000 ms IO deadline. The supplied population must be nonempty and unique.
Output overflow, timeout, missing program, malformed/duplicate/unknown verdict,
pin mismatch or missing arm is a failure/incomplete capture, never a runtime skip.
Raw stdout/stderr bytes, status, elapsed time, platform, invocation and a compiled
model/runner source digest are retained in the JSON report.
Coverage (`attempted/completed/unsupported` over `required`) and independent
oracle/differential counts are separate. `full_corpus_qualified` stays false:
future effect observers and owner inventory reconciliation are required for the
broader design in `internal-design-docs`.

`attempted_invocations` counts execution-arm calls including pre-spawn errors;
`spawned_invocations` counts actual process starts. Duplicate JSON object keys
are rejected recursively, including nested rewrite objects and fixture maps.
Keep the supplied corpus secret-free: raw capture reports go to test stdout.

The supervisor observes exit with `waitid(WNOWAIT)` and retains the unreaped
leader identity until any group signal. It never sends a group signal after
reaping. Normal EOF completion reaps without signaling. Inherited pipes after
leader exit require cleanup and yield `forced_cleanup`, an incomplete capture;
`forced_cleanup` records a requested group signal, not proof of containment.
Cleanup retries interrupted wait observations, also signals the verified unreaped
direct child by PID if it changes groups, and polls exit for a bounded 250 ms
grace. It calls blocking `wait` only after exit was observed with `WNOWAIT`.
Unconfirmed cleanup reports `cleanup_unknown` and cannot pass comparison.
