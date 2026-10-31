# Proof instrument support

These Python 3.11+ helpers prepare and check proof instruments. Instrument
readiness, complete artifact transport, and a successful product control are
separate results. The helpers do not dispatch fleet jobs or authorize controls.

## Source and mutation binding

Start with a full frozen commit, tree, and SHA-256 map for the source files.
`proof_support.render_manifest` fills each selected edit's complete metadata
from those frozen bytes. Missing hashes, ambiguous match counts, inert edits,
and changed source bytes are unavailable observations.

`proof_git` resolves and pins a vetted absolute Git executable.
Every Git observation, clone and checkout uses its argv/environment builders.
They discard ambient `GIT_*`, developer-tool and dynamic-loader overrides, use
an empty private Git HOME/XDG directory, disable system/global config and global
ignore/attributes/hooks files, and admit only an explicitly supplied private
index path. Git is resolved lazily, version-gated to at least 2.32, and pinned;
on Darwin the real executable is resolved through scrubbed `xcrun --find git`.
The process-owned Git HOME lease is cleaned at normal process exit; this does
not promise cleanup after SIGKILL. Mutation
targets must occur in both the scrubbed index inventory and the frozen HEAD
tree. A `.git`, `.cargo` or `target` path component is always forbidden,
including case variants, before any file write.

Create a control with `external_control(source, commit, tree,
target_roots=roots)`. Its context yields a live `OwnedLeg` and the external
checkout at `leg.child("source")`. Pass both that checkout and the same lease
to `preflight_manifest`. It validates every case before writing, applies the
actual final edit metadata, observes its materialized tree using an external
Git index, restores the original bytes and modes, and checks the source again.
The shipping checkout is not a permitted preflight mutation target.
The lower-level `applied_edits(..., owned_leg=leg)` and `preflight_edits` APIs
enforce that same live lease/root relationship themselves. Omitting authority
raises `ProofUnavailable`; it never implicitly authorizes a mutation.

`scripts/verify/proof-preflight.py` exposes this preparation as a CLI with
`--source`, `--manifest`, and `--output`. The output must be a new file outside
the checkout and its Cargo targets. Exit 0 reports
`INSTRUMENT_READY_NOT_PRODUCT_PASS`; unavailable preparation exits 2. Existing
receipt files are never overwritten.

## External ownership

Collect Cargo roots with `cargo_target_roots`. Discovery retains the default
target, environment paths, Cargo configuration paths and symlink aliases.
`target-dir` and `build-dir` are collected from configs and environment.
Paths are based the way Cargo bases them. Relative environment values and a
relative `CARGO_HOME` depend on Cargo's working directory, which is unknown
here, so both the invoking directory and the repo root are kept as bases.
Config values are based on the directory above the config's directory as
written, so a symlinked `.cargo` or `CARGO_HOME` does not move the base. A
config directly under `CARGO_HOME` is standard whatever that directory is
named. A target or build directory containing `{` (a template) and a config
using `include` are refused.
Callers must also supply the actual metadata target or extra roots when the
Cargo invocation uses additional configuration overrides. A name or prefix
does not exempt a scaffold from this boundary.

All control clones, helper carriers, temporary indexes, proof output, and test
HOME/TMP/base directories belong in external owned legs. Temporary Git indexes
are allocated through `owned_leg.child(...)`, after verifying the live lease.
Cargo build artifacts continue to use Cargo's normal target selection.
`private_environment` creates an empty private Cargo home and replaces test
HOME; it does not expose the original Cargo credentials or config and never
sets `CARGO_TARGET_DIR`. It refuses an actual working directory under the
original HOME, including identity aliases, because replacing HOME does not
stop Cargo from walking ancestor configuration. Fixture preparation and
execution use the external owned directory. `PKG_CONFIG_PATH` is dropped.
Credential-free offline cache provisioning is not implemented by these helpers;
no Cargo proof adapter is dispatchable today. The receipt checker refuses
Cargo-adapter dispatch instead of treating an empty-cache Cargo exit as a
measured product failure. Ordinary source feature-check logs are a separate
command-checking surface.

The child PATH consists of its private bin and the fixed system directories
`/usr/bin:/bin:/usr/sbin:/sbin`, never inherited PATH or user-writable Homebrew
bin directories. Where a trusted existing Rustup executable is
available, private bin contains pinned absolute Rustup proxies for Cargo and
Rust tools. The original Rustup home remains available to those tools. Ambient
compiler executables and wrappers (`RUSTC`, `RUSTDOC`, `RUSTC_WRAPPER`, `CC`,
`CXX`, `AR`) are not inherited.

Use `OwnedLeg` as a context manager. Allocation and cleanup retain parent and
child UID/device/inode identities, private permissions, and directory handles.
Darwin's `/tmp` alias is resolved consistently. Replaced or unowned directories
are refused; this helper does not reclaim historical or shared cache entries.
The boundary is an invocation-private POSIX directory with a single writer and
point-in-time identity checks, not continuous protection against another process
exchanging entries under the same UID. Linux and Darwin fixtures cover this
boundary; the helpers do not establish native Windows behavior.

## Observation and transport

`proof_inventory` derives the selected native test inventory from successful,
complete `--list` output. Runtime scoring binds the exact source, platform,
edition, features, argv, required names, and explicit ignore policy. Missing,
clipped, inconsistent, or unreadable evidence stays `UNDETERMINED` (2), distinct
from a measured failure (1) and a measured pass (0).

`proof-command-run.py EXPECTED.json COMPLETE-RAW.log` checks source, command,
cleanup, and native terminal observations plus requested phase oracles. Command
markers attest labels; argv comes from the expected manifest. This check does
not by itself establish complete native test inventory coverage. Expected manifests
and wrapper markers share a per-run 128-bit nonce to distinguish accidental or
glued markers. The nonce is visible to a same-user child; it does not defend
against that child forging a marker. A measured PASS still requires the actual
native command exit 0. A timeout after COMMAND_EXIT is UNDETERMINED even if a
child emitted an earlier failure marker. The fixture driver reports measurement
uncertainty with native exit 2 and a nonce-bound `PROOF_FIXTURE_DRIVER` record
after cleanup; that record takes precedence over an earlier failure marker.
A genuine command/native exit 2 without the driver record remains a failure.

Strict libtest parsing requires explicit outcomes for every primary row. An
explicitly serial, non-exact invocation may opt into
`libtest.full_native_summary: true` to reconcile a complete primary frame after
its bound command exits 0. Unique primary names must equal the native selected
count; the positive summary must have zero failures and measured cases; and
explicit ignored rows must exactly match its ignored partition. Remaining rows
are inferred passed by that complete summary, with their inference basis
retained separately from direct outcomes. Nested helper sections cannot satisfy
primary required names. This mode also requires a successful earlier --list
observation from the same binary and filter, bound to the same source, platform,
edition, features and invocation, with an exact primary-row name set. Missing or
inconsistent listing evidence is UNDETERMINED. This mode does not evaluate
warning or panic prose or an isolated diagnostic oracle.

The bootstrap, bundle, and stdout helpers bind exact primitive and runtime
bytes, export complete raw artifacts with their digests, and observe external
cleanup. A decoder result of `TRANSPORT_COMPLETE_NOT_PRODUCT_PASS` can contain
an inner command failure. Callers must independently score the retained inner
observations. A finalized byte binding also requires review and explicit
authorization before any real product proof is dispatched.

Run the tracked fixture entrypoint through the normal offload wrapper:
`bash scripts/tests/proof-support.test.sh`. It resolves an absolute isolated
Python interpreter, checks source before allocation, and runs only synthetic
Python/Git fixtures. Explicit `--source-commit` and `--source-tree` flags bind a
frozen snapshot; omitted flags bind the observed checkout rather than an
independent release reference.

The wrapper compiles every tracked proof Python module after successful
fixtures by default; explicit `--pycompile` remains accepted. The compiler binds the original reference,
carried HEAD and frozen tree, and writes explicit cfiles into an external owned
leg. Its self-tests distinguish invalid syntax from unreadable inputs or cleanup
uncertainty. Shellcheck and the existing pipeline gate/self-test run separately
under the normal offload wrapper. Fixture timeouts start a dedicated process
group and terminate that group with TERM then KILL before reaping the leader.
The original timeout remains the reported uncertainty; cleanup failures are
recorded alongside it. Darwin permission refusals require positive nonreaping
leader-exit evidence and a complete kernel census containing only that leader.
The shared membership oracle also serves shell-tool preparation; unavailable
or incomplete evidence never confirms cleanup.
A child that deliberately escapes the process group is outside this contract.

Census parsing deliberately refuses a non-JSON line beginning with `{`. A
malformed or unrelated brace line cannot be silently skipped to recover a later
plausible census; that observation stays UNDETERMINED.

Full-summary input uses `libtest.inventory` with `command`, `binding`,
`binary_sha256`, and `allowed_ignored`. `command` names an earlier successful
listing phase. The runtime argv begins with the absolute native test-binary
path; the listing argv is exactly that same argv plus `--list`. Before native
output, both phases emit one `NATIVE_BINARY_SHA256 <sha256>` line and one
`NATIVE_BINDING <json>` line. The binding records `source_commit`, `source_tree`,
`platform`, `edition`, `features`, and `runtime_argv`; it must match in both
phases and the expected input. The receipt retains the listing's raw bytes and
digest. These markers record the trusted caller's execution observations; they
do not make arbitrary child stdout an independent execution authority.

Cargo proof adapters must identify their command with `adapter: "cargo"` and
are refused while their offline cache remains unprovisioned. Known adapter
entrypoint names are also refused. An arbitrary shell program's semantics
cannot be inferred from its name; omitting or concealing adapter classification
is outside the documented dispatch contract. These helpers authorize no such
dispatch.
