# csq — Authoritative Specs Index

Source of truth for the Code Squad Q (csq) implementation. Detailed specs govern architecture, invariants, and contracts. When an implementation contradicts a spec in this directory, **the spec wins** — reconcile by updating the offender, not the spec.

Specs here are:

- **Normative.** They define what the code MUST do.
- **Anchored in upstream behavior.** Whenever a spec depends on Claude Code CLI behavior, it describes that published behavior.
- **Immutable in history.** Revisions are additive: a new version supersedes an old one.

## Detailed Specifications

| #   | Document                                                                        | Governs                                                                                                                                                                                                                              |
| --- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 00  | [Manifest](00-manifest.md)                                                      | Product scope, goals, non-goals, invariants summary                                                                                                                                                                                  |
| 01  | [Claude Code Credential Architecture](01-cc-credential-architecture.md)         | How CC reads, writes, caches, and invalidates OAuth credentials                                                                                                                                                                      |
| 02  | [csq Handle-Dir Model](02-csq-handle-dir-model.md)                              | Per-account `config-N` + per-terminal `term-<pid>` handle dirs with symlinks; swap semantics; lifecycle                                                                                                                              |
| 03  | [csq Session Lifecycle](03-csq-session-lifecycle.md)                            | `csq run`, `csq swap`, `csq login`, `csq exit` — what each does, what they must not do                                                                                                                                               |
| 04  | [csq Daemon Architecture](04-csq-daemon-architecture.md)                        | Daemon subsystems, IPC surface, refresh + fanout, usage poller, supervisor                                                                                                                                                           |
| 05  | [Quota Polling Contracts](05-quota-polling-contracts.md)                        | Anthropic `/api/oauth/usage`, 3P provider probes, poll cadence, backoff                                                                                                                                                              |
| 06  | [Keychain Integration](06-keychain-integration.md)                              | macOS service name derivation, write path, TTL, Linux/Windows fallback                                                                                                                                                               |
| 07  | [Provider Surface Dispatch](07-provider-surface-dispatch.md)                    | Surface enum, per-surface on-disk layout, spawn/login/quota/model-config dispatch, cross-surface swap                                                                                                                                |
| 09  | [Unified `.coc/` Artifact Standard](09-unified-coc-artifact-standard.md)        | csq-side consumer contract for `.coc/`: directory shape, frontmatter, fallback chain, version envelope, read-only invariant                                                                                                          |
| 11  | [Probe-Driven Verification](11-probe-driven-verification.md)                    | Operator-run live-wire `(provider × auth-mode)` contract verification; `csq probe` surface; pre-tag gate                                                                                                                             |
| 12  | [Audit Trail](12-audit-trail.md)                                                | Per-`csq run` JSONL audit-record schema, hash-linked + locally-signed chain, single-write-site invariant, IPC emit + drain                                                                                                           |
| 13  | [Multi-CLI Detection Contract](13-multi-cli-detection-contract.md)              | Detection, version gating, install/upgrade dispatch for claude/codex/gemini binaries; doctor + login/run pre-flight                                                                                                                  |
| 14  | [Release Artifact Contract](14-release-artifact-contract.md)                    | Platforms published per release, `latest.json` schema, universal-binary invariant, signing, artifact backstops                                                                                                                       |
| 15  | [LedgerSink Trait and Reference-Impl Catalog](15-ledgersink-trait-and-sinks.md) | `LedgerSink` trait, cfg-gating discipline, reference-impl catalog (Rekor/S3/Azure/GCP/csq-ledger), operator config, conformance harness, `csq doctor` surface                                                                        |
| 16  | [Audit Export Bundle](16-audit-export-bundle.md)                                | `csq audit export` verifiable-bundle producer — bundle shape, `BUNDLE.lock`/`BUNDLE.sig` discipline, embedded stdlib-only `verify` script (pure-Python Ed25519), canonical-form vectors, cross-org verifiability                     |
| 17  | [csq-ledger Transparency-Log Protocol](17-csq-ledger-protocol.md)               | Foundation-owned transparency-log server: HTTP routes, RFC 6962 inclusion/consistency proofs, signed checkpoint contract, fsync-before-200 + storage-no-delete invariants, WORM-storage threat model, Docker deploy, `CsqLedgerSink` |

## How to use

- **Before implementing a feature**, read the spec that governs it. Cite the spec's section in the PR description.
- **Before modifying credential-handling code** (credentials, keychain, OAuth), re-read `01-cc-credential-architecture.md` and `02-csq-handle-dir-model.md`.

## Versioning

Each spec file has a `Spec version` header. Breaking changes bump the version. Minor clarifications append a `## Revisions` section.
