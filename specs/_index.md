# csq — Authoritative Specs Index

Source of truth for the Code Session Quota (csq) implementation. Detailed specs govern architecture, invariants, and contracts. When an implementation, rule, journal entry, or todo contradicts a spec in this directory, **the spec wins** — reconcile by updating the offender, not the spec.

Specs here are:

- **Normative.** They define what the code MUST do.
- **Anchored in upstream source.** Whenever a spec depends on Claude Code CLI behavior, it cites `~/repos/contrib/claude-code-source-code` with `file:line`.
- **Immutable in history.** Revisions are additive: a new version supersedes an old one, the old one is kept and marked superseded.

Workspace artifacts (`workspaces/csq-v2/journal`, `workspaces/csq-v2/todos`) are working material. Rules (`.claude/rules/`) are enforcement policy derived from these specs. If a spec is wrong, it's the first thing to fix — everything downstream follows.

## Detailed Specifications

| #   | Document                                                                | Governs                                                                                                 |
| --- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| 00  | [Manifest](00-manifest.md)                                              | Product scope, goals, non-goals, invariants summary                                                     |
| 01  | [Claude Code Credential Architecture](01-cc-credential-architecture.md) | How CC reads, writes, caches, and invalidates OAuth credentials — derived from CC source                |
| 02  | [csq Handle-Dir Model](02-csq-handle-dir-model.md)                      | Per-account `config-N` + per-terminal `term-<pid>` handle dirs with symlinks; swap semantics; lifecycle |
| 03  | [csq Session Lifecycle](03-csq-session-lifecycle.md)                    | `csq run`, `csq swap`, `csq login`, `csq exit` — what each does, what they must not do                  |
| 04  | [csq Daemon Architecture](04-csq-daemon-architecture.md)                | Daemon subsystems, IPC surface, refresh + fanout, usage poller, supervisor                              |
| 05  | [Quota Polling Contracts](05-quota-polling-contracts.md)                | Anthropic `/api/oauth/usage`, 3P provider probes, poll cadence, backoff                                 |
| 06  | [Keychain Integration](06-keychain-integration.md)                      | macOS service name derivation, write path, 30s TTL, Linux/Windows fallback                              |
| 07  | [Provider Surface Dispatch](07-provider-surface-dispatch.md)            | Surface enum, per-surface on-disk layout, spawn/login/quota/model-config dispatch, cross-surface swap   |

## How to use

- **Before implementing a feature**, read the spec that governs it. Cite the spec's section in the PR description.
- **Before writing a new rule in `.claude/rules/`**, check that it does not contradict a spec. If it does, either update the spec (with retraction journal) or reject the rule.
- **Before codifying a journal entry into a rule**, check the rule against the spec. Journal 0029 Finding 4 ("CC caches credentials at startup") is the canonical example of a finding that contradicted spec and was retracted.
- **Before modifying CC-adjacent code** (credential handling, keychain, OAuth), re-read `01-cc-credential-architecture.md` and cross-check against the cited CC source files. If CC has changed upstream, update the spec first.

## Versioning

Each spec file has a `Spec version` header. Breaking changes bump the version. Minor clarifications append a `## Revisions` section. Retracted specs are NOT deleted — they are renamed to `NN-{topic}-v1-SUPERSEDED.md` and kept for history.
