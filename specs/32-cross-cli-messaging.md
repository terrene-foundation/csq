# 32 — Cross-CLI Session Messaging

**Spec version:** 1.0.0
**Status:** active (first shipped in csq 2.21.0)

**Files.** Section numbers are shared across the pair: §1–§4 and the revisions are in this file; §5–§9 are in [`32a-cross-cli-messaging-surfaces-delivery.md`](32a-cross-cli-messaging-surfaces-delivery.md).

## 1. Purpose and boundary

Cross-CLI messaging lets a live Claude Code session and a live Codex session on the same host ask
each other questions, answer, and coordinate **while both are working**. It is a mid-task
conversation channel, not a hand-over of finished work and not an executor: csq stores and delivers
text, and never runs anything a message says. The receiving agent, and its human, decide what to do.

- **csq-launched sessions only.** Identity and delivery come from the per-terminal handle dirs csq
  creates (`term-<pid>`, spec 02). A bare `claude` or `codex` started outside csq can neither send
  nor be reached.
- **Same host only.** Every party is a process on this machine. A target that is not a live local
  session is refused.
- **No network.** Messages travel through a file store under the csq accounts directory. There is no
  socket, no TCP route and no daemon involvement.

## 2. Identity

### 2.1 What a session is

A session is the pair `(pid, started_at)` of a CLI process, plus its canonical handle dir and its
`surface` (`claude-code` or `codex`). `started_at` is the operating system's process start time, so a
recycled pid is a different session. For Claude Code the handle dir is the process's
`CLAUDE_CONFIG_DIR`; for Codex it is its `CODEX_HOME`.

`csq sessions list` lists both Claude Code and Codex sessions (`surface: "codex"` rows are additive;
a consumer that ignores unknown surfaces keeps working).

### 2.2 The sender is always the resolved calling session

The sender of a message is **never chosen** — not by a message field, an argument, or an environment
variable the caller sets. csq derives it by proving which session is calling:

- the caller's handle-dir variable (`CLAUDE_CONFIG_DIR` or `CODEX_HOME`; both set is refused) must
  canonicalise to the handle dir of exactly one live CLI process;
- that process must be an ancestor of the calling process (at most 64 hops), with its start time
  re-read and unchanged;
- it must be the **nearest** session above the caller: if another CLI process sits between them (for
  example a `codex` started as a tool inside a Claude session, inheriting `CLAUDE_CONFIG_DIR`), the
  call is refused rather than attributed to the outer session.

The MCP server (§5.2) and the hook command (§6.2) are children of the CLI process, so both pass the
ancestor test. No match, more than one match, or an unreadable process table yields `undetermined` —
never a guess. On Linux with `/proc` mounted `hidepid`, other processes' details are hidden, so
identity cannot be proved and messaging reports `undetermined`.

The stored sender block is written by csq from this proof. A record's type can only be built by the
resolver, so no surface can construct a sender from user input.

## 3. Session registry: names and discovery

A session finds its peers with `csq sessions list` or the MCP tool `list_sessions`, and may address
them by name.

- **Self-naming.** A session names ITSELF with `csq sessions name <name>` or the MCP tool `set_name`,
  and removes the name with `csq sessions name --clear`. Neither takes a target: the name always
  applies to the proven caller (§2.2), so one session cannot name another. The name is stored in the
  caller's own handle dir as `.csq-session-name`, written atomically with mode 0600.
- **Valid names.** 1–48 characters from `[A-Za-z0-9._-]`, starting with a letter or digit, compared
  case-insensitively. Anything else is refused and is not echoed back. The character set has no space,
  newline, bidirectional or zero-width character, so a valid name is safe to display.
- **Labels.** Each listed session carries a `label` (the name a `send` resolves against) and a
  `label_source`: `self` (the session named itself), `claude` (Claude Code's own session name, folded
  onto the valid character set) or `default` (`<repo>-<surface>-<pid>`, which is unique because it
  carries the pid). The existing `name` field keeps its meaning (Claude Code's own name).
- **Repo and branch.** Derived from the session's working directory without running git: csq walks up
  to the first `.git` (directory or worktree `gitdir:` file) and reads `HEAD`. The repo is the
  top-level directory's basename only, never a path; a detached `HEAD` reads `detached`.
- **Listing fields.** Rows gain `label`, `label_source`, `repo`, `branch`, and `self: true` on the
  caller's own row. All additions are optional fields.
- **Send by name.** A case-insensitive exact match over live sessions, excluding the caller. Exactly
  one match: the message is sent and the receipt names the resolved `to_pid` and `to_started_at`. No
  match: `not_found`, listing up to 10 live names. Two or more: `ambiguous` — nothing is stored and
  the candidates are listed; csq never picks one. If the listing could not see every process, "no
  match" becomes `undetermined`.
- **A name is a label, not an identity.** The stored sender is always the proven `(pid, started_at)`.
  A name feeds no identity, rate limit or address; it only selects a `(pid, started_at)` that is then
  verified like any explicit target. Two sessions sharing a name resolve to `ambiguous`, a refusal,
  never a misdelivery.

## 4. Message model and lifecycle

Each message is one record, schema `csq.message.v1`, stored as `<accounts>/messages/<id>.json`.

| field | rule |
| --- | --- |
| `id` | lowercase UUID minted by csq at send; never caller-supplied |
| `from` | the proven sender (§2.2): pid, start, surface, a hash of the handle dir, optional name. The handle-dir path itself never leaves the store |
| `to` | an existing live session, checked at send. An ended session is `target_mismatch`; an unreadable process table is `undetermined`; neither writes anything |
| `in_reply_to` | optional; must name a message addressed TO the sender. A reply goes only to that message's sender, so a reply cannot pull a third session into a thread |
| `thread` | the first message's id; set by csq |
| `body` | UTF-8, 1–4 000 characters. Newlines allowed; other control, bidirectional and line-separator characters refused |
| `ack_note` | optional, ≤ 500 characters, one line |
| `created_at` | unix seconds from csq's clock |

**Lifecycle.** `queued` → `surfaced` (shown to the recipient by a hook) → `read` (the recipient fetched
the body) → `acked` (optionally with a note). An unread message whose recipient session has ended is
marked `undeliverable` and stops counting as pending. Records are pruned 7 days after their last
transition. Because csq mints every id after the body is accepted, a deleted id cannot be replayed.

**Isolation.** A session reads and acknowledges only messages addressed to its own `(pid,
started_at)`; acknowledging someone else's message is `target_mismatch`.

**Limits** (enforced in the store, so the CLI and MCP share them; a refused send consumes nothing and
renaming does not reset them):

| limit | value |
| --- | --- |
| messages per (sender, recipient) per rolling 10 minutes | 30 |
| unread messages per recipient, all senders | 50 |
| unread outstanding per sender, all recipients | 100 |
| records in the store | 2 000 |

A full store evicts acknowledged records first, then expired ones, then unread records of ended
recipients, then read-but-unacknowledged ones. It never evicts an unread message of a live recipient
or any record younger than 10 minutes; if nothing can be evicted, the send is refused `rate_limited`
with `next_allowed_at`. Acknowledging or replying to a message that has been evicted is
`invalid_input` with a message saying so.

**Store safety.** Every record is re-validated on every load. A record that is malformed, oversized,
a symlink or other non-regular file, or stamped more than 300 seconds in the future is moved to
`messages/rejected/` (newest 20 kept) under the store lock, so one bad file cannot block messaging.
Outside the lock, an unreadable record makes the result `undetermined` — never an empty inbox.

## Revisions

- 1.0.0 — initial public specification.
