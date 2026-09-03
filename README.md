# Code Squad Q (csq)

Run several Claude Code accounts on one machine, switch between them per terminal,
and see how much quota each one has left.

Claude Code stores its credentials in a single config directory. If you have more
than one account, using them at the same time means logging in and out — and every
switch invalidates the session you just left. csq gives each account a permanent
home and each terminal its own view, so several sessions can run side by side
against different accounts without disturbing one another.

Apache-2.0 licensed, maintained by the Terrene Foundation.

## What it does

- **Keeps several accounts signed in at once.** Each account keeps its own
  credentials and refreshes its own tokens in the background, so none of them go
  stale while you are using another.
- **Isolates terminals.** Every session gets its own handle directory. Switching
  accounts in one terminal leaves the others exactly where they were.
- **Shows quota.** A background daemon polls each account's usage and renders it
  in `csq status`, in your statusline, and in the desktop app — so you can see
  which account has room before you start a long task, not after it stops.
- **Suggests where to go next.** `csq suggest` picks the account with the most
  headroom.
- **Speaks to other providers too.** Alongside Claude accounts, csq can bind a
  slot to a third-party API key or a local model, and manage those the same way.
- **Records what ran.** An optional hash-linked audit trail logs each session with
  a local signing key, and `csq audit verify` checks the chain.

## Install

### macOS — Homebrew

```bash
brew tap terrene-foundation/csq
brew install csq
```

### macOS / Linux — direct download

Grab the archive for your platform from the
[latest release](https://github.com/terrene-foundation/csq/releases/latest),
unpack it, and put `csq` somewhere on your `PATH`:

```bash
install -m 0755 csq ~/.local/bin/csq
```

Once installed, `csq update` checks for newer releases and `csq update install`
applies one.

### Desktop app

The macOS `.dmg` and the Linux `.AppImage` are attached to the same release. The
desktop app shows the same account and quota state as the CLI, and updates itself.

### From source

You need a recent stable Rust toolchain. On Linux you also need the system
libraries Tauri builds against (`libwebkit2gtk-4.1-dev`,
`libayatana-appindicator3-dev`, `librsvg2-dev`, `patchelf`).

```bash
cargo build --release -p csq --features cli --no-default-features
install -m 0755 target/release/csq ~/.local/bin/csq
```

## Getting started

```bash
csq install          # create the directories csq needs, once
csq login 1          # sign in — opens your browser
csq login 2          # ...as many accounts as you want
csq status           # see all of them, with quota
csq run 1            # start Claude Code on account 1
```

`csq run 1` starts a session bound to account 1. Open a second terminal, run
`csq run 2`, and the two sessions coexist — different accounts, neither one
logging the other out.

Inside a session, `csq swap 3` repoints *that* terminal at account 3. Claude Code
picks the change up on its next API call; you do not need to restart it, and no
other terminal is affected.

When an account runs low:

```bash
csq suggest          # which account has the most headroom
csq swap 4           # move this terminal there
```

## Accounts and terminals

Almost every subtle bug in a tool like this comes from confusing these two, so it
is worth being explicit.

An **account** is an identity you signed in as. It owns a permanent directory, its
own credentials, and its own quota. It refreshes its own tokens and polls its own
usage, and it is the only authority on how much quota it has left.

A **terminal** is one running session. It has an ephemeral handle directory whose
symlinks point at whichever account it is currently using. A terminal *displays*
quota; it never *writes* it. Swapping in one terminal repoints that terminal's
symlinks and leaves its siblings untouched.

The rule that falls out: a quota figure must come from the poller that fetched it
for a known account — never from "which account does this terminal seem to be
on?", a question with several answers that disagree.

## Other providers

A slot does not have to be a Claude subscription account. `csq setkey` binds a
slot to an API key or a local model instead, and `csq run <N>` launches against
it the same way:

```bash
csq setkey ollama --slot 7                 # a local model, no key needed
csq setkey deepseek --slot 8               # reads the key from stdin
csq listkeys                               # what is configured where
```

Run `csq setkey --help` for the providers available in your build. Keys are read
from stdin rather than argv, so they do not land in your shell history, and the
files csq writes them to are created `0600`.

## Diagnostics

```bash
csq doctor           # check the whole installation and explain anything odd
csq daemon status    # is the background daemon running
csq probe <N>        # live-check one slot's credentials against its provider
csq repair           # fix credential/slot inconsistencies
```

`csq doctor` is the one to reach for first. It knows the difference between a slot
that is broken and one that merely *looks* broken — an expected-stale poll, for
instance — and says which.

## Audit trail

Each `csq run` can append a signed, hash-linked record of the session. The chain
is verified when the daemon starts, and on demand:

```bash
csq audit verify
```

Records are signed with a local key that csq generates and keeps to your user
account. If the chain is ever broken, csq says so rather than quietly continuing.

## Development

```bash
cargo test --workspace --features csq/test-utils   # the test suite
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

The frontend lives in `csq/ui`:

```bash
cd csq/ui && npm install && npm test
```

Tests, clippy, and fmt passing is necessary but not sufficient before calling a
user-facing change done. Build the binary, install it, and run the command a user
would actually run — a green suite says the code is right, not that the artifact
on disk is the one you fixed.

`specs/` is the authoritative description of how the system behaves; start at
`specs/_index.md` and read only what your change touches.

## Contributing

Contributions are welcome. Changes go through pull requests, commit messages
follow [Conventional Commits](https://www.conventionalcommits.org/), and tests
land alongside the code they cover. Anything touching credentials, the keychain,
or the sign-in flows deserves a careful security read before it merges.

## License

Apache-2.0. See [LICENSE](LICENSE).
