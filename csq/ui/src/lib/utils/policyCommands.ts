// ── Policy publish command builder ────────────────────────────────────
//
// Pure helper that constructs the copy-ready CLI commands for offline
// signing and installation of a policy bundle. Kept as a separate module
// so it can be unit-tested independently of the Svelte component.

// CLI command templates. Verbatim from `csq/src/cli/mod.rs`:
//   csq audit bundle-sign    <FILE> --secret-key <PATH> [--out <FILE>]
//   csq audit bundle-install <FILE> --pubkey <PUBKEY_HEX>
// The subcommands are hyphenated (`bundle-sign`, not `bundle sign`) and the
// bundle FILE is the leading positional argument. Change flags here to swap
// them globally.
const SIGN_CMD_TEMPLATE = (
  secretKeyPath: string,
  signedPath: string,
  draftPath: string,
) =>
  `csq audit bundle-sign ${draftPath} --secret-key ${secretKeyPath} --out ${signedPath}`;

const INSTALL_CMD_TEMPLATE = (pubkeyHex: string, signedPath: string) =>
  `csq audit bundle-install ${signedPath} --pubkey ${pubkeyHex}`;

export interface PublishCommandOpts {
  draftPath: string;
  signedPath: string;
  pubkeyHex: string;
  secretKeyPath: string;
}

export interface PublishCommands {
  signCmd: string;
  installCmd: string;
}

/** Builds the copy-ready CLI publish commands from the given options. */
export function buildPublishCommands(
  opts: PublishCommandOpts,
): PublishCommands {
  return {
    signCmd: SIGN_CMD_TEMPLATE(
      opts.secretKeyPath,
      opts.signedPath,
      opts.draftPath,
    ),
    installCmd: INSTALL_CMD_TEMPLATE(opts.pubkeyHex, opts.signedPath),
  };
}
