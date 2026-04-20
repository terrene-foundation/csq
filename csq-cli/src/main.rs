//! csq v2.0 CLI entry point.
//!
//! Routes subcommands to handlers in `commands/`. Single binary replaces
//! the v1.x bash + Python toolchain.

mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};
use clap_complete::Shell;
use csq_core::types::AccountNum;
use tracing_subscriber::EnvFilter;

/// csq — Claude Code multi-account rotation and session management
#[derive(Parser, Debug)]
#[command(name = "csq", version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Output results as JSON (for scripting/automation)
    #[arg(long, global = true)]
    json: bool,

    /// Positional account number — shorthand for `csq run <N>`
    #[arg(value_name = "ACCOUNT")]
    account: Option<u16>,

    /// Remaining args passed through to `claude`
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    rest: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run claude with an isolated config directory for the given account
    Run {
        /// Account number (1-999)
        account: Option<u16>,
        /// Optional profile (overrides credentials with a provider settings file)
        #[arg(short, long)]
        profile: Option<String>,
        /// Arguments passed through to `claude`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },

    /// Swap the active account in the current config dir
    Swap {
        /// Account number to swap to
        account: u16,
    },

    /// Show status of all accounts
    Status,

    /// Suggest the best account to switch to (JSON output)
    Suggest,

    /// Show the statusline string (reads CC JSON from stdin)
    Statusline,

    /// OAuth login flow for a new account
    Login {
        /// Account number to login as
        account: u16,
    },

    /// Remove an account: deletes credentials, config dir, and profile entry.
    /// Refuses if a live `claude` process is still bound to the account.
    #[command(alias = "remove")]
    Logout {
        /// Account number to log out
        account: u16,
        /// Skip the interactive confirmation prompt
        #[arg(short = 'y', long = "yes")]
        yes: bool,
    },

    /// Provider key management
    #[command(subcommand)]
    Setkey(SetkeyCmd),

    /// List configured provider keys
    Listkeys,

    /// Remove a provider key
    Rmkey {
        /// Provider ID (mm, zai, etc.)
        provider: String,
    },

    /// Model catalog operations
    Models {
        #[command(subcommand)]
        action: Option<ModelsCmd>,
    },

    /// Install csq into ~/.claude (creates dirs, patches settings.json)
    Install,

    /// Run diagnostics and report system health
    Doctor,

    /// Background daemon lifecycle (start/stop/status)
    Daemon {
        #[command(subcommand)]
        action: DaemonCmd,
    },

    /// Check for newer csq releases on GitHub
    Update {
        #[command(subcommand)]
        action: UpdateCmd,
    },

    /// Repair cross-slot credential contamination
    ///
    /// Detects when multiple OAuth slots share the same refresh
    /// token (happens after a fanout/rotation bug) and reports the
    /// affected slots. Does not modify files — use the output to
    /// decide which slots to re-authenticate.
    RepairCredentials {
        /// Actually delete the contaminated canonical files,
        /// forcing re-login on next use. Off by default (dry run).
        #[arg(long)]
        apply: bool,
    },

    /// Generate shell completions for bash, zsh, fish, or powershell
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },
}

#[derive(Subcommand, Debug)]
enum UpdateCmd {
    /// Query GitHub Releases and compare to the current version.
    /// Prints a one-line notice if a newer release is available.
    Check,
    /// Download, verify (SHA256 + Ed25519), and atomically replace the
    /// current binary with the latest GitHub Release for this platform.
    Install,
}

#[derive(Subcommand, Debug)]
enum DaemonCmd {
    /// Start the daemon (foreground by default; use -d to background)
    Start {
        /// Detach and run in the background (re-execs the binary without this flag)
        #[arg(short = 'd', long = "background")]
        background: bool,
    },
    /// Stop the running daemon via SIGTERM
    Stop,
    /// Show the daemon's status (running / stale / not running)
    Status,
    /// Install csq as a platform service (launchd on macOS, systemd on Linux)
    Install,
    /// Uninstall the platform service installed by `csq daemon install`
    Uninstall,
}

#[derive(Subcommand, Debug)]
enum SetkeyCmd {
    /// MiniMax API key
    Mm {
        #[arg(long)]
        key: Option<String>,
        /// Bind the key to slot N (e.g. `--slot 9`). If omitted, the key
        /// is only stored in the global settings-mm.json.
        #[arg(long)]
        slot: Option<u16>,
    },
    /// Z.AI API key
    Zai {
        #[arg(long)]
        key: Option<String>,
        /// Bind the key to slot N (e.g. `--slot 10`). If omitted, the key
        /// is only stored in the global settings-zai.json.
        #[arg(long)]
        slot: Option<u16>,
    },
    /// Claude API key (for non-OAuth flows)
    Claude {
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        slot: Option<u16>,
    },
    /// Ollama profile (keyless — creates the settings file with defaults)
    Ollama {
        /// Bind the Ollama profile to slot N (e.g. `--slot 9`). If
        /// omitted, only the global `settings-ollama.json` is written.
        #[arg(long)]
        slot: Option<u16>,
    },
}

#[derive(Subcommand, Debug)]
enum ModelsCmd {
    /// List all models, or filter by provider
    List {
        /// Provider ID or "all"
        #[arg(default_value = "all")]
        provider: String,
    },
    /// Switch the active model for a provider
    Switch {
        /// Provider ID (claude, mm, zai, ollama)
        provider: String,
        /// Model ID or alias
        model: String,
        /// Retarget a slot's `config-N/settings.json` instead of
        /// the global profile file. Required when the slot was
        /// bound via `csq setkey <provider> --slot N` — editing
        /// the global profile wouldn't affect the slot.
        #[arg(long)]
        slot: Option<u16>,
        /// For keyless providers (Ollama): when the chosen model
        /// isn't in `ollama list`, run `ollama pull <model>`
        /// before writing. Default: on. Pass `--no-pull` to
        /// refuse the network fetch (e.g. writing a model id
        /// for a machine you'll `ollama pull` on later).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        pull_if_missing: bool,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("CSQ_LOG").unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    // No subcommand: default to `run` (optionally with positional account)
    let command = cli.command.unwrap_or(Command::Run {
        account: cli.account,
        profile: None,
        rest: cli.rest,
    });

    let json = cli.json;
    let base_dir = commands::base_dir()?;

    // Spawn a background thread to check for updates on every command run
    // except `csq update` itself. The thread checks at most once per 24 hours
    // (cached) and prints a one-line notice if a newer version is available.
    // It never blocks or delays the main command.
    match &command {
        Command::Update { .. } => {} // skip: user is already in the update flow
        _ => csq_core::update::auto_update_bg(base_dir.clone()),
    }

    match command {
        Command::Run {
            account,
            profile,
            rest,
        } => {
            let account_num = match account {
                Some(n) => Some(
                    AccountNum::try_from(n).map_err(|e| anyhow::anyhow!("invalid account: {e}"))?,
                ),
                None => None,
            };
            commands::run::handle(&base_dir, account_num, profile.as_deref(), &rest)
        }
        Command::Swap { account } => {
            let account_num = AccountNum::try_from(account)
                .map_err(|e| anyhow::anyhow!("invalid account: {e}"))?;
            commands::swap::handle(&base_dir, account_num)
        }
        Command::Status => commands::status::handle(&base_dir, json),
        Command::Suggest => commands::suggest::handle(&base_dir),
        Command::Statusline => commands::statusline::handle(&base_dir),
        Command::Login { account } => {
            let account_num = AccountNum::try_from(account)
                .map_err(|e| anyhow::anyhow!("invalid account: {e}"))?;
            commands::login::handle(&base_dir, account_num)
        }
        Command::Logout { account, yes } => {
            let account_num = AccountNum::try_from(account)
                .map_err(|e| anyhow::anyhow!("invalid account: {e}"))?;
            commands::logout::handle(&base_dir, account_num, yes)
        }
        Command::Setkey(sk) => {
            let (provider, key, slot) = match sk {
                SetkeyCmd::Mm { key, slot } => ("mm", key, slot),
                SetkeyCmd::Zai { key, slot } => ("zai", key, slot),
                SetkeyCmd::Claude { key, slot } => ("claude", key, slot),
                SetkeyCmd::Ollama { slot } => ("ollama", None, slot),
            };
            let slot = match slot {
                Some(n) => Some(
                    AccountNum::try_from(n).map_err(|e| anyhow::anyhow!("invalid --slot: {e}"))?,
                ),
                None => None,
            };
            commands::setkey::handle(&base_dir, provider, key.as_deref(), slot)
        }
        Command::Listkeys => commands::listkeys::handle(&base_dir, json),
        Command::Rmkey { provider } => commands::rmkey::handle(&base_dir, &provider),
        Command::Models { action } => {
            let action = action.unwrap_or(ModelsCmd::List {
                provider: "all".to_string(),
            });
            match action {
                ModelsCmd::List { provider } => {
                    commands::models::handle_list(&base_dir, &provider, json)
                }
                ModelsCmd::Switch {
                    provider,
                    model,
                    slot,
                    pull_if_missing,
                } => {
                    let slot = match slot {
                        Some(n) => Some(
                            AccountNum::try_from(n)
                                .map_err(|e| anyhow::anyhow!("invalid --slot: {e}"))?,
                        ),
                        None => None,
                    };
                    commands::models::handle_switch(
                        &base_dir,
                        &provider,
                        &model,
                        slot,
                        pull_if_missing,
                    )
                }
            }
        }
        Command::Install => commands::install::handle(),
        Command::Doctor => commands::doctor::handle(&base_dir, json),
        Command::Daemon { action } => match action {
            DaemonCmd::Start { background } => {
                if background {
                    commands::daemon::handle_start_background(&base_dir)
                } else {
                    commands::daemon::handle_start(&base_dir)
                }
            }
            DaemonCmd::Stop => commands::daemon::handle_stop(&base_dir),
            DaemonCmd::Status => commands::daemon::handle_status(&base_dir),
            DaemonCmd::Install => commands::daemon::handle_install(&base_dir),
            DaemonCmd::Uninstall => commands::daemon::handle_uninstall(&base_dir),
        },
        Command::Update { action } => match action {
            UpdateCmd::Check => commands::update::check(),
            UpdateCmd::Install => commands::update::install(),
        },
        Command::RepairCredentials { apply } => {
            commands::repair_credentials::handle(&base_dir, apply)
        }
        Command::Completions { shell } => {
            commands::completions::handle(shell);
            Ok(())
        }
    }
}
