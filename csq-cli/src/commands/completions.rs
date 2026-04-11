//! `csq completions <SHELL>` — generate shell completions.

use clap::CommandFactory;
use clap_complete::{generate, Shell};
use std::io;

/// Generates shell completions for the given shell and writes to stdout.
pub fn handle(shell: Shell) {
    let mut cmd = crate::Cli::command();
    generate(shell, &mut cmd, "csq", &mut io::stdout());
}
