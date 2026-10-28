//! Independent Windows upgrade gate. Never enters csq CLI/app/daemon startup.

// S1 does not wire an installer. S2 must close the final census/replacement gap.
#[cfg(windows)]
const RECHECK: &str = "installer MUST re-check and hold an admission lock across replace";

#[cfg(windows)]
fn run() -> anyhow::Result<()> {
    use anyhow::{bail, Context};
    use csq_core::update::upgrade_guard::{stop_installed, windows::WindowsBackend, Limits};
    use std::path::PathBuf;

    use windows_sys::Win32::System::LibraryLoader::{
        SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };
    // SAFETY: restrict subsequent DLL loads to System32 before parsing or probing.
    if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("upgrade refused: System32 DLL policy unavailable");
    }
    let mut images = Vec::new();
    let mut daemon_pid = None;
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            println!("usage: csq-upgrade-guard --image EXISTING_ABSOLUTE_BINARY_PATH [--image EXISTING_ABSOLUTE_BINARY_PATH ...] [--daemon-pid-file ABSOLUTE_PATH]");
            println!("{RECHECK}");
            return Ok(());
        }
        let value = args
            .next()
            .context("upgrade refused: missing argument value")?;
        match arg.to_str() {
            Some("--image") if images.len() < 16 => images.push(PathBuf::from(value)),
            Some("--daemon-pid-file") if daemon_pid.is_none() => {
                let path = PathBuf::from(value);
                if !path.is_absolute() {
                    bail!("upgrade refused: daemon PID path must be absolute");
                }
                daemon_pid = Some(path);
            }
            _ => bail!("upgrade refused: unsupported or repeated argument"),
        }
    }
    let helper = std::env::current_exe()?.canonicalize()?;
    for (index, image) in images.iter().enumerate() {
        let resolved = image.canonicalize().with_context(|| {
            format!(
                "upgrade refused: --image must name an existing installed binary (target {})",
                index + 1
            )
        })?;
        if !resolved.is_file() {
            bail!(
                "upgrade refused: --image must name an existing installed binary (target {})",
                index + 1
            );
        }
        if resolved == helper {
            bail!("upgrade refused: helper cannot be one of its own installed targets");
        }
    }
    let mut backend = WindowsBackend::new(daemon_pid)?;
    let report = stop_installed(&mut backend, &images, Limits::default())?;
    println!(
        "UPGRADE_DRAIN_VERIFIED selected={} verified_exits={}",
        report.selected, report.verified_exits
    );
    println!("{RECHECK}");
    Ok(())
}

#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(2);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("upgrade refused: this helper requires Windows");
    std::process::exit(2);
}
