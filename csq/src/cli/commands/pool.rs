//! Account-independent API-key pool configuration. No key argument exists.
use anyhow::Result;
use clap::Subcommand;
use csq_core::pool::{Pool, PoolError, Reset};
use secrecy::SecretString;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Subcommand)]
pub enum PoolCommand {
    /// Add a key from hidden stdin, or admit names from a literal env file
    Add {
        #[arg(required = true, num_args = 1..)]
        names: Vec<String>,
        #[arg(long, default_value = "anthropic")]
        provider: String,
        #[arg(long)]
        from_env_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "reset_date")]
        reset_day: Option<u8>,
        #[arg(long)]
        reset_date: Option<String>,
        #[arg(long)]
        cap: Option<f64>,
    },
    /// List metadata and presence, never values
    List,
    /// Set or clear a key's optional reset metadata
    SetReset {
        name: String,
        #[arg(long, conflicts_with_all = ["reset_date", "clear"])]
        reset_day: Option<u8>,
        #[arg(long, conflicts_with = "clear")]
        reset_date: Option<String>,
        #[arg(long)]
        clear: bool,
    },
    /// Remove a manifest entry and its protected stored key
    Remove { name: String },
    /// Recover an interrupted custody operation once its writer has stopped
    Recover,
}
fn reset(day: Option<u8>, date: Option<String>) -> Option<Reset> {
    day.map(|day_of_month| Reset::Day { day_of_month })
        .or_else(|| date.map(|date| Reset::Date { date }))
}
pub fn handle(base_dir: &Path, action: PoolCommand, json: bool) -> Result<()> {
    let pool = Pool::new(base_dir);
    match action {
        PoolCommand::Add {
            names,
            provider,
            from_env_file,
            reset_day,
            reset_date,
            cap,
        } => {
            let reset = reset(reset_day, reset_date);
            if let Some(path) = from_env_file {
                pool.add_env_file(&path, &names, &provider, reset, cap)?;
            } else {
                if names.len() != 1 {
                    return Err(PoolError::InvalidName.into());
                }
                // Validate metadata before prompting for a secret.
                Pool::validate_add(&names[0], &provider, reset.as_ref(), cap)?;
                pool.check_add_available(&names[0])?;
                let key = read_key()?;
                csq_core::credentials::keychain::with_interactive_keychain(|| {
                    pool.add(&names[0], &provider, key, reset, cap)
                })?;
            }
            println!(
                "{}",
                if json {
                    "{\"added\":true}"
                } else {
                    "Pool entry added."
                }
            );
        }
        PoolCommand::List => {
            let rows = pool.list()?;
            if json {
                println!("{}", serde_json::to_string(&rows)?);
            } else {
                for row in rows {
                    println!(
                        "{}\t{}\t{}\treset={}\tcap={}\tpresent={}",
                        row.entry.name.as_str(),
                        row.entry.provider,
                        match row.entry.source {
                            csq_core::pool::KeySource::EnvFile => "env-file",
                            csq_core::pool::KeySource::SecretStore => "secret-store",
                        },
                        serde_json::to_string(&row.entry.reset)?,
                        serde_json::to_string(&row.entry.monthly_cap_usd)?,
                        row.present
                    );
                }
            }
        }
        PoolCommand::SetReset {
            name,
            reset_day,
            reset_date,
            clear,
        } => {
            if !clear && reset_day.is_none() && reset_date.is_none() {
                return Err(PoolError::InvalidReset.into());
            }
            pool.set_reset(&name, reset(reset_day, reset_date))?;
            println!(
                "{}",
                if json {
                    "{\"updated\":true}"
                } else {
                    "Pool reset updated."
                }
            );
        }
        PoolCommand::Remove { name } => {
            csq_core::credentials::keychain::with_interactive_keychain(|| pool.remove(&name))?;
            println!(
                "{}",
                if json {
                    "{\"removed\":true}"
                } else {
                    "Pool entry removed."
                }
            );
        }
        PoolCommand::Recover => {
            csq_core::credentials::keychain::with_interactive_keychain(|| pool.recover_pending())?;
            println!(
                "{}",
                if json {
                    "{\"recovered\":true}"
                } else {
                    "Pool custody recovered."
                }
            );
        }
    }
    Ok(())
}
fn read_input(reader: &mut impl Read) -> csq_core::pool::Result<SecretString> {
    // The extra byte bounds capacity without reallocating unwiped key prefixes.
    let mut bytes = Zeroizing::new(Vec::<u8>::with_capacity(4097));
    let mut byte = Zeroizing::new([0u8]);
    loop {
        match reader.read(&mut *byte) {
            Ok(0) => break,
            Ok(_) if matches!(byte[0], b'\n' | b'\r') => break,
            Ok(_) if byte[0] == 3 => return Err(PoolError::InvalidKey),
            Ok(_) if matches!(byte[0], 8 | 127) => {
                if let Some(last) = bytes.last_mut() {
                    last.zeroize();
                }
                bytes.pop();
            }
            Ok(_) => {
                if bytes.len() == 4096 {
                    return Err(PoolError::InvalidKey);
                }
                bytes.push(byte[0]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(PoolError::InvalidKey),
        }
    }
    let value = std::str::from_utf8(&bytes).map_err(|_| PoolError::InvalidKey)?;
    csq_core::pool::validate_key(value)?;
    Ok(SecretString::from(value.to_owned()))
}
fn read_key() -> Result<SecretString> {
    let stdin = std::io::stdin();
    let _guard = if stdin.is_terminal() {
        eprint!("API key (hidden): ");
        std::io::stderr().flush()?;
        Some(EchoGuard::disable()?)
    } else {
        None
    };
    // std::io::Stdin owns a process-lifetime buffered reader. Read the OS handle
    // directly so no persistent stdin buffer retains the submitted credential.
    let result = read_input(&mut RawStdin);
    if stdin.is_terminal() {
        eprintln!();
    }
    Ok(result?)
}
struct RawStdin;
impl Read for RawStdin {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        #[cfg(unix)]
        {
            // SAFETY: fd 0 is borrowed, and this mutable slice is writable for
            // its reported length. No pointer escapes the synchronous read.
            let count = unsafe { libc::read(0, buffer.as_mut_ptr().cast(), buffer.len()) };
            if count < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(count as usize)
            }
        }
        #[cfg(windows)]
        {
            let handle = unsafe { get_std_handle((-10i32) as u32) };
            let mut count = 0;
            let length = buffer.len().min(u32::MAX as usize) as u32;
            // SAFETY: the borrowed OS stdin handle, writable slice and count
            // pointer remain valid throughout this synchronous ReadFile call.
            if unsafe {
                read_file(
                    handle,
                    buffer.as_mut_ptr().cast(),
                    length,
                    &mut count,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                let error = std::io::Error::last_os_error();
                // A closed redirected pipe or exhausted file is EOF, so a
                // final key without a newline has the same semantics as Unix.
                if matches!(error.raw_os_error(), Some(109 | 38)) {
                    Ok(0)
                } else {
                    Err(error)
                }
            } else {
                Ok(count as usize)
            }
        }
    }
}
#[cfg(unix)]
struct EchoGuard(libc::termios);
#[cfg(unix)]
fn hidden_terminal_mode(mut mode: libc::termios) -> libc::termios {
    // Ctrl-C must reach read_input so its error path drops EchoGuard and
    // restores echo instead of terminating before restoration.
    mode.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG);
    mode.c_cc[libc::VMIN] = 1;
    mode.c_cc[libc::VTIME] = 0;
    mode
}
#[cfg(unix)]
impl EchoGuard {
    fn disable() -> Result<Self> {
        let mut original = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(0, &mut original) } != 0 {
            return Err(PoolError::InvalidKey.into());
        }
        let changed = hidden_terminal_mode(original);
        if unsafe { libc::tcsetattr(0, libc::TCSANOW, &changed) } != 0 {
            return Err(PoolError::InvalidKey.into());
        }
        Ok(Self(original))
    }
}
#[cfg(unix)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.0);
        }
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    #[link_name = "GetStdHandle"]
    fn get_std_handle(which: u32) -> *mut std::ffi::c_void;
    #[link_name = "GetConsoleMode"]
    fn get_console_mode(handle: *mut std::ffi::c_void, mode: *mut u32) -> i32;
    #[link_name = "SetConsoleMode"]
    fn set_console_mode(handle: *mut std::ffi::c_void, mode: u32) -> i32;
    #[link_name = "ReadFile"]
    fn read_file(
        handle: *mut std::ffi::c_void,
        buffer: *mut std::ffi::c_void,
        length: u32,
        count: *mut u32,
        overlapped: *mut std::ffi::c_void,
    ) -> i32;
}
#[cfg(windows)]
struct EchoGuard(*mut std::ffi::c_void, u32);
#[cfg(windows)]
impl EchoGuard {
    fn disable() -> Result<Self> {
        let handle = unsafe { get_std_handle((-10i32) as u32) };
        let mut mode = 0;
        if unsafe { get_console_mode(handle, &mut mode) } == 0
            || unsafe { set_console_mode(handle, mode & !(1 | 2 | 4)) } == 0
        {
            return Err(PoolError::InvalidKey.into());
        }
        Ok(Self(handle, mode))
    }
}
#[cfg(windows)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        unsafe {
            set_console_mode(self.0, self.1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    #[test]
    fn pool_stdin_is_bounded_and_key_errors_never_echo_input() {
        let secret = read_input(&mut &b"synthetic-pool-key\n"[..]).unwrap();
        assert_eq!(secret.expose_secret(), "synthetic-pool-key");
        for bytes in [vec![b'x'; 4097], b"secret with spaces".to_vec(), vec![0xff]] {
            let error = read_input(&mut bytes.as_slice()).unwrap_err();
            assert_eq!(error.to_string(), "pool_invalid_key");
        }
        assert!(!format!("{secret:?}").contains("synthetic-pool-key"));
        for input in [&b"synthetic-pool-key\r\n"[..], &b"synthetic-pool-key"[..]] {
            assert_eq!(
                read_input(&mut &input[..]).unwrap().expose_secret(),
                "synthetic-pool-key"
            );
        }
        assert_eq!(
            read_input(&mut &b"synx\x08thetic\n"[..])
                .unwrap()
                .expose_secret(),
            "synthetic"
        );
        assert!(read_input(&mut &b"partial\x03"[..]).is_err());
        struct InterruptedOnce {
            interrupted: bool,
            rest: std::io::Cursor<&'static [u8]>,
        }
        impl Read for InterruptedOnce {
            fn read(&mut self, byte: &mut [u8]) -> std::io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                self.rest.read(byte)
            }
        }
        let mut interrupted = InterruptedOnce {
            interrupted: false,
            rest: std::io::Cursor::new(b"synthetic\n"),
        };
        assert_eq!(
            read_input(&mut interrupted).unwrap().expose_secret(),
            "synthetic"
        );
        #[cfg(unix)]
        {
            // SAFETY: zero is an initialized termios value for this pure
            // bit-transform fixture; it is never passed to an OS terminal.
            let mut mode: libc::termios = unsafe { std::mem::zeroed() };
            mode.c_lflag = libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG;
            let hidden = hidden_terminal_mode(mode);
            assert_eq!(hidden.c_lflag & (libc::ECHO | libc::ISIG | libc::ICANON), 0);
            assert_eq!(hidden.c_cc[libc::VMIN], 1);
            assert_eq!(hidden.c_cc[libc::VTIME], 0);
        }
    }
    #[test]
    fn pool_cli_rejects_key_arguments_and_conflicting_reset_metadata() {
        use crate::cli::Cli;
        use clap::Parser;
        assert!(Cli::try_parse_from(["csq", "pool", "list", "--json"]).is_ok());
        assert!(Cli::try_parse_from(["csq", "pool", "recover"]).is_ok());
        assert!(Cli::try_parse_from(["csq", "pool", "add", "one", "--provider", "openai"]).is_ok());
        assert!(
            Cli::try_parse_from(["csq", "pool", "add", "one", "--key", "synthetic-argv-key"])
                .is_err()
        );
        assert!(Cli::try_parse_from([
            "csq",
            "pool",
            "add",
            "one",
            "--reset-day",
            "7",
            "--reset-date",
            "2100-01-01"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "csq",
            "pool",
            "set-reset",
            "one",
            "--clear",
            "--reset-day",
            "7"
        ])
        .is_err());
        let dir = tempfile::tempdir().unwrap();
        let error = handle(
            dir.path(),
            PoolCommand::Add {
                names: vec!["one".into()],
                provider: "openai".into(),
                from_env_file: None,
                reset_day: None,
                reset_date: None,
                cap: Some(-1.0),
            },
            true,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "pool_invalid_cap");
        assert!(!dir.path().join("pool").exists());
    }
}
