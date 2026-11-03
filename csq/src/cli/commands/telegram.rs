//! `csq telegram …` — local administration of the owner bridge.
//!
//! Every subcommand runs on the owner's own terminal and the machine's own
//! vault. None of them prints the bot token or the attestation origin key; the
//! one deliberate exception is the one-time pairing code, which the owner must
//! send to the bot.
//!
//! `pair` performs the whole enrolment handshake in this process: the code
//! lives only in memory, the CLI polls the Bot API for at most five minutes,
//! and the first message that passes every check becomes the pinned owner.
//! `on` then removes the daemon's kill-switch marker — the only way the bridge
//! can be restarted after a phone `/csq off`.
//!
//! `csq telegram on --allow <class>` is the ONLY surface that grants a
//! Telegram message permission to trigger an action class. The stored list is
//! empty unless an operator named a class here, and nothing an inbound message
//! contains can add to it.
//!
//! The bot token is read from **stdin only**, never from argv, because argv is
//! visible to every process on the machine (`ps`). `setup` disables terminal
//! echo while the token is typed and refuses a value that is not shaped like a
//! Telegram token before it reaches the vault.
//!
//! # Fail-safe direction
//!
//! `off` and `rotate` always work; `on` refuses unless an owner is pinned and a
//! bot token is stored. A half-configured bridge that reports "enabled" would
//! either poll with no credential or accept a DM from an unpinned sender.

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use csq_core::bridge::config::SWAP_CLASS;
use csq_core::bridge::enroll::{self, EnrolError, FsStore, PairingChallenge};
use csq_core::bridge::secrets::{self, SecretError};
use csq_core::bridge::telegram_api::{ReqwestTransport, TelegramApiError};
use csq_core::bridge::{config as bridge_config, BridgeConfig, BridgeConfigError};
use secrecy::SecretString;
use std::path::Path;
use zeroize::Zeroizing;

/// Action classes `--allow` accepts. Closed on purpose: an unknown class is a
/// configuration mistake, not something to store and hope the daemon ignores.
const ALLOWED_CLASSES: [&str; 1] = [SWAP_CLASS];

/// Owner-bridge subcommands.
#[derive(Subcommand, Debug)]
pub enum TelegramCommand {
    /// Store the Telegram bot token read from stdin (never from argv).
    Setup,
    /// Show bridge state; credentials are reported as PRESENT or ABSENT only.
    Status,
    /// Print a one-time pairing code for the daemon to consume.
    Pair,
    /// Enable the bridge and set the action classes Telegram may trigger.
    ///
    /// The bridge refuses unless an owner is pinned and a bot token is stored.
    /// Each `--allow` names one class; the only class today is `swap`. With no
    /// `--allow`, the stored list becomes empty and no action can be triggered
    /// from Telegram (messages still work).
    On {
        /// Action class to allow from Telegram. Repeatable; only `swap` is
        /// accepted.
        #[arg(long = "allow", value_name = "CLASS")]
        allow: Vec<String>,
    },
    /// Disable the bridge and discard any pending pairing code.
    Off,
    /// Clear the stored bot token and disable the bridge.
    Rotate,
}

/// Dispatches one `csq telegram` subcommand.
pub fn handle(base_dir: &Path, command: TelegramCommand) -> Result<()> {
    match command {
        TelegramCommand::Setup => setup(base_dir),
        TelegramCommand::Status => status(base_dir),
        TelegramCommand::Pair => pair(base_dir),
        TelegramCommand::On { allow } => turn_on(base_dir, &allow),
        TelegramCommand::Off => turn_off(base_dir),
        TelegramCommand::Rotate => rotate(base_dir),
    }
}

fn setup(base_dir: &Path) -> Result<()> {
    // The load also exercises the state directory, so a broken base dir is
    // reported before the owner types a token into a prompt that cannot store
    // it.
    if let Some(config) = bridge_config::load(base_dir).map_err(config_error)? {
        if config.enabled {
            eprintln!("The bridge is currently enabled; storing a new token leaves it enabled.");
        }
    }
    let token = read_bot_token_from_stdin()?;
    secrets::store_bot_token(&token).map_err(secret_error)?;
    // The origin key is minted once, locally. The daemon needs it to attest
    // owner deliveries; it never leaves this machine.
    secrets::ensure_origin_key().map_err(secret_error)?;
    println!("bot_token: PRESENT");
    println!("origin_key: PRESENT");
    println!("next: csq telegram pair");
    Ok(())
}

fn status(base_dir: &Path) -> Result<()> {
    let config = bridge_config::load(base_dir).map_err(config_error)?;
    let token = secrets::bot_token_present().map_err(secret_error)?;
    match config {
        Some(config) => {
            println!(
                "bridge: {}",
                if config.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!("owner_user_id: {}", presence(config.owner_user_id > 0));
            println!("owner_chat_id: {}", presence(config.owner_chat_id > 0));
            // The cursor lives in its own state file so the bridge never
            // writes the config; an unreadable cursor is reported, never
            // silently shown as 0.
            let cursor = bridge_config::load_cursor(base_dir)
                .map(|cursor| cursor.high_water_update_id.to_string())
                .unwrap_or_else(|_| "UNREADABLE".to_owned());
            println!("high_water_update_id: {cursor}");
            println!("allow_classes: {}", known_classes(&config));
        }
        None => {
            println!("bridge: not-set-up");
            println!("owner_user_id: ABSENT");
            println!("owner_chat_id: ABSENT");
            println!("high_water_update_id: 0");
            println!("allow_classes: none");
        }
    }
    let kill_switch = bridge_config::kill_switch_engaged(base_dir)
        .map(|engaged| if engaged { "ENGAGED" } else { "clear" })
        .unwrap_or("UNREADABLE");
    println!("kill_switch: {kill_switch}");
    println!("bot_token: {}", presence(token));
    Ok(())
}

fn pair(base_dir: &Path) -> Result<()> {
    // Re-pairing while the daemon is polling would run a second `getUpdates`
    // against the same bot token and Telegram answers 409 Conflict, so the
    // local CLI refuses before it touches the network.
    let config = bridge_config::load(base_dir).map_err(config_error)?;
    if config.as_ref().is_some_and(|config| config.enabled) {
        bail!("the bridge is enabled; run `csq telegram off` before pairing a new owner");
    }
    let token = match secrets::load_bot_token() {
        Ok(token) => token,
        Err(SecretError::NamedNotFound) => {
            bail!("no bot token is stored: run `csq telegram setup` first")
        }
        Err(error) => return Err(secret_error(error)),
    };

    let now = now_unix()?;
    let challenge = PairingChallenge::generate(now).map_err(enrol_error)?;
    println!("pairing_code: {}", challenge.code());
    println!("valid_for: {}s", enroll::PAIRING_TTL_SECS);
    println!("send this code to your bot from the owner's Telegram account; waiting...");

    let transport = ReqwestTransport::new(token).map_err(api_error)?;
    // A clock failure reads as the far future — past every challenge
    // deadline — so pairing fails closed immediately instead of polling
    // forever with a window that can never close.
    let clock = || pairing_clock(now_unix());
    let enrolled = enroll::enrol_owner(base_dir, &challenge, &transport, &FsStore, &clock)
        .map_err(enrol_error)?;
    if !enrolled.ack_delivered {
        eprintln!("warning: the bot acknowledgement could not be sent; the owner is pinned");
    }
    println!("owner_user_id: {}", enrolled.owner_user_id);
    println!("owner_chat_id: {}", enrolled.owner_chat_id);
    println!("next: csq telegram on");
    Ok(())
}

fn turn_on(base_dir: &Path, allow: &[String]) -> Result<()> {
    // Validate the requested classes before any state is read or written, so a
    // typo cannot leave the bridge half-updated.
    let classes = parse_allow_classes(allow)?;
    let Some(mut config) = bridge_config::load(base_dir).map_err(config_error)? else {
        bail!("the bridge is not set up: run `csq telegram setup`, then `pair` from Telegram");
    };
    if !config.is_pinned() {
        bail!("no owner is pinned yet: run `csq telegram pair` and send the code to your bot");
    }
    if !secrets::bot_token_present().map_err(secret_error)? {
        bail!("no bot token is stored: run `csq telegram setup`");
    }
    config.allow_classes = classes;
    // The kill marker is cleared BEFORE `enabled` is published. A phone
    // `/csq off` that lands between the two steps writes the marker after
    // this clear, so that later set survives and keeps the bridge off;
    // clearing after the write would erase a marker the phone had just
    // written. `engaged` is the state after the write, reported below as-is.
    let engaged = bridge_config::enable_bridge(&config, base_dir, &bridge_config::FsEnable)
        .map_err(config_error)?;
    println!("bridge: enabled");
    println!("allow_classes: {}", known_classes(&config));
    if engaged {
        println!("kill_switch: ENGAGED");
        eprintln!(
            "note: a phone `/csq off` arrived during this command; the bridge will not poll until you run `csq telegram on` again"
        );
    } else {
        println!("kill_switch: clear");
    }
    Ok(())
}

fn turn_off(base_dir: &Path) -> Result<()> {
    match bridge_config::load(base_dir).map_err(config_error)? {
        Some(mut config) => {
            config.enabled = false;
            bridge_config::save(&config, base_dir).map_err(config_error)?;
            println!("bridge: disabled");
        }
        None => println!("bridge: disabled (not set up)"),
    }
    Ok(())
}

fn rotate(base_dir: &Path) -> Result<()> {
    // Disable before the credential disappears, so no daemon poll starts
    // between the clear and the config write.
    if let Some(mut config) = bridge_config::load(base_dir).map_err(config_error)? {
        config.enabled = false;
        bridge_config::save(&config, base_dir).map_err(config_error)?;
    }
    secrets::clear_bot_token().map_err(secret_error)?;
    println!("bot_token: ABSENT");
    println!("bridge: disabled");
    println!("revoke the old token in BotFather (/revoke) before issuing a new one");
    Ok(())
}

/// Validates `--allow` values against the closed class list and drops
/// duplicates, preserving first-seen order.
///
/// The value is rendered with `{:?}` so a control character in a pasted
/// argument cannot reach the terminal raw.
fn parse_allow_classes(values: &[String]) -> Result<Vec<String>> {
    let mut classes: Vec<String> = Vec::new();
    for value in values {
        if !ALLOWED_CLASSES.contains(&value.as_str()) {
            bail!(
                "unknown action class {value:?}: the only class the bridge can allow today is `swap`"
            );
        }
        if !classes.iter().any(|existing| existing == value) {
            classes.push(value.clone());
        }
    }
    Ok(classes)
}

/// Renders only the classes the bridge knows, so a hand-edited config cannot
/// echo arbitrary text through `status`.
fn known_classes(config: &BridgeConfig) -> String {
    let mut known: Vec<&str> = ALLOWED_CLASSES
        .iter()
        .copied()
        .filter(|class| config.allow_classes.iter().any(|stored| stored == class))
        .collect();
    if known.is_empty() {
        "none".to_owned()
    } else {
        known.sort_unstable();
        known.join(",")
    }
}

/// Reads the bot token from stdin (one line), refusing an empty or malformed
/// value before it is wrapped.
///
/// Terminal echo is disabled while the line is typed: without that, the pasted
/// token is echoed into the terminal scrollback (a shared screen, a recorded
/// session) even though csq never prints it. When stdin is a pipe, `disable`
/// returns `None` — a pipe does not echo anywhere.
fn read_bot_token_from_stdin() -> Result<SecretString> {
    eprintln!(
        "Paste the Telegram bot token and press Enter (stored in the vault; never written to logs)."
    );
    let _echo = EchoGuard::disable();
    // The stdin line holds the raw token until it is parsed, so the buffer is
    // wiped on drop; the returned `SecretString` is the only long-lived copy.
    let mut raw = Zeroizing::new(String::new());
    std::io::stdin()
        .read_line(&mut raw)
        .context("could not read the bot token from stdin")?;
    let Some(token) = token_from_input(raw.as_str()) else {
        bail!("no bot token on stdin");
    };
    if !secrets::validate_bot_token_shape(token) {
        bail!("that does not look like a Telegram bot token (expected <bot id>:<secret>)");
    }
    Ok(SecretString::from(token.to_owned()))
}

/// Strips the trailing line terminator `read_line` keeps, and treats an empty
/// line as absent.
fn token_from_input(raw: &str) -> Option<&str> {
    let trimmed = raw.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn presence(present: bool) -> &'static str {
    if present {
        "PRESENT"
    } else {
        "ABSENT"
    }
}

/// Disables terminal echo while it is alive.
///
/// Same primitive as `commands::pool`'s `EchoGuard` and `commands::setkey`'s
/// termios block. `ISIG` is kept so Ctrl-C still interrupts and the `Drop`
/// guard restores echo. `disable` returns `None` when stdin is not a terminal:
/// a piped `setup` must still work, and a pipe echoes nowhere.
#[cfg(unix)]
struct EchoGuard(libc::termios);

#[cfg(unix)]
impl EchoGuard {
    fn disable() -> Option<Self> {
        let fd = libc::STDIN_FILENO;
        // SAFETY: `termios` is a plain C struct with no invalid bit patterns;
        // `tcgetattr` fills the stack local before it is read.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is this process's own stdin and `&mut original` is a
        // valid, properly aligned, exclusively borrowed termios for the call.
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return None;
        }
        let mut modified = original;
        modified.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ECHONL);
        modified.c_cc[libc::VMIN] = 1;
        modified.c_cc[libc::VTIME] = 0;
        // SAFETY: same live fd and a fully initialised `modified` termios; the
        // call only reads it.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &modified) } != 0 {
            return None;
        }
        Some(Self(original))
    }
}

#[cfg(unix)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        // SAFETY: restoring the termios captured by `disable` on the same fd;
        // the struct is owned by `self` and lives for the call.
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0);
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
}

#[cfg(windows)]
struct EchoGuard(*mut std::ffi::c_void, u32);

#[cfg(windows)]
impl EchoGuard {
    fn disable() -> Option<Self> {
        // SAFETY: STD_INPUT_HANDLE (-10) is a documented pseudo-handle; no
        // pointer argument is dereferenced by the caller.
        let handle = unsafe { get_std_handle((-10i32) as u32) };
        let mut mode = 0;
        // SAFETY: `handle` came from the call above and `&mut mode` is a valid
        // out-parameter; a failure is checked before `mode` is used.
        if unsafe { get_console_mode(handle, &mut mode) } == 0
            // SAFETY: same valid handle; the mode is the one just read. Bits
            // 1|2|4 are ENABLE_*_INPUT (processed, line, echo).
            || unsafe { set_console_mode(handle, mode & !(1 | 2 | 4)) } == 0
        {
            return None;
        }
        Some(Self(handle, mode))
    }
}

#[cfg(windows)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        // SAFETY: restoring the mode captured by `disable` on the same handle.
        unsafe {
            set_console_mode(self.0, self.1);
        }
    }
}

fn now_unix() -> Result<i64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("the system clock is before the Unix epoch")?;
    i64::try_from(elapsed.as_secs()).context("the system clock is out of range")
}

/// The pairing loop's clock value.
///
/// A failed read becomes the far future, past every challenge deadline, so
/// the handshake refuses (and the caller reports an expired window) instead of
/// polling forever with a deadline that can never arrive.
fn pairing_clock(now: Result<i64>) -> i64 {
    now.unwrap_or(i64::MAX)
}

/// Fixed-text error: the variant's message is already free of paths and
/// secret material, and the tag is what logs and bug reports should key on.
fn config_error(error: BridgeConfigError) -> anyhow::Error {
    anyhow::anyhow!("bridge state error: {error} ({})", error.error_kind_tag())
}

/// Enrolment failures carry fixed text; the tag is what to key support on.
fn enrol_error(error: EnrolError) -> anyhow::Error {
    anyhow::anyhow!("pairing failed: {error} ({})", error.error_kind_tag())
}

/// Telegram transport failures carry fixed text and, at most, an HTTP status.
fn api_error(error: TelegramApiError) -> anyhow::Error {
    anyhow::anyhow!("telegram api error: {error} ({})", error.error_kind_tag())
}

/// Only the fixed tag is surfaced; the vault's own message never reaches the
/// terminal, so an upstream body or path cannot echo a credential
/// (`security.md` MUST-2).
fn secret_error(error: SecretError) -> anyhow::Error {
    anyhow::anyhow!(
        "secret store error ({}); no secret material was read or written",
        error.error_kind_tag()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn token_input_strips_only_line_terminators() {
        assert_eq!(token_from_input("123456789:abc\n"), Some("123456789:abc"));
        assert_eq!(token_from_input("123456789:abc\r\n"), Some("123456789:abc"));
        assert_eq!(token_from_input("123456789:abc"), Some("123456789:abc"));
        assert_eq!(token_from_input("\n"), None);
        assert_eq!(token_from_input(""), None);
        // A leading space is not a terminator; the shape check refuses it.
        assert_eq!(token_from_input(" 123:abc\n"), Some(" 123:abc"));
    }

    #[test]
    fn presence_reports_no_values() {
        assert_eq!(presence(true), "PRESENT");
        assert_eq!(presence(false), "ABSENT");
    }

    #[test]
    fn allow_accepts_swap_and_drops_duplicates() {
        assert_eq!(
            parse_allow_classes(&values(&["swap"])).expect("swap is allowed"),
            values(&["swap"])
        );
        assert_eq!(
            parse_allow_classes(&values(&["swap", "swap"])).expect("duplicates collapse"),
            values(&["swap"])
        );
        assert_eq!(
            parse_allow_classes(&[]).expect("no classes is valid"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn allow_refuses_every_other_class_by_name() {
        for rejected in ["clear", "run", "", "SWAP", "swap ", "swap\n"] {
            let error = parse_allow_classes(&values(&[rejected]))
                .expect_err("unknown class must be refused");
            let text = error.to_string();
            assert!(text.starts_with("unknown action class"), "{text}");
            assert!(
                text.contains("swap"),
                "the error names the only class: {text}"
            );
            assert!(
                !text.contains(&format!("{rejected}\n")),
                "a control character must not reach the terminal raw: {text}"
            );
        }
    }

    #[test]
    fn no_flag_means_no_action_class_is_stored() {
        let config = BridgeConfig {
            enabled: true,
            owner_user_id: 1,
            owner_chat_id: 1,
            allow_classes: Vec::new(),
        };
        assert_eq!(known_classes(&config), "none");
        assert!(!config.allows_swap());
    }

    #[test]
    fn status_reports_only_known_classes() {
        let mut config = BridgeConfig {
            enabled: false,
            owner_user_id: 0,
            owner_chat_id: 0,
            allow_classes: Vec::new(),
        };
        assert_eq!(known_classes(&config), "none");
        config.allow_classes = values(&["swap"]);
        assert_eq!(known_classes(&config), "swap");
        // A hand-edited unknown entry is never echoed and grants nothing.
        config.allow_classes = values(&["swap", "evil\nclass"]);
        assert_eq!(known_classes(&config), "swap");
        config.allow_classes = values(&["evil\nclass"]);
        assert_eq!(known_classes(&config), "none");
        assert!(!config.allows_swap());
    }

    #[test]
    fn secret_error_never_includes_the_upstream_text() {
        let error = secret_error(SecretError::BackendUnavailable {
            reason: "upstream body: bot123456:SENTINEL-TOKEN".into(),
        });
        assert_eq!(error.to_string(), "secret store error (vault_backend_unavailable); no secret material was read or written");
        assert!(!error.to_string().contains("SENTINEL-TOKEN"));
    }

    #[test]
    fn a_failed_clock_read_fails_pairing_closed() {
        let challenge = PairingChallenge::generate(1_700_000_000).expect("challenge");
        let failed = pairing_clock(Err(anyhow::anyhow!("clock unavailable")));
        assert_eq!(failed, i64::MAX);
        assert!(
            challenge.is_expired(failed),
            "a failed clock read must read as past every deadline"
        );
        assert_eq!(pairing_clock(Ok(5)), 5);
    }

    #[test]
    fn config_error_includes_a_fixed_tag() {
        let error = config_error(BridgeConfigError::ConfigCorrupt);
        assert_eq!(
            error.to_string(),
            "bridge state error: bridge config file is not valid JSON (bridge_config_corrupt)"
        );
    }
}
