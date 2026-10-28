//! Explicit test-utils fixture. It never opens an unscoped daemon event.
#[cfg(not(windows))]
fn main() {
    eprintln!("windows_daemon_stop_fixture_requires_windows");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    if run().is_err() {
        eprintln!("windows_daemon_stop_fixture_failed");
        std::process::exit(2);
    }
}

#[cfg(windows)]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        path::PathBuf,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::{
            Threading::{OpenEventW, WaitForSingleObject},
            WindowsProgramming::GetUserNameW,
        },
    };
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let offset = if args.first().is_some_and(|arg| arg == "daemon") {
        if args.get(1).is_none_or(|arg| arg != "start") {
            return Err("fixture_role_invalid".into());
        }
        2
    } else if args.first().is_some_and(|arg| arg == "status") {
        1
    } else {
        return Err("fixture_role_invalid".into());
    };
    if args.len() != offset + 6
        || args[offset] != "--fixture-scope"
        || args[offset + 2] != "--fixture-base"
        || args[offset + 4] != "--fixture-mode"
    {
        return Err("fixture_arguments_invalid".into());
    }
    let scope = args[offset + 1].to_str().ok_or("fixture_scope_invalid")?;
    if !scope.starts_with("-test-")
        || scope.len() > 120
        || !scope
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == b'-')
    {
        return Err("fixture_scope_invalid".into());
    }
    let base = PathBuf::from(&args[offset + 3]);
    if !base.is_absolute()
        || std::fs::read(base.join(".csq-stop-fixture"))? != b"csq-private-native-fixture-v1"
    {
        return Err("fixture_base_invalid".into());
    }
    let mode = args[offset + 5].to_str().ok_or("fixture_mode_invalid")?;
    if !matches!(mode, "exit" | "never") {
        return Err("fixture_mode_invalid".into());
    }
    let _event = csq_core::daemon::create_shutdown_event_scoped(scope)?;
    let mut user = vec![0u16; 257];
    let mut size = user.len() as u32;
    // SAFETY: writable username buffer covers its declared capacity.
    if unsafe { GetUserNameW(user.as_mut_ptr(), &mut size) } == 0
        || size < 2
        || size as usize > user.len()
    {
        return Err("fixture_username_failed".into());
    }
    let user = String::from_utf16(&user[..size as usize - 1])?;
    let name: Vec<_> = format!(r"Local\csq-daemon-shutdown-{user}{scope}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // SAFETY: validated test scope and live NUL-terminated name; observation only.
    let raw = unsafe { OpenEventW(0x0010_0000, 0, name.as_ptr()) };
    if raw == 0 {
        return Err("fixture_event_open_failed".into());
    }
    struct Event(HANDLE);
    impl Drop for Event {
        fn drop(&mut self) {
            // SAFETY: sole ownership of the successful secondary event open.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let event = Event(raw);
    std::fs::write(base.join("ready"), b"1")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut observed_signal = false;
    while !base.join("stop").exists() && Instant::now() < deadline {
        // SAFETY: retained synchronize event handle; zero-duration observation.
        match unsafe { WaitForSingleObject(event.0, 0) } {
            WAIT_OBJECT_0 => {
                if !observed_signal {
                    std::fs::write(base.join("signalled"), b"1")?;
                    observed_signal = true;
                }
                if mode == "exit" {
                    std::thread::sleep(Duration::from_millis(250));
                    break;
                }
            }
            WAIT_TIMEOUT => {}
            _ => return Err("fixture_event_wait_failed".into()),
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}
