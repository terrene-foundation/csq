//! NSIS currentUser helper; no CLI/application/daemon initialization.
#[cfg(windows)]
fn main() {
    std::process::exit(csq_core::update::installer_admission::windows::run(
        std::env::args_os().skip(1),
    ));
}
#[cfg(not(windows))]
fn main() {
    eprintln!("CSQ_INSTALL_V1 REFUSED unsupported_platform");
    std::process::exit(2);
}
