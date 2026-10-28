// The startup loader reads this PE flag before any helper code can run.
// Runtime SetDefaultDllDirectories alone cannot protect initial static imports.
fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ENV");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "msvc" {
        println!("cargo:rustc-link-arg-bin=csq-upgrade-guard=/DEPENDENTLOADFLAG:0x800");
        println!("cargo:rustc-link-arg-bin=csq-installer-admission=/DEPENDENTLOADFLAG:0x800");
    }
}
