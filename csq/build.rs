// Tauri's build script generates resource bindings consumed by the desktop
// surface. It MUST run only when the desktop feature is active — invoking
// `tauri_build::build()` for a CLI-only build pulls in WebView2/WKWebView
// scaffolding that has no place in a `--no-default-features --features cli`
// binary. Cargo exposes feature flags as `CARGO_FEATURE_<NAME>` env vars
// during build script execution, so the gate is a single env_var check.
#[path = "../csq-core/src/messaging/image_build_grammar.rs"]
mod image_build_grammar;
fn build_input(name: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed={name}");
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err("csq image build input is not valid Unicode".into()),
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use image_build_grammar::{validate_build_target, validate_build_version, validate_revision};
    let revision = build_input("CSQ_BUILD_REVISION")?;
    let state = build_input("CSQ_BUILD_SOURCE_STATE")?;
    let target = std::env::var("TARGET").map_err(|_| "csq image target unavailable")?;
    if revision.as_ref().is_some_and(|r| !validate_revision(r))
        || state
            .as_ref()
            .is_some_and(|s| !matches!(s.as_str(), "clean" | "dirty" | "unknown"))
        || !validate_build_target(&target)
        || !validate_build_version(env!("CARGO_PKG_VERSION"))
    {
        return Err("csq image build metadata refused".into());
    }
    let state = if revision.is_none() {
        "unknown"
    } else {
        state.as_deref().unwrap_or("unknown")
    };
    let revision = revision.as_deref().unwrap_or("");
    println!("cargo:rerun-if-changed=../csq-core/src/messaging/image_build_grammar.rs");
    println!("cargo:rustc-env=CSQ_IMAGE_REVISION={revision}");
    println!("cargo:rustc-env=CSQ_IMAGE_SOURCE_STATE={state}");
    println!("cargo:rustc-env=CSQ_IMAGE_TARGET={target}");
    if std::env::var("CARGO_FEATURE_DESKTOP").is_ok() {
        tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
            tauri_build::AppManifest::new().commands(&[
                "pool_list",
                "pool_add",
                "pool_remove",
                "pool_set_reset",
            ]),
        ))?;
    }
    Ok(())
}
