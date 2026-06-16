// Tauri's build script generates resource bindings consumed by the desktop
// surface. It MUST run only when the desktop feature is active — invoking
// `tauri_build::build()` for a CLI-only build pulls in WebView2/WKWebView
// scaffolding that has no place in a `--no-default-features --features cli`
// binary. Cargo exposes feature flags as `CARGO_FEATURE_<NAME>` env vars
// during build script execution, so the gate is a single env_var check.
fn main() {
    if std::env::var("CARGO_FEATURE_DESKTOP").is_ok() {
        tauri_build::build();
    }
}
