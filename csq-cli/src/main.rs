use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("CSQ_LOG").unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();

    tracing::info!("csq v{}", env!("CARGO_PKG_VERSION"));

    // TODO: clap routing will be added in M7-11
    println!("csq v{} — not yet implemented", env!("CARGO_PKG_VERSION"));
    println!("This is the v2.0 Rust binary. The v1.x bash script is at ./csq");

    Ok(())
}
