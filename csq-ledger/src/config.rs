//! Server CLI configuration (M10).
//!
//! Parsed from command-line flags + environment. The signing-key path is read
//! from `CSQ_LEDGER_SIGNING_KEY_PATH` (see [`crate::signing`]); everything else
//! is a flag with an env fallback for container deployment.

use std::path::PathBuf;

use clap::Parser;

/// Default anchor cadence: one anchor per day (per workspace-owner decision §5).
pub const DEFAULT_ANCHOR_CADENCE_SECS: u64 = 86_400;

/// csq-ledger server configuration.
#[derive(Debug, Parser)]
#[command(
    name = "csq-ledger",
    about = "Foundation-owned transparency-log server for csq audit anchoring (M10)",
    version
)]
pub struct Config {
    /// Data directory for segment files, the size marker, anchor receipts, and
    /// the auto-generated signing key. Maps to the Docker volume mount point.
    #[arg(
        long,
        env = "CSQ_LEDGER_DATA_DIR",
        default_value = "/var/lib/csq-ledger"
    )]
    pub data_dir: PathBuf,

    /// TCP port to bind.
    #[arg(long, env = "CSQ_LEDGER_PORT", default_value_t = 8080)]
    pub port: u16,

    /// Bind address. Defaults to all interfaces (operator fronts this with a
    /// reverse proxy / firewall per the no-authn-in-M10 scope).
    #[arg(long, env = "CSQ_LEDGER_BIND", default_value = "0.0.0.0")]
    pub bind: String,

    /// External sink to anchor checkpoints to (Strengthening 1). One of the
    /// M07 sink names: `rekor`, `s3`, `azure`, `gcp`, or another csq-ledger
    /// instance. Absent = no external anchoring. Requires the binary to be
    /// built with the matching `csq-core/<name>-sink` feature.
    #[arg(long, value_name = "NAME")]
    pub anchor_to_sink: Option<String>,

    /// Seconds between routine anchors when `--anchor-to-sink` is set.
    /// Default 86400 (1/day). High-impact ops anchor immediately regardless.
    #[arg(long, default_value_t = DEFAULT_ANCHOR_CADENCE_SECS)]
    pub anchor_cadence: u64,
}

impl Config {
    /// The socket address string (`bind:port`) to bind the axum server to.
    #[must_use]
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.bind, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `test config_parses_minimal_args_with_defaults`
    #[test]
    fn config_parses_minimal_args_with_defaults() {
        let cfg = Config::try_parse_from(["csq-ledger", "--data-dir", "/tmp/x"]).unwrap();
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.bind, "0.0.0.0");
        assert_eq!(cfg.anchor_cadence, DEFAULT_ANCHOR_CADENCE_SECS);
        assert!(cfg.anchor_to_sink.is_none());
    }

    /// `test config_parses_anchor_to_sink_and_cadence`
    #[test]
    fn config_parses_anchor_to_sink_and_cadence() {
        let cfg = Config::try_parse_from([
            "csq-ledger",
            "--data-dir",
            "/tmp/x",
            "--anchor-to-sink",
            "rekor",
            "--anchor-cadence",
            "3600",
        ])
        .unwrap();
        assert_eq!(cfg.anchor_to_sink.as_deref(), Some("rekor"));
        assert_eq!(cfg.anchor_cadence, 3600);
    }

    /// `test config_socket_addr_formats_bind_and_port`
    #[test]
    fn config_socket_addr_formats_bind_and_port() {
        let cfg = Config::try_parse_from([
            "csq-ledger",
            "--data-dir",
            "/tmp/x",
            "--port",
            "9090",
            "--bind",
            "127.0.0.1",
        ])
        .unwrap();
        assert_eq!(cfg.socket_addr(), "127.0.0.1:9090");
    }
}
