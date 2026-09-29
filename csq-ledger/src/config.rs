//! Server CLI configuration (M10).
//!
//! Parsed from command-line flags + environment. The signing-key path is read
//! from `CSQ_LEDGER_SIGNING_KEY_PATH` (see [`crate::signing`]); everything else
//! is a flag with an env fallback for container deployment.

use std::net::{IpAddr, SocketAddr};
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

    /// Literal IP address for the read/write listener (no hostnames).
    /// Non-loopback addresses require --allow-public-bind.
    #[arg(long, env = "CSQ_LEDGER_BIND", default_value = "127.0.0.1")]
    pub bind: IpAddr,

    /// Acknowledge non-loopback exposure of either listener, including private
    /// and wildcard addresses. No authentication is added: operators MUST keep
    /// both listeners inside a trusted network, never on the public internet.
    #[arg(long, env = "CSQ_LEDGER_ALLOW_PUBLIC_BIND")]
    pub allow_public_bind: bool,

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

    /// TCP port for the AUTHORITY listener (`POST .../revoke`,
    /// `POST .../verifier-bootstraps/{id}`). Split from the read/write
    /// listener (H3): revocation is irreversible, so any principal that can
    /// reach it can permanently deny any anchor for any tenant. A distinct
    /// port lets the operator firewall it independently of the read/write
    /// traffic the log otherwise serves.
    #[arg(long, env = "CSQ_LEDGER_AUTHORITY_PORT", default_value_t = 8081)]
    pub authority_port: u16,

    /// Literal IP address for the AUTHORITY listener (no hostnames).
    /// Non-loopback addresses require --allow-public-bind.
    #[arg(long, env = "CSQ_LEDGER_AUTHORITY_BIND", default_value = "127.0.0.1")]
    pub authority_bind: IpAddr,
}

impl Config {
    /// Reject non-loopback exposure BEFORE creating files or starting tasks.
    /// Validate the same typed IPs passed to bind: no DNS re-resolution/TOCTOU.
    pub fn validate_bind_posture(&self) -> Result<(), String> {
        for (flag, addr) in [
            ("--bind", self.bind),
            ("--authority-bind", self.authority_bind),
        ] {
            if !addr.is_loopback() && !self.allow_public_bind {
                return Err(format!(
                    "{flag} {addr} is non-loopback; --allow-public-bind (or \
                     CSQ_LEDGER_ALLOW_PUBLIC_BIND=true) is required; keep both \
                     unauthenticated listeners inside a trusted network"
                ));
            }
        }
        Ok(())
    }

    /// Exact read/write socket address; accepts IPv4 and IPv6, never DNS.
    #[must_use]
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.bind, self.port)
    }

    /// Exact AUTHORITY socket address; accepts IPv4 and IPv6, never DNS.
    #[must_use]
    pub fn authority_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.authority_bind, self.authority_port)
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
        assert_eq!(cfg.bind.to_string(), "127.0.0.1");
        assert!(!cfg.allow_public_bind);
        assert!(cfg.validate_bind_posture().is_ok());
        assert_eq!(cfg.anchor_cadence, DEFAULT_ANCHOR_CADENCE_SECS);
        assert!(cfg.anchor_to_sink.is_none());
        assert_eq!(cfg.authority_port, 8081);
        assert_eq!(
            cfg.authority_bind.to_string(),
            "127.0.0.1",
            "the authority listener defaults to loopback-only (H3): internal-only \
             is the out-of-box posture, not a deployment note"
        );
    }

    /// `test config_authority_socket_addr_formats_bind_and_port`
    #[test]
    fn config_authority_socket_addr_formats_bind_and_port() {
        let cfg = Config::try_parse_from([
            "csq-ledger",
            "--data-dir",
            "/tmp/x",
            "--authority-port",
            "9091",
            "--authority-bind",
            "10.0.0.5",
        ])
        .unwrap();
        assert_eq!(cfg.authority_socket_addr().to_string(), "10.0.0.5:9091");
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
        assert_eq!(cfg.socket_addr().to_string(), "127.0.0.1:9090");
    }

    #[test]
    fn explicit_acknowledgement_accepts_non_loopback_on_both_typed_addresses() {
        for ip in ["0.0.0.0", "10.0.0.5", "8.8.8.8", "::", "fc00::1"] {
            let addr: IpAddr = ip.parse().unwrap();
            let cfg = Config {
                data_dir: PathBuf::new(),
                port: 0,
                bind: addr,
                allow_public_bind: true,
                anchor_to_sink: None,
                anchor_cadence: DEFAULT_ANCHOR_CADENCE_SECS,
                authority_port: 0,
                authority_bind: addr,
            };
            assert!(cfg.validate_bind_posture().is_ok(), "{ip}");
            assert_eq!(cfg.socket_addr().ip(), addr);
            assert_eq!(cfg.authority_socket_addr().ip(), addr);
        }
    }
}
