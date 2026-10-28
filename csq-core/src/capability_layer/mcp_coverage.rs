//! MCP coverage detection for the `csq doctor` partial-coverage warning
//! (spec 10 §10.8.3).
//!
//! The capability layer's MCP gate (`§10.8`) intercepts prompt-edit tool
//! allow/deny BEFORE the downstream CLI is spawned. It does NOT see the
//! runtime MCP traffic of the CLIs' OWN MCP servers (those connect inside
//! the CLI process after spawn). So when the user has CLI-bound MCP servers
//! configured AND the capability layer is enabled, csq's coverage is
//! *partial* — and `csq doctor` says so.
//!
//! This module is pure detection: it reads only the EXISTENCE + non-empty
//! server map of each CLI's native MCP config under a given home dir; it
//! never reads server contents and writes nothing. The enforcement gate
//! itself is a separate concern (the Amendment-H-gated `.coc/tools/policy.json`
//! reader; see `mcp_gate.rs` + the CU4 task file).

use std::path::Path;

/// A CLI surface whose native config declares ≥1 MCP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CliMcpSource {
    Claude,
    Codex,
    Gemini,
}

impl CliMcpSource {
    pub fn as_str(self) -> &'static str {
        match self {
            CliMcpSource::Claude => "claude",
            CliMcpSource::Codex => "codex",
            CliMcpSource::Gemini => "gemini",
        }
    }
}

/// Returns the CLI surfaces that have ≥1 MCP server configured in their
/// native config under `home`, in deterministic order (Claude, Codex,
/// Gemini). Paths per spec 10 §10.8.3:
/// - cc:     `~/.claude/mcp_settings.json`  (JSON, `mcpServers` map)
/// - codex:  `~/.codex/mcp.toml`            (TOML, `mcp_servers` table)
/// - gemini: `~/.gemini/settings.json`      (JSON, `mcpServers` map)
///
/// A missing/unreadable/unparseable/empty-map config is simply "no servers"
/// (never an error — this drives an advisory only). Detection keys on the
/// `mcpServers` (JSON) / `mcp_servers` (TOML) convention confirmed for
/// gemini-cli (`providers/gemini/settings.rs`); a config using a different
/// shape yields no advisory rather than a false alarm.
pub fn detect_cli_bound_mcp_servers(home: &Path) -> Vec<CliMcpSource> {
    let mut out = Vec::new();
    if json_has_nonempty_mcp_servers(&home.join(".claude").join("mcp_settings.json")) {
        out.push(CliMcpSource::Claude);
    }
    if toml_has_nonempty_mcp_servers(&home.join(".codex").join("mcp.toml")) {
        out.push(CliMcpSource::Codex);
    }
    if json_has_nonempty_mcp_servers(&home.join(".gemini").join("settings.json")) {
        out.push(CliMcpSource::Gemini);
    }
    out
}

fn json_has_nonempty_mcp_servers(path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    v.get("mcpServers")
        .and_then(|m| m.as_object())
        .is_some_and(|m| !m.is_empty())
}

fn toml_has_nonempty_mcp_servers(path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(v) = toml::from_str::<toml::Value>(&text) else {
        return false;
    };
    // codex-cli writes `mcp_servers` (snake_case) tables in mcp.toml; accept
    // either spelling defensively.
    let table = v.get("mcp_servers").or_else(|| v.get("mcpServers"));
    table
        .and_then(|t| t.as_table())
        .is_some_and(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write(home: &Path, rel: &str, body: &str) {
        let p = home.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    #[test]
    fn empty_home_detects_nothing() {
        let h = TempDir::new().unwrap();
        assert!(detect_cli_bound_mcp_servers(h.path()).is_empty());
    }

    #[test]
    fn claude_mcp_settings_with_servers_detected() {
        let h = TempDir::new().unwrap();
        write(
            h.path(),
            ".claude/mcp_settings.json",
            r#"{"mcpServers":{"filesystem":{"command":"mcp-fs"}}}"#,
        );
        assert_eq!(
            detect_cli_bound_mcp_servers(h.path()),
            vec![CliMcpSource::Claude]
        );
    }

    #[test]
    fn empty_mcp_servers_map_is_not_detected() {
        let h = TempDir::new().unwrap();
        write(
            h.path(),
            ".claude/mcp_settings.json",
            r#"{"mcpServers":{}}"#,
        );
        write(h.path(), ".gemini/settings.json", r#"{"ui":{"theme":"x"}}"#);
        assert!(detect_cli_bound_mcp_servers(h.path()).is_empty());
    }

    #[test]
    fn codex_mcp_toml_with_table_detected() {
        let h = TempDir::new().unwrap();
        write(
            h.path(),
            ".codex/mcp.toml",
            "[mcp_servers.filesystem]\ncommand = \"mcp-fs\"\n",
        );
        assert_eq!(
            detect_cli_bound_mcp_servers(h.path()),
            vec![CliMcpSource::Codex]
        );
    }

    #[test]
    fn gemini_settings_mcp_block_detected() {
        let h = TempDir::new().unwrap();
        write(
            h.path(),
            ".gemini/settings.json",
            r#"{"mcpServers":{"fs":{"command":"x"}},"ui":{"theme":"y"}}"#,
        );
        assert_eq!(
            detect_cli_bound_mcp_servers(h.path()),
            vec![CliMcpSource::Gemini]
        );
    }

    #[test]
    fn all_three_detected_in_deterministic_order() {
        let h = TempDir::new().unwrap();
        write(
            h.path(),
            ".claude/mcp_settings.json",
            r#"{"mcpServers":{"a":{"command":"x"}}}"#,
        );
        write(
            h.path(),
            ".codex/mcp.toml",
            "[mcp_servers.b]\ncommand = \"y\"\n",
        );
        write(
            h.path(),
            ".gemini/settings.json",
            r#"{"mcpServers":{"c":{"command":"z"}}}"#,
        );
        assert_eq!(
            detect_cli_bound_mcp_servers(h.path()),
            vec![
                CliMcpSource::Claude,
                CliMcpSource::Codex,
                CliMcpSource::Gemini
            ]
        );
    }

    #[test]
    fn malformed_json_is_not_detected() {
        let h = TempDir::new().unwrap();
        write(h.path(), ".claude/mcp_settings.json", "{not valid json");
        assert!(detect_cli_bound_mcp_servers(h.path()).is_empty());
    }
}
