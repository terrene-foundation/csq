//! Pure project MCP admission for Claude 2.1.292 source-restricted launches.
//! This does not establish trust, read files, launch servers, or disable native
//! managed MCP policy. Launch owners provide already source-admitted settings
//! and exact workspace state; project bytes never supply their own authority.
//! Every original descriptor is validated before selection. Invalid entries
//! are skipped with typed warnings; valid approved siblings remain available.
//! This pure helper is not a native MCP runtime parity certification.
use serde_json::{Map, Value};
use std::collections::BTreeSet;

const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_SERVERS: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SettingsSource {
    User,
    Project,
    Local,
    Flag,
    Managed,
}

pub struct ScopedSettings<'a> {
    pub source: SettingsSource,
    /// Native-authorized settings from this source, never an arbitrary merged
    /// object relabelled as User or Managed by the project configuration.
    pub settings: &'a Value,
}

pub struct AdmissionContext<'a> {
    /// Proved against the native persisted workspace key by the launch owner.
    pub persisted_trust: bool,
    /// State for that exact key in the native user configuration. In particular,
    /// disabledMcpServers is workspace state, not a project settings field.
    pub workspace_state: &'a Value,
    /// Actual names from native Local, Managed and existing Explicit server
    /// sources. Rehoming project to Explicit must not override those sources.
    pub higher_precedence_names: &'a BTreeSet<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Admission {
    pub config: Option<Value>,
    /// The launch owner must display these even when config is None.
    pub warnings: Vec<ServerWarning>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServerWarning {
    /// Quoted ASCII-escaped name, bounded to 128 original Unicode characters.
    /// Descriptor fields and their potentially secret values are never copied.
    pub server_name: String,
    pub reason: WarningReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningReason {
    InvalidName,
    MalformedDescriptor,
    UnsupportedTransport,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum McpError {
    #[error("MCP admission input exceeds its bound")]
    Limit,
    #[error("MCP admission input is malformed")]
    Malformed,
    #[error("MCP settings source occurs more than once")]
    DuplicateSource,
    #[error("MCP transport cannot be admitted from project configuration")]
    UnsupportedTransport,
}

/// Return only previously approved project descriptors. An empty result means
/// no extra --mcp-config argument; it does not suppress existing user servers.
/// Native managed policy remains authoritative when the caller launches Claude.
pub fn admit(
    project_config: &Value,
    sources: &[ScopedSettings<'_>],
    context: AdmissionContext<'_>,
) -> Result<Admission, McpError> {
    bounded_object(project_config)?;
    let servers = project_config
        .get("mcpServers")
        .and_then(Value::as_object)
        .ok_or(McpError::Malformed)?;
    if servers.len() > MAX_SERVERS || sources.len() > 5 {
        return Err(McpError::Limit);
    }
    let (validated_names, warnings) = validate_original_servers(servers);
    if !context.persisted_trust {
        return Ok(Admission {
            config: None,
            warnings,
        });
    }
    bounded_object(context.workspace_state)?;
    let mut seen = BTreeSet::new();
    let mut ordered: Vec<_> = sources.iter().collect();
    ordered.sort_by_key(|entry| entry.source);
    let mut enabled = Vec::new();
    let mut rejected = Vec::new();
    let mut enable_all = false;
    for entry in ordered {
        if !seen.insert(entry.source) {
            return Err(McpError::DuplicateSource);
        }
        bounded_object(entry.settings)?;
        enabled.extend(string_list(entry.settings, "enabledMcpjsonServers")?);
        rejected.extend(string_list(entry.settings, "disabledMcpjsonServers")?);
        if let Some(value) = entry.settings.get("enableAllProjectMcpServers") {
            enable_all = value.as_bool().ok_or(McpError::Malformed)?;
        }
    }
    let disabled = string_list(context.workspace_state, "disabledMcpServers")?;
    let builtin_enabled = string_list(context.workspace_state, "enabledMcpServers")?;
    let mut admitted = Map::new();
    for (name, descriptor) in servers {
        if !validated_names.contains(name.as_str()) {
            continue;
        }
        if context.higher_precedence_names.contains(name)
            || disabled.contains(&name.as_str())
            || (name == "computer-use" && !builtin_enabled.contains(&name.as_str()))
            || rejected.iter().any(|rule| same_native_name(rule, name))
        {
            continue;
        }
        if !enable_all && !enabled.iter().any(|rule| same_native_name(rule, name)) {
            continue;
        }
        // Preserve original bytes represented by this Value, including unknown
        // fields and native catch/default/transform inputs. Native parsing and
        // environment expansion remain authoritative at launch.
        admitted.insert(name.clone(), descriptor.clone());
    }
    Ok(Admission {
        config: (!admitted.is_empty()).then(|| {
            let mut config = Map::new();
            config.insert("mcpServers".into(), Value::Object(admitted));
            Value::Object(config)
        }),
        warnings,
    })
}

fn validate_original_servers(servers: &Map<String, Value>) -> (BTreeSet<&str>, Vec<ServerWarning>) {
    let mut valid = BTreeSet::new();
    let mut warnings = Vec::new();
    for (name, descriptor) in servers {
        let reason =
            if name.is_empty() || name.len() > 4096 || name.contains('\0') || name == "__proto__" {
                Some(WarningReason::InvalidName)
            } else {
                match validate_descriptor(descriptor) {
                    Ok(()) => None,
                    Err(McpError::UnsupportedTransport) => {
                        Some(WarningReason::UnsupportedTransport)
                    }
                    Err(_) => Some(WarningReason::MalformedDescriptor),
                }
            };
        if let Some(reason) = reason {
            warnings.push(ServerWarning {
                server_name: warning_name(name),
                reason,
            });
        } else {
            valid.insert(name.as_str());
        }
    }
    (valid, warnings)
}

fn warning_name(name: &str) -> String {
    let escaped: String = name
        .chars()
        .take(128)
        .flat_map(char::escape_default)
        .collect();
    format!(
        "\"{escaped}{}\"",
        if name.chars().count() > 128 {
            "..."
        } else {
            ""
        }
    )
}

fn validate_descriptor(value: &Value) -> Result<(), McpError> {
    let descriptor = value.as_object().ok_or(McpError::Malformed)?;
    let transport = match descriptor.get("type") {
        None => "stdio",
        Some(value) => value.as_str().ok_or(McpError::Malformed)?,
    };
    // Claude 2.1.292 Bqe/wRt/dit/ZXt and m_t. SDK and connector entries
    // require their native host source; IDE entries are not project transports.
    if !matches!(
        transport,
        "stdio" | "sse" | "http" | "streamable-http" | "ws"
    ) {
        return Err(McpError::UnsupportedTransport);
    }
    optional(descriptor, "timeout", positive_safe_integer)?;
    for key in ["alwaysLoad", "bareElicitationCapability"] {
        optional(descriptor, key, is_boolean)?;
    }
    // role and request_timeout_ms use native .catch(undefined), so invalid
    // values are accepted here and left for the original native parser to drop.
    if transport == "stdio" {
        if descriptor
            .get("command")
            .and_then(Value::as_str)
            .is_none_or(|command| command.is_empty())
        {
            return Err(McpError::Malformed);
        }
        optional(descriptor, "args", string_array)?;
        optional(descriptor, "env", string_map)?;
        return Ok(());
    }
    // Native server URL schemas require a string, not URL syntax or a scheme.
    if !descriptor.get("url").is_some_and(Value::is_string) {
        return Err(McpError::Malformed);
    }
    optional(descriptor, "headers", string_map)?;
    optional(descriptor, "headersHelper", is_string)?;
    if transport != "ws" {
        optional(descriptor, "oauth", oauth)?;
        optional(descriptor, "discoveryCache", is_boolean)?;
        optional(descriptor, "tools", tools)?;
        optional(descriptor, "toolPermissions", tool_permissions)?;
    }
    Ok(())
}

fn optional(
    object: &Map<String, Value>,
    key: &str,
    valid: fn(&Value) -> bool,
) -> Result<(), McpError> {
    if object.get(key).is_some_and(|value| !valid(value)) {
        return Err(McpError::Malformed);
    }
    Ok(())
}

fn is_string(value: &Value) -> bool {
    value.is_string()
}

fn is_boolean(value: &Value) -> bool {
    value.is_boolean()
}

fn positive_safe_integer(value: &Value) -> bool {
    value.as_f64().is_some_and(|number| {
        number > 0.0 && number <= 9_007_199_254_740_991.0 && number.fract() == 0.0
    })
}

fn string_array(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(Value::is_string))
}

fn string_map(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|items| items.values().all(Value::is_string))
}

fn oauth(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    optional(object, "clientId", is_string).is_ok()
        && optional(object, "callbackPort", positive_safe_integer).is_ok()
        && optional(object, "authServerMetadataUrl", |value| {
            value
                .as_str()
                .is_some_and(|url| url.starts_with("https://") && reqwest::Url::parse(url).is_ok())
        })
        .is_ok()
        && optional(object, "scopes", |value| {
            value.as_str().is_some_and(|scopes| !scopes.is_empty())
        })
        .is_ok()
        && optional(object, "xaa", is_boolean).is_ok()
}

fn tools(value: &Value) -> bool {
    value.as_array().is_some_and(|items| {
        items.iter().all(|item| {
            let Some(object) = item.as_object() else {
                return false;
            };
            object.get("name").is_some_and(Value::is_string)
                && optional(object, "permission_policy", |value| {
                    matches!(
                        value.as_str(),
                        Some("always_allow" | "always_ask" | "always_deny")
                    )
                })
                .is_ok()
        })
    })
}

fn tool_permissions(value: &Value) -> bool {
    value.as_object().is_some_and(|items| {
        items
            .values()
            .all(|value| matches!(value.as_str(), Some("allow" | "ask" | "blocked")))
    })
}

fn bounded_object(value: &Value) -> Result<(), McpError> {
    if !value.is_object() {
        return Err(McpError::Malformed);
    }
    if serde_json::to_vec(value)
        .map_err(|_| McpError::Malformed)?
        .len()
        > MAX_CONFIG_BYTES
    {
        return Err(McpError::Limit);
    }
    Ok(())
}

fn string_list<'a>(value: &'a Value, key: &str) -> Result<Vec<&'a str>, McpError> {
    match value.get(key) {
        None => Ok(Vec::new()),
        Some(value) => value
            .as_array()
            .filter(|items| items.len() <= MAX_SERVERS)
            .ok_or(McpError::Malformed)?
            .iter()
            .map(|item| {
                item.as_str()
                    .filter(|text| text.len() <= 4096 && !text.contains('\0'))
                    .ok_or(McpError::Malformed)
            })
            .collect(),
    }
}

fn same_native_name(left: &str, right: &str) -> bool {
    if left.starts_with("plugin:") || right.starts_with("plugin:") {
        return left == right;
    }
    normalize_name(left) == normalize_name(right)
}

fn normalize_name(name: &str) -> String {
    // Native xn() uses a non-Unicode JavaScript regex, so a supplementary
    // Unicode character becomes two underscores, one for each UTF-16 unit.
    let normalized: String = name
        .encode_utf16()
        .map(|unit| {
            if unit < 128 && ((unit as u8).is_ascii_alphanumeric() || unit == 45 || unit == 95) {
                char::from_u32(unit.into()).expect("ASCII unit")
            } else {
                '_'
            }
        })
        .collect();
    if name.starts_with("claude.ai ") {
        normalized
            .split('_')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("_")
    } else {
        normalized
    }
}

#[cfg(test)]
#[path = "mcp_tests.rs"]
mod tests;
