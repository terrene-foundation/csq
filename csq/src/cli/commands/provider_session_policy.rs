//! Owner-configured launch posture. This is not a filesystem isolation boundary.

use super::*;
use serde::Deserialize;
use url::{Host, Url};

const KEY: &str = "provider_session.primary_checkout";
const POLICY_LIMIT: u64 = 65_536;

#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
enum Posture {
    #[default]
    Allow,
    Warn,
    Refuse,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Policy {
    primary_checkout: Option<Posture>,
    trusted_endpoints: Option<Vec<String>>,
    trust_loopback: Option<bool>,
    allow_repo_relax: Option<bool>,
}

fn read_json(path: &Path, limit: u64) -> Result<Option<serde_json::Value>> {
    use std::io::Read;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() => {
            bail!("provider-session fence: configuration is not a regular file; check {KEY}")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => bail!("provider-session fence: cannot inspect configuration; check {KEY}"),
        _ => {}
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return match std::fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                _ => Err(anyhow!(
                    "provider-session fence: unreadable present configuration; check {KEY}"
                )),
            };
        }
        Err(_) => bail!("provider-session fence: cannot read configuration; check {KEY}"),
    };
    if !file
        .metadata()
        .map_err(|_| anyhow!("provider-session fence: cannot inspect configuration; check {KEY}"))?
        .is_file()
    {
        bail!("provider-session fence: configuration is not a regular file; check {KEY}");
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow!("provider-session fence: cannot read configuration; check {KEY}"))?;
    if bytes.len() as u64 > limit {
        bail!("provider-session fence: configuration exceeds size limit; check {KEY}");
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow!("provider-session fence: invalid configuration JSON; check {KEY}"))?;
    if !value.is_object() {
        bail!("provider-session fence: configuration must be an object; check {KEY}");
    }
    Ok(Some(value))
}

fn policy_file(path: &Path) -> Result<Option<Policy>> {
    let Some(value) = read_json(path, POLICY_LIMIT)? else {
        return Ok(None);
    };
    let Some(namespace) = value.get("provider_session") else {
        return Ok(None);
    };
    if [
        "primary_checkout",
        "trusted_endpoints",
        "trust_loopback",
        "allow_repo_relax",
    ]
    .iter()
    .any(|key| namespace.get(key).is_some_and(serde_json::Value::is_null))
    {
        bail!("provider-session fence: malformed policy; check {KEY}");
    }
    let policy: Policy = serde_json::from_value(namespace.clone())
        .map_err(|_| anyhow!("provider-session fence: malformed policy; check {KEY}"))?;
    if policy
        .trusted_endpoints
        .as_ref()
        .is_some_and(|endpoints| endpoints.len() > 256)
    {
        bail!("provider-session fence: too many trusted endpoints; check {KEY}");
    }
    for endpoint in policy.trusted_endpoints.iter().flatten() {
        let parsed = parse_endpoint(endpoint)?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            bail!("provider-session fence: trusted_endpoints requires credential-free HTTP(S) origins; check {KEY}");
        }
    }
    Ok(Some(policy))
}

fn parse_endpoint(endpoint: &str) -> Result<Url> {
    if endpoint.len() > 16_384 || endpoint.chars().any(char::is_control) {
        bail!("provider-session fence: invalid endpoint; check {KEY}");
    }
    let parsed = Url::parse(endpoint)
        .map_err(|_| anyhow!("provider-session fence: invalid endpoint; check {KEY}"))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
        bail!("provider-session fence: endpoint must use HTTP(S); check {KEY}");
    }
    Ok(parsed)
}

/// Read global policy and the outermost primary owner's policy before admission.
fn load_policy(base_dir: &Path, cwd: &Path) -> Result<(Policy, Option<PathBuf>, Option<bool>)> {
    let global = policy_file(&base_dir.join("provider-session-policy.json"))?;
    let context = super::provider_session_repository_context(cwd);
    let project_root = context.as_ref().ok().and_then(|(root, _, _)| root.clone());
    let owner_root = context
        .as_ref()
        .ok()
        .and_then(|(_, primary, _)| primary.clone());
    let repo = match owner_root {
        Some(root) => policy_file(&root.join(".coc/csq.json"))?,
        None => None,
    };
    let mut policy = global.unwrap_or_default();
    if let Some(repo) = repo {
        if repo.allow_repo_relax.is_some() {
            bail!("provider-session fence: allow_repo_relax is global-only; check {KEY}");
        }
        let floor = policy.primary_checkout.unwrap_or_default();
        let tighten = floor != Posture::Allow && policy.allow_repo_relax != Some(true);
        let global_loopback = loopback_trusted(&policy);
        if let Some(posture) = repo.primary_checkout {
            policy.primary_checkout = Some(if tighten { posture.max(floor) } else { posture });
        }
        if let Some(endpoints) = repo.trusted_endpoints {
            policy.trusted_endpoints = Some(if tighten {
                endpoints
                    .into_iter()
                    .filter(|endpoint| {
                        parse_endpoint(endpoint)
                            .is_ok_and(|endpoint| endpoint_trusted(&policy, &endpoint))
                    })
                    .collect()
            } else {
                endpoints
            });
        }
        if let Some(trust_loopback) = repo.trust_loopback {
            policy.trust_loopback = Some(trust_loopback && (!tighten || global_loopback));
        }
    }
    Ok((
        policy,
        project_root,
        context
            .ok()
            .and_then(|(_, primary, ambiguous)| (!ambiguous).then_some(primary.is_some())),
    ))
}

#[cfg(any(test, feature = "native-harness"))]
pub(super) fn evaluate(base_dir: &Path, cwd: &Path, endpoint: &str) -> Result<Option<String>> {
    let (policy, _, primary) = load_policy(base_dir, cwd)?;
    evaluate_policy(&policy, primary, endpoint)
}

fn evaluate_policy(
    policy: &Policy,
    primary: Option<bool>,
    endpoint: &str,
) -> Result<Option<String>> {
    let posture = policy.primary_checkout.unwrap_or_default();
    if primary == Some(false) || posture == Posture::Allow {
        return Ok(None);
    }
    if primary.is_none() {
        return unknown_policy(policy, "repository location is unresolved");
    }
    let parsed = match parse_endpoint(endpoint) {
        Ok(parsed) => parsed,
        Err(_) => return unknown_policy(policy, "endpoint cannot be parsed"),
    };
    let origin = parsed.origin();
    if endpoint_trusted(policy, &parsed) {
        return Ok(None);
    }
    let message = format!(
        "provider-session fence: endpoint {} starts inside a primary checkout; {KEY}={}. \
         Set {KEY}=allow or use a linked worktree outside the primary checkout. \
         A linked worktree does not restrict filesystem access.",
        origin.ascii_serialization(),
        if posture == Posture::Warn {
            "warn"
        } else {
            "refuse"
        },
    );
    if posture == Posture::Refuse {
        bail!("{message}");
    }
    Ok(Some(message))
}

fn loopback_trusted(policy: &Policy) -> bool {
    policy
        .trust_loopback
        .unwrap_or(policy.trusted_endpoints.is_none())
}

fn endpoint_trusted(policy: &Policy, parsed: &Url) -> bool {
    let origin = parsed.origin();
    let local = match parsed.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(host)) => host == "localhost",
        None => false,
    };
    let trusted = policy.trusted_endpoints.iter().flatten().any(|trusted| {
        // Every trust entry was validated at load time.
        parse_endpoint(trusted).is_ok_and(|trusted| trusted.origin() == origin)
    });
    let anthropic = origin.ascii_serialization() == "https://api.anthropic.com";
    (local && loopback_trusted(policy)) || trusted || anthropic
}

fn unknown_policy(policy: &Policy, reason: &str) -> Result<Option<String>> {
    let posture = policy.primary_checkout.unwrap_or_default();
    if posture == Posture::Allow {
        return Ok(None);
    }
    let message =
        format!("provider-session fence: endpoint unresolved/untrusted ({reason}); check {KEY}");
    if posture == Posture::Refuse {
        bail!("{message}");
    }
    Ok(Some(message))
}

pub(super) fn check_unknown_launch(base_dir: &Path) -> Result<Option<String>> {
    check_unknown_launch_with_args(base_dir, &[])
}

pub(super) fn check_unknown_launch_with_args(
    base_dir: &Path,
    rest: &[String],
) -> Result<Option<String>> {
    let cwd = std::env::current_dir().unwrap_or_default();
    check_unknown_launch_at(base_dir, &cwd, rest)
}

fn check_unknown_launch_at(base_dir: &Path, cwd: &Path, rest: &[String]) -> Result<Option<String>> {
    let cwd = match effective_start_directory(cwd, rest) {
        Ok(cwd) => cwd,
        Err(_) => {
            let (policy, _, _) = load_policy(base_dir, cwd)?;
            return unknown_policy(&policy, "CLI start directory is unresolved");
        }
    };
    let (policy, _, primary) = load_policy(base_dir, &cwd)?;
    if primary != Some(false) {
        return unknown_policy(
            &policy,
            "vendor configuration and endpoint overrides are not resolved",
        );
    }
    Ok(None)
}

pub(super) fn check_exec_vendor_launch(base_dir: &Path, cwd: &Path) -> Result<Option<String>> {
    check_unknown_launch_at(base_dir, cwd, &[])
}

fn effective_start_directory(cwd: &Path, rest: &[String]) -> Result<PathBuf> {
    let mut args = rest.iter();
    let mut destination = cwd.to_path_buf();
    while let Some(arg) = args.next() {
        if arg == "--" {
            break;
        }
        let value = if matches!(
            arg.as_str(),
            "-C" | "--cd"
                | "--cwd"
                | "-w"
                | "--work-dir"
                | "--working-directory"
                | "--directory"
                | "--workspace"
        ) {
            Some(
                args.next()
                    .ok_or_else(|| {
                        anyhow!("provider-session fence: CLI start directory is unresolved")
                    })?
                    .as_str(),
            )
        } else {
            [
                "--cd=",
                "--cwd=",
                "--work-dir=",
                "--working-directory=",
                "--directory=",
                "--workspace=",
                "-C",
                "-w",
            ]
            .iter()
            .find_map(|prefix| arg.strip_prefix(prefix).filter(|value| !value.is_empty()))
        };
        if let Some(value) = value {
            if value.is_empty() {
                bail!("provider-session fence: CLI start directory is unresolved");
            }
            destination = cwd.join(value);
        }
    }
    Ok(std::fs::canonicalize(&destination).unwrap_or(destination))
}

pub(super) fn emit_warning(warning: Option<String>) {
    if let Some(warning) = warning {
        eprintln!("csq: warning: {warning}");
    }
}

#[cfg(feature = "native-harness")]
pub(super) fn check(base_dir: &Path, cwd: &Path, endpoint: &str) -> Result<()> {
    emit_warning(evaluate(base_dir, cwd, endpoint)?);
    Ok(())
}

/// Resolve exactly the global/UUID/legacy env precedence used by fresh handles.
/// A second call against the materialized handle checks the child's actual input.
pub(super) fn check_claude_launch(
    base_dir: &Path,
    claude_home: &Path,
    account: AccountNum,
    materialized: Option<&Path>,
    rest: &[String],
) -> Result<Option<String>> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let cwd = match effective_start_directory(&cwd, rest) {
        Ok(cwd) => cwd,
        Err(_) => {
            let (policy, _, _) = load_policy(base_dir, &cwd)?;
            return unknown_policy(&policy, "CLI start directory is unresolved");
        }
    };
    let (policy, project_root, primary) = load_policy(base_dir, &cwd)?;
    let posture = policy.primary_checkout.unwrap_or_default();
    if primary == Some(false) || posture == Posture::Allow {
        return Ok(None);
    }
    if primary.is_none() {
        return unknown_policy(&policy, "repository location is unresolved");
    }
    let mut warnings = BTreeSet::new();
    if rest.iter().any(|arg| {
        matches!(arg.as_str(), "--settings" | "--setting-sources")
            || arg.starts_with("--settings=")
            || arg.starts_with("--setting-sources=")
    }) {
        add_unknown(
            &policy,
            &mut warnings,
            "CLI settings overrides are unresolved",
        )?;
    }
    let settings = if let Some(path) = materialized {
        match read_launch_settings(&policy, path, &mut warnings)? {
            Some(value) => value,
            None => {
                add_unknown(&policy, &mut warnings, "materialized settings are missing")?;
                serde_json::json!({})
            }
        }
    } else {
        let base =
            read_launch_settings(&policy, &claude_home.join("settings.json"), &mut warnings)?
                .unwrap_or_else(|| serde_json::json!({}));
        let uuid = csq_core::accounts::profiles::resolve_slot_to_uuid(base_dir, account.get())
            .map(|uuid| csq_core::accounts::identity_store::settings_path_for(base_dir, uuid));
        let overlay = match uuid {
            Some(path) => match read_launch_settings(&policy, &path, &mut warnings)? {
                Some(value) => value,
                None => read_launch_settings(
                    &policy,
                    &base_dir.join(format!("config-{account}/settings.json")),
                    &mut warnings,
                )?
                .unwrap_or_else(|| serde_json::json!({})),
            },
            None => read_launch_settings(
                &policy,
                &base_dir.join(format!("config-{account}/settings.json")),
                &mut warnings,
            )?
            .unwrap_or_else(|| serde_json::json!({})),
        };
        session::merge_settings(
            &serde_json::json!({"env": base.get("env")}),
            &serde_json::json!({"env": overlay.get("env").or_else(|| base.get("env"))}),
        )
    };
    let mut effective = settings;
    evaluate_settings_candidate(&policy, &effective, &mut warnings)?;
    if let Some(root) = project_root {
        let mut ancestors = Vec::new();
        for ancestor in cwd.ancestors() {
            ancestors.push(ancestor);
            if ancestor == root {
                break;
            }
        }
        for ancestor in ancestors.into_iter().rev() {
            for filename in ["settings.json", "settings.local.json"] {
                if let Some(candidate) = read_launch_settings(
                    &policy,
                    &ancestor.join(".claude").join(filename),
                    &mut warnings,
                )? {
                    effective = session::merge_settings(&effective, &candidate);
                    evaluate_settings_candidate(&policy, &effective, &mut warnings)?;
                }
            }
        }
    }
    if let Some(directory) = managed_settings_directory() {
        if let Some(candidate) = read_launch_settings(
            &policy,
            &directory.join("managed-settings.json"),
            &mut warnings,
        )? {
            effective = session::merge_settings(&effective, &candidate);
            evaluate_settings_candidate(&policy, &effective, &mut warnings)?;
        }
        let fragments = directory.join("managed-settings.d");
        match std::fs::symlink_metadata(&fragments) {
            Ok(metadata) if metadata.is_dir() => {
                let entries = std::fs::read_dir(&fragments);
                match entries {
                    Ok(entries) => {
                        let mut paths = Vec::new();
                        for entry in entries.take(257) {
                            match entry {
                                Ok(entry) => paths.push(entry.path()),
                                Err(_) => add_unknown(
                                    &policy,
                                    &mut warnings,
                                    "managed settings cannot be inspected",
                                )?,
                            }
                        }
                        if paths.len() > 256 {
                            add_unknown(
                                &policy,
                                &mut warnings,
                                "managed settings fragment count exceeds limit",
                            )?;
                        } else {
                            paths.sort();
                            for path in paths {
                                if path
                                    .extension()
                                    .is_some_and(|extension| extension == "json")
                                    && !path
                                        .file_name()
                                        .is_some_and(|name| name.to_string_lossy().starts_with('.'))
                                {
                                    if let Some(candidate) =
                                        read_launch_settings(&policy, &path, &mut warnings)?
                                    {
                                        effective = session::merge_settings(&effective, &candidate);
                                        evaluate_settings_candidate(
                                            &policy,
                                            &effective,
                                            &mut warnings,
                                        )?;
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => add_unknown(
                        &policy,
                        &mut warnings,
                        "managed settings cannot be inspected",
                    )?,
                }
            }
            Ok(_) => add_unknown(
                &policy,
                &mut warnings,
                "managed settings fragments are not a regular directory",
            )?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => add_unknown(
                &policy,
                &mut warnings,
                "managed settings cannot be inspected",
            )?,
        }
    }
    Ok((!warnings.is_empty()).then(|| warnings.into_iter().collect::<Vec<_>>().join(" ")))
}

fn add_unknown(policy: &Policy, warnings: &mut BTreeSet<String>, reason: &str) -> Result<()> {
    if let Some(warning) = unknown_policy(policy, reason)? {
        warnings.insert(warning);
    }
    Ok(())
}

fn read_launch_settings(
    policy: &Policy,
    path: &Path,
    warnings: &mut BTreeSet<String>,
) -> Result<Option<serde_json::Value>> {
    match read_json(path, 1_048_576) {
        Ok(value) => Ok(value),
        Err(_) => {
            add_unknown(
                policy,
                warnings,
                "launch settings are invalid or unreadable",
            )?;
            Ok(None)
        }
    }
}

fn evaluate_settings_candidate(
    policy: &Policy,
    settings: &serde_json::Value,
    warnings: &mut BTreeSet<String>,
) -> Result<()> {
    let mut env = serde_json::Map::new();
    for key in [
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
    ] {
        if let Some(value) = std::env::var_os(key) {
            env.insert(
                key.to_string(),
                serde_json::Value::String(value.to_string_lossy().into_owned()),
            );
        }
    }
    if let Some(value) = settings.get("env") {
        if let Some(values) = value.as_object() {
            env.extend(values.clone());
        } else if !value.is_null() {
            return add_unknown(policy, warnings, "settings environment is not an object");
        }
    }
    let selected: Vec<&str> = [
        ("CLAUDE_CODE_USE_BEDROCK", "ANTHROPIC_BEDROCK_BASE_URL"),
        ("CLAUDE_CODE_USE_VERTEX", "ANTHROPIC_VERTEX_BASE_URL"),
        ("CLAUDE_CODE_USE_FOUNDRY", "ANTHROPIC_FOUNDRY_BASE_URL"),
    ]
    .into_iter()
    .filter_map(|(flag, key)| {
        env.get(flag)
            .is_some_and(|value| value != "0" && value != "" && value != false)
            .then_some(key)
    })
    .collect();
    if selected.len() > 1 {
        return add_unknown(policy, warnings, "multiple cloud transports are selected");
    }
    let endpoint = if let Some(key) = selected.first() {
        match env.get(*key) {
            Some(value) => value.as_str(),
            None => {
                return add_unknown(
                    policy,
                    warnings,
                    "cloud transport endpoint is unresolved; configure its documented base URL",
                )
            }
        }
    } else {
        env.get("ANTHROPIC_BASE_URL")
            .map_or(Some("https://api.anthropic.com"), serde_json::Value::as_str)
    };
    let Some(endpoint) = endpoint else {
        return add_unknown(policy, warnings, "endpoint is not a string");
    };
    if let Some(warning) = evaluate_policy(policy, Some(true), endpoint)? {
        warnings.insert(warning);
    }
    Ok(())
}

fn managed_settings_directory() -> Option<PathBuf> {
    #[cfg(test)]
    {
        std::env::var_os("CSQ_FENCE_MANAGED_FIXTURE").map(PathBuf::from)
    }
    #[cfg(all(not(test), target_os = "macos"))]
    {
        Some(PathBuf::from("/Library/Application Support/ClaudeCode"))
    }
    #[cfg(all(not(test), target_os = "linux"))]
    {
        Some(PathBuf::from("/etc/claude-code"))
    }
    #[cfg(all(not(test), target_os = "windows"))]
    {
        Some(PathBuf::from(r"C:\Program Files\ClaudeCode"))
    }
    #[cfg(all(
        not(test),
        not(any(target_os = "macos", target_os = "linux", target_os = "windows"))
    ))]
    {
        None
    }
}
