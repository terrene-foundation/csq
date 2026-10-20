//! Pure, injectable S1 directory contract from ratified F-B1 (S0).
//! No discovery executable, socket, enrollment or local messaging dependency.
//! Wire DTOs contain daemon-private reach; their Debug output deliberately omits it.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::HashSet, fmt, net::IpAddr};

pub const MAX_OUTPUT_BYTES: usize = 256 * 1024;
pub const MAX_INPUT_BYTES: usize = 4096;
pub const MAX_CURSOR_BYTES: usize = 256;
pub const MAX_PAGE_HOSTS: usize = 64;
pub const MAX_PAGES: usize = 4;
pub const MAX_HOSTS: usize = MAX_PAGE_HOSTS * MAX_PAGES;
pub const MAX_DESCRIPTOR_BYTES: usize = 1024;
pub const MAX_AGE_SECS: u64 = 60;
pub const CLOCK_SKEW_SECS: u64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    Complete,
    Incomplete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryTag {
    Ok,
    UnknownHost,
    DirectoryHostOffline,
    DirectoryHostRevoked,
    DescriptorExpired,
    IncompatibleVersion,
    DirectoryIdentityMismatch,
    DirectoryRateLimited,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterFailure {
    Timeout,
    InvalidDescriptor,
    DirectoryUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationFailure {
    InvalidDescriptor,
    IncompatibleVersion,
    DescriptorExpired,
    ClockSkew,
    CoverageIncomplete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryFailure {
    Adapter(AdapterFailure),
    Validation(ValidationFailure),
}

/// Caller-asserted clock safety, not a physical-clock verification mechanism.
/// S2 must establish safety through its actual bounded uncertainty detector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryClock {
    Known(u64),
    Unsafe,
    Unknown,
}

impl From<u64> for DirectoryClock {
    fn from(now: u64) -> Self {
        Self::Known(now)
    }
}

pub fn checked_clock(clock: DirectoryClock) -> Result<u64, ValidationFailure> {
    match clock {
        DirectoryClock::Known(now) => Ok(now),
        DirectoryClock::Unsafe | DirectoryClock::Unknown => Err(ValidationFailure::ClockSkew),
    }
}

impl From<ValidationFailure> for DirectoryFailure {
    fn from(value: ValidationFailure) -> Self {
        Self::Validation(value)
    }
}

// Fixed contract text only: no peer strings or endpoint details in errors.
impl DirectoryTag {
    pub fn text(self) -> &'static str {
        match self {
            Self::Ok => "fleet directory query completed; inspect coverage",
            Self::UnknownHost => "fleet host unknown; recipient undetermined",
            Self::DirectoryHostOffline => {
                "fleet directory reports host offline; reachability undetermined"
            }
            Self::DirectoryHostRevoked => "fleet directory reports host revoked; discovery refused",
            Self::DirectoryIdentityMismatch => {
                "fleet directory identity mismatch; discovery refused"
            }
            Self::DescriptorExpired => "fleet directory descriptor expired; discovery refused",
            Self::IncompatibleVersion => "fleet directory version incompatible; discovery refused",
            Self::DirectoryRateLimited => {
                "fleet directory rate limit exceeded; coverage undetermined"
            }
        }
    }
}

impl AdapterFailure {
    pub fn text(self) -> &'static str {
        match self {
            Self::Timeout => "fleet directory query timed out; coverage undetermined",
            Self::InvalidDescriptor => "fleet directory descriptor invalid; discovery refused",
            Self::DirectoryUnavailable => "fleet directory unavailable, coverage undetermined",
        }
    }
    pub fn coverage(self) -> Coverage {
        Coverage::Incomplete
    }
}

impl ValidationFailure {
    pub fn text(self) -> &'static str {
        match self {
            Self::InvalidDescriptor => AdapterFailure::InvalidDescriptor.text(),
            Self::IncompatibleVersion => DirectoryTag::IncompatibleVersion.text(),
            Self::DescriptorExpired => DirectoryTag::DescriptorExpired.text(),
            Self::ClockSkew => "fleet clock unsafe or skew exceeds 300 seconds; operation refused",
            Self::CoverageIncomplete => "fleet discovery incomplete; recipient undetermined",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryResult<T> {
    pub version: u64,
    pub coverage: Coverage,
    pub tag: DirectoryTag,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<T>,
}

impl<T> fmt::Debug for DirectoryResult<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectoryResult")
            .field("coverage", &self.coverage)
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
}

/// Only the future daemon adapter may serialize this endpoint onto its private wire.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpReach {
    pub transport: Transport,
    pub address: String,
    pub port: u16,
}

impl fmt::Debug for TcpReach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TcpReach { <private> }")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostReach {
    pub host_id: String,
    pub descriptor_version: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub reach: TcpReach,
}

impl fmt::Debug for HostReach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HostReach { <private> }")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPage {
    pub snapshot_id: String,
    pub hosts: Vec<HostReach>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl fmt::Debug for HostPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostPage")
            .field("host_count", &self.hosts.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectoryOutcome<T> {
    Response(DirectoryResult<T>),
    AdapterFailure(AdapterFailure),
    ValidationFailure(ValidationFailure),
}

impl<T> DirectoryOutcome<T> {
    pub fn coverage(&self) -> Coverage {
        match self {
            Self::Response(result) => result.coverage,
            Self::AdapterFailure(_) | Self::ValidationFailure(_) => Coverage::Incomplete,
        }
    }
}

/// Implementations must apply the bounded decoder, not return unchecked wire data.
/// This abstraction grants neither enrollment nor authentication authority.
pub trait HostDirectory {
    fn resolve(&self, host_id: &str) -> DirectoryOutcome<HostReach>;
    fn list(&self, limit: u8, cursor: Option<&str>) -> DirectoryOutcome<HostPage>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveRequest {
    pub version: u64,
    pub host_id: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListRequest {
    pub version: u64,
    pub limit: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

impl fmt::Debug for ListRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListRequest")
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

pub fn validate_resolve_request(host_id: &str) -> Result<(), ValidationFailure> {
    if !valid_host_id(host_id) {
        return Err(ValidationFailure::InvalidDescriptor);
    }
    Ok(())
}

pub fn validate_list_request(limit: u8, cursor: Option<&str>) -> Result<(), ValidationFailure> {
    if limit == 0 || usize::from(limit) > MAX_PAGE_HOSTS {
        return Err(ValidationFailure::InvalidDescriptor);
    }
    if let Some(cursor) = cursor {
        validate_cursor(cursor)?;
    }
    Ok(())
}

pub fn decode_resolve_request(bytes: &[u8]) -> Result<ResolveRequest, ValidationFailure> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(ValidationFailure::InvalidDescriptor);
    }
    let request: ResolveRequest =
        serde_json::from_slice(bytes).map_err(|_| ValidationFailure::InvalidDescriptor)?;
    if request.version != 1 {
        return Err(ValidationFailure::IncompatibleVersion);
    }
    validate_resolve_request(&request.host_id)?;
    Ok(request)
}

pub fn decode_list_request(bytes: &[u8]) -> Result<ListRequest, ValidationFailure> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(ValidationFailure::InvalidDescriptor);
    }
    let request: ListRequest =
        serde_json::from_slice(bytes).map_err(|_| ValidationFailure::InvalidDescriptor)?;
    if request.version != 1 {
        return Err(ValidationFailure::IncompatibleVersion);
    }
    validate_list_request(request.limit, request.cursor.as_deref())?;
    Ok(request)
}

pub fn valid_host_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub fn validate_cursor(cursor: &str) -> Result<(), ValidationFailure> {
    if cursor.is_empty() || cursor.len() > MAX_CURSOR_BYTES || cursor.chars().any(char::is_control)
    {
        return Err(ValidationFailure::InvalidDescriptor);
    }
    Ok(())
}

fn freshness(issued: u64, expires: u64, now: u64) -> Result<(), ValidationFailure> {
    let (issued, expires, now) = (u128::from(issued), u128::from(expires), u128::from(now));
    let (skew, age) = (u128::from(CLOCK_SKEW_SECS), u128::from(MAX_AGE_SECS));
    if issued > now + skew {
        return Err(ValidationFailure::ClockSkew);
    }
    if expires < issued || expires > issued + age {
        return Err(ValidationFailure::InvalidDescriptor);
    }
    if now > issued + skew + age || now > expires + skew {
        return Err(ValidationFailure::DescriptorExpired);
    }
    Ok(())
}

fn valid_address(value: &str) -> bool {
    if let Ok(ip) = value.parse::<IpAddr>() {
        return !ip.is_unspecified()
            && !ip.is_multicast()
            && !matches!(ip, IpAddr::V4(v4) if v4.is_broadcast());
    }
    let name = value.strip_suffix('.').unwrap_or(value);
    if value.len() > 253 || name.is_empty() || name.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

fn validate_host(host: &HostReach, now: u64) -> Result<(), ValidationFailure> {
    if host.descriptor_version != 1 {
        return Err(ValidationFailure::IncompatibleVersion);
    }
    if !valid_host_id(&host.host_id)
        || host.reach.port == 0
        || !valid_address(&host.reach.address)
        || serde_json::to_vec(host)
            .map_err(|_| ValidationFailure::InvalidDescriptor)?
            .len()
            > MAX_DESCRIPTOR_BYTES
    {
        return Err(ValidationFailure::InvalidDescriptor);
    }
    freshness(host.issued_at, host.expires_at, now)
}

fn validate_result<T>(response: &DirectoryResult<T>, now: u64) -> Result<(), ValidationFailure> {
    if response.version != 1 {
        return Err(ValidationFailure::IncompatibleVersion);
    }
    if (response.tag == DirectoryTag::Ok) != response.value.is_some() {
        return Err(ValidationFailure::InvalidDescriptor);
    }
    freshness(response.issued_at, response.expires_at, now)
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<DirectoryResult<T>, ValidationFailure> {
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(ValidationFailure::InvalidDescriptor);
    }
    // Presence is stricter than Option: even `value:null` is forbidden on errors.
    let raw: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ValidationFailure::InvalidDescriptor)?;
    if raw
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|v| v != 1)
    {
        return Err(ValidationFailure::IncompatibleVersion);
    }
    if raw.get("tag").and_then(serde_json::Value::as_str) != Some("ok")
        && raw.get("value").is_some()
    {
        return Err(ValidationFailure::InvalidDescriptor);
    }
    // Deserialize ORIGINAL bytes so duplicate known keys are refused, not overwritten.
    serde_json::from_slice(bytes).map_err(|_| ValidationFailure::InvalidDescriptor)
}

pub fn decode_resolve(
    bytes: &[u8],
    expected_host: &str,
    now: impl Into<DirectoryClock>,
) -> Result<DirectoryResult<HostReach>, ValidationFailure> {
    let now = checked_clock(now.into())?;
    validate_resolve_request(expected_host)?;
    let result: DirectoryResult<HostReach> = decode(bytes)?;
    validate_result(&result, now)?;
    if let Some(host) = &result.value {
        validate_host(host, now)?;
        if host.host_id != expected_host {
            return Err(ValidationFailure::InvalidDescriptor);
        }
    }
    Ok(result)
}

fn validate_page(
    result: &DirectoryResult<HostPage>,
    limit: u8,
    now: u64,
) -> Result<(), ValidationFailure> {
    validate_list_request(limit, None)?;
    validate_result(result, now)?;
    if let Some(page) = &result.value {
        if page.snapshot_id.is_empty()
            || page.snapshot_id.len() > 64
            || !page.snapshot_id.bytes().all(|b| (b' '..=b'~').contains(&b))
        {
            return Err(ValidationFailure::InvalidDescriptor);
        }
        if page.hosts.len() > usize::from(limit) {
            return Err(ValidationFailure::InvalidDescriptor);
        }
        let mut ids = HashSet::new();
        for host in &page.hosts {
            validate_host(host, now)?;
            if !ids.insert(&host.host_id) {
                return Err(ValidationFailure::InvalidDescriptor);
            }
        }
        if let Some(cursor) = &page.next_cursor {
            validate_cursor(cursor)?;
        }
    }
    Ok(())
}

pub fn decode_list(
    bytes: &[u8],
    limit: u8,
    now: impl Into<DirectoryClock>,
) -> Result<DirectoryResult<HostPage>, ValidationFailure> {
    let now = checked_clock(now.into())?;
    let result = decode(bytes)?;
    validate_page(&result, limit, now)?;
    Ok(result)
}

/// Bounded same-snapshot collection using the ratified opaque snapshot identity
/// plus unchanged issuance/expiry. `now` must be verified by the caller.
/// Partial coverage remains partial even when all returned pages contain zero rows.
pub fn collect_hosts(
    directory: &(impl HostDirectory + ?Sized),
    now: impl Into<DirectoryClock>,
) -> Result<DirectoryResult<HostPage>, DirectoryFailure> {
    let now = checked_clock(now.into())?;
    let mut cursor: Option<String> = None;
    let mut cursors = HashSet::new();
    let mut ids = HashSet::new();
    let mut hosts = Vec::new();
    let mut snapshot = None;
    let mut snapshot_id: Option<String> = None;
    let mut coverage = Coverage::Complete;
    for _ in 0..MAX_PAGES {
        let result = match directory.list(MAX_PAGE_HOSTS as u8, cursor.as_deref()) {
            DirectoryOutcome::Response(result) => result,
            DirectoryOutcome::AdapterFailure(failure) => {
                return Err(DirectoryFailure::Adapter(failure))
            }
            DirectoryOutcome::ValidationFailure(failure) => return Err(failure.into()),
        };
        validate_page(&result, MAX_PAGE_HOSTS as u8, now)?;
        if result.tag != DirectoryTag::Ok {
            return Ok(DirectoryResult {
                coverage: Coverage::Incomplete,
                ..result
            });
        }
        let pair = (result.issued_at, result.expires_at);
        if snapshot.is_some_and(|previous| previous != pair) {
            return Err(ValidationFailure::InvalidDescriptor.into());
        }
        snapshot = Some(pair);
        if result.coverage == Coverage::Incomplete {
            coverage = Coverage::Incomplete;
        }
        let page = result.value.ok_or(ValidationFailure::InvalidDescriptor)?;
        if snapshot_id
            .as_ref()
            .is_some_and(|id| id != &page.snapshot_id)
        {
            return Err(ValidationFailure::InvalidDescriptor.into());
        }
        snapshot_id = Some(page.snapshot_id.clone());
        for host in page.hosts {
            if !ids.insert(host.host_id.clone()) {
                return Err(ValidationFailure::InvalidDescriptor.into());
            }
            hosts.push(host);
        }
        if hosts.len() > MAX_HOSTS {
            return Err(ValidationFailure::CoverageIncomplete.into());
        }
        match page.next_cursor {
            Some(next) => {
                if !cursors.insert(next.clone()) {
                    return Err(ValidationFailure::InvalidDescriptor.into());
                }
                cursor = Some(next);
            }
            None => {
                return Ok(DirectoryResult {
                    version: 1,
                    coverage,
                    tag: DirectoryTag::Ok,
                    issued_at: pair.0,
                    expires_at: pair.1,
                    value: Some(HostPage {
                        snapshot_id: page.snapshot_id,
                        hosts,
                        next_cursor: None,
                    }),
                })
            }
        }
    }
    Err(ValidationFailure::CoverageIncomplete.into())
}
