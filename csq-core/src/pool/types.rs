use super::{PoolError, Result};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

/// Account-independent key name. It is never interpreted as a filesystem path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PoolName(String);

impl PoolName {
    pub fn new(value: &str) -> Result<Self> {
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(PoolError::InvalidName);
        }
        Ok(Self(value.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for PoolName {
    type Error = PoolError;
    fn try_from(value: String) -> Result<Self> {
        Self::new(&value)
    }
}
impl From<PoolName> for String {
    fn from(value: PoolName) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeySource {
    EnvFile,
    SecretStore,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Reset {
    Day { day_of_month: u8 },
    Date { date: String },
}
impl Reset {
    pub fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::Day { day_of_month } => (1..=28).contains(day_of_month),
            Self::Date { date } => {
                date.len() == 10
                    && NaiveDate::parse_from_str(date, "%Y-%m-%d")
                        .is_ok_and(|d| d.to_string() == *date)
            }
        };
        if valid {
            Ok(())
        } else {
            Err(PoolError::InvalidReset)
        }
    }
}

/// Non-secret metadata shared by the CLI and desktop adapter.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolEntry {
    pub name: PoolName,
    pub provider: String,
    pub source: KeySource,
    pub reset: Option<Reset>,
    pub monthly_cap_usd: Option<f64>,
    pub added_at: String,
}
impl PoolEntry {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_provider(&self.provider)?;
        validate_options(self.reset.as_ref(), self.monthly_cap_usd)?;
        if chrono::DateTime::parse_from_rfc3339(&self.added_at).is_err() {
            return Err(PoolError::ManifestInvalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PoolRow {
    #[serde(flatten)]
    pub entry: PoolEntry,
    pub present: bool,
    #[serde(default)]
    pub vault_file_missing: bool,
}

pub(crate) fn validate_provider(provider: &str) -> Result<()> {
    if matches!(provider, "anthropic" | "openai")
        || crate::providers::catalog::get_provider(provider)
            .is_some_and(|p| p.auth_type == crate::providers::catalog::AuthType::Bearer)
    {
        Ok(())
    } else {
        Err(PoolError::InvalidProvider)
    }
}
pub(crate) fn validate_options(reset: Option<&Reset>, cap: Option<f64>) -> Result<()> {
    if let Some(reset) = reset {
        reset.validate()?;
    }
    if cap.is_some_and(|c| !c.is_finite() || c <= 0.0) {
        return Err(PoolError::InvalidCap);
    }
    Ok(())
}
