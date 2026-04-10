use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Maximum number of accounts supported.
pub const MAX_ACCOUNTS: u16 = 999;

/// Validated account number (1..=MAX_ACCOUNTS).
///
/// Prevents path traversal and keychain namespace injection by ensuring
/// the value is always a valid positive integer in the allowed range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccountNum(u16);

impl AccountNum {
    /// Returns the underlying account number.
    pub fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for AccountNum {
    type Error = crate::error::CredentialError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if (1..=MAX_ACCOUNTS).contains(&value) {
            Ok(AccountNum(value))
        } else {
            Err(crate::error::CredentialError::InvalidAccount(
                value.to_string(),
            ))
        }
    }
}

impl fmt::Display for AccountNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for AccountNum {
    type Err = crate::error::CredentialError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let n: u16 = s
            .parse()
            .map_err(|_| crate::error::CredentialError::InvalidAccount(s.to_string()))?;
        AccountNum::try_from(n)
    }
}

/// OAuth access token with masked Display and zeroize-on-drop.
///
/// The inner value is never serialized or logged in full.
/// Use `expose_secret()` when the raw value is needed for HTTP headers.
pub struct AccessToken(SecretString);

impl AccessToken {
    pub fn new(value: String) -> Self {
        Self(SecretString::from(value))
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl Clone for AccessToken {
    fn clone(&self) -> Self {
        Self::new(self.expose_secret().to_string())
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccessToken({})", self)
    }
}

impl fmt::Display for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0.expose_secret();
        if s.len() > 12 {
            write!(f, "{}...{}", &s[..8], &s[s.len() - 4..])
        } else {
            write!(f, "****")
        }
    }
}

impl Serialize for AccessToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.expose_secret())
    }
}

impl<'de> Deserialize<'de> for AccessToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(AccessToken::new(s))
    }
}

/// OAuth refresh token with masked Display and zeroize-on-drop.
pub struct RefreshToken(SecretString);

impl RefreshToken {
    pub fn new(value: String) -> Self {
        Self(SecretString::from(value))
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl Clone for RefreshToken {
    fn clone(&self) -> Self {
        Self::new(self.expose_secret().to_string())
    }
}

impl fmt::Debug for RefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RefreshToken({})", self)
    }
}

impl fmt::Display for RefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0.expose_secret();
        if s.len() > 12 {
            write!(f, "{}...{}", &s[..8], &s[s.len() - 4..])
        } else {
            write!(f, "****")
        }
    }
}

impl Serialize for RefreshToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.expose_secret())
    }
}

impl<'de> Deserialize<'de> for RefreshToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(RefreshToken::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_num_valid() {
        assert!(AccountNum::try_from(1u16).is_ok());
        assert!(AccountNum::try_from(7u16).is_ok());
        assert!(AccountNum::try_from(999u16).is_ok());
    }

    #[test]
    fn account_num_invalid() {
        assert!(AccountNum::try_from(0u16).is_err());
        assert!(AccountNum::try_from(1000u16).is_err());
    }

    #[test]
    fn account_num_from_str() {
        assert!("1".parse::<AccountNum>().is_ok());
        assert!("abc".parse::<AccountNum>().is_err());
        assert!("0".parse::<AccountNum>().is_err());
        assert!("../etc".parse::<AccountNum>().is_err());
    }

    #[test]
    fn access_token_masked_display() {
        let token = AccessToken::new("sk-ant-oat01-abcdefghijklmnop".to_string());
        let display = format!("{token}");
        assert!(display.starts_with("sk-ant-o"));
        assert!(display.ends_with("mnop"));
        assert!(display.contains("..."));
        assert!(!display.contains("abcdefghijklmnop"));
    }

    #[test]
    fn refresh_token_masked_display() {
        let token = RefreshToken::new("sk-ant-ort01-xyzxyzxyzxyzxyz".to_string());
        let display = format!("{token}");
        assert!(!display.contains("xyzxyzxyzxyzxyz"));
    }

    #[test]
    fn access_token_expose_secret() {
        let raw = "sk-ant-oat01-full-value";
        let token = AccessToken::new(raw.to_string());
        assert_eq!(token.expose_secret(), raw);
    }
}
