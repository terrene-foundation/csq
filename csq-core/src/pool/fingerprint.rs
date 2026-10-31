//! Private pool-local HMAC key identity. Neither salt nor digest is diagnostic data.
use super::{PoolError, Result};
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub(super) struct Salt(String);

impl Salt {
    pub(super) fn fresh() -> Result<Self> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::getrandom(bytes.as_mut()).map_err(|_| PoolError::StoreUnavailable)?;
        Ok(Self(hex(bytes.as_ref())))
    }

    pub(super) fn validate(&self) -> Result<()> {
        validate_digest(&self.0)
    }

    pub(super) fn id(&self) -> String {
        hex(&Sha256::digest(self.0.as_bytes()))
    }

    pub(super) fn fingerprint(&self, secret: &SecretString) -> Result<String> {
        digest(&self.0, secret)
    }
}

impl Drop for Salt {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(super) fn digest(salt: &str, secret: &SecretString) -> Result<String> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(salt.as_bytes()).map_err(|_| PoolError::ManifestInvalid)?;
    mac.update(secret.expose_secret().as_bytes());
    Ok(hex(&mac.finalize().into_bytes()))
}

pub(super) fn validate_digest(value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(PoolError::ManifestInvalid)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
