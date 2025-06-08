use std::borrow::Cow;
use std::fmt::Display;
use std::ops::Deref;

#[cfg(feature = "rustcrypto")]
use aes_kw::{KekAes128, KekAes192, KekAes256};
use anyhow::bail;
#[cfg(feature = "openssl")]
use openssl::aes::{self, AesKey};

#[cfg(feature = "rustcrypto")]
use crate::jwe::alg::aeskw::AeskwJweAlgorithm::A128kw;
use crate::jwe::{JweAlgorithm, JweContentEncryption, JweDecrypter, JweEncrypter, JweHeader};
use crate::jwk::Jwk;
use crate::{util, JoseError, Value};

#[cfg(feature = "rustcrypto")]
pub enum AesKey {
    Aes128(KekAes128),
    Aes192(KekAes192),
    Aes256(KekAes256),
}

#[cfg(feature = "rustcrypto")]
impl AesKey {
    pub fn new(private_key: &[u8]) -> Result<Self, anyhow::Error> {
        if let Ok(aes) = KekAes128::try_from(private_key) {
            return Ok(AesKey::Aes128(aes));
        }
        if let Ok(aes) = KekAes192::try_from(private_key) {
            return Ok(AesKey::Aes192(aes));
        }
        if let Ok(aes) = KekAes256::try_from(private_key) {
            return Ok(AesKey::Aes256(aes));
        }
        bail!("Unsupported key size");
    }
    pub fn new_encrypt(private_key: &[u8]) -> Result<Self, anyhow::Error> {
        Self::new(private_key)
    }
    pub fn new_decrypt(private_key: &[u8]) -> Result<Self, anyhow::Error> {
        Self::new(private_key)
    }

    pub fn wrap_key(
        &self,
        _aad: Option<()>,
        encrypted_key: &mut [u8],
        key: &[u8],
    ) -> Result<(), anyhow::Error> {
        match self {
            AesKey::Aes128(aes) => aes
                .wrap(key, encrypted_key)
                .map_err(|e| anyhow::anyhow!("Failed to set encrypt key: {}", e)),
            AesKey::Aes192(aes) => aes
                .wrap(key, encrypted_key)
                .map_err(|e| anyhow::anyhow!("Failed to set encrypt key: {}", e)),
            AesKey::Aes256(aes) => aes
                .wrap(key, encrypted_key)
                .map_err(|e| anyhow::anyhow!("Failed to set encrypt key: {}", e)),
        }
    }
    pub fn unwrap_key(
        &self,
        _aad: Option<()>,
        key: &mut [u8],
        encrypted_key: &[u8],
    ) -> Result<(), anyhow::Error> {
        match self {
            AesKey::Aes128(aes) => aes
                .unwrap(encrypted_key, key)
                .map_err(|e| anyhow::anyhow!("Failed to set encrypt key: {}", e)),
            AesKey::Aes192(aes) => aes
                .unwrap(encrypted_key, key)
                .map_err(|e| anyhow::anyhow!("Failed to set encrypt key: {}", e)),
            AesKey::Aes256(aes) => aes
                .unwrap(encrypted_key, key)
                .map_err(|e| anyhow::anyhow!("Failed to set encrypt key: {}", e)),
        }
    }
}
#[cfg(feature = "rustcrypto")]
pub mod aes {
    pub fn wrap_key(
        aes: &super::AesKey,
        _aad: Option<()>,
        encrypted_key: &mut [u8],
        key: &[u8],
    ) -> Result<(), anyhow::Error> {
        aes.wrap_key(_aad, encrypted_key, key)
    }
    pub fn unwrap_key(
        aes: &super::AesKey,
        _aad: Option<()>,
        key: &mut [u8],
        encrypted_key: &[u8],
    ) -> Result<(), anyhow::Error> {
        aes.unwrap_key(_aad, key, encrypted_key)
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AeskwJweAlgorithm {
    /// AES Key Wrap with default initial value using 128-bit key
    A128kw,
    /// AES Key Wrap with default initial value using 192-bit key
    A192kw,
    /// AES Key Wrap with default initial value using 256-bit key
    A256kw,
}

impl AeskwJweAlgorithm {
    pub fn encrypter_from_bytes(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<AeskwJweEncrypter, JoseError> {
        (|| -> anyhow::Result<AeskwJweEncrypter> {
            let private_key = input.as_ref().to_vec();

            if private_key.len() != self.key_len() {
                bail!(
                    "The key size must be {}: {}",
                    self.key_len(),
                    private_key.len()
                );
            }

            Ok(AeskwJweEncrypter {
                algorithm: self.clone(),
                private_key,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<AeskwJweEncrypter, JoseError> {
        (|| -> anyhow::Result<AeskwJweEncrypter> {
            match jwk.key_type() {
                val if val == "oct" => {}
                val => bail!("A parameter kty must be oct: {}", val),
            }
            match jwk.key_use() {
                Some(val) if val == "enc" => {}
                None => {}
                Some(val) => bail!("A parameter use must be enc: {}", val),
            }
            if !jwk.is_for_key_operation("wrapKey") {
                bail!("A parameter key_ops must contains wrapKey.");
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }
            let k = match jwk.parameter("k") {
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(val) => bail!("A parameter k must be string type but {:?}", val),
                None => bail!("A parameter k is required."),
            };

            if k.len() != self.key_len() {
                bail!("The key size must be {}: {}", self.key_len(), k.len());
            }

            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(AeskwJweEncrypter {
                algorithm: self.clone(),
                private_key: k,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_bytes(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<AeskwJweDecrypter, JoseError> {
        (|| -> anyhow::Result<AeskwJweDecrypter> {
            let private_key = input.as_ref().to_vec();

            if private_key.len() != self.key_len() {
                bail!(
                    "The key size must be {}: {}",
                    self.key_len(),
                    private_key.len()
                );
            }

            Ok(AeskwJweDecrypter {
                algorithm: self.clone(),
                private_key,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_jwk(&self, jwk: &Jwk) -> Result<AeskwJweDecrypter, JoseError> {
        (|| -> anyhow::Result<AeskwJweDecrypter> {
            match jwk.key_type() {
                val if val == "oct" => {}
                val => bail!("A parameter kty must be oct: {}", val),
            }
            match jwk.key_use() {
                Some(val) if val == "enc" => {}
                None => {}
                Some(val) => bail!("A parameter use must be enc: {}", val),
            }
            if !jwk.is_for_key_operation("unwrapKey") {
                bail!("A parameter key_ops must contains unwrapKey.");
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }

            let k = match jwk.parameter("k") {
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(val) => bail!("A parameter k must be string type but {:?}", val),
                None => bail!("A parameter k is required."),
            };

            if k.len() != self.key_len() {
                bail!("The key size must be {}: {}", self.key_len(), k.len());
            }

            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(AeskwJweDecrypter {
                algorithm: self.clone(),
                private_key: k,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn key_len(&self) -> usize {
        match self {
            Self::A128kw => 16,
            Self::A192kw => 24,
            Self::A256kw => 32,
        }
    }
}

impl JweAlgorithm for AeskwJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::A128kw => "A128KW",
            Self::A192kw => "A192KW",
            Self::A256kw => "A256KW",
        }
    }

    fn box_clone(&self) -> Box<dyn JweAlgorithm> {
        Box::new(self.clone())
    }
}

impl Display for AeskwJweAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for AeskwJweAlgorithm {
    type Target = dyn JweAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct AeskwJweEncrypter {
    algorithm: AeskwJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl AeskwJweEncrypter {
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
}

impl JweEncrypter for AeskwJweEncrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn compute_content_encryption_key(
        &self,
        _cencryption: &dyn JweContentEncryption,
        _in_header: &JweHeader,
        _out_header: &mut JweHeader,
    ) -> Result<Option<Cow<[u8]>>, JoseError> {
        Ok(None)
    }

    fn encrypt(
        &self,
        key: &[u8],
        _in_header: &JweHeader,
        _out_header: &mut JweHeader,
    ) -> Result<Option<Vec<u8>>, JoseError> {
        (|| -> anyhow::Result<Option<Vec<u8>>> {
            let aes = match AesKey::new_encrypt(&self.private_key) {
                Ok(val) => val,
                Err(_) => bail!("Failed to set encrypt key."),
            };

            let mut encrypted_key = vec![0; key.len() + 8];

            match aes::wrap_key(&aes, None, &mut encrypted_key, &key) {
                Ok(val) =>
                {
                    #[cfg(feature = "openssl")]
                    if val < encrypted_key.len() {
                        encrypted_key.truncate(val);
                    }
                }
                Err(_) => bail!("Failed to wrap key."),
            }

            Ok(Some(encrypted_key))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweEncrypter> {
        Box::new(self.clone())
    }
}

impl Deref for AeskwJweEncrypter {
    type Target = dyn JweEncrypter;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct AeskwJweDecrypter {
    algorithm: AeskwJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl AeskwJweDecrypter {
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
}

impl JweDecrypter for AeskwJweDecrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn decrypt(
        &self,
        encrypted_key: Option<&[u8]>,
        _cencryption: &dyn JweContentEncryption,
        _header: &JweHeader,
    ) -> Result<Cow<[u8]>, JoseError> {
        (|| -> anyhow::Result<Cow<[u8]>> {
            let encrypted_key = match encrypted_key {
                Some(val) => val,
                None => bail!("A encrypted_key is required."),
            };
            // #[cfg(feature = "openssl")]
            let aes = match AesKey::new_decrypt(&self.private_key) {
                Ok(val) => val,
                Err(_) => bail!("Failed to set decrypt key."),
            };

            let mut key = vec![0; encrypted_key.len() - 8];
            // #[cfg(feature = "openssl")]
            match aes::unwrap_key(&aes, None, &mut key, encrypted_key) {
                Ok(val) =>
                {
                    #[cfg(feature = "openssl")]
                    if val < key.len() {
                        key.truncate(val);
                    }
                }
                Err(_) => bail!("Failed to unwrap key."),
            };
            Ok(Cow::Owned(key))
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweDecrypter> {
        Box::new(self.clone())
    }
}

impl Deref for AeskwJweDecrypter {
    type Target = dyn JweDecrypter;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serde_json::json;

    use super::AeskwJweAlgorithm;
    use crate::jwe::enc::aescbc_hmac::AescbcHmacJweEncryption;
    use crate::jwe::JweHeader;
    use crate::jwk::Jwk;
    use crate::util;

    #[test]
    fn encrypt_and_decrypt_aes() -> Result<()> {
        let enc = AescbcHmacJweEncryption::A128cbcHs256;

        for alg in vec![
            AeskwJweAlgorithm::A128kw,
            AeskwJweAlgorithm::A192kw,
            AeskwJweAlgorithm::A256kw,
        ] {
            let mut header = JweHeader::new();
            header.set_content_encryption(enc.name());

            let jwk = {
                let key = util::random_bytes(alg.key_len());
                let key = util::encode_base64_urlsafe_nopad(&key);

                let mut jwk = Jwk::new("oct");
                jwk.set_key_use("enc");
                jwk.set_parameter("k", Some(json!(key)))?;
                jwk
            };

            let encrypter = alg.encrypter_from_jwk(&jwk)?;
            let src_key = util::random_bytes(enc.key_len());
            let mut out_header = header.clone();
            let encrypted_key = encrypter.encrypt(&src_key, &header, &mut out_header)?;

            println!("{alg:?} {:?}", encrypted_key);

            let decrypter = alg.decrypter_from_jwk(&jwk)?;
            let dst_key = decrypter.decrypt(encrypted_key.as_deref(), &enc, &out_header)?;

            assert_eq!(&src_key as &[u8], &dst_key as &[u8]);
        }

        Ok(())
    }
}
