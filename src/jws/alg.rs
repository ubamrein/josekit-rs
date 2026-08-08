use anyhow::bail;
use kapun_crypto_provider::{
    oid_registry::OID_PKCS1_SHA1WITHRSA, DecodingError, KapunCryptoProvider,
};

use crate::{
    jwk::{Jwk, KeyPair},
    jws::{alg::rsassa::RsassaJwsAlgorithm::Rs1, JwsSigner, JwsVerifier},
};

pub mod ecdsa;
pub mod eddsa;
pub mod hmac;
#[cfg(feature = "pqc")]
pub mod ml_dsa;
pub mod rsassa;
pub mod rsassa_pss;

impl TryFrom<&[u8]> for Box<dyn JwsVerifier> {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let der = value.as_ref();
        for alg in [crate::jws::ES256, crate::jws::ES384, crate::jws::ES512] {
            let Ok(verifier) = alg.verifier_from_der(der) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        for alg in [
            crate::jws::RS256,
            crate::jws::RS384,
            crate::jws::RS512,
            #[cfg(feature = "rsa-sha1")]
            crate::jws::RS1,
        ] {
            let Ok(verifier) = alg.verifier_from_der(der) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        for alg in [crate::jws::PS256, crate::jws::PS384, crate::jws::PS512] {
            let Ok(verifier) = alg.verifier_from_der(der) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        for alg in [crate::jws::EdDSA] {
            let Ok(verifier) = alg.verifier_from_der(der) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        for alg in [
            crate::jws::MlDSA44,
            crate::jws::MlDSA65,
            crate::jws::MlDSA87,
        ] {
            let Ok(verifier) = alg.verifier_from_der(der) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        bail!("invalid algorithm")
    }
}

impl TryFrom<&[u8]> for Box<dyn JwsSigner> {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let der = value.as_ref();
        for alg in [crate::jws::ES256, crate::jws::ES384, crate::jws::ES512] {
            let Ok(signer) = alg.signer_from_der(der) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        for alg in [
            crate::jws::RS256,
            crate::jws::RS384,
            crate::jws::RS512,
            #[cfg(feature = "rsa-sha1")]
            crate::jws::RS1,
        ] {
            let Ok(signer) = alg.signer_from_der(der) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        for alg in [crate::jws::PS256, crate::jws::PS384, crate::jws::PS512] {
            let Ok(signer) = alg.signer_from_der(der) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        for alg in [crate::jws::EdDSA] {
            let Ok(signer) = alg.signer_from_der(der) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        for alg in [
            crate::jws::MlDSA44,
            crate::jws::MlDSA65,
            crate::jws::MlDSA87,
        ] {
            let Ok(signer) = alg.signer_from_der(der) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        bail!("invalid algorithm")
    }
}

impl TryFrom<&str> for Box<dyn JwsVerifier> {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let jwk = Jwk::from_bytes(value.as_bytes())?;
        for alg in [crate::jws::ES256, crate::jws::ES384, crate::jws::ES512] {
            let Ok(verifier) = alg.verifier_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        for alg in [
            crate::jws::RS256,
            crate::jws::RS384,
            crate::jws::RS512,
            #[cfg(feature = "rsa-sha1")]
            crate::jws::RS1,
        ] {
            let Ok(verifier) = alg.verifier_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        for alg in [crate::jws::PS256, crate::jws::PS384, crate::jws::PS512] {
            let Ok(verifier) = alg.verifier_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        for alg in [crate::jws::EdDSA] {
            let Ok(verifier) = alg.verifier_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        for alg in [
            crate::jws::MlDSA44,
            crate::jws::MlDSA65,
            crate::jws::MlDSA87,
        ] {
            let Ok(verifier) = alg.verifier_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        bail!("invalid algorithm")
    }
}

impl TryFrom<&str> for Box<dyn JwsSigner> {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let jwk = Jwk::from_bytes(value.as_bytes())?;
        for alg in [crate::jws::ES256, crate::jws::ES384, crate::jws::ES512] {
            let Ok(signer) = alg.signer_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        for alg in [
            crate::jws::RS256,
            crate::jws::RS384,
            crate::jws::RS512,
            #[cfg(feature = "rsa-sha1")]
            crate::jws::RS1,
        ] {
            let Ok(signer) = alg.signer_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        for alg in [crate::jws::PS256, crate::jws::PS384, crate::jws::PS512] {
            let Ok(signer) = alg.signer_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        for alg in [crate::jws::EdDSA] {
            let Ok(signer) = alg.signer_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        for alg in [
            crate::jws::MlDSA44,
            crate::jws::MlDSA65,
            crate::jws::MlDSA87,
        ] {
            let Ok(signer) = alg.signer_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        bail!("invalid algorithm")
    }
}

impl TryFrom<&[u8]> for Box<dyn KeyPair> {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let der = value.as_ref();
        for alg in [crate::jws::ES256, crate::jws::ES384, crate::jws::ES512] {
            let Ok(key_pair) = alg.key_pair_from_der(der) else {
                continue;
            };
            return Ok(Box::new(key_pair));
        }

        for alg in [
            crate::jws::RS256,
            crate::jws::RS384,
            crate::jws::RS512,
            #[cfg(feature = "rsa-sha1")]
            crate::jws::RS1,
        ] {
            let Ok(key_pair) = alg.key_pair_from_der(der) else {
                continue;
            };
            return Ok(Box::new(key_pair));
        }
        for alg in [crate::jws::PS256, crate::jws::PS384, crate::jws::PS512] {
            let Ok(key_pair) = alg.key_pair_from_der(der) else {
                continue;
            };
            return Ok(Box::new(key_pair));
        }
        for alg in [crate::jws::EdDSA] {
            let Ok(key_pair) = alg.key_pair_from_der(der) else {
                continue;
            };
            return Ok(Box::new(key_pair));
        }
        for alg in [
            crate::jws::MlDSA44,
            crate::jws::MlDSA65,
            crate::jws::MlDSA87,
        ] {
            let Ok(key_pair) = alg.key_pair_from_der(der) else {
                continue;
            };
            return Ok(Box::new(key_pair));
        }
        bail!("invalid algorithm")
    }
}

pub struct JosekitCryptoProvider;
impl KapunCryptoProvider for JosekitCryptoProvider {
    fn verifier(
        key_data: Vec<u8>,
    ) -> Result<Box<dyn kapun_crypto_provider::Verifier>, DecodingError> {
        let jws_verifier: Box<dyn JwsVerifier> = key_data
            .as_slice()
            .try_into()
            .map_err(|_| DecodingError::InvalidAlgorithm)?;
        Ok(jws_verifier)
    }
    fn verifier_for_oid<'a>(
        key_data: Vec<u8>,
        oid: kapun_crypto_provider::oid_registry::Oid<'a>,
    ) -> Result<Box<dyn kapun_crypto_provider::Verifier + 'a>, DecodingError> {
        if oid == OID_PKCS1_SHA1WITHRSA {
            Ok(Box::new(
                Rs1.verifier_from_der(key_data)
                    .map_err(|_| DecodingError::InvalidAlgorithm)?,
            ))
        } else {
            Self::verifier(key_data)
        }
    }

    fn signer(key_data: Vec<u8>) -> Result<Box<dyn kapun_crypto_provider::Signer>, DecodingError> {
        let jws_signer: Box<dyn JwsSigner> = key_data
            .as_slice()
            .try_into()
            .map_err(|_| DecodingError::InvalidAlgorithm)?;
        Ok(jws_signer)
    }
}

#[macro_export]
macro_rules! kapun_signing_provider {
    ($alg:ty) => {
        use kapun_crypto_provider::{
            KeyEncoding, Metadata, Signer, Signing, VerificationProblem, Verifier, Verifying,
        };
        impl Signer for $alg {}
        impl Signing for $alg {
            fn kapun_sign(
                &self,
                data: Vec<u8>,
            ) -> Result<Vec<u8>, kapun_crypto_provider::SigningProblem> {
                JwsSigner::sign(&*self, &data)
                    .map_err(|_| kapun_crypto_provider::SigningProblem::SigningFailed)
            }

            fn kapun_sign_hash(
                &self,
                hash: Vec<u8>,
            ) -> Result<Vec<u8>, kapun_crypto_provider::SigningProblem> {
                JwsSigner::sign_prehashed(&*self, &hash)
                    .map_err(|_| kapun_crypto_provider::SigningProblem::SigningFailed)
            }
        }
        impl KeyEncoding for $alg {
            fn kapun_private_jwk(&self) -> Option<String> {
                self.private_key.ec_key_jwk().ok()
            }

            fn kapun_public_jwk(&self) -> Option<String> {
                self.private_key.public_key().ec_key_jwk().ok()
            }

            fn kapun_private_pkcs8_der(&self) -> Option<Vec<u8>> {
                self.private_key.ec_key_der().ok()
            }

            fn kapun_private_pkcs8_pem(&self) -> Option<String> {
                self.private_key.ec_key_pem().ok()
            }

            fn kapun_public_spki_der(&self) -> Option<Vec<u8>> {
                self.private_key.public_key().ec_key_der().ok()
            }

            fn kapun_public_spki_pem(&self) -> Option<String> {
                self.private_key.public_key().ec_key_pem().ok()
            }
        }
        impl Metadata for $alg {
            fn kapun_jose_alg(&self) -> Option<String> {
                Some(self.algorithm.name().to_string())
            }

            fn kapun_oid(&self) -> Option<Vec<u8>> {
                None
            }

            fn kapun_additional(&self) -> Option<kapun_crypto_provider::KapunValue> {
                None
            }
        }
    };
}

#[macro_export]
macro_rules! kapun_verifying_provider {
    ($alg:ty) => {
        impl Verifier for $alg {}
        impl Verifying for $alg {
            fn kapun_verify(
                &self,
                data: Vec<u8>,
                signature: Vec<u8>,
            ) -> Result<(), kapun_crypto_provider::VerificationProblem> {
                self.verify(&data, &signature)
                    .map_err(|_| VerificationProblem::SignatureInvalid)
            }

            fn kapun_verify_hash(
                &self,
                hash: Vec<u8>,
                signature: Vec<u8>,
            ) -> Result<(), kapun_crypto_provider::VerificationProblem> {
                self.verify_prehashed(&hash, &signature)
                    .map_err(|_| VerificationProblem::SignatureInvalid)
            }
        }
        impl KeyEncoding for $alg {
            fn kapun_public_jwk(&self) -> Option<String> {
                self.public_key.ec_key_jwk().ok()
            }

            fn kapun_public_spki_der(&self) -> Option<Vec<u8>> {
                self.public_key.ec_key_der().ok()
            }

            fn kapun_public_spki_pem(&self) -> Option<String> {
                self.public_key.ec_key_pem().ok()
            }
        }
        impl Metadata for $alg {
            fn kapun_jose_alg(&self) -> Option<String> {
                Some(self.algorithm.name().to_string())
            }

            fn kapun_oid(&self) -> Option<Vec<u8>> {
                None
            }

            fn kapun_additional(&self) -> Option<kapun_crypto_provider::KapunValue> {
                None
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::{
        jwk::KeyPair,
        jws::{alg::ecdsa::EcdsaJwsAlgorithm::Es256, JwsSigner, JwsVerifier},
    };

    #[test]
    fn test_from() {
        let k = Es256.generate_key_pair().unwrap();
        let pk = k.to_der_public_key();
        let sk = k.into_private_key().ec_key_der().unwrap();

        let signer: Box<dyn JwsSigner> = sk.as_slice().try_into().unwrap();
        let verifier: Box<dyn JwsVerifier> = pk.as_slice().try_into().unwrap();

        let sig = signer.sign(b"test").unwrap();
        verifier.verify(b"test", &sig).unwrap();

        let kp: Box<dyn KeyPair> = sk.as_slice().try_into().unwrap();
        assert_eq!(kp.algorithm(), Some("ES256"));
        assert_eq!(kp.to_der_public_key(), pk);
    }
}
