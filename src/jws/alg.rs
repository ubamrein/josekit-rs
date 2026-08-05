use anyhow::bail;

use crate::{
    jwk::Jwk,
    jws::{JwsSigner, JwsVerifier},
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
        for alg in [crate::jws::RS256, crate::jws::RS384, crate::jws::RS512] {
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
        for alg in [crate::jws::RS256, crate::jws::RS384, crate::jws::RS512] {
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
        for alg in [crate::jws::RS256, crate::jws::RS384, crate::jws::RS512] {
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
        for alg in [crate::jws::RS256, crate::jws::RS384, crate::jws::RS512] {
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

#[cfg(test)]
mod tests {
    use crate::jws::{alg::ecdsa::EcdsaJwsAlgorithm::Es256, JwsSigner, JwsVerifier};

    #[test]
    fn test_from() {
        let k = Es256.generate_key_pair().unwrap();
        let pk = k.to_der_public_key();
        let sk = k.into_private_key().private_key_to_der().unwrap();

        let signer: Box<dyn JwsSigner> = sk.as_slice().try_into().unwrap();
        let verifier: Box<dyn JwsVerifier> = pk.as_slice().try_into().unwrap();

        let sig = signer.sign(b"test").unwrap();
        verifier.verify(b"test", &sig).unwrap();
    }
}
