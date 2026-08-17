use std::fmt::Debug;

use crate::jwk::Jwk;

/// Common encodings supported by a public key.
pub trait PublicKey: Debug + Send + Sync {
    /// Encode the public key as DER.
    fn to_der_public_key(&self) -> Vec<u8>;

    /// Encode the public key as PEM.
    fn to_pem_public_key(&self) -> Vec<u8>;

    /// Encode the public key as a public JWK.
    fn to_jwk_public_key(&self) -> Jwk;

    /// Encode the public key as a public JWK.
    fn to_jwk(&self) -> Jwk {
        self.to_jwk_public_key()
    }
}
