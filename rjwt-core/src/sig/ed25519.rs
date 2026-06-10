use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH, Signer, Verifier};
use rand::rngs::OsRng;

use crate::error::Error;
use super::AlgKind;

pub struct Ed25519SigningKey(ed25519_dalek::SigningKey);

pub struct Ed25519VerifyingKey(ed25519_dalek::VerifyingKey);

pub struct Ed25519Signature(ed25519_dalek::Signature);

const ALGORITHM_NAME: &str = "Ed25519";

impl Ed25519SigningKey {
    pub fn generate() -> Self {
        Self(ed25519_dalek::SigningKey::generate(&mut OsRng))
    }

    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        Ed25519VerifyingKey(self.0.verifying_key())
    }

    pub fn from_bytes(secret: &[u8]) -> Result<Self, Error> {
        let secret: &[u8; SECRET_KEY_LENGTH] = secret.try_into().map_err(|_| {
            Error::format(format!(
                "{} signing key must be {} bytes, got {}",
                AlgKind::Ed25519.jwt_name(),
                SECRET_KEY_LENGTH,
                secret.len()
            ))
        })?;
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(secret)))
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Ed25519Signature, Error> {
        Ok(Ed25519Signature(self.0.try_sign(msg)?))
    }
}

impl Ed25519VerifyingKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: &[u8; PUBLIC_KEY_LENGTH] = bytes.try_into().map_err(|_| {
            Error::format(format!(
                "{} verifying key must be {} bytes, got {}",
                AlgKind::Ed25519.jwt_name(),
                PUBLIC_KEY_LENGTH,
                bytes.len()
            ))
        })?;
        Ok(Self(ed25519_dalek::VerifyingKey::from_bytes(arr)?))
    }

    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    pub fn verify(&self, msg: &[u8], sig: &Ed25519Signature) -> Result<(), Error> {
        self.0.verify(msg, &sig.0).map_err(Error::from)
    }
}

impl Clone for Ed25519VerifyingKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Ed25519Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: &[u8; SIGNATURE_LENGTH] = bytes.try_into().map_err(|_| {
            Error::format(format!(
                "{} signature must be {} bytes, got {}",
                AlgKind::Ed25519.jwt_name(),
                SIGNATURE_LENGTH,
                bytes.len()
            ))
        })?;
        Ok(Self(ed25519_dalek::Signature::from_bytes(arr)))
    }

    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.0.to_bytes()
    }
}
