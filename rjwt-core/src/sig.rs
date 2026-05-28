mod ed25519;
#[cfg(feature = "falcon")]
pub mod falcon;

#[cfg(feature = "falcon")]
use std::sync::Arc;

use crate::error::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AlgKind {
    Ed25519,
    #[cfg(feature = "falcon")]
    Falcon512,
}

impl AlgKind {
    pub(crate) fn jwt_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "EdDSA",
            #[cfg(feature = "falcon")]
            Self::Falcon512 => "FN-DSA-512",
        }
    }

    pub(crate) fn from_jwt_name(s: &str) -> Result<Self, Error> {
        match s {
            "EdDSA" => Ok(Self::Ed25519),
            #[cfg(feature = "falcon")]
            "FN-DSA-512" => Ok(Self::Falcon512),
            other => Err(Error::format(format!("unsupported alg: {other}"))),
        }
    }
}

pub enum SigningKey {
    Ed25519(ed25519::Ed25519SigningKey),
    #[cfg(feature = "falcon")]
    Falcon512 {
        keypair: falcon::Falcon512KeyPair,
        backend: Arc<dyn falcon::Falcon512Backend>,
    },
}

pub enum VerifyingKey {
    Ed25519(ed25519::Ed25519VerifyingKey),
    #[cfg(feature = "falcon")]
    Falcon512 {
        public_key: falcon::Falcon512PublicKey,
        backend: Arc<dyn falcon::Falcon512Backend>,
    },
}

pub enum Signature {
    Ed25519(ed25519::Ed25519Signature),
    #[cfg(feature = "falcon")]
    Falcon512(falcon::Falcon512Signature),
}

impl SigningKey {
    pub fn alg(&self) -> AlgKind {
        match self {
            Self::Ed25519(_) => AlgKind::Ed25519,
            #[cfg(feature = "falcon")]
            Self::Falcon512 { .. } => AlgKind::Falcon512,
        }
    }

    pub fn generate_ed25519() -> Self {
        Self::Ed25519(ed25519::Ed25519SigningKey::generate())
    }

    #[cfg(feature = "falcon")]
    pub fn falcon512_with(
        keypair: falcon::Falcon512KeyPair,
        backend: Arc<dyn falcon::Falcon512Backend>,
    ) -> Self {
        Self::Falcon512 { keypair, backend }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        match self {
            Self::Ed25519(k) => VerifyingKey::Ed25519(k.verifying_key()),
            #[cfg(feature = "falcon")]
            Self::Falcon512 { keypair, backend } => VerifyingKey::Falcon512 {
                public_key: keypair.public.clone(),
                backend: backend.clone(),
            },
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        match self {
            Self::Ed25519(k) => Ok(Signature::Ed25519(k.sign(msg)?)),
            #[cfg(feature = "falcon")]
            Self::Falcon512 { keypair, backend } => {
                Ok(Signature::Falcon512(backend.sign(&keypair.private, msg)?))
            }
        }
    }
}

impl VerifyingKey {
    pub fn alg(&self) -> AlgKind {
        match self {
            Self::Ed25519(_) => AlgKind::Ed25519,
            #[cfg(feature = "falcon")]
            Self::Falcon512 { .. } => AlgKind::Falcon512,
        }
    }

    #[cfg(feature = "falcon")]
    pub fn falcon512_with(
        public_key: falcon::Falcon512PublicKey,
        backend: Arc<dyn falcon::Falcon512Backend>,
    ) -> Self {
        Self::Falcon512 {
            public_key,
            backend,
        }
    }

    pub fn from_bytes(alg: AlgKind, bytes: &[u8]) -> Result<Self, Error> {
        match alg {
            AlgKind::Ed25519 => Ok(Self::Ed25519(ed25519::Ed25519VerifyingKey::from_bytes(
                bytes,
            )?)),
            #[cfg(feature = "falcon")]
            AlgKind::Falcon512 => Err(Error::auth(
                "Falcon-512 verifying keys require a backend; use VerifyingKey::falcon512_with",
            )),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(k) => k.to_bytes().to_vec(),
            #[cfg(feature = "falcon")]
            Self::Falcon512 { public_key, .. } => public_key.as_bytes().to_vec(),
        }
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        match (self, sig) {
            (Self::Ed25519(k), Signature::Ed25519(s)) => k.verify(msg, s),
            #[cfg(feature = "falcon")]
            (
                Self::Falcon512 {
                    public_key,
                    backend,
                },
                Signature::Falcon512(s),
            ) => backend.verify(public_key, msg, s),
            #[cfg(feature = "falcon")]
            _ => Err(Error::auth(
                "verifying key and signature algorithm mismatch",
            )),
        }
    }
}

impl Clone for VerifyingKey {
    fn clone(&self) -> Self {
        match self {
            Self::Ed25519(k) => Self::Ed25519(k.clone()),
            #[cfg(feature = "falcon")]
            Self::Falcon512 {
                public_key,
                backend,
            } => Self::Falcon512 {
                public_key: public_key.clone(),
                backend: backend.clone(),
            },
        }
    }
}

impl Signature {
    pub fn alg(&self) -> AlgKind {
        match self {
            Self::Ed25519(_) => AlgKind::Ed25519,
            #[cfg(feature = "falcon")]
            Self::Falcon512(_) => AlgKind::Falcon512,
        }
    }

    pub fn from_bytes(alg: AlgKind, bytes: &[u8]) -> Result<Self, Error> {
        match alg {
            AlgKind::Ed25519 => Ok(Self::Ed25519(ed25519::Ed25519Signature::from_bytes(bytes)?)),
            #[cfg(feature = "falcon")]
            AlgKind::Falcon512 => Ok(Self::Falcon512(falcon::Falcon512Signature::from_bytes(
                bytes,
            )?)),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(s) => s.to_bytes().to_vec(),
            #[cfg(feature = "falcon")]
            Self::Falcon512(s) => s.as_bytes().to_vec(),
        }
    }
}
