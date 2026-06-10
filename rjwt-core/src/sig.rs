mod ed25519;

#[cfg(test)]
mod ed25519_tests;

#[cfg(feature = "falcon")]
mod falcon;

#[cfg(all(test, feature = "falcon"))]
mod falcon_tests;

#[cfg(feature = "falcon")]
use falcon::Falcon512Backend;

#[cfg(feature = "falcon")]
use falcon::FalconBackend;

use crate::error::Error;
use crate::sig::ed25519::Ed25519Signature;
use crate::sig::ed25519::Ed25519VerifyingKey;
#[cfg(feature = "falcon")]
use crate::sig::falcon::Falcon512PublicKey;
#[cfg(feature = "falcon")]
use crate::sig::falcon::Falcon512Signature;

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

enum SigningKeyTypes {
    Ed25519(ed25519::Ed25519SigningKey),
    #[cfg(feature = "falcon")]
    Falcon512 (falcon::Falcon512KeyPair),
}

pub struct SigningKey {
   inner: SigningKeyTypes
}

enum VerifyingKeyTypes {
    Ed25519(ed25519::Ed25519VerifyingKey),
    #[cfg(feature = "falcon")]
    Falcon512(falcon::Falcon512PublicKey),
}

pub struct VerifyingKey {
    inner: VerifyingKeyTypes
}

enum SignatureTypes {
    Ed25519(ed25519::Ed25519Signature),
    #[cfg(feature = "falcon")]
    Falcon512(falcon::Falcon512Signature),
}

pub struct Signature {
    inner: SignatureTypes
}

impl SigningKey {
    pub fn alg(&self) -> AlgKind {
        match self.inner {
            SigningKeyTypes::Ed25519(_) => AlgKind::Ed25519,
            #[cfg(feature = "falcon")]
            SigningKeyTypes::Falcon512(_) => AlgKind::Falcon512,
        }
    }

    pub fn generate_ed25519() -> Self {
        Self {
            inner: SigningKeyTypes::Ed25519(ed25519::Ed25519SigningKey::generate())
        }
    }

    #[cfg(feature = "falcon")]
    pub fn generate_falcon512() -> Result<Self, Error> {
        let kp = FalconBackend::generate()?;
        Ok(Self {
            inner: SigningKeyTypes::Falcon512(kp)
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        match &self.inner {
            SigningKeyTypes::Ed25519(k) => VerifyingKey::new(k.verifying_key()),
            #[cfg(feature = "falcon")]
            SigningKeyTypes::Falcon512(kp ) => VerifyingKey::new_falcon512(kp.public.clone())
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        match &self.inner {
            SigningKeyTypes::Ed25519(k) => Ok(Signature::new(k.sign(msg)?)),
            #[cfg(feature = "falcon")]
            SigningKeyTypes::Falcon512(kp) => {
                Ok(Signature::new_falcon512(FalconBackend::sign(&kp.private, msg)?))
            }
        }
    }

    pub fn from_bytes(alg: AlgKind, bytes: &[u8]) -> Result<Self, Error> {
        match alg {
            AlgKind::Ed25519 => Ok(Self {
                inner: SigningKeyTypes::Ed25519(ed25519::Ed25519SigningKey::from_bytes(bytes)?)
            }),
            #[cfg(feature = "falcon")]
            AlgKind::Falcon512 => Ok(Self {
                inner: SigningKeyTypes::Falcon512(FalconBackend::from_bytes(bytes)?)
            })
        }
    }
}

impl VerifyingKey {
    pub fn alg(&self) -> AlgKind {
        match &self.inner {
            VerifyingKeyTypes::Ed25519(_) => AlgKind::Ed25519,
            #[cfg(feature = "falcon")]
            VerifyingKeyTypes::Falcon512 { .. } => AlgKind::Falcon512,
        }
    }

    pub fn from_bytes(alg: AlgKind, bytes: &[u8]) -> Result<Self, Error> {
        match alg {
            AlgKind::Ed25519 => Ok(Self {
                inner: VerifyingKeyTypes::Ed25519(ed25519::Ed25519VerifyingKey::from_bytes(bytes)?)
            }),
            #[cfg(feature = "falcon")]
            AlgKind::Falcon512 => Ok(Self {
                inner: VerifyingKeyTypes::Falcon512(falcon::Falcon512PublicKey::from_bytes(bytes)?)
            })
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.inner {
            VerifyingKeyTypes::Ed25519(k) => k.to_bytes().to_vec(),
            #[cfg(feature = "falcon")]
            VerifyingKeyTypes::Falcon512(pk) => pk.as_bytes().to_vec(),
        }
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        match (&self.inner, &sig.inner) {
            (
                VerifyingKeyTypes::Ed25519(k), 
                SignatureTypes::Ed25519(s)
            ) => k.verify(msg, s),
            #[cfg(feature = "falcon")]
            (
                VerifyingKeyTypes::Falcon512(pk),
                SignatureTypes::Falcon512(s),
            ) => FalconBackend::verify(pk, msg, s),
            #[cfg(feature = "falcon")]
            _ => Err(Error::auth(
                "verifying key and signature algorithm mismatch",
            )),
        }
    }

    fn new(key: Ed25519VerifyingKey) -> Self {
        Self {
            inner: VerifyingKeyTypes::Ed25519(key)
        }
    }

    #[cfg(feature = "falcon")]
    fn new_falcon512(key: Falcon512PublicKey) -> Self {
        Self {
            inner: VerifyingKeyTypes::Falcon512(key)
        }
    }
}

impl Clone for VerifyingKey {
    fn clone(&self) -> Self {
        match &self.inner {
            VerifyingKeyTypes::Ed25519(k) => Self {
                inner: VerifyingKeyTypes::Ed25519(*k.clone())
            },
            #[cfg(feature = "falcon")]
            VerifyingKeyTypes::Falcon512(pk) => Self {
                inner: VerifyingKeyTypes::Falcon512(pk.clone())
            }
        }
    }
}

impl Signature {
    pub fn alg(&self) -> AlgKind {
        match self.inner {
            SignatureTypes::Ed25519(_) => AlgKind::Ed25519,
            #[cfg(feature = "falcon")]
            SignatureTypes::Falcon512(_) => AlgKind::Falcon512,
        }
    }

    pub fn from_bytes(alg: AlgKind, bytes: &[u8]) -> Result<Self, Error> {
        match alg {
            AlgKind::Ed25519 => Ok(Self {
                inner: SignatureTypes::Ed25519(ed25519::Ed25519Signature::from_bytes(bytes)?)
            }),
            #[cfg(feature = "falcon")]
            AlgKind::Falcon512 => Ok(Self {
                inner: SignatureTypes::Falcon512(falcon::Falcon512Signature::from_bytes(bytes)?)
            }),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.inner {
            SignatureTypes::Ed25519(s) => s.to_bytes().to_vec(),
            #[cfg(feature = "falcon")]
            SignatureTypes::Falcon512(s) => s.as_bytes().to_vec(),
        }
    }

    fn new(sig: Ed25519Signature) -> Self {
        Self {
            inner: SignatureTypes::Ed25519(sig)
        }
    }

    #[cfg(feature = "falcon")]
    fn new_falcon512(sig: Falcon512Signature) -> Self {
        Self {
            inner: SignatureTypes::Falcon512(sig)
        }
    }
}
