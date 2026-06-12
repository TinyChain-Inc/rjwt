use std::fmt;

use zeroize::Zeroizing;

use crate::error::Error;

pub(super) const PUBLIC_KEY_LEN: usize = 897;
pub(super) const PRIVATE_KEY_LEN: usize = 1281;
pub(super) const SIGNATURE_LEN: usize = 666; // FALCON_SIG_PADDED size for FN-DSA-512 (logn=9); see ADR-002.

#[derive(Clone)]
pub(crate) struct Falcon512PublicKey(Box<[u8; PUBLIC_KEY_LEN]>);

pub(crate) struct Falcon512PrivateKey(Box<Zeroizing<[u8; PRIVATE_KEY_LEN]>>);

#[derive(Clone)]
pub(crate) struct Falcon512Signature(Box<[u8; SIGNATURE_LEN]>);

pub(crate) struct Falcon512KeyPair {
    pub public: Falcon512PublicKey,
    pub private: Falcon512PrivateKey,
}

/// Backend trait — swap implementations of FN-DSA-512 without touching rjwt-core.
pub(crate) trait Falcon512Backend: Send + Sync + fmt::Debug {
    const FALCON_CONTEXT: &[u8];
    fn generate() -> Result<Falcon512KeyPair, Error>;
    fn sign(sk: &Falcon512PrivateKey, msg: &[u8]) -> Result<Falcon512Signature, Error>;
    fn verify(pk: &Falcon512PublicKey, msg: &[u8], sig: &Falcon512Signature) -> Result<(), Error>;
    fn from_bytes(secret: &[u8]) -> Result<Falcon512KeyPair, Error>;
}

impl Falcon512PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; PUBLIC_KEY_LEN] = bytes.try_into().map_err(|_| {
            Error::format(format!(
                "Falcon-512 public key must be {} bytes, got {}",
                PUBLIC_KEY_LEN,
                bytes.len()
            ))
        })?;
        Ok(Self(Box::new(arr)))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Falcon512PrivateKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; PRIVATE_KEY_LEN] = bytes.try_into().map_err(|_| {
            Error::format(format!(
                "Falcon-512 private key must be {} bytes, got {}",
                PRIVATE_KEY_LEN,
                bytes.len()
            ))
        })?;
        Ok(Self(Box::new(Zeroizing::new(arr))))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref().as_ref()
    }
}

impl Falcon512Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; SIGNATURE_LEN] = bytes.try_into().map_err(|_| {
            Error::format(format!(
                "Falcon-512 signature must be exactly {} bytes (PADDED format), got {}",
                SIGNATURE_LEN,
                bytes.len()
            ))
        })?;
        Ok(Self(Box::new(arr)))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

pub(crate) mod default_backend {
    use falcon::FnDsaKeyPair;
    use falcon::falcon::{
        FALCON_SIG_PADDED, falcon_sign_dyn_finish, falcon_sign_start, falcon_tmpsize_signdyn,
        falcon_tmpsize_verify, falcon_verify_finish, falcon_verify_start, shake256_inject,
    };
    use falcon::shake::InnerShake256Context;
    use zeroize::Zeroizing;

    use super::PRIVATE_KEY_LEN;
    use super::{
        Falcon512Backend, Falcon512KeyPair, Falcon512PrivateKey, Falcon512PublicKey,
        Falcon512Signature, SIGNATURE_LEN,
    };
    use crate::error::Error;
    use crate::sig::AlgKind;

    const LOGN: u32 = 9;

    #[derive(Clone, Debug, Default)]
    pub struct FalconRsBackend;

    pub(crate) fn map_err(rc: i32) -> Error {
        Error::auth(format!("falcon-rs low-level error: {rc}"))
    }

    pub(crate) fn init_rng() -> Result<InnerShake256Context, Error> {
        let mut rng = InnerShake256Context::new();
        let rc = falcon::falcon::shake256_init_prng_from_system(&mut rng);
        if rc != 0 {
            return Err(Error::auth("falcon-rs: OS RNG unavailable"));
        }
        Ok(rng)
    }

    pub(crate) fn inject_domain_and_message(
        hd: &mut InnerShake256Context,
        msg: &[u8],
        context: &[u8],
    ) {
        // FIPS 206 pure-FN-DSA domain prefix for DomainSeparation::Context:
        //   ph_flag (0x00) || ctx_len || ctx_bytes || raw_message
        // Mirrors safe_api::DomainSeparation::inject_header + inject_message.
        let ph_flag: u8 = 0x00;
        let ctx_len: u8 = context.len() as u8;
        shake256_inject(hd, &[ph_flag, ctx_len]);
        shake256_inject(hd, context);
        shake256_inject(hd, msg);
    }

    impl Falcon512Backend for FalconRsBackend {
        /// Hardcoded domain-separation context for rjwt Falcon-512 signatures.
        /// Locked as part of the wire-format contract — see ADR-001.
        const FALCON_CONTEXT: &[u8] = b"rjwt-v1";

        fn generate() -> Result<Falcon512KeyPair, Error> {
            use falcon::prelude::*;
            let kp = FnDsaKeyPair::generate(LOGN)
                .map_err(|e| Error::auth(format!("falcon-rs: {e:?}")))?;
            let public = Falcon512PublicKey::from_bytes(kp.public_key())?;
            let private = Falcon512PrivateKey::from_bytes(kp.private_key())?;
            Ok(Falcon512KeyPair { public, private })
        }

        fn sign(sk: &Falcon512PrivateKey, msg: &[u8]) -> Result<Falcon512Signature, Error> {
            let mut rng = init_rng()?;
            let tmp_len = falcon_tmpsize_signdyn(LOGN);
            let mut tmp = Zeroizing::new(vec![0u8; tmp_len]);
            let mut sig = [0u8; SIGNATURE_LEN];
            let mut sig_len = SIGNATURE_LEN;

            let mut nonce = [0u8; 40];
            let mut hd = InnerShake256Context::new();
            let rc = falcon_sign_start(&mut rng, &mut nonce, &mut hd);
            if rc != 0 {
                return Err(map_err(rc));
            }
            inject_domain_and_message(&mut hd, msg, Self::FALCON_CONTEXT);

            let rc = falcon_sign_dyn_finish(
                &mut rng,
                &mut sig,
                &mut sig_len,
                FALCON_SIG_PADDED,
                sk.as_bytes(),
                &mut hd,
                &nonce,
                &mut tmp,
            );
            if rc != 0 {
                return Err(map_err(rc));
            }
            debug_assert_eq!(
                sig_len, SIGNATURE_LEN,
                "PADDED format must be exactly {SIGNATURE_LEN} bytes"
            );

            Falcon512Signature::from_bytes(&sig)
        }

        fn verify(
            pk: &Falcon512PublicKey,
            msg: &[u8],
            sig: &Falcon512Signature,
        ) -> Result<(), Error> {
            let tmp_len = falcon_tmpsize_verify(LOGN);
            let mut tmp = vec![0u8; tmp_len];
            let sig_bytes = sig.as_bytes();

            let mut hd = InnerShake256Context::new();
            let rc = falcon_verify_start(&mut hd, sig_bytes);
            if rc != 0 {
                return Err(map_err(rc));
            }
            inject_domain_and_message(&mut hd, msg, Self::FALCON_CONTEXT);

            let rc = falcon_verify_finish(
                sig_bytes,
                FALCON_SIG_PADDED,
                pk.as_bytes(),
                &mut hd,
                &mut tmp,
            );
            if rc != 0 {
                return Err(map_err(rc));
            }
            Ok(())
        }

        fn from_bytes(pk: &[u8]) -> Result<Falcon512KeyPair, Error> {
            let pk: &[u8; PRIVATE_KEY_LEN] = pk.try_into().map_err(|_| {
                Error::format(format!(
                    "{} private key is {} bytes, got {}",
                    AlgKind::Falcon512.jwt_name(),
                    PRIVATE_KEY_LEN,
                    pk.len()
                ))
            })?;
            let kp = FnDsaKeyPair::from_private_key(pk)
                .map_err(|e| Error::format(format!("falcon-rs: {e:?}")))?;

            Ok(Falcon512KeyPair {
                public: Falcon512PublicKey::from_bytes(kp.public_key())?,
                private: Falcon512PrivateKey::from_bytes(kp.private_key())?,
            })
        }
    }
}

pub type FalconBackend = default_backend::FalconRsBackend;
