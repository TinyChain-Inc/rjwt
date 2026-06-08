use std::fmt;
use std::time::SystemTime;

use base64::prelude::*;
use serde::Serialize;

use crate::claims::Claims;
use crate::error::Error;
use crate::sig::{SigningKey, VerifyingKey};
use crate::token::{SignedToken, Token, TokenHeader};

#[cfg(feature = "falcon")]
use std::sync::Arc;
use crate::sig::falcon::Falcon512Backend;

#[cfg(feature = "falcon-rs")]
use crate::sig::falcon::FalconRsBackend;

enum Key {
    Public(VerifyingKey),
    Private(SigningKey),
}

impl Key {
    fn has_private_key(&self) -> bool {
        match &self {
            Self::Public(_) => false,
            Self::Private(_) => true,
        }
    }
}

/// An actor with an identifier of type `T` and an ECDSA keypair used to sign tokens.
///
/// *IMPORTANT NOTE*: for security reasons, although `Actor` implements `Clone`, its secret key will
/// NOT be cloned. For example:
/// ```
/// # use rjwt_core::Actor;
/// let actor = Actor::<String>::new("id".to_string()); // this has a new secret key
/// let cloned = actor.clone(); // this does NOT have a secret key, only a public key
/// ```
pub struct Actor<A> {
    pub(crate) id: A,
    key: Key,
}

impl<A> Actor<A> {
    /// Return an `Actor` with a newly-generated Ed25519 keypair.
    pub fn new(id: A) -> Self {
        Self {
            id,
            key: Key::Private(SigningKey::generate_ed25519()),
        }
    }

    /// Return an `Actor` with a newly-generated Falcon-512 keypair using the given backend.
    #[cfg(feature = "falcon")]
    pub fn new_falcon512_with(
        id: A,
        backend: Arc<dyn Falcon512Backend>,
    ) -> Result<Self, Error> {
        let keypair = backend.generate()?;
        Ok(Self {
            id,
            key: Key::Private(SigningKey::falcon512_with(keypair, backend)),
        })
    }

    /// Return an `Actor` with a newly-generated Falcon-512 keypair using the default `falcon-rs` backend.
    #[cfg(feature = "falcon-rs")]
    pub fn new_falcon512(id: A) -> Result<Self, Error> {
        Self::new_falcon512_with(id, Arc::new(FalconRsBackend))
    }

    /// Return an `Actor` with the given signing key.
    pub fn with_signing_key(id: A, sk: SigningKey) -> Self {
        Self {
            id,
            key: Key::Private(sk),
        }
    }

    /// Return an `Actor` with the given verifying key (public only, cannot sign).
    pub fn with_verifying_key(id: A, vk: VerifyingKey) -> Self {
        Self {
            id,
            key: Key::Public(vk),
        }
    }

    /// Borrow the identifier of this actor.
    pub fn id(&self) -> &A {
        &self.id
    }

    /// Return `true` if this [`Actor`] has a private key which can be used to sign [`Token`]s.
    pub fn has_private_key(&self) -> bool {
        self.key.has_private_key()
    }

    /// Return the verifying key of this actor, which a client can use to verify a signature.
    pub fn verifying_key(&self) -> VerifyingKey {
        match &self.key {
            Key::Public(vk) => vk.clone(),
            Key::Private(sk) => sk.verifying_key(),
        }
    }

    fn sign_token_inner<H, C>(&self, token: &Token<H, A, C>) -> Result<String, Error>
    where
        H: Serialize,
        A: Serialize,
        C: Serialize,
    {
        let sk = match &self.key {
            Key::Private(sk) => Ok(sk),
            Key::Public(_) => Err(Error::auth("cannot sign a token without a private key")),
        }?;

        let header =
            BASE64_STANDARD.encode(serde_json::to_string(&TokenHeader::for_alg(sk.alg()))?);
        let claims = BASE64_STANDARD.encode(serde_json::to_string(&token)?);

        let signature = sk.sign(format!("{header}.{claims}").as_bytes())?;
        let signature = BASE64_STANDARD.encode(signature.to_bytes());

        Ok(format!("{header}.{claims}.{signature}"))
    }

    /// Encode and sign the given `token` data.
    pub fn sign_token<H, C>(&self, token: Token<H, A, C>) -> Result<SignedToken<H, A, C>, Error>
    where
        H: Serialize,
        A: Serialize,
        C: Serialize,
    {
        let jwt = self.sign_token_inner(&token)?;
        let claims = Claims::new(token.exp, token.iss, token.actor_id, token.custom);
        Ok(SignedToken::new(claims, jwt))
    }

    /// Encode and sign a new token which inherits the claims of the given `token` and includes the new `claims`.
    pub fn consume_and_sign<H, C>(
        &self,
        token: SignedToken<H, A, C>,
        host_id: H,
        claims: C,
        now: SystemTime,
    ) -> Result<SignedToken<H, A, C>, Error>
    where
        H: Serialize + Clone,
        A: Serialize + Clone,
        C: Serialize + Clone,
    {
        let (token, claims) = Token::consume(token, now, host_id.clone(), self.id.clone(), claims)?;
        let token = self.sign_token_inner(&token)?;
        Ok(SignedToken::new(claims, token))
    }
}

impl<A: Clone> Clone for Actor<A> {
    fn clone(&self) -> Self {
        Actor {
            id: self.id.clone(),
            key: Key::Public(self.verifying_key()),
        }
    }
}

impl<A: fmt::Debug> fmt::Debug for Actor<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "actor {:?}", self.id)
    }
}
