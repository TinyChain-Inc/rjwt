use std::fmt;
use std::time::SystemTime;

use base64::prelude::*;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::Serialize;

use crate::claims::Claims;
use crate::error::Error;
use crate::token::{SignedToken, Token, TokenHeader};

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
/// # use rjwt::Actor;
/// let actor = Actor::<String>::new("id".to_string()); // this has a new secret key
/// let cloned = actor.clone(); // this does NOT have a secret key, only a public key
/// ```
pub struct Actor<A> {
    pub(crate) id: A,
    key: Key,
}

impl<A> Actor<A> {
    /// Return an `Actor` with a newly-generated keypair.
    pub fn new(id: A) -> Self {
        Self::with_keypair(id, SigningKey::generate(&mut OsRng))
    }

    /// Return an `Actor` with the given keypair, or an error if the keypair is invalid.
    pub fn with_keypair(id: A, keypair: SigningKey) -> Self {
        Self {
            id,
            key: Key::Private(keypair),
        }
    }

    /// Return an `Actor` with the given public key, or an error if the key is invalid.
    pub fn with_public_key(id: A, public_key: VerifyingKey) -> Self {
        Self {
            id,
            key: Key::Public(public_key),
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

    /// Borrow the public key of this actor, which a client can use to verify a signature.
    pub fn public_key(&self) -> VerifyingKey {
        match &self.key {
            Key::Public(public_key) => *public_key,
            Key::Private(keypair) => keypair.verifying_key(),
        }
    }

    fn sign_token_inner<H, C>(&self, token: &Token<H, A, C>) -> Result<String, Error>
    where
        H: Serialize,
        A: Serialize,
        C: Serialize,
    {
        let keypair = match &self.key {
            Key::Private(keypair) => Ok(keypair),
            Key::Public(_) => Err(Error::auth("cannot sign a token without a private key")),
        }?;

        let header = BASE64_STANDARD.encode(serde_json::to_string(&TokenHeader::default())?);
        let claims = BASE64_STANDARD.encode(serde_json::to_string(&token)?);

        let signature = keypair.try_sign(format!("{header}.{claims}").as_bytes())?;
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
            key: match &self.key {
                Key::Public(public_key) => Key::Public(*public_key),
                Key::Private(keypair) => Key::Public(keypair.verifying_key()),
            },
        }
    }
}

impl<A: fmt::Debug> fmt::Debug for Actor<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "actor {:?}", self.id)
    }
}
