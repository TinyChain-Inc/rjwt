use std::fmt;
use std::pin::Pin;
use std::time::SystemTime;

use ed25519_dalek::Verifier;
use futures::Future;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::actor::Actor;
use crate::claims::Claims;
use crate::error::{Error, ErrorKind};
use crate::token::{SignedToken, Token, decode_token, token_signature};

type ResolveResult<A> = Result<Actor<A>, Error>;
type VerifyResult<H, A, C> = Result<SignedToken<H, A, C>, Error>;
type Verification<'a, H, A, C> =
    Pin<Box<dyn Future<Output = Result<Claims<H, A, C>, Error>> + Send + 'a>>;

/// Trait which defines how to fetch an [`Actor`] given its host and ID
pub trait Resolve: Send + Sync {
    type HostId: Serialize + DeserializeOwned + fmt::Debug + Send + Sync;
    type ActorId: Serialize + DeserializeOwned + fmt::Debug + Send + Sync;
    type Claims: Serialize + DeserializeOwned + Send + Sync;

    /// Given a host and actor ID, return a corresponding [`Actor`].
    fn resolve(
        &self,
        host: &Self::HostId,
        actor_id: &Self::ActorId,
    ) -> impl Future<Output = ResolveResult<Self::ActorId>> + Send;

    /// Decode and verify the given `encoded` token.
    fn verify(
        &self,
        encoded: String,
        now: SystemTime,
    ) -> impl Future<Output = VerifyResult<Self::HostId, Self::ActorId, Self::Claims>> + Send
    where
        Self::ActorId: PartialEq,
    {
        async move {
            let claims = verify_claims(self, &encoded, now).await?;
            Ok(SignedToken::new(claims, encoded))
        }
    }
}

async fn decode_and_verify_token<R>(
    resolver: &R,
    encoded: &str,
    now: SystemTime,
) -> Result<Token<R::HostId, R::ActorId, R::Claims>, Error>
where
    R: Resolve + ?Sized,
    R::ActorId: PartialEq,
{
    let (message, signature) = token_signature(encoded)?;
    let token: Token<R::HostId, R::ActorId, R::Claims> = decode_token(message)?;

    if token.is_expired(now) {
        return Err(Error::new(ErrorKind::Time, "token is expired".into()));
    }

    let actor = resolver.resolve(&token.iss, &token.actor_id).await?;

    if actor.id() != &token.actor_id {
        return Err(Error::auth(
            "attempted to use a bearer token for a different actor",
        ));
    }

    if let Err(cause) = actor.public_key().verify(message.as_bytes(), &signature) {
        Err(Error::auth(format!("invalid bearer token: {cause}")))
    } else {
        Ok(token)
    }
}

fn verify_claims<'a, R>(
    resolver: &'a R,
    encoded: &'a str,
    now: SystemTime,
) -> Verification<'a, R::HostId, R::ActorId, R::Claims>
where
    R: Resolve + ?Sized,
    R::ActorId: PartialEq,
{
    Box::pin(async move {
        let token = decode_and_verify_token(resolver, encoded, now).await?;

        if let Some(parent) = token.inherit {
            let parent_claims = verify_claims(resolver, &parent, now).await?;

            if token.exp <= parent_claims.exp {
                parent_claims.consume(token.iss, token.actor_id, token.custom)
            } else {
                Err(Error::new(
                    ErrorKind::Time,
                    "cannot extend the expiration time of a recursive token".into(),
                ))
            }
        } else {
            Ok(Claims::new(
                token.exp,
                token.iss,
                token.actor_id,
                token.custom,
            ))
        }
    })
}
