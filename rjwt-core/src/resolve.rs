use std::fmt;
use std::pin::Pin;
use std::time::SystemTime;

use futures::Future;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::actor::Actor;
use crate::claims::Claims;
use crate::error::Error;
use crate::sig::AlgKind;
use crate::token::{SignedToken, Token, decode_header_and_inherit, decode_token, token_signature};

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
            validate_uniform_alg(&encoded)?;
            let claims = verify_claims(self, &encoded, now).await?;
            Ok(SignedToken::new(claims, encoded))
        }
    }
}

/// Walk the inherit chain header-only and return the single [`AlgKind`] shared by every segment.
///
/// Returns `Error::Auth` if any two segments have differing alg headers.
/// Returns `Error::Format` on malformed header/JWT structure.
///
/// Does NOT invoke the resolver or verify any signature — purely a header-level scan.
fn validate_uniform_alg(encoded: &str) -> Result<AlgKind, Error> {
    let (first_alg, mut maybe_inherit) = decode_header_and_inherit(encoded)?;

    while let Some(inner) = maybe_inherit {
        let (inner_alg, next_inherit) = decode_header_and_inherit(&inner)?;
        if inner_alg != first_alg {
            return Err(Error::auth("mixed-algorithm chains are not supported"));
        }
        maybe_inherit = next_inherit;
    }

    Ok(first_alg)
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
    let (alg, token): (_, Token<R::HostId, R::ActorId, R::Claims>) = decode_token(encoded)?;
    let (message, signature) = token_signature(encoded, alg)?;

    if token.is_expired(now) {
        return Err(Error::Time("token is expired".to_owned()));
    }

    let actor = resolver.resolve(&token.iss, &token.actor_id).await?;

    if actor.id() != &token.actor_id {
        return Err(Error::auth(
            "attempted to use a bearer token for a different actor",
        ));
    }

    if let Err(cause) = actor.verifying_key().verify(message.as_bytes(), &signature) {
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
                Err(Error::Time(
                    "cannot extend the expiration time of a recursive token".to_owned(),
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
