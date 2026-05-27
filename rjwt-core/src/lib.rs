//! Provides an [`Actor`] and (de)serializable [`Token`] struct which support authenticating
//! JSON Web Tokens with a custom payload. See [jwt.io](http://jwt.io) for more information
//! on the JWT spec.
//!
//! The provided [`Actor`] uses the
//! [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
//! algorithm to sign tokens (using the [`ed25519_dalek`] crate).
//!
//! This library differs from other JWT implementations in that it allows for recursive [`Token`]s.
//!
//! Note that if the same `(host, actor)` pair is specified multiple times in the token chain,
//! only the latest is returned by [`Claims::get`].
//!
//! Example:
//! ```
//! # use std::collections::HashMap;
//! # use std::time::{Duration, SystemTime};
//! # use futures::executor::block_on;
//! use rjwt_core::*;
//!
//! #[derive(Clone)]
//! struct Resolver {
//!     hostname: String,
//!     actors: HashMap<String, Actor<String>>,
//!     peers: Vec<Self>,
//! }
//! // ...
//! # impl Resolver {
//! #    fn new<A: IntoIterator<Item = Actor<String>>>(hostname: String, actors: A, peers: Vec<Self>) -> Self {
//! #        Self { hostname, actors: actors.into_iter().map(|a| (a.id().clone(), a)).collect(), peers }
//! #    }
//! # }
//!
//! impl Resolve for Resolver {
//!     type HostId = String;
//!     type ActorId = String;
//!     type Claims = String;
//!
//!     fn resolve(&self, host: &Self::HostId, actor_id: &Self::ActorId)
//!         -> impl std::future::Future<Output = Result<Actor<Self::ActorId>, Error>> + Send
//!     {
//!         let this = self;
//!         async move {
//!             if host == &this.hostname {
//!                 this.actors.get(actor_id).cloned().ok_or_else(|| Error::fetch(actor_id))
//!             } else if let Some(peer) = this.peers.iter().filter(|p| &p.hostname == host).next() {
//!                 Box::pin(peer.resolve(host, actor_id)).await
//!             } else {
//!                 Err(Error::fetch(host))
//!             }
//!         }
//!     }
//! }
//!
//! let now = SystemTime::now();
//!
//! // Say that Bob is a user on example.com.
//! let bobs_id = "bob".to_string();
//! let example_dot_com = "example.com".to_string();
//!
//! let actor_bob = Actor::new(bobs_id.clone());
//! let example = Resolver::new(example_dot_com.clone(), [actor_bob.clone()], vec![]);
//!
//! // Bob makes a request through the retailer.com app.
//! let retailer_dot_com = "retailer.com".to_string();
//! let retail_app = Actor::new("app".to_string());
//! let retailer = Resolver::new(
//!     retailer_dot_com.clone(),
//!     [retail_app.clone()],
//!     vec![example.clone()]);
//!
//! // The retailer.com app makes a request to Bob's bank.
//! let bank_account = Actor::new("bank".to_string());
//! let bank = Resolver::new(
//!     "bank.com".to_string(),
//!     [bank_account.clone()],
//!     vec![example, retailer.clone()]);
//!
//! // First, example.com issues a token to authenticate Bob.
//! let bobs_claim = String::from("I am Bob and retailer.com may debit my bank.com account");
//!
//! // This requires constructing the token...
//! let bobs_token = Token::new(
//!     example_dot_com.clone(),
//!     now,
//!     Duration::from_secs(30),
//!     actor_bob.id().to_string(),
//!     bobs_claim.clone());
//!
//! // and signing it with Bob's private key.
//! let bobs_token = actor_bob.sign_token(bobs_token).expect("signed token");
//!
//! // Then, retailer.com validates the token...
//! let bobs_token = block_on(retailer.verify(bobs_token.into_jwt(), now)).expect("claims");
//! assert!(bobs_token.claims().get(&example_dot_com, &bobs_id).expect("claim").starts_with("I am Bob"));
//!
//! // and adds its own claim, that Bob owes it $1.
//! let retailer_claim = String::from("Bob spent $1 on retailer.com");
//! let retailer_token = retail_app.consume_and_sign(
//!     bobs_token,
//!     retailer_dot_com.clone(),
//!     retailer_claim.clone(),
//!     now).expect("signed token");
//!
//! assert_eq!(retailer_token
//!     .claims()
//!     .get(&retailer_dot_com, retail_app.id()), Some(&retailer_claim));
//!
//! assert_eq!(retailer_token
//!     .claims()
//!     .get(&example_dot_com, actor_bob.id()), Some(&bobs_claim));
//!
//! // Finally, Bob's bank verifies the token...
//! let retailer_token_as_received = block_on(
//!     bank.verify(retailer_token.jwt().to_string(), now)
//! ).expect("claims");
//!
//! assert_eq!(retailer_token, retailer_token_as_received);
//!
//! // to authenticate that the request came from Bob...
//! assert!(retailer_token_as_received
//!     .claims()
//!     .get(&example_dot_com, &bobs_id)
//!     .expect("claim")
//!     .starts_with("I am Bob and retailer.com may debit my bank.com account"));
//!
//! // via retailer.com.
//! assert!(retailer_token_as_received
//!     .claims()
//!     .get(&retailer_dot_com, retail_app.id())
//!     .expect("claim")
//!     .starts_with("Bob spent $1"));
//! ```

mod actor;
mod claims;
mod error;
mod resolve;
mod token;

pub use actor::Actor;
pub use claims::{Claims, Iter};
pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
pub use error::Error;
pub use rand::rngs::OsRng;
pub use resolve::Resolve;
pub use token::{SignedToken, Token};

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use crate::token::token_signature;

    use super::*;

    const SIZE_LIMIT: usize = 8000; // max HTTP header size

    #[test]
    fn test_format() {
        let actor = Actor::new("actor".to_string());
        let token = Token::new(
            "example.com".to_string(),
            SystemTime::now(),
            Duration::from_secs(30),
            actor.id().to_string(),
            (),
        );

        let signed = actor.sign_token(token).unwrap();
        let (message, _) = token_signature(signed.jwt()).unwrap();

        assert!(signed.jwt().starts_with(message));
        assert!(signed.jwt().len() < SIZE_LIMIT);
    }
}
