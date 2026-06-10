//! Provides an [`Actor`] and (de)serializable [`Token`] struct which support authenticating
//! JSON Web Tokens with a custom payload. See [jwt.io](http://jwt.io) for more information
//! on the JWT spec.
//!
//! Two signature algorithms are supported:
//! - Ed25519 (EdDSA), via the [`ed25519_dalek`] crate — the default.
//! - Falcon-512 (FN-DSA-512), a post-quantum lattice signature, behind the `falcon`
//!   feature flag — gated by [`Actor::new_falcon512`].
//!
//! This library differs from other JWT implementations in that it allows for recursive [`Token`]s.
//!
//! Note that if the same `(host, actor)` pair is specified multiple times in the token chain,
//! only the latest is returned by [`Claims::get`].
//!
//! See the `ed25519` and `falcon` runnable examples under `rjwt-core/examples/` for a complete
//! walk-through of issuing, chaining, and verifying recursive tokens.

mod actor;
mod claims;
mod error;
mod resolve;
mod sig;
mod token;

pub use actor::Actor;
pub use claims::{Claims, Iter};
pub use error::Error;
pub use rand::rngs::OsRng;
pub use resolve::Resolve;
pub use sig::{AlgKind, Signature, SigningKey, VerifyingKey};
pub use token::{SignedToken, Token};
