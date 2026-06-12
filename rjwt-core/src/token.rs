use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::prelude::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::claims::Claims;
use crate::error::Error;
use crate::sig::{AlgKind, Signature};

#[derive(Eq, PartialEq, Debug, Deserialize, Serialize)]
pub(crate) struct TokenHeader {
    alg: Option<String>,
    typ: String,
}

impl TokenHeader {
    pub(crate) fn for_alg(alg: AlgKind) -> Self {
        Self {
            alg: Some(alg.jwt_name().to_string()),
            typ: "JWT".to_string(),
        }
    }
}

/// The JSON Web Token wire format
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct Token<H, A, C> {
    pub(crate) iss: H,
    iat: u64,
    pub(crate) exp: u64,
    pub(crate) actor_id: A,
    pub(crate) custom: C,
    pub(crate) inherit: Option<String>,
}

impl<H, A, C> Token<H, A, C> {
    /// Create a new (unsigned) token.
    pub fn new(iss: H, iat: SystemTime, ttl: Duration, actor_id: A, claims: C) -> Self {
        let iat = iat.duration_since(UNIX_EPOCH).expect("duration");
        let exp = iat + ttl;

        Self {
            iss,
            iat: iat.as_secs(),
            exp: exp.as_secs(),
            actor_id,
            custom: claims,
            inherit: None,
        }
    }

    pub(crate) fn consume(
        parent: SignedToken<H, A, C>,
        iat: SystemTime,
        host_id: H,
        actor_id: A,
        claims: C,
    ) -> Result<(Self, Claims<H, A, C>), Error>
    where
        H: Clone,
        A: Clone,
        C: Clone,
    {
        let iat = iat.duration_since(UNIX_EPOCH)?;
        let exp = parent.expires().duration_since(UNIX_EPOCH)?;

        let token = Self {
            iss: host_id.clone(),
            iat: iat.as_secs(),
            exp: exp.as_secs(),
            actor_id: actor_id.clone(),
            custom: claims.clone(),
            inherit: Some(parent.jwt),
        };

        let claims = parent.claims.consume(host_id, actor_id, claims)?;

        Ok((token, claims))
    }

    /// Borrow the claimed issuer of this token.
    pub fn issuer(&self) -> &H {
        &self.iss
    }

    /// Borrow the actor to whom this token claims to belong.
    pub fn actor_id(&self) -> &A {
        &self.actor_id
    }

    /// Return `true` if this token is expired (or not yet issued) at the given moment.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        let iat = UNIX_EPOCH + Duration::from_secs(self.iat);
        let exp = UNIX_EPOCH + Duration::from_secs(self.exp);
        now < iat || now >= exp
    }
}

impl<H: fmt::Display, A: fmt::Display, C> fmt::Debug for Token<H, A, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "JWT token claiming to authenticate actor {} at host {}",
            self.actor_id, self.iss
        )
    }
}

/// The data of a JWT including its (inherited) claims and encoded, signed representation.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedToken<H, A, C> {
    claims: Claims<H, A, C>,
    jwt: String,
}

impl<H, A, C> SignedToken<H, A, C> {
    pub(crate) fn new(data: Claims<H, A, C>, jwt: String) -> Self {
        Self { claims: data, jwt }
    }

    /// Borrow the [`Claims`] of this [`SignedToken`].
    pub fn claims(&self) -> &Claims<H, A, C> {
        &self.claims
    }

    /// Check the expiration time of this [`SignedToken`].
    pub fn expires(&self) -> SystemTime {
        self.claims.expires()
    }

    /// Borrow the signed, encoded representation of this token.
    pub fn jwt(&self) -> &str {
        &self.jwt
    }

    /// Destructure this [`SignedToken`] into its encoded representation.
    pub fn into_jwt(self) -> String {
        self.jwt
    }
}

impl<H: fmt::Debug, A: fmt::Debug, C: fmt::Debug> fmt::Debug for SignedToken<H, A, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "JWT {} which claims {:?}", self.jwt, self.claims)
    }
}

pub(crate) fn token_signature(encoded: &str, alg: AlgKind) -> Result<(&str, Signature), Error> {
    if encoded.ends_with('.') {
        return Err(Error::format("encoded token cannot end with ."));
    }

    let i = encoded
        .rfind('.')
        .ok_or_else(|| Error::format(format!("invalid token: {}", encoded)))?;

    let message = &encoded[..i];

    let signature_bytes = BASE64_STANDARD
        .decode(&encoded[(i + 1)..])
        .map_err(|e| Error::Base64(e.to_string()))?;

    let signature = Signature::from_bytes(alg, &signature_bytes)?;

    Ok((message, signature))
}

/// Decode only the JWT header and extract the `inherit` field from the body as a raw JSON value,
/// without binding generic payload types. Used by the alg-uniformity pre-pass.
pub(crate) fn decode_header_and_inherit(encoded: &str) -> Result<(AlgKind, Option<String>), Error> {
    let i = encoded
        .find('.')
        .ok_or_else(|| Error::format(format!("invalid token: {}", encoded)))?;

    let header_bytes = BASE64_STANDARD.decode(&encoded[..i])?;
    let header: TokenHeader =
        serde_json::from_slice(&header_bytes).map_err(|e| Error::Format(e.to_string()))?;

    if header.typ != "JWT" {
        return Err(Error::format(format!(
            "unsupported token type: {}",
            header.typ
        )));
    }

    let alg_str = header
        .alg
        .ok_or_else(|| Error::format("missing alg field in token header"))?;
    let alg = AlgKind::from_jwt_name(&alg_str)?;

    let body_part = &encoded[(i + 1)..];
    let dot = body_part
        .find('.')
        .ok_or_else(|| Error::format(format!("invalid token: {}", encoded)))?;

    let body_bytes = BASE64_STANDARD.decode(&body_part[..dot])?;
    let body: serde_json::Value = serde_json::from_slice(&body_bytes)?;

    let inherit = body
        .get("inherit")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());

    Ok((alg, inherit))
}

pub(crate) fn decode_token<H, A, C>(encoded: &str) -> Result<(AlgKind, Token<H, A, C>), Error>
where
    H: DeserializeOwned,
    A: DeserializeOwned,
    C: DeserializeOwned,
{
    let i = encoded
        .find('.')
        .ok_or_else(|| Error::format(format!("invalid token: {}", encoded)))?;

    let header_bytes = BASE64_STANDARD.decode(&encoded[..i])?;
    let header: TokenHeader =
        serde_json::from_slice(&header_bytes).map_err(|e| Error::Format(e.to_string()))?;

    if header.typ != "JWT" {
        return Err(Error::format(format!(
            "unsupported token type: {}",
            header.typ
        )));
    }

    let alg_str = header
        .alg
        .ok_or_else(|| Error::format("missing alg field in token header"))?;
    let alg = AlgKind::from_jwt_name(&alg_str)?;

    let body_part = &encoded[(i + 1)..];
    let dot = body_part
        .find('.')
        .ok_or_else(|| Error::format(format!("invalid token: {}", encoded)))?;

    let token_bytes = BASE64_STANDARD.decode(&body_part[..dot])?;
    let token = serde_json::from_slice(&token_bytes)?;

    Ok((alg, token))
}
