use std::str::FromStr;
use std::time::Duration;

use pathlink::Link;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use ::rjwt::{SignedToken, Token};

use crate::claims::PyClaims;
use crate::{A, C, H, py_to_claims, system_time_to_unix, unix_to_system_time};

/// An unsigned JWT: issuing host, actor, TTL, and a claims dict[str, int].
#[pyclass(name = "Token")]
pub(crate) struct PyToken(pub(crate) Token<H, A, C>);

#[pymethods]
impl PyToken {
    /// Construct a token.
    ///
    /// Args:
    ///     iss:       issuing host (str parsed as Link, e.g. ``"example.com"``)
    ///     iat_unix:  issue time as a Unix timestamp (float seconds)
    ///     ttl_secs:  time-to-live in seconds
    ///     actor_id:  actor identifier (str parsed as Id)
    ///     claims:    ``dict[str, int]`` — path strings mapped to octal mode ints
    #[new]
    pub(crate) fn new(
        iss: &str,
        iat_unix: f64,
        ttl_secs: f64,
        actor_id: &str,
        claims: &Bound<'_, PyAny>,
    ) -> PyResult<Self> {
        let iss = Link::from_str(iss).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let actor_id = A::from_str(actor_id).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let claims = py_to_claims(claims)?;
        let iat = unix_to_system_time(iat_unix);
        let ttl = Duration::from_secs_f64(ttl_secs);
        Ok(Self(Token::new(iss, iat, ttl, actor_id, claims)))
    }

    /// Return the issuing host as a string.
    fn issuer(&self) -> String {
        self.0.issuer().to_string()
    }

    /// Return the actor identifier as a string.
    fn actor_id(&self) -> String {
        self.0.actor_id().to_string()
    }

    fn is_expired(&self, now_unix: f64) -> bool {
        self.0.is_expired(unix_to_system_time(now_unix))
    }
}

/// A signed, encoded JWT together with its decoded chain of Claims.
#[pyclass(name = "SignedToken")]
pub(crate) struct PySignedToken(pub(crate) SignedToken<H, A, C>);

#[pymethods]
impl PySignedToken {
    /// Return the Claims chain for this token.
    fn claims(&self) -> PyClaims {
        PyClaims(self.0.claims().clone())
    }

    /// Return the expiration time as a Unix timestamp (float seconds).
    fn expires(&self) -> f64 {
        system_time_to_unix(self.0.expires())
    }

    /// Return the encoded JWT string.
    fn jwt(&self) -> &str {
        self.0.jwt()
    }

    fn __repr__(&self) -> String {
        format!("SignedToken(jwt={:?})", self.0.jwt())
    }
}
