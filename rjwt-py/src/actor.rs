use std::str::FromStr;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pymethods};

use ::rjwt_core::{Actor, SigningKey, VerifyingKey};

use crate::token::{PySignedToken, PyToken};
use crate::{A, H, py_to_claims, to_py_err, unix_to_system_time};

/// An actor with an [`hr_id::Id`] identifier and an ECDSA keypair used to sign tokens.
///
/// Cloning an Actor strips the private key — the clone holds only the public key.
#[gen_stub_pyclass]
#[pyclass(name = "Actor")]
pub(crate) struct PyActor(pub(crate) Actor<A>);

#[gen_stub_pymethods]
#[pymethods]
impl PyActor {
    /// Create an Actor with a newly-generated keypair.
    #[new]
    fn new(id: &str) -> PyResult<Self> {
        let id = A::from_str(id).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self(Actor::new(id)))
    }

    /// Create an Actor from a 32-byte Ed25519 private key.
    #[staticmethod]
    fn with_keypair(id: &str,
        #[gen_stub(override_type(type_repr = "bytes"))]
        private_key: &[u8]) -> PyResult<Self> {
        let id = A::from_str(id).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let bytes: [u8; 32] = private_key
            .try_into()
            .map_err(|_| PyValueError::new_err("private key must be exactly 32 bytes"))?;
        Ok(Self(Actor::with_keypair(
            id,
            SigningKey::from_bytes(&bytes),
        )))
    }

    /// Create an Actor from a 32-byte Ed25519 public key (verify-only, cannot sign).
    #[staticmethod]
    fn with_public_key(id: &str, 
        #[gen_stub(override_type(type_repr = "bytes"))]
        public_key: &[u8]) -> PyResult<Self> {
        let id = A::from_str(id).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let bytes: &[u8; 32] = public_key
            .try_into()
            .map_err(|_| PyValueError::new_err("public key must be exactly 32 bytes"))?;
        let key = VerifyingKey::from_bytes(bytes)
            .map_err(|e: ed25519_dalek::SignatureError| PyValueError::new_err(e.to_string()))?;
        Ok(Self(Actor::with_public_key(id, key)))
    }

    /// Return the actor identifier as a string
    fn id(&self) -> String {
        self.0.id().to_string()
    }

    /// Return true if private key is present
    fn has_private_key(&self) -> bool {
        self.0.has_private_key()
    }

    /// Return the 32-byte Ed25519 public key.
    fn public_key_bytes(&self) -> Vec<u8> {
        self.0.public_key().to_bytes().to_vec()
    }

    /// Sign a Token, returning a SignedToken.
    fn sign_token(&self, token: &PyToken) -> PyResult<PySignedToken> {
        self.0
            .sign_token(token.0.clone())
            .map(PySignedToken)
            .map_err(to_py_err)
    }

    /// Consume a SignedToken and sign a new child token that inherits its claims.
    ///
    /// Args:
    ///     token:    the parent SignedToken to inherit from
    ///     host_id:  issuing host URL string for the new segment (e.g. ``"http://retailer.com"``)
    ///     claims:   new claims dict[str, int] (path → mode bits)
    ///     now_unix: current time as Unix timestamp (float seconds)
    fn consume_and_sign(
        &self,
        token: &PySignedToken,
        host_id: &str,
        claims: &Bound<'_, PyAny>,
        now_unix: f64,
    ) -> PyResult<PySignedToken> {
        let host_id = H::from_str(host_id).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let claims = py_to_claims(claims)?;
        let now = unix_to_system_time(now_unix);
        self.0
            .consume_and_sign(token.0.clone(), host_id, claims, now)
            .map(PySignedToken)
            .map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!("Actor(id={:?})", self.0.id().to_string())
    }
}
