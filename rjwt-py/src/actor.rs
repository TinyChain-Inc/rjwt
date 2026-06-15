use std::str::FromStr;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pymethods};

use rjwt_core::{Actor, AlgKind, Error, SigningKey, VerifyingKey};

use crate::token::{PySignedToken, PyToken};
use crate::{A, H, py_to_claims, to_py_err, unix_to_system_time};

fn parse_alg(alg: Option<&str>) -> PyResult<AlgKind> {
    match alg.unwrap_or("falcon512").to_ascii_lowercase().as_str() {
        "falcon512" | "falcon-512" | "fn-dsa-512" => Ok(AlgKind::Falcon512),
        "ed25519" | "eddsa" => Ok(AlgKind::Ed25519),
        other => Err(PyValueError::new_err(format!(
            "unsupported signature algorithm: {other}"
        ))),
    }
}

/// An actor with an [`hr_id::Id`] identifier and an rjwt signing keypair used to sign tokens.
///
/// Cloning an Actor strips the private key — the clone holds only the public key.
#[gen_stub_pyclass]
#[pyclass(name = "Actor")]
pub(crate) struct PyActor(pub(crate) Actor<A>);

#[gen_stub_pymethods]
#[pymethods]
impl PyActor {
    /// Create an Actor with a newly-generated signing keypair.
    #[new]
    fn new(id: &str) -> PyResult<Self> {
        let id = A::from_str(id).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self(Actor::new(id)))
    }

    /// Create an Actor from private-key bytes.
    #[staticmethod]
    fn with_keypair(
        id: &str,
        #[gen_stub(override_type(type_repr = "bytes"))] private_key: &[u8],
        alg: Option<&str>,
    ) -> PyResult<Self> {
        let id = A::from_str(id).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let alg = parse_alg(alg)?;
        let key = SigningKey::from_bytes(alg, private_key)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self(Actor::with_signing_key(id, key)))
    }

    /// Create an Actor from public-key bytes (verify-only, cannot sign).
    #[staticmethod]
    fn with_public_key(
        id: &str,
        #[gen_stub(override_type(type_repr = "bytes"))] public_key: &[u8],
        alg: Option<&str>,
    ) -> PyResult<Self> {
        let id = A::from_str(id).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let alg = parse_alg(alg)?;
        let key = VerifyingKey::from_bytes(alg, public_key)
            .map_err(|e: Error| PyValueError::new_err(e.to_string()))?;
        Ok(Self(Actor::with_verifying_key(id, key)))
    }

    #[cfg(feature = "falcon")]
    #[staticmethod]
    fn new_falcon512(id: &str) -> PyResult<Self> {
        let id = A::from_str(id).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let actor = Actor::new_falcon512(id).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self(actor))
    }

    /// Return the actor identifier as a string
    fn id(&self) -> String {
        self.0.id().to_string()
    }

    /// Return true if private key is present
    fn has_private_key(&self) -> bool {
        self.0.has_private_key()
    }

    /// Return public-key bytes.
    fn public_key_bytes(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }

    /// Return private-key bytes.
    fn private_key_bytes(&self) -> PyResult<Vec<u8>> {
        self.0
            .signing_key_bytes()
            .map_err(|e| PyValueError::new_err(e.to_string()))
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
