//! Python bindings for the [`rjwt`] crate.
//!
//! Concrete type parameters used throughout:
//! - **host** (`H`): [`pathlink::Link`] — a typed URL / host identifier
//! - **actor** (`A`): [`hr_id::Id`] — a human-readable, reference-counted identifier
//! - **claims** (`C`): [`HashMap`]`<`[`pathlink::PathBuf`]`, `[`umask::Mode`]`>` — a map of
//!   path → POSIX permission bits granted by this token segment
//!
//! # Python usage
//!
//! ```python
//! import asyncio, time
//! import rjwt_py
//!
//! class ExampleResolver:
//!     def __init__(self, host, actors, peers=None):
//!         self.host   = host
//!         self.actors = actors   # {actor_id_str: rjwt_py.Actor}
//!         self.peers  = peers or []
//!
//!     async def resolve(self, host: str, actor_id: str) -> rjwt_py.Actor:
//!         if host == self.host:
//!             if actor_id in self.actors:
//!                 return self.actors[actor_id]
//!             raise RuntimeError(f"Unknown actor: {actor_id}")
//!         for peer in self.peers:
//!             if peer.host == host:
//!                 return await peer.resolve(host, actor_id)
//!         raise RuntimeError(f"Unknown host: {host}")
//!
//! async def main():
//!     now = time.time()
//!
//!     # Bob is a user on example.com.
//!     bob = rjwt_py.Actor("bob")
//!     example = ExampleResolver("example.com", {"bob": bob})
//!
//!     # The retailer.com app acts on Bob's behalf.
//!     app = rjwt_py.Actor("app")
//!     retailer = ExampleResolver("retailer.com", {"app": app}, peers=[example])
//!
//!     # example.com issues a token granting Bob access to specific paths.
//!     # Claims are expressed as {path_str: octal_mode_int}.
//!     bobs_claims = {"/home/bob": 0o755, "/tmp": 0o777}
//!     token = rjwt_py.Token("example.com", now, 30.0, "bob", bobs_claims)
//!     bobs_token = bob.sign_token(token)
//!
//!     # retailer.com verifies the token and reads Bob's claims.
//!     verified = await rjwt_py.Resolver(example).verify(bobs_token.jwt(), now)
//!     assert verified.claims().get("example.com", "bob") == bobs_claims
//!
//!     # retailer.com adds its own claim and re-signs.
//!     app_claims = {"/orders/42": 0o644}
//!     retail_token = app.consume_and_sign(verified, "retailer.com", app_claims, now)
//!
//!     # Bob's bank verifies the full chain.
//!     bank = ExampleResolver("bank.com", {}, peers=[example, retailer])
//!     final = await rjwt_py.Resolver(bank).verify(retail_token.jwt(), now)
//!
//!     # Both claim segments are accessible.
//!     assert final.claims().get("example.com", "bob") == bobs_claims
//!     assert final.claims().get("retailer.com", "app") == app_claims
//!
//! asyncio.run(main())
//! ```

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hr_id::Id;
use pathlink::{Link, PathBuf as LinkBuf};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3_async_runtimes::tokio::future_into_py;
use serde::{Deserialize, Serialize};
use umask::Mode;

// Use absolute paths to avoid ambiguity with the `rjwt_py` pymodule name below.
use ::rjwt::{Actor, Claims, Error, Resolve, SignedToken, SigningKey, Token, VerifyingKey};

/// Host identifier type: a typed URL / host address.
type H = Link;
/// Actor identifier type: a human-readable, reference-counted string id.
type A = Id;
/// Claims payload type: a map of path → POSIX permission bits.
type C = HashMap<LinkBuf, SerMode>;

/// Newtype wrapper around [`umask::Mode`] that provides [`Serialize`]/[`Deserialize`]
/// by round-tripping through `u32`, since `umask` does not enable serde itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
struct SerMode(u32);

impl From<Mode> for SerMode {
    fn from(m: Mode) -> Self {
        Self(u32::from(m))
    }
}

impl From<SerMode> for Mode {
    fn from(s: SerMode) -> Self {
        Mode::from(s.0)
    }
}

// ── Conversion helpers ────────────────────────────────────────────────────────

fn to_py_err(e: Error) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

fn unix_to_system_time(unix_secs: f64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs_f64(unix_secs)
}

fn system_time_to_unix(t: SystemTime) -> f64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64()
}

/// Convert a Python `dict[str, int]` to `BTreeMap<LinkBuf, SerMode>`.
///
/// Keys are parsed as [`pathlink::PathBuf`]; values are treated as raw `u32` mode bits
/// (e.g. `0o755`) and stored as [`SerMode`].
fn py_to_claims(obj: &Bound<'_, PyAny>) -> PyResult<C> {
    let raw: std::collections::HashMap<String, u32> = obj
        .extract()
        .map_err(|_| PyValueError::new_err("claims must be a dict[str, int]"))?;
    raw.into_iter()
        .map(|(k, v)| {
            LinkBuf::from_str(&k)
                .map(|path| (path, SerMode(v)))
                .map_err(|e| PyValueError::new_err(e.to_string()))
        })
        .collect()
}

/// Convert `BTreeMap<LinkBuf, SerMode>` to a Python `dict[str, int]`.
fn claims_to_py(py: Python<'_>, claims: &C) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    for (path, mode) in claims {
        dict.set_item(path.to_string(), mode.0)?;
    }
    Ok(dict.into_any().unbind())
}

// ── PyActor ───────────────────────────────────────────────────────────────────

/// An actor with an [`hr_id::Id`] identifier and an ECDSA keypair used to sign tokens.
///
/// Cloning an Actor strips the private key — the clone holds only the public key.
#[pyclass(name = "Actor")]
struct PyActor(Actor<A>);

#[pymethods]
impl PyActor {
    /// Create an Actor with a newly-generated keypair.
    #[new]
    fn new(id: &str) -> PyResult<Self> {
        let id = Id::from_str(id).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self(Actor::new(id)))
    }

    /// Create an Actor from a 32-byte Ed25519 private key.
    #[staticmethod]
    fn with_keypair(id: &str, private_key: &[u8]) -> PyResult<Self> {
        let id = Id::from_str(id).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let bytes: [u8; 32] = private_key
            .try_into()
            .map_err(|_| PyValueError::new_err("private key must be exactly 32 bytes"))?;
        Ok(Self(Actor::with_keypair(id, SigningKey::from_bytes(&bytes))))
    }

    /// Create an Actor from a 32-byte Ed25519 public key (verify-only, cannot sign).
    #[staticmethod]
    fn with_public_key(id: &str, public_key: &[u8]) -> PyResult<Self> {
        let id = Id::from_str(id).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let bytes: &[u8; 32] = public_key
            .try_into()
            .map_err(|_| PyValueError::new_err("public key must be exactly 32 bytes"))?;
        let key = VerifyingKey::from_bytes(bytes)
            .map_err(|e: ed25519_dalek::SignatureError| PyValueError::new_err(e.to_string()))?;
        Ok(Self(Actor::with_public_key(id, key)))
    }

    fn id(&self) -> String {
        self.0.id().to_string()
    }

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
    ///     host_id:  issuing host for the new segment (str parsed as Link)
    ///     claims:   new claims dict[str, int] (path → mode bits)
    ///     now_unix: current time as Unix timestamp (float seconds)
    fn consume_and_sign(
        &self,
        token: &PySignedToken,
        host_id: &str,
        claims: &Bound<'_, PyAny>,
        now_unix: f64,
    ) -> PyResult<PySignedToken> {
        let host_id =
            Link::from_str(host_id).map_err(|e| PyValueError::new_err(e.to_string()))?;
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

// ── PyToken ───────────────────────────────────────────────────────────────────

/// An unsigned JWT: issuing host, actor, TTL, and a claims dict[str, int].
#[pyclass(name = "Token")]
struct PyToken(Token<H, A, C>);

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
    fn new(
        iss: &str,
        iat_unix: f64,
        ttl_secs: f64,
        actor_id: &str,
        claims: &Bound<'_, PyAny>,
    ) -> PyResult<Self> {
        let iss = Link::from_str(iss).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let actor_id =
            Id::from_str(actor_id).map_err(|e| PyValueError::new_err(e.to_string()))?;
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

// ── PySignedToken ─────────────────────────────────────────────────────────────

/// A signed, encoded JWT together with its decoded chain of Claims.
#[pyclass(name = "SignedToken")]
struct PySignedToken(SignedToken<H, A, C>);

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

// ── PyClaims ──────────────────────────────────────────────────────────────────

/// The chain of claims carried by a SignedToken, from newest to oldest.
#[pyclass(name = "Claims")]
struct PyClaims(Claims<H, A, C>);

#[pymethods]
impl PyClaims {
    /// Return the most recent claim for ``(host, actor_id)``, or ``None``.
    ///
    /// The returned value is a ``dict[str, int]`` mapping path strings to mode bits.
    fn get(
        &self,
        py: Python<'_>,
        host: &str,
        actor_id: &str,
    ) -> PyResult<Option<PyObject>> {
        let h = Link::from_str(host).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let a = Id::from_str(actor_id).map_err(|e| PyValueError::new_err(e.to_string()))?;
        match self.0.get(&h, &a) {
            Some(c) => Ok(Some(claims_to_py(py, c)?)),
            None => Ok(None),
        }
    }

    /// Return all claims as a list of ``(host_str, actor_id_str, dict[str, int])``
    /// tuples, from newest segment to oldest.
    fn iter(&self, py: Python<'_>) -> PyResult<Vec<(String, String, PyObject)>> {
        self.0
            .iter()
            .map(|(h, a, c)| {
                let py_c = claims_to_py(py, c)?;
                Ok((h.to_string(), a.to_string(), py_c))
            })
            .collect()
    }
}

// ── Resolver ─────────────────────────────────────────────────────────────────

struct InnerResolver {
    py_obj: Py<PyAny>,
}

// SAFETY: Py<PyAny> is a reference-counted pointer; it is only dereferenced
// while holding the GIL, which is enforced by the Python::with_gil calls below.
unsafe impl Send for InnerResolver {}
unsafe impl Sync for InnerResolver {}

impl Resolve for InnerResolver {
    type HostId = H;
    type ActorId = A;
    type Claims = C;

    fn resolve(
        &self,
        host: &H,
        actor_id: &A,
    ) -> impl std::future::Future<Output = Result<Actor<A>, Error>> + Send {
        // Convert Link/Id to strings before entering the async block so there
        // are no borrows of `self` inside the future.
        let host_str = host.to_string();
        let actor_str = actor_id.to_string();
        // clone_ref increments the CPython refcount; requires the GIL.
        let py_obj = Python::with_gil(|py| self.py_obj.clone_ref(py));

        async move {
            // Call Python's async resolve(host, actor_id).
            // Acquire the GIL to call the method and convert the coroutine to a
            // Rust Future, then release the GIL before awaiting.
            let future = Python::with_gil(|py| {
                let coro = py_obj
                    .call_method1(py, "resolve", (host_str.clone(), actor_str.clone()))
                    .map_err(|e: PyErr| Error::fetch(e.to_string()))?;
                pyo3_async_runtimes::tokio::into_future(coro.into_bound(py))
                    .map_err(|e: PyErr| Error::fetch(e.to_string()))
            })?;

            let result = future.await.map_err(|e: PyErr| Error::fetch(e.to_string()))?;

            // Extract the PyActor returned by Python.
            // Actor::clone() strips the private key, returning a public-key-only
            // actor suitable for signature verification.
            Python::with_gil(|py| {
                let py_actor: PyRef<'_, PyActor> = result.bind(py).extract()?;
                Ok::<_, PyErr>(py_actor.0.clone())
            })
            .map_err(|e: PyErr| Error::fetch(e.to_string()))
        }
    }
}

/// Wraps a Python object implementing ``async def resolve(host: str, actor_id: str) -> Actor``
/// and exposes a ``verify`` coroutine that decodes and validates signed JWT strings.
///
/// The Python resolver is responsible for looking up actors by host and ID and
/// returning an ``Actor`` constructed via ``Actor.with_public_key``.
#[pyclass(name = "Resolver")]
struct PyResolver {
    inner: Arc<InnerResolver>,
}

#[pymethods]
impl PyResolver {
    #[new]
    fn new(py_obj: Py<PyAny>) -> Self {
        Self {
            inner: Arc::new(InnerResolver { py_obj }),
        }
    }

    /// Decode and verify ``encoded`` as of ``now_unix`` (Unix timestamp, float seconds).
    ///
    /// Returns a coroutine that resolves to a ``SignedToken`` containing the full
    /// claim chain. Raises ``RuntimeError`` if the token is invalid or expired.
    fn verify<'py>(
        &self,
        py: Python<'py>,
        encoded: String,
        now_unix: f64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let now = unix_to_system_time(now_unix);
        // Arc::clone gives the async block an owned handle so the future is 'static.
        let inner = Arc::clone(&self.inner);

        future_into_py(py, async move {
            let signed = inner.verify(encoded, now).await.map_err(to_py_err)?;
            Ok(PySignedToken(signed))
        })
    }
}

// ── Module ───────────────────────────────────────────────────────────────────

#[pymodule]
fn rjwt_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyActor>()?;
    m.add_class::<PyToken>()?;
    m.add_class::<PySignedToken>()?;
    m.add_class::<PyClaims>()?;
    m.add_class::<PyResolver>()?;
    Ok(())
}
