//! Python bindings for the [`rjwt`] crate.
//!
//! Concrete type parameters used throughout:
//! - **host** (`H`): [`pathlink::Link`] — a typed URL / host identifier
//! - **actor** (`A`): [`hr_id::Id`] — a human-readable, reference-counted identifier
//! - **claims** (`C`): [`HashMap`]`<`[`pathlink::PathBuf`]`, [`SerMode`]`>` — a map of
//!   path → POSIX permission bits granted by this token segment
//!
//! # Python usage
//!
//! ```python
//! import asyncio, time
//! import rjwt
//!
//! class ExampleResolver:
//!     def __init__(self, host, actors, peers=None):
//!         self.host   = host
//!         self.actors = actors   # {actor_id_str: rjwt.Actor}
//!         self.peers  = peers or []
//!
//!     async def resolve(self, host: str, actor_id: str) -> rjwt.Actor:
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
//!     bob = rjwt.Actor("bob")
//!     example = ExampleResolver("http://example.com", {"bob": bob})
//!
//!     # The retailer.com app acts on Bob's behalf.
//!     app = rjwt.Actor("app")
//!     retailer = ExampleResolver("http://retailer.com", {"app": app}, peers=[example])
//!
//!     # example.com issues a token granting Bob access to specific paths.
//!     # Claims are expressed as {path_str: octal_mode_int}.
//!     bobs_claims = {"/home/bob": 0o755, "/tmp": 0o777}
//!     token = rjwt.Token("http://example.com", now, 30.0, "bob", bobs_claims)
//!     bobs_token = bob.sign_token(token)
//!
//!     # retailer.com verifies the token and reads Bob's claims.
//!     verified = await rjwt.Resolver(example).verify(bobs_token.jwt(), now)
//!     assert verified.claims().get("http://example.com", "bob") == bobs_claims
//!
//!     # retailer.com adds its own claim and re-signs.
//!     app_claims = {"/orders/42": 0o644}
//!     retail_token = app.consume_and_sign(verified, "http://retailer.com", app_claims, now)
//!
//!     # Bob's bank verifies the full chain.
//!     bank = ExampleResolver("http://bank.com", {}, peers=[example, retailer])
//!     final = await rjwt.Resolver(bank).verify(retail_token.jwt(), now)
//!
//!     # Both claim segments are accessible.
//!     assert final.claims().get("http://example.com", "bob") == bobs_claims
//!     assert final.claims().get("http://retailer.com", "app") == app_claims
//!
//! asyncio.run(main())
//! ```

mod actor;
mod claims;
mod resolve;
mod token;

use std::collections::HashMap;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hr_id::Id;
use pathlink::PathBuf as LinkBuf;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde::{Deserialize, Serialize};
use umask::Mode;

use ::rjwt::Error;

/// Host identifier type: a URL string (e.g. ``"http://example.com"``).
pub(crate) type H = String;
/// Actor identifier type: a human-readable, reference-counted string id.
pub(crate) type A = Id;
/// Claims payload type: a map of path → POSIX permission bits.
pub(crate) type C = HashMap<LinkBuf, SerMode>;

/// Newtype wrapper around [`umask::Mode`] that provides [`Serialize`]/[`Deserialize`]
/// by round-tripping through `u32`, since `umask` does not enable serde itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct SerMode(pub(crate) u32);

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

pub(crate) fn to_py_err(e: Error) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

pub(crate) fn unix_to_system_time(unix_secs: f64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs_f64(unix_secs)
}

pub(crate) fn system_time_to_unix(t: SystemTime) -> f64 {
    t.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Convert a Python `dict[str, int]` to `HashMap<LinkBuf, SerMode>`.
///
/// Keys are parsed as [`pathlink::PathBuf`]; values are treated as raw `u32` mode bits
/// (e.g. `0o755`) and stored as [`SerMode`].
pub(crate) fn py_to_claims(obj: &Bound<'_, PyAny>) -> PyResult<C> {
    let raw: HashMap<String, u32> = obj
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

/// Convert `HashMap<LinkBuf, SerMode>` to a Python `dict[str, int]`.
pub(crate) fn claims_to_py(py: Python<'_>, claims: &C) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    for (path, mode) in claims {
        dict.set_item(path.to_string(), mode.0)?;
    }
    Ok(dict.into_any().unbind())
}

// ── Module ───────────────────────────────────────────────────────────────────

#[pymodule]
fn rjwt(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<actor::PyActor>()?;
    m.add_class::<token::PyToken>()?;
    m.add_class::<token::PySignedToken>()?;
    m.add_class::<claims::PyClaims>()?;
    m.add_class::<resolve::PyResolver>()?;
    Ok(())
}
